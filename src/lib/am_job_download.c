//===-- am_job_download.c - job download stage implementation -------------===//
//
// Copyright (c) 2025 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Implementation of @ref tsci_am_job_download.
///
//===----------------------------------------------------------------------===//
#include "common/am.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"
#include "tek-steamclient/sp.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//===-- Private types -----------------------------------------------------===//

/// Compound of SteamPipe chunk request and associated delta chunk pointer.
typedef struct tscp_amjdw_req tscp_amjdw_req;
/// @copydoc tscp_amjdw_req
struct tscp_amjdw_req {
  /// SteamPipe chunk download and decode request.
  tek_sc_sp_multi_chunk_req req;
  /// Pointer to the associated delta chunk entry.
  tek_sc_dd_chunk *_Nullable dd_chunk;
};

/// Shared download context.
typedef struct tscp_amjdw_ctx tscp_amjdw_ctx;

/// Worker thread context.
typedef struct tscp_amjdw_wt_ctx tscp_amjdw_wt_ctx;
/// @copydoc tscp_amjdw_wt_ctx
struct tscp_amjdw_wt_ctx {
  /// Pointer to the download context.
  tscp_amjdw_ctx *_Nonnull ctx;
  /// Pointer to the array of SteamPipe chunk requests.
  tscp_amjdw_req *_Nonnull reqs;
  /// Number of entries in @ref reqs.
  int num_reqs;
  /// The result of running the thread. Receives an error if one occurs.
  tek_sc_err result;
  /// Asynchronous I/O context.
  tsci_os_aio_ctx aio_ctx;
};

/// @copydoc tscp_amjdw_ctx
struct tscp_amjdw_ctx {
  /// Pointer to the state descriptor of the item that the job is operating on.
  tsci_am_item_desc *_Nonnull desc;
  /// Pointer to the job context.
  tsci_am_job_ctx *_Nonnull job_ctx;
  /// Handle for the chunk buffer file.
  tek_sc_os_handle cb_handle;
  /// Size of the buffer reserved for every compressed chunk.
  int comp_buf_size;
  /// Total number of worker threads.
  int num_threads;
  /// Number of chunk request entries per worker thread.
  int num_reqs_per_thread;
  /// Pointer to the SteamPipe multi downloader instance.
  tek_sc_sp_multi_dlr *_Nonnull dlr;
  /// Pointer to the buffer to download chunks into.
  void *_Nonnull buffer;
  /// Pointer to the worker thread context array.
  tscp_amjdw_wt_ctx *_Nonnull wt_ctxs;
  /// Pointer to the worker thread array.
  pthread_t *_Nonnull threads;
};

//===-- Private functions -------------------------------------------------===//

/// Download chunks in specified directory.
///
/// @param [in, out] ctx
///    Pointer to the download context.
/// @param [in, out] wt_ctx
///    Pointer to the worker thread context.
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @return Value indicating whether the operation was successful.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static bool tscp_amjdw_process_dir(tscp_amjdw_ctx *_Nonnull ctx,
                                   tscp_amjdw_wt_ctx *_Nonnull wt_ctx,
                                   tek_sc_dd_dir *_Nonnull dir) {
  const int wt_index = wt_ctx - ctx->wt_ctxs;
  auto const dlr = ctx->dlr;
  auto const desc = &ctx->desc->desc;
  auto const state = &desc->job.state;
  auto const progress_current = &desc->job.progress_current_a;
  auto const upd_handler = ctx->desc->job_upd_handler;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags & TEK_SC_DD_FILE_FLAG_download)) {
      continue;
    }
    const bool is_new = file->flags & TEK_SC_DD_FILE_FLAG_new;
    if (is_new) {
      // Attempt to claim the entry for file setup
      tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
      if (atomic_compare_exchange_strong_explicit(
              &file->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
              memory_order_acquire, memory_order_acquire)) {
        // Open/create the file
        auto const handle = tsci_os_file_create_at_notrunc(
            dir->handle, file->file->name, TSCI_OS_FILE_ACCESS_write);
        if (handle == TSCI_OS_INVALID_HANDLE) {
          wt_ctx->result = tsci_os_io_err_at(
              dir->handle, file->file->name, TEK_SC_ERRC_am_io,
              tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
          atomic_store_explicit(&file->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_pending,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&file->status_a);
          return false;
        }
        if (atomic_fetch_sub_explicit(&dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(dir->handle);
          dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        // Finalize entry setup and mark it as active, notifying other threads
        file->handle = handle;
        atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_active,
                              memory_order_release);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&file->status_a);
      } else { // if (file->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup)
        switch (expected) {
        case TEK_SC_JOB_ENTRY_STATUS_setup:
          // Wait for another thread to finish file setup and check results
          tsci_os_futex_wait((const _Atomic(uint32_t) *)&file->status_a,
                             TEK_SC_JOB_ENTRY_STATUS_setup, UINT32_MAX);
          switch (atomic_load_explicit(&file->status_a, memory_order_acquire)) {
          case TEK_SC_JOB_ENTRY_STATUS_pending:
            // An error has occurred during file setup
            return false;
          case TEK_SC_JOB_ENTRY_STATUS_active:
            // Fallthrough to the same case in outer switch
            break;
          case TEK_SC_JOB_ENTRY_STATUS_done:
            // No more chunks to process in this file
            continue;
          default:
          }
          [[fallthrough]];
        case TEK_SC_JOB_ENTRY_STATUS_active:
          // Proceed to processing chunks
          break;
        case TEK_SC_JOB_ENTRY_STATUS_done:
          // Skip this entry
          continue;
        default:
        } // switch (expected)
      } // if (file->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup) else
    } else if (atomic_load_explicit(&file->status_a,
                                    memory_order_relaxed) ==
               TEK_SC_JOB_ENTRY_STATUS_done) { // if (is_new)
      continue;
    } // if (is_new) else if (...)
    auto const handle = is_new ? file->handle : ctx->cb_handle;
    bool registered = false;
    auto next_req = wt_ctx->reqs;
    int num_submitted = 0;
    // Iterate chunks
    for (int j = 0; j < file->num_chunks; ++j) {
      auto const chunk = &file->chunks[j];
      // Attempt to claim the chunk
      tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
      if (!atomic_compare_exchange_strong_explicit(
              &chunk->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_active,
              memory_order_relaxed, memory_order_relaxed)) {
        continue;
      }
      // Pause if requested
      if (atomic_load_explicit(state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        wt_ctx->result = tsc_err_basic(TEK_SC_ERRC_paused);
        return false;
      }
      // Register the file for AIO if necessary
      if (!registered) {
        auto const errc = tsci_os_aio_register_file(&wt_ctx->aio_ctx, handle);
        if (errc) {
          wt_ctx->result = tsci_os_io_err(handle, TEK_SC_ERRC_am_io, errc,
                                          TEK_SC_ERR_IO_TYPE_aio_reg);
          return false;
        }
        registered = true;
      }
      // Submit chunk to the downloader
      next_req->req.chunk = chunk->chunk;
      next_req->dd_chunk = chunk;
      wt_ctx->result =
          tek_sc_sp_multi_dlr_submit_req(dlr, wt_index, &next_req->req);
      if (!tek_sc_err_success(&wt_ctx->result)) {
        return false;
      }
      ++next_req;
      enum { NEXT_CHUNK, NEXT_FILE, NEXT_DIR } proceed_type = NEXT_CHUNK;
      if (++num_submitted == wt_ctx->num_reqs) {
        // Process one of the pending chunks
        tek_sc_sp_multi_chunk_req *req;
        for (;;) {
          req = tek_sc_sp_multi_dlr_process(dlr, wt_index, &wt_ctx->result);
          if (!req) {
            if (tek_sc_err_success(&wt_ctx->result)) {
              continue;
            }
            return false;
          }
          break;
        }
        if (!tek_sc_err_success(&req->result)) {
          wt_ctx->result = req->result;
          return false;
        }
        --num_submitted;
        auto const chunk = req->chunk;
        next_req = (tscp_amjdw_req *)req;
        auto const dd_chunk = next_req->dd_chunk;
        // Write chunk data to the file
        auto const errc = tsci_os_aio_write(
            &wt_ctx->aio_ctx, req->data, chunk->size,
            is_new ? chunk->offset : dd_chunk->chunk_buf_offset);
        if (errc) {
          wt_ctx->result = tsci_os_io_err(handle, TEK_SC_ERRC_am_io, errc,
                                          TEK_SC_ERR_IO_TYPE_write);
          return false;
        }
        // Update delta entries
        atomic_store_explicit(&dd_chunk->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        if (atomic_fetch_sub_explicit(&file->num_rem_children_a, 1,
                                      memory_order_relaxed) == 1) {
          atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                                memory_order_relaxed);
          if (is_new) {
            tsci_os_close_handle(file->handle);
            file->handle = TSCI_OS_INVALID_HANDLE;
          }
          if (atomic_fetch_sub_explicit(&dir->num_rem_children_a, 1,
                                        memory_order_relaxed) == 1) {
            tsci_am_job_finish_dir(dir);
            proceed_type = NEXT_DIR;
          } else {
            proceed_type = NEXT_FILE;
          }
        }
        // Report progress
        atomic_fetch_add_explicit(progress_current, chunk->comp_size,
                                  memory_order_relaxed);
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
      } // if (++num_submitted == wt_ctx->num_reqs)
      if (proceed_type == NEXT_FILE) {
        break;
      }
      if (proceed_type == NEXT_DIR) {
        return true;
      }
    } // for (int j = 0; j < file->num_chunks; ++j)
    // Process remaining chunks
    while (num_submitted--) {
      auto const req =
          tek_sc_sp_multi_dlr_process(dlr, wt_index, &wt_ctx->result);
      if (!req) {
        if (tek_sc_err_success(&wt_ctx->result)) {
          ++num_submitted;
          continue;
        }
        return false;
      }
      if (!tek_sc_err_success(&req->result)) {
        wt_ctx->result = req->result;
        return false;
      }
      auto const chunk = req->chunk;
      auto const dd_chunk = ((tscp_amjdw_req *)req)->dd_chunk;
      // Write chunk data to the file
      auto const errc = tsci_os_aio_write(
          &wt_ctx->aio_ctx, req->data, chunk->size,
          is_new ? chunk->offset : dd_chunk->chunk_buf_offset);
      if (errc) {
        wt_ctx->result = tsci_os_io_err(handle, TEK_SC_ERRC_am_io, errc,
                                        TEK_SC_ERR_IO_TYPE_write);
        return false;
      }
      // Update delta entries
      atomic_store_explicit(&dd_chunk->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                            memory_order_relaxed);
      bool last_file = false;
      if (atomic_fetch_sub_explicit(&file->num_rem_children_a, 1,
                                    memory_order_relaxed) == 1) {
        atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        if (is_new) {
          tsci_os_close_handle(file->handle);
          file->handle = TSCI_OS_INVALID_HANDLE;
        }
        if (atomic_fetch_sub_explicit(&dir->num_rem_children_a, 1,
                                      memory_order_relaxed) == 1) {
          tsci_am_job_finish_dir(dir);
          last_file = true;
        }
      }
      // Report progress
      atomic_fetch_add_explicit(progress_current, chunk->comp_size,
                                memory_order_relaxed);
      if (upd_handler) {
        upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
      }
      if (last_file) {
        return true;
      }
    } // while (num_submitted--)
  } // for (int i = 0; i < dir->num_files; ++i)
  // Iterate subdirectories
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags & TEK_SC_DD_DIR_FLAG_children_download)) {
      continue;
    }
    const bool has_new = subdir->flags & TEK_SC_DD_DIR_FLAG_children_new;
    if (has_new) {
      // Attempt to claim the entry for subdirectory setup
      tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
      if (atomic_compare_exchange_strong_explicit(
              &subdir->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
              memory_order_acquire, memory_order_acquire)) {
        // Setup the subdirectory
        auto const handle =
            tsci_os_dir_create_at(dir->handle, subdir->dir->name);
        if (handle == TSCI_OS_INVALID_HANDLE) {
          wt_ctx->result = tsci_os_io_err_at(
              dir->handle, subdir->dir->name, TEK_SC_ERRC_am_io,
              tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
          atomic_store_explicit(&subdir->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_pending,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
          return false;
        }
        if (atomic_fetch_sub_explicit(&dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(dir->handle);
          dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        // Finalize entry setup and mark it as active, notifying other threads
        subdir->handle = handle;
        atomic_store_explicit(&subdir->status_a, TEK_SC_JOB_ENTRY_STATUS_active,
                              memory_order_release);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
      } else { // if (subdir->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup)
        switch (expected) {
        case TEK_SC_JOB_ENTRY_STATUS_setup:
          // Wait for another thread to finish subdirectory setup and check
          //    results
          tsci_os_futex_wait((const _Atomic(uint32_t) *)&subdir->status_a,
                             TEK_SC_JOB_ENTRY_STATUS_setup, UINT32_MAX);
          switch (
              atomic_load_explicit(&subdir->status_a, memory_order_acquire)) {
          case TEK_SC_JOB_ENTRY_STATUS_pending:
            // An error has occurred during subdirectory setup
            return false;
          case TEK_SC_JOB_ENTRY_STATUS_active:
            // Fallthrough to the same case in outer switch
            break;
          case TEK_SC_JOB_ENTRY_STATUS_done:
            // The subdirectory doesn't exist, there's nothing to process
            continue;
          default:
          }
          [[fallthrough]];
        case TEK_SC_JOB_ENTRY_STATUS_active:
          // Proceed to processing children
          break;
        case TEK_SC_JOB_ENTRY_STATUS_done:
          // Skip this entry
          continue;
        default:
        } // switch (expected)
      } // if (subdir->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup) else
    } else if (atomic_load_explicit(&subdir->status_a,
                                    memory_order_acquire) ==
               TEK_SC_JOB_ENTRY_STATUS_done) { // if (is_new)
      continue;
    } // if (is_new) else if (...)
    // Recurse to subdirectory
    if (!tscp_amjdw_process_dir(ctx, wt_ctx, subdir)) {
      return false;
    }
  }
  return true;
}

/// Download worker thread procedure.
///
/// @param [in, out] arg
///    Pointer to a @ref tscp_amjdw_wt_ctx.
/// @return `nullptr`.
[[gnu::nonnull(1), gnu::accress(read_write, 1)]] static void
    *_Nullable tscp_amjdw_wt_proc(void *_Nonnull arg) {
  tscp_amjdw_wt_ctx *const wt_ctx = arg;
  auto const ctx = wt_ctx->ctx;
  const int ind = wt_ctx - ctx->wt_ctxs;
  tek_sc_os_char name[16];
  TSCI_OS_SNPRINTF(name, sizeof name / sizeof *name,
                   TEK_SC_OS_STR("tsc worker #%u"), ind);
  tsci_os_set_thread_name(name);
  auto const data_base = ctx->buffer + 0x100000 * ind;
  auto const comp_data_base =
      ctx->buffer + 0x100000 * ctx->num_threads +
      ctx->comp_buf_size * ctx->num_reqs_per_thread * ind;
  for (int i = 0; i < wt_ctx->num_reqs; ++i) {
    auto const req = &wt_ctx->reqs[i];
    req->req.comp_data = comp_data_base + ctx->comp_buf_size * i;
    req->req.data = data_base;
  }
  auto const errc = tsci_os_aio_ctx_init(&wt_ctx->aio_ctx, data_base, 0x100000);
  auto const state = &ctx->desc->desc.job.state;
  if (errc) {
    tek_sc_am_job_state expected = TEK_SC_AM_JOB_STATE_running;
    if (atomic_compare_exchange_strong_explicit(
            state, &expected, TEK_SC_AM_JOB_STATE_pause_pending,
            memory_order_relaxed, memory_order_relaxed)) {
      tek_sc_sp_multi_dlr_cancel(ctx->dlr);
    }
    wt_ctx->result = tsci_err_os(TEK_SC_ERRC_aio_init, errc);
    return nullptr;
  }
  wt_ctx->result = tsc_err_ok();
  if (!tscp_amjdw_process_dir(ctx, wt_ctx, ctx->job_ctx->delta.dirs)) {
    tek_sc_am_job_state expected = TEK_SC_AM_JOB_STATE_running;
    if (atomic_compare_exchange_strong_explicit(
            state, &expected, TEK_SC_AM_JOB_STATE_pause_pending,
            memory_order_relaxed, memory_order_relaxed)) {
      tek_sc_sp_multi_dlr_cancel(ctx->dlr);
    }
  }
  tsci_os_aio_ctx_destroy(&wt_ctx->aio_ctx);
  return nullptr;
}

/// Set reference counters and get current download progress for specified
///    directory.
///
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @return Current download progress for the directory, in bytes.
[[gnu::nonnull(1), gnu::access(read_write, 1)]]
static int64_t tscp_amjdw_init_dir(tek_sc_dd_dir *_Nonnull dir) {
  int64_t progress = 0;
  int ref_count = 0;
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags & TEK_SC_DD_FILE_FLAG_download)) {
      continue;
    }
    for (int j = 0; j < file->num_chunks; ++j) {
      auto const chunk = &file->chunks[j];
      if (chunk->status == TEK_SC_JOB_ENTRY_STATUS_done) {
        progress += chunk->chunk->comp_size;
      } else {
        ++file->num_rem_children;
      }
    }
    if (file->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      if (file->flags & TEK_SC_DD_FILE_FLAG_new) {
        ++ref_count;
      }
      ++dir->num_rem_children;
    }
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags & TEK_SC_DD_DIR_FLAG_children_download)) {
      continue;
    }
    progress += tscp_amjdw_init_dir(subdir);
    if (subdir->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      if (subdir->flags & TEK_SC_DD_DIR_FLAG_children_new) {
        ++ref_count;
      }
      ++dir->num_rem_children;
    }
  }
  atomic_init(&dir->ref_count, ref_count);
  return progress;
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_job_download(tek_sc_am *am, tsci_am_item_desc *desc,
                                tsci_am_job_ctx *ctx) {
  tscp_amjdw_ctx dwctx;
  dwctx.desc = desc;
  dwctx.job_ctx = ctx;
  auto const root_delta_dir = ctx->delta.dirs;
  // Setup progress and notify update handler
  auto const job = &desc->desc.job;
  job->stage = TEK_SC_AM_JOB_STAGE_downloading;
  job->progress_current = tscp_amjdw_init_dir(root_delta_dir);
  job->progress_total = ctx->delta.download_size;
  auto const upd_handler = desc->job_upd_handler;
  if (upd_handler) {
    upd_handler(&desc->desc,
                TEK_SC_AM_UPD_TYPE_stage | TEK_SC_AM_UPD_TYPE_progress);
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
  }
  atomic_init(&root_delta_dir->ref_count, -1);
  root_delta_dir->handle = ctx->img_dir_handle;
  // Scan all delta files to determine if chunk buffer file is needed
  dwctx.cb_handle = TSCI_OS_INVALID_HANDLE;
  for (int i = 0; i < ctx->delta.num_files; ++i) {
    auto const flags = ctx->delta.files[i].flags;
    if (flags & TEK_SC_DD_FILE_FLAG_download &&
        !(flags & TEK_SC_DD_FILE_FLAG_new)) {
      // Open the chunk buffer file right here
      dwctx.cb_handle = tsci_os_file_create_at_notrunc(
          ctx->dir_handle, TEK_SC_OS_STR("chunk_buf"),
          TSCI_OS_FILE_ACCESS_write);
      if (dwctx.cb_handle == TSCI_OS_INVALID_HANDLE) {
        return tsci_os_io_err_at(ctx->dir_handle, TEK_SC_OS_STR("chunk_buf"),
                                 TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                                 TEK_SC_ERR_IO_TYPE_open);
      }
      break;
    }
  }
  // Scan all delta chunks to determine max compressed chunk size
  dwctx.comp_buf_size = 0;
  for (int i = 0; i < ctx->delta.num_chunks; ++i) {
    auto const comp_size = ctx->delta.chunks[i].chunk->comp_size;
    if (comp_size > dwctx.comp_buf_size) {
      dwctx.comp_buf_size = comp_size;
    }
  }
  // Round comp_buf_size up to the next page boundary
  dwctx.comp_buf_size = (dwctx.comp_buf_size + 0xFFF) & ~0xFFF;
  tek_sc_err res;
  // Initialize the rest of download context
  auto const depot_id = desc->desc.id.depot_id;
  tek_sc_aes256_key depot_key;
  if (!tek_sc_lib_get_depot_key(am->lib_ctx, desc->desc.id.depot_id,
                                depot_key)) {
    res = tsc_err_basic(TEK_SC_ERRC_depot_key_not_found);
    goto close_cb_file;
  }
  tek_sc_sp_multi_dlr_desc dlr_desc = {.num_threads = ctx->nproc,
                                       .num_srvs = ctx->num_sp_srvs,
                                       .srvs = ctx->sp_srvs};
  dwctx.dlr = tek_sc_sp_multi_dlr_create(&dlr_desc, depot_id, depot_key, &res);
  if (!dwctx.dlr) {
    goto close_cb_file;
  }
  desc->dlr = dwctx.dlr;
  dwctx.num_threads = dlr_desc.num_threads;
  dwctx.num_reqs_per_thread = dlr_desc.num_reqs_per_thread;
  const int num_threads = dlr_desc.num_threads;
  const int num_reqs = dlr_desc.num_reqs_per_thread * (num_threads - 1) +
                       dlr_desc.num_reqs_last_thread;
  const size_t buf_size =
      0x100000 * num_threads + dwctx.comp_buf_size * num_reqs;
  dwctx.buffer = tsci_os_mem_alloc(buf_size);
  if (!dwctx.buffer) {
    res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
    goto destroy_dlr;
  }
  dwctx.wt_ctxs =
      malloc((sizeof *dwctx.wt_ctxs + sizeof *dwctx.threads) * num_threads +
             sizeof(tscp_amjdw_req) * num_reqs);
  if (!dwctx.wt_ctxs) {
    res = tsc_err_basic(TEK_SC_ERRC_mem_alloc);
    goto free_buffer;
  }
  dwctx.threads = (pthread_t *)(dwctx.wt_ctxs + num_threads);
  auto const reqs = (tscp_amjdw_req *)(dwctx.threads + num_threads);
  for (int i = 0; i < num_threads; ++i) {
    auto const wt_ctx = &dwctx.wt_ctxs[i];
    wt_ctx->ctx = &dwctx;
    wt_ctx->reqs = &reqs[dlr_desc.num_reqs_per_thread * i];
    wt_ctx->num_reqs = dlr_desc.num_reqs_per_thread;
  }
  dwctx.wt_ctxs[num_threads - 1].num_reqs = dlr_desc.num_reqs_last_thread;
  // Start worker threads
  for (int i = 0; i < num_threads; ++i) {
    if (pthread_create(&dwctx.threads[i], nullptr, tscp_amjdw_wt_proc,
                       &dwctx.wt_ctxs[i])) {
      tek_sc_am_job_state expected = TEK_SC_AM_JOB_STATE_running;
      if (atomic_compare_exchange_strong_explicit(
              &job->state, &expected, TEK_SC_AM_JOB_STATE_pause_pending,
              memory_order_relaxed, memory_order_relaxed)) {
        tek_sc_sp_multi_dlr_cancel(dwctx.dlr);
      }
      for (int j = 0; j < i; ++j) {
        pthread_join(dwctx.threads[j], nullptr);
        free((void *)dwctx.wt_ctxs[j].result.uri);
      }
      res = tsc_err_basic(TEK_SC_ERRC_wt_start);
      goto free_arrs;
    }
  }
  // Wait for worker threads to exit and gather their results
  res = tsc_err_ok();
  for (int i = 0; i < num_threads; ++i) {
    pthread_join(dwctx.threads[i], nullptr);
    auto const wt_res = &dwctx.wt_ctxs[i].result;
    if (tek_sc_err_success(wt_res)) {
      continue;
    }
    if (tek_sc_err_success(&res) || (res.primary == TEK_SC_ERRC_paused &&
                                     wt_res->primary != TEK_SC_ERRC_paused)) {
      res = *wt_res;
    } else {
      free((void *)wt_res->uri);
    }
  }
  // Make sure no dangling handles are left opened
  for (int i = 0; i < ctx->delta.num_files; ++i) {
    auto const file = &ctx->delta.files[i];
    if (file->handle != TSCI_OS_INVALID_HANDLE) {
      tsci_os_close_handle(file->handle);
      file->handle = TSCI_OS_INVALID_HANDLE;
    }
  }
  for (int i = 1; i < ctx->delta.num_dirs; ++i) {
    auto const dir = &ctx->delta.dirs[i];
    if (dir->handle != TSCI_OS_INVALID_HANDLE) {
      tsci_os_close_handle(dir->handle);
      dir->handle = TSCI_OS_INVALID_HANDLE;
    }
  }
  if (tek_sc_err_success(&res)) {
    // Reset delta progress and set the next stage
    for (int i = 0; i < ctx->delta.num_chunks; ++i) {
      ctx->delta.chunks[i].status = TEK_SC_JOB_ENTRY_STATUS_pending;
    }
    for (int i = 0; i < ctx->delta.num_files; ++i) {
      auto const file = &ctx->delta.files[i];
      file->status = TEK_SC_JOB_ENTRY_STATUS_pending;
      file->num_rem_children = 0;
    }
    for (int i = 0; i < ctx->delta.num_dirs; ++i) {
      auto const dir = &ctx->delta.dirs[i];
      dir->status = TEK_SC_JOB_ENTRY_STATUS_pending;
      dir->num_rem_children = 0;
    }
    ctx->delta.stage = ctx->delta.num_io_ops ? TEK_SC_DD_STAGE_patching
                                             : TEK_SC_DD_STAGE_installing;
  }
  // Cleanup
free_arrs:
  free(dwctx.wt_ctxs);
free_buffer:
  tsci_os_mem_free(dwctx.buffer, buf_size);
destroy_dlr:
  desc->dlr = nullptr;
  tek_sc_sp_multi_dlr_destroy(dwctx.dlr);
close_cb_file:
  if (dwctx.cb_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(dwctx.cb_handle);
  }
  return res;
}
