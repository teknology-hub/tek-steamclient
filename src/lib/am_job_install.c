//===-- am_job_install.c - job install stage implementation ---------------===//
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
/// Implementation of @ref tsci_am_job_install.
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

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//===-- Private types -----------------------------------------------------===//

/// Shared installation context.
typedef struct tscp_amji_ctx tscp_amji_ctx;

/// Worker thread context.
typedef struct tscp_amji_wt_ctx tscp_amji_wt_ctx;
/// @copydoc tscp_amji_wt_ctx
struct tscp_amji_wt_ctx {
  /// Pointer to the installation context.
  tscp_amji_ctx *_Nonnull ctx;
  /// The result of running the thread. Receives an error if one occurs.
  tek_sc_err result;
};

/// @copydoc tscp_amji_ctx
struct tscp_amji_ctx {
  /// Pointer to the state descriptor of the item that the job is operating on.
  tsci_am_item_desc *_Nonnull desc;
  /// Pointer to the job context.
  tsci_am_job_ctx *_Nonnull job_ctx;
  /// Handle for the chunk buffer file.
  tek_sc_os_handle cb_handle;
  /// Number of currently running worker threads.
  _Atomic(uint32_t) num_wts_active;
  /// Current verification progress value.
  _Atomic(int64_t) progress;
  /// Pointer to the temporary copy buffer.
  void *_Nonnull buffer;
  /// Pointer to the worker thread context array.
  tscp_amji_wt_ctx *_Nonnull wt_ctxs;
};

//===-- Private functions -------------------------------------------------===//

/// Count the total number of chunks in specified directory tree.
///
/// @param [in] dir
///    Pointer to the delta directory entry to process.
/// @return Total number of chunks in the directory tree.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int64_t tscp_amji_count_dir(const tek_sc_dd_dir *_Nonnull dir) {
  int64_t res = 0;
  for (int i = 0; i < dir->num_files; ++i) {
    res += dir->files[i].file->num_chunks;
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    res += tscp_amji_count_dir(&dir->subdirs[i]);
  }
  return res;
}

/// Install data in specified directory.
///
/// @param [in, out] ctx
///    Pointer to the installation context.
/// @param [in, out] wt_ctx
///    Pointer to the worker thread context.
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @param [in, out] copy_args
///    Pointer to the thread's copy arguments structure.
/// @return Value indicating whether the operation was successful.
[[gnu::nonnull(1, 2, 3, 4), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_write, 3),
  gnu::access(read_write, 4)]]
static bool tscp_amji_process_dir(tscp_amji_ctx *_Nonnull ctx,
                                  tscp_amji_wt_ctx *_Nonnull wt_ctx,
                                  tek_sc_dd_dir *_Nonnull dir,
                                  tsci_os_copy_args *_Nonnull copy_args) {
  auto const desc = &ctx->desc->desc;
  auto const state = &desc->job.state;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags &
          (TEK_SC_DD_FILE_FLAG_new | TEK_SC_DD_FILE_FLAG_download))) {
      continue;
    }
    const bool is_new = file->flags & TEK_SC_DD_FILE_FLAG_new;
    if (is_new) {
      // Pause if requested
      if (atomic_load_explicit(state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        wt_ctx->result = tsc_err_basic(TEK_SC_ERRC_paused);
        return false;
      }
      // Attempt to claim the entry for processing
      tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
      if (!atomic_compare_exchange_strong_explicit(
              &file->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_active,
              memory_order_relaxed, memory_order_relaxed)) {
        continue;
      }
      auto const name = file->file->name;
      auto const dm_flags = file->file->flags;
      if (file->flags & TEK_SC_DD_FILE_FLAG_download) {
        // Move the file, fallback to copying if the installation is on
        //    different filesystem
        if (!copy_args->not_same_dev) {
          if (!tsci_os_file_move(dir->cache_handle, dir->handle, name)) {
            auto const errc = tsci_os_get_last_error();
            if (errc == TSCI_OS_ERR_NOT_SAME_DEV) {
              copy_args->not_same_dev = true;
            } else {
              wt_ctx->result =
                  tsci_os_io_err_at(dir->cache_handle, name, TEK_SC_ERRC_am_io,
                                    errc, TEK_SC_ERR_IO_TYPE_move);
              return false;
            }
          }
        }
        if (copy_args->not_same_dev) {
          copy_args->src_handle = dir->cache_handle;
          copy_args->tgt_handle = dir->handle;
          if (!tsci_os_file_copy(copy_args, name, file->file->size,
                                 TEK_SC_ERRC_am_io)) {
            wt_ctx->result = copy_args->error;
            return false;
          }
        }
        if (!tsci_os_file_apply_flags_at(dir->handle, name, dm_flags)) {
          wt_ctx->result = tsci_os_io_err_at(
              dir->handle, name, TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
              TEK_SC_ERR_IO_TYPE_apply_flags);
          return false;
        }
      } else { // if (file->flags & TEK_SC_DD_FILE_FLAG_download)
        // Empty file, just create it
        if (dm_flags & TEK_SC_DM_FILE_FLAG_symlink) {
          if (!tsci_os_symlink_at(file->file->target_path, dir->handle, name)) {
            wt_ctx->result = tsci_os_io_err_at(
                dir->handle, name, TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                TEK_SC_ERR_IO_TYPE_symlink);
            return false;
          }
        } else {
          auto const handle = tsci_os_file_create_at(dir->handle, name,
                                                     TSCI_OS_FILE_ACCESS_rdwr,
                                                     TSCI_OS_FILE_OPT_trunc);
          if (handle == TSCI_OS_INVALID_HANDLE) {
            wt_ctx->result = tsci_os_io_err_at(
                dir->handle, name, TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                TEK_SC_ERR_IO_TYPE_open);
            return false;
          }
          if (!tsci_os_file_apply_flags(handle, dm_flags)) {
            wt_ctx->result = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                            tsci_os_get_last_error(),
                                            TEK_SC_ERR_IO_TYPE_apply_flags);
            tsci_os_close_handle(handle);
            return false;
          }
          tsci_os_close_handle(handle);
        }
      } // if (file->flags & TEK_SC_DD_FILE_FLAG_download) else
      if (atomic_fetch_sub_explicit(&dir->ref_count, 1, memory_order_relaxed) ==
          1) {
        tsci_os_close_handle(dir->handle);
        dir->handle = TSCI_OS_INVALID_HANDLE;
        tsci_os_close_handle(dir->cache_handle);
        dir->cache_handle = TSCI_OS_INVALID_HANDLE;
      }
      atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                            memory_order_relaxed);
      const bool last_ref =
          atomic_fetch_sub_explicit(&dir->num_rem_children_a, 1,
                                    memory_order_relaxed) == 1;
      if (last_ref) {
        tsci_am_job_finish_dir(dir);
      }
      const int num_chunks = file->file->num_chunks;
      if (num_chunks) {
        atomic_fetch_add_explicit(&ctx->progress, num_chunks,
                                  memory_order_relaxed);
      }
      if (last_ref) {
        return true;
      }
      continue;
    } // if (is_new)
    // Attempt to claim the entry for file setup
    tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
    if (atomic_compare_exchange_strong_explicit(
            &file->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
            memory_order_acquire, memory_order_acquire)) {
      // Open the file
      auto const handle = tsci_os_file_open_at(dir->handle, file->file->name,
                                               TSCI_OS_FILE_ACCESS_write,
                                               TSCI_OS_FILE_OPT_sync);
      if (handle == TSCI_OS_INVALID_HANDLE) {
        wt_ctx->result = tsci_os_io_err_at(
            dir->handle, file->file->name, TEK_SC_ERRC_am_io,
            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
        atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_pending,
                              memory_order_relaxed);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&file->status_a);
        return false;
      }
      if (atomic_fetch_sub_explicit(&dir->ref_count, 1, memory_order_relaxed) ==
          1) {
        tsci_os_close_handle(dir->handle);
        dir->handle = TSCI_OS_INVALID_HANDLE;
        if (dir->flags & TEK_SC_DD_DIR_FLAG_children_new) {
          tsci_os_close_handle(dir->cache_handle);
          dir->cache_handle = TSCI_OS_INVALID_HANDLE;
        }
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
    copy_args->src_handle = ctx->cb_handle;
    copy_args->tgt_handle = file->handle;
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
      // Copy the chunk
      auto const dm_chunk = chunk->chunk;
      if (!tsci_os_file_copy_chunk(copy_args, chunk->chunk_buf_offset,
                                   dm_chunk->offset, dm_chunk->size)) {
        wt_ctx->result =
            tsci_os_io_err(copy_args->src_handle, TEK_SC_ERRC_am_io,
                           tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_copy);
        return false;
      }
      // Update delta entries
      atomic_store_explicit(&chunk->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                            memory_order_relaxed);
      enum { NEXT_CHUNK, NEXT_FILE, NEXT_DIR } proceed_type;
      if (atomic_fetch_sub_explicit(&file->num_rem_children_a, 1,
                                    memory_order_relaxed) == 1) {
        atomic_store_explicit(&file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        tsci_os_close_handle(file->handle);
        file->handle = TSCI_OS_INVALID_HANDLE;
        if (atomic_fetch_sub_explicit(&dir->num_rem_children_a, 1,
                                      memory_order_relaxed) == 1) {
          tsci_am_job_finish_dir(dir);
          proceed_type = NEXT_DIR;
        } else {
          proceed_type = NEXT_FILE;
        }
      } else {
        proceed_type = NEXT_CHUNK;
      }
      // Report progress
      atomic_fetch_add_explicit(&ctx->progress, 1, memory_order_relaxed);
      if (proceed_type == NEXT_FILE) {
        break;
      }
      if (proceed_type == NEXT_DIR) {
        return true;
      }
    } // for (int j = 0; j < file->num_chunks; ++j)
  } // for (int i = 0; i < dir->num_files; ++i)
  // Iterate subdirectories
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags &
          (TEK_SC_DD_DIR_FLAG_new | TEK_SC_DD_DIR_FLAG_children_new |
           TEK_SC_DD_DIR_FLAG_children_download))) {
      continue;
    }
    const bool is_empty = subdir->flags == TEK_SC_DD_DIR_FLAG_new;
    // Attempt to claim the entry for subdirectory setup
    tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
    if (atomic_compare_exchange_strong_explicit(
            &subdir->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
            memory_order_acquire, memory_order_acquire)) {
      // Setup the subdirectory
      enum {
        DD_DIR_NEW_NON_EMPTY =
            TEK_SC_DD_DIR_FLAG_new | TEK_SC_DD_DIR_FLAG_children_download
      };
      if ((subdir->flags & DD_DIR_NEW_NON_EMPTY) == DD_DIR_NEW_NON_EMPTY &&
          !copy_args->not_same_dev) {
        // Attempt to move the directory first.
        if (tsci_os_dir_move(dir->cache_handle, dir->handle,
                             subdir->dir->name)) {
          if (atomic_fetch_sub_explicit(&dir->ref_count, 1,
                                        memory_order_relaxed) == 1) {
            tsci_os_close_handle(dir->handle);
            dir->handle = TSCI_OS_INVALID_HANDLE;
            tsci_os_close_handle(dir->cache_handle);
            dir->cache_handle = TSCI_OS_INVALID_HANDLE;
          }
          atomic_store_explicit(&subdir->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
          atomic_fetch_add_explicit(&ctx->progress, tscp_amji_count_dir(subdir), memory_order_relaxed);
          if (atomic_fetch_sub_explicit(&dir->num_rem_children_a, 1,
                                        memory_order_relaxed) == 1) {
            tsci_am_job_finish_dir(dir);
            return true;
          }
          continue;
        } else { // if (tsci_os_dir_move(...))
          switch (tsci_os_get_last_error()) {
          case TSCI_OS_ERR_ALREADY_EXISTS:
            break;
          case TSCI_OS_ERR_NOT_SAME_DEV:
            copy_args->not_same_dev = true;
            break;
          default:
            wt_ctx->result = tsci_os_io_err_at(
                dir->cache_handle, subdir->dir->name, TEK_SC_ERRC_am_io,
                tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_move);
            atomic_store_explicit(&subdir->status_a,
                                  TEK_SC_JOB_ENTRY_STATUS_pending,
                                  memory_order_relaxed);
            tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
            return false;
          }
        } // if (tsci_os_dir_move(...)) else
      } // if (new non empty && !copy_args->not_same_dev)
      auto const handle =
          (subdir->flags & TEK_SC_DD_DIR_FLAG_new)
              ? tsci_os_dir_create_at(dir->handle, subdir->dir->name)
              : tsci_os_dir_open_at(dir->handle, subdir->dir->name);
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
      if (is_empty) {
        tsci_os_close_handle(handle);
        if (atomic_fetch_sub_explicit(&dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(dir->handle);
          dir->handle = TSCI_OS_INVALID_HANDLE;
          if (dir->flags & TEK_SC_DD_DIR_FLAG_children_new) {
            tsci_os_close_handle(dir->cache_handle);
            dir->cache_handle = TSCI_OS_INVALID_HANDLE;
          }
        }
        tsci_am_job_finish_dir(subdir);
        continue;
      }
      enum {
        DD_DIR_NEW_DW_FILES = TEK_SC_DD_DIR_FLAG_children_new |
                              TEK_SC_DD_DIR_FLAG_children_download
      };
      if ((subdir->flags & DD_DIR_NEW_DW_FILES) == DD_DIR_NEW_DW_FILES) {
        subdir->cache_handle =
            tsci_os_dir_open_at(dir->cache_handle, subdir->dir->name);
        if (subdir->cache_handle == TSCI_OS_INVALID_HANDLE) {
          wt_ctx->result = tsci_os_io_err_at(
              dir->cache_handle, subdir->dir->name, TEK_SC_ERRC_am_io,
              tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
          atomic_store_explicit(&subdir->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_pending,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
          return false;
        }
      }
      if (atomic_fetch_sub_explicit(&dir->ref_count, 1, memory_order_relaxed) ==
          1) {
        tsci_os_close_handle(dir->handle);
        dir->handle = TSCI_OS_INVALID_HANDLE;
        if (dir->flags & TEK_SC_DD_DIR_FLAG_children_new) {
          tsci_os_close_handle(dir->cache_handle);
          dir->cache_handle = TSCI_OS_INVALID_HANDLE;
        }
      }
      // Finalize entry setup and mark it as active, notifying other threads
      subdir->handle = handle;
      atomic_store_explicit(&subdir->status_a, TEK_SC_JOB_ENTRY_STATUS_active,
                            memory_order_release);
      tsci_os_futex_wake((_Atomic(uint32_t) *)&subdir->status_a);
    } else { // if (subdir->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup)
      if (is_empty) {
        // No need to wait on this subdirectory
        continue;
      }
      switch (expected) {
      case TEK_SC_JOB_ENTRY_STATUS_setup:
        // Wait for another thread to finish subdirectory setup and check
        //    results
        tsci_os_futex_wait((const _Atomic(uint32_t) *)&subdir->status_a,
                           TEK_SC_JOB_ENTRY_STATUS_setup, UINT32_MAX);
        switch (atomic_load_explicit(&subdir->status_a, memory_order_acquire)) {
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
    // Recurse to subdirectory
    if (!tscp_amji_process_dir(ctx, wt_ctx, subdir, copy_args)) {
      return false;
    }
  } // for (int i = 0; i < dir->num_subdirs; ++i)
  return true;
}

/// Installation worker thread procedure.
///
/// @param [in, out] arg
///    Pointer to a @ref tscp_amji_wt_ctx.
/// @return `nullptr`.
[[gnu::nonnull(1), gnu::accress(read_write, 1)]] static void
    *_Nullable tscp_amji_wt_proc(void *_Nonnull arg) {
  tscp_amji_wt_ctx *const wt_ctx = arg;
  auto const ctx = wt_ctx->ctx;
  const int ind = wt_ctx - ctx->wt_ctxs;
  tek_sc_os_char name[16];
  TSCI_OS_SNPRINTF(name, sizeof name / sizeof *name,
                   TEK_SC_OS_STR("tsc worker #%u"), ind);
  tsci_os_set_thread_name(name);
  wt_ctx->result = tsc_err_ok();
  tsci_os_copy_args copy_args;
  copy_args.not_same_dev = false;
  copy_args.buf = ctx->buffer + 0x100000 * ind;
  copy_args.buf_size = 0x100000;
  if (!tscp_amji_process_dir(ctx, wt_ctx, ctx->job_ctx->delta.dirs,
                             &copy_args)) {
    atomic_store_explicit(&ctx->desc->desc.job.state,
                          TEK_SC_AM_JOB_STATE_pause_pending,
                          memory_order_relaxed);
  }
  if (atomic_fetch_sub_explicit(&ctx->num_wts_active, 1,
                                memory_order_relaxed) == 1) {
    tsci_os_futex_wake(&ctx->num_wts_active);
  }
  return nullptr;
}

/// Set reference counters and get current installation progress for specified
///    directory.
///
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @return Current installation progress for the directory, in bytes.
[[gnu::nonnull(1), gnu::access(read_write, 1)]]
static int64_t tscp_amji_init_dir(tek_sc_dd_dir *_Nonnull dir) {
  int64_t progress = 0;
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags &
          (TEK_SC_DD_FILE_FLAG_new | TEK_SC_DD_FILE_FLAG_download))) {
      continue;
    }
    const bool is_new = file->flags & TEK_SC_DD_FILE_FLAG_new;
    for (int j = 0; j < file->num_chunks; ++j) {
      auto const chunk = &file->chunks[j];
      if (chunk->status == TEK_SC_JOB_ENTRY_STATUS_done) {
        ++progress;
      } else if (!is_new) {
        ++file->num_rem_children;
      }
    }
    if (file->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      ++dir->num_rem_children;
    }
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags &
          (TEK_SC_DD_DIR_FLAG_new | TEK_SC_DD_DIR_FLAG_children_new |
           TEK_SC_DD_DIR_FLAG_children_download))) {
      continue;
    }
    progress += tscp_amji_init_dir(subdir);
    if (subdir->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      ++dir->num_rem_children;
    }
  }
  atomic_init(&dir->ref_count, dir->num_rem_children);
  return progress;
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_job_install(tek_sc_am *am, tsci_am_item_desc *desc,
                               tsci_am_job_ctx *ctx) {
  tscp_amji_ctx ictx;
  ictx.desc = desc;
  ictx.job_ctx = ctx;
  auto const root_delta_dir = ctx->delta.dirs;
  // Setup progress and notify update handler
  auto const job = &desc->desc.job;
  job->stage = TEK_SC_AM_JOB_STAGE_installing;
  job->progress_current = tscp_amji_init_dir(root_delta_dir);
  job->progress_total = ctx->delta.num_chunks;
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
  // Open/set item's root installation directory handle
  auto const ws_item_id = desc->desc.id.ws_item_id;
  if (ws_item_id) {
    tek_sc_os_char dir_name[21];
    TSCI_OS_SNPRINTF(dir_name, sizeof dir_name / sizeof *dir_name,
                     TEK_SC_OS_STR("%" PRIu64), ws_item_id);
    root_delta_dir->handle = tsci_os_dir_create_at(am->ws_dir_handle, dir_name);
    if (root_delta_dir->handle == TSCI_OS_INVALID_HANDLE) {
      return tsci_os_io_err_at(am->ws_dir_handle, dir_name, TEK_SC_ERRC_am_io,
                               tsci_os_get_last_error(),
                               TEK_SC_ERR_IO_TYPE_open);
    }
  } else {
    root_delta_dir->handle = am->inst_dir_handle;
  }
  root_delta_dir->cache_handle = ctx->img_dir_handle;
  tek_sc_err res;
  // Scan all delta files to determine if chunk buffer file is needed
  ictx.cb_handle = TSCI_OS_INVALID_HANDLE;
  for (int i = 0; i < ctx->delta.num_files; ++i) {
    auto const flags = ctx->delta.files[i].flags;
    if ((flags & (TEK_SC_DD_FILE_FLAG_new | TEK_SC_DD_FILE_FLAG_download)) ==
        TEK_SC_DD_FILE_FLAG_download) {
      // Open the chunk buffer file right here
      ictx.cb_handle =
          tsci_os_file_open_at(ctx->dir_handle, TEK_SC_OS_STR("chunk_buf"),
                               TSCI_OS_FILE_ACCESS_read, TSCI_OS_FILE_OPT_sync);
      if (ictx.cb_handle == TSCI_OS_INVALID_HANDLE) {
        res = tsci_os_io_err_at(ctx->dir_handle, TEK_SC_OS_STR("chunk_buf"),
                                TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                                TEK_SC_ERR_IO_TYPE_open);
        goto close_root_dir;
      }
      break;
    }
  }
  // Initialize the rest of installation context
  atomic_init(&ictx.num_wts_active, 0);
  atomic_init(&ictx.progress, job->progress_current);
  const int num_threads = ctx->nproc;
  const size_t buf_size = 0x100000 * num_threads;
  ictx.buffer = tsci_os_mem_alloc(buf_size);
  if (!ictx.buffer) {
    res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
    goto close_cb_file;
  }
  ictx.wt_ctxs = malloc(sizeof *ictx.wt_ctxs * num_threads);
  if (!ictx.wt_ctxs) {
    res = tsc_err_basic(TEK_SC_ERRC_mem_alloc);
    goto free_buffer;
  }
  for (int i = 0; i < num_threads; ++i) {
    ictx.wt_ctxs[i].ctx = &ictx;
  }
  // Start worker threads
  pthread_attr_t attr;
  if (pthread_attr_init(&attr)) {
    res = tsc_err_basic(TEK_SC_ERRC_wt_start);
    goto free_arrs;
  }
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
    pthread_attr_destroy(&attr);
    res = tsc_err_basic(TEK_SC_ERRC_wt_start);
    goto free_arrs;
  }
  for (int i = 0; i < num_threads; ++i) {
    atomic_fetch_add_explicit(&ictx.num_wts_active, 1, memory_order_relaxed);
    pthread_t id;
    if (pthread_create(&id, &attr, tscp_amji_wt_proc, &ictx.wt_ctxs[i])) {
      atomic_fetch_sub_explicit(&ictx.num_wts_active, 1, memory_order_relaxed);
      atomic_store_explicit(&job->state, TEK_SC_AM_JOB_STATE_pause_pending,
                            memory_order_relaxed);
      pthread_attr_destroy(&attr);
      for (auto num =
               atomic_load_explicit(&ictx.num_wts_active, memory_order_relaxed);
           num; num = atomic_load_explicit(&ictx.num_wts_active,
                                           memory_order_relaxed)) {
        tsci_os_futex_wait(&ictx.num_wts_active, num, UINT32_MAX);
      }
      for (int j = 0; j < i; ++j) {
        free((void *)ictx.wt_ctxs[j].result.uri);
      }
      res = tsc_err_basic(TEK_SC_ERRC_wt_start);
      goto free_arrs;
    }
  }
  pthread_attr_destroy(&attr);
  // Poll the progress every 200ms while waiting for worker threads to finish
  for (auto num =
           atomic_load_explicit(&ictx.num_wts_active, memory_order_relaxed);
       num;
       num = atomic_load_explicit(&ictx.num_wts_active, memory_order_relaxed)) {
    tsci_os_futex_wait(&ictx.num_wts_active, num, 200);
    job->progress_current =
        atomic_load_explicit(&ictx.progress, memory_order_relaxed);
    if (upd_handler) {
      upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_progress);
    }
  }
  // Gather worker thread context results
  res = tsc_err_ok();
  for (int i = 0; i < num_threads; ++i) {
    auto const wt_res = &ictx.wt_ctxs[i].result;
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
    if (dir->cache_handle != TSCI_OS_INVALID_HANDLE) {
      tsci_os_close_handle(dir->cache_handle);
    }
  }
  if (tek_sc_err_success(&res) && ctx->delta.num_deletions) {
    // Reset delta progress and set the next stage if available
    // Chunk progress is not used at deletion stage
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
    ctx->delta.stage = TEK_SC_DD_STAGE_deleting;
  }
  // Cleanup
free_arrs:
  free(ictx.wt_ctxs);
free_buffer:
  tsci_os_mem_free(ictx.buffer, buf_size);
close_cb_file:
  if (ictx.cb_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(ictx.cb_handle);
  }
close_root_dir:
  if (ws_item_id) {
    tsci_os_close_handle(root_delta_dir->handle);
  }
  return res;
}
