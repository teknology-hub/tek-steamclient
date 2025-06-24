//===-- am_job_verify.c - job verification stage implementation -----------===//
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
/// Implementation of @ref tsci_am_job_verify.
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
#include <openssl/evp.h>
#include <openssl/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//===-- Private types -----------------------------------------------------===//

/// Shared verification context.
typedef struct tscp_amjv_ctx tscp_amjv_ctx;

/// Worker thread context.
typedef struct tscp_amjv_wt_ctx tscp_amjv_wt_ctx;
/// @copydoc tscp_amjv_wt_ctx
struct tscp_amjv_wt_ctx {
  /// Pointer to the verification context.
  tscp_amjv_ctx *_Nonnull ctx;
  /// Pointer to the buffer segment to read chunks into.
  void *_Nonnull buffer;
  /// Pointer to the OpenSSL EVP message digest context.
  EVP_MD_CTX *_Nonnull md_ctx;
  /// The result of running the thread. Receives an error if one occurs.
  tek_sc_err result;
  /// Asynchronous I/O context.
  tsci_os_aio_ctx aio_ctx;
};

/// @copydoc tscp_amjv_ctx
struct tscp_amjv_ctx {
  /// Pointer to the state descriptor of the item that the job is operating on.
  tsci_am_item_desc *_Nonnull desc;
  /// Pointer to the OpenSSL EVP SHA-1 message digest algorithm object.
  const EVP_MD *_Nonnull sha1;
  /// Pointer to the buffer to read chunks into.
  void *_Nonnull buffer;
  /// Pointer to the worker thread context array.
  tscp_amjv_wt_ctx *_Nonnull wt_ctxs;
  /// Pointer to the worker thread array.
  pthread_t *_Nonnull threads;
  /// Verification cache instance.
  tek_sc_verification_cache vcache;
};

//===-- Private functions -------------------------------------------------===//

/// Propagate directory verification completion to its ancestors.
///
/// @param [in] dir
///    Pointer to the manifest entry for the directory being finished.
/// @param [in] vc_dir
///    Pointer to the verification cache entry for the directory being finished.
/// @param [in] vc
///    Pointer to the verification cache.
[[gnu::nonnull(1, 2, 3), gnu::access(read_only, 1), gnu::access(read_write, 2),
  gnu::access(read_only, 3)]]
static void tscp_amjv_finish_dir(const tek_sc_dm_dir *_Nonnull dir,
                                 tek_sc_vc_dir *_Nonnull vc_dir,
                                 const tek_sc_verification_cache *_Nonnull vc) {
  auto const man_dirs = vc->manifest->dirs;
  for (;;) {
    atomic_store_explicit(&vc_dir->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                          memory_order_relaxed);
    auto const next_dir = dir->parent;
    if (!next_dir) {
      break;
    }
    auto const next_vc_dir = &vc->dirs[next_dir - man_dirs];
    if (vc_dir->num_dirty_files || vc_dir->num_dirty_subdirs) {
      atomic_fetch_add_explicit(&next_vc_dir->num_dirty_subdirs_a, 1,
                                memory_order_relaxed);
    }
    if (atomic_fetch_sub_explicit(&next_vc_dir->num_rem_children_a, 1,
                                  memory_order_acq_rel) > 1) {
      break;
    }
    dir = next_dir;
    vc_dir = next_vc_dir;
  }
}

/// Propagate file verification completion to its ancestor directories.
///
/// @param [in] vc_file
///    Pointer to the verification cache entry for the file being finished.
/// @param [in] dir
///    Pointer to the manifest entry for the file's parent directory.
/// @param [in, out] vc_dir
///    Pointer to the verification cache entry for the file's parent directory.
/// @param [in] vc
///    Pointer to the verification cache.
/// @return Value indicating whether the file was the last unverified child of
///    the directory.
[[gnu::nonnull(1, 2, 3, 4), gnu::access(read_only, 1),
  gnu::access(read_only, 2), gnu::access(read_write, 3),
  gnu::access(read_only, 4)]]
static inline bool
tscp_amjv_finish_file(const tek_sc_vc_file *_Nonnull vc_file,
                      const tek_sc_dm_dir *_Nonnull dir,
                      tek_sc_vc_dir *_Nonnull vc_dir,
                      const tek_sc_verification_cache *_Nonnull vc) {
  if (vc_file->file_status != TEK_SC_VC_FILE_STATUS_regular ||
      vc_file->num_dirty_chunks) {
    atomic_fetch_add_explicit(&vc_dir->num_dirty_files_a, 1,
                              memory_order_relaxed);
  }
  if (atomic_fetch_sub_explicit(&vc_dir->num_rem_children_a, 1,
                                memory_order_acq_rel) == 1) {
    tscp_amjv_finish_dir(dir, vc_dir, vc);
    return true;
  }
  return false;
}

/// Get total size of all files in a directory tree.
///
/// @param [in] dir
///    Pointer to the manifest entry for the root of the directory tree.
/// @return Total size of all files in the directory tree, in bytes.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int64_t tscp_amjv_get_dir_size(const tek_sc_dm_dir *_Nonnull dir) {
  int64_t size = 0;
  for (int i = 0; i < dir->num_files; ++i) {
    size += dir->files[i].size;
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    size += tscp_amjv_get_dir_size(&dir->subdirs[i]);
  }
  return size;
}

/// Verify specified directory.
///
/// @param [in, out] ctx
///    Pointer to the verification context.
/// @param [in, out] wt_ctx
///    Pointer to the worker thread context.
/// @param [in] dir
///    Pointer to the manifest entry for the directory to process.
/// @param [in, out] vc_dir
///    Pointer to the verification cache entry for the directory to process.
/// @return Value indicating whether the operation was successful.
[[gnu::nonnull(1, 2, 3, 4), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_only, 3),
  gnu::access(read_write, 4)]]
static bool tscp_amjv_process_dir(tscp_amjv_ctx *_Nonnull ctx,
                                  tscp_amjv_wt_ctx *_Nonnull wt_ctx,
                                  const tek_sc_dm_dir *_Nonnull dir,
                                  tek_sc_vc_dir *_Nonnull vc_dir) {
  auto const man = ctx->vcache.manifest;
  auto const vc_files = &ctx->vcache.files[dir->files - man->files];
  auto const vc_subdirs = &ctx->vcache.dirs[dir->subdirs - man->dirs];
  auto const desc = &ctx->desc->desc;
  auto const state = &desc->job.state;
  auto const progress_current = &desc->job.progress_current_a;
  auto const upd_handler = ctx->desc->job_upd_handler;
  auto const sha1 = wt_ctx->ctx->sha1;
  auto const md_ctx = wt_ctx->md_ctx;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    auto const vc_file = &vc_files[i];
    // Attempt to claim the entry for file setup
    tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
    if (atomic_compare_exchange_strong_explicit(
            &vc_file->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
            memory_order_acquire, memory_order_acquire)) {
      // Setup the file
      if (!file->num_chunks) {
        // Pause if requested
        if (atomic_load_explicit(state, memory_order_relaxed) ==
            TEK_SC_AM_JOB_STATE_pause_pending) {
          wt_ctx->result = tsc_err_basic(TEK_SC_ERRC_paused);
          return false;
        }
        // Supposedly empty file, check if it's actually empty
        auto const size = tsci_os_file_get_size_at(vc_dir->handle, file->name);
        if (size == SIZE_MAX) {
          auto const errc = tsci_os_get_last_error();
          if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
            wt_ctx->result =
                tsci_os_io_err_at(vc_dir->handle, file->name, TEK_SC_ERRC_am_io,
                                  errc, TEK_SC_ERR_IO_TYPE_get_size);
            return false;
          }
          // The file does not exist in filesystem
          if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                        memory_order_relaxed) == 1) {
            tsci_os_close_handle(vc_dir->handle);
            vc_dir->handle = TSCI_OS_INVALID_HANDLE;
          }
          vc_file->file_status = TEK_SC_VC_FILE_STATUS_missing;
          atomic_store_explicit(&vc_file->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_done,
                                memory_order_relaxed);
          if (tscp_amjv_finish_file(vc_file, dir, vc_dir, &ctx->vcache)) {
            return true;
          }
          continue;
        } // if (size == SIZE_MAX)
        // The file does exist, check if size is non-zero
        if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(vc_dir->handle);
          vc_dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        if (size) {
          vc_file->file_status = TEK_SC_VC_FILE_STATUS_truncate;
        }
        atomic_store_explicit(&vc_file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        if (tscp_amjv_finish_file(vc_file, dir, vc_dir, &ctx->vcache)) {
          return true;
        }
        continue;
      } // if (!file->num_chunks)
      auto const handle = tsci_os_file_open_at(vc_dir->handle, file->name,
                                               TSCI_OS_FILE_ACCESS_read);
      if (handle == TSCI_OS_INVALID_HANDLE) {
        auto const errc = tsci_os_get_last_error();
        if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
          wt_ctx->result =
              tsci_os_io_err_at(vc_dir->handle, file->name, TEK_SC_ERRC_am_io,
                                errc, TEK_SC_ERR_IO_TYPE_open);
          atomic_store_explicit(&vc_file->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_pending,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_file->status_a);
          return false;
        }
        // The file does not exist in filesystem
        if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(vc_dir->handle);
          vc_dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        vc_file->file_status = TEK_SC_VC_FILE_STATUS_missing;
        atomic_store_explicit(&vc_file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_file->status_a);
        const bool last_ref =
            tscp_amjv_finish_file(vc_file, dir, vc_dir, &ctx->vcache);
        atomic_fetch_add_explicit(progress_current, file->size,
                                  memory_order_relaxed);
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
        if (last_ref) {
          return true;
        }
        continue;
      } // if (handle == TSCI_OS_INVALID_HANDLE)
      // The file does exist, check its size
      if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                    memory_order_relaxed) == 1) {
        tsci_os_close_handle(vc_dir->handle);
        vc_dir->handle = TSCI_OS_INVALID_HANDLE;
      }
      auto const size = tsci_os_file_get_size(handle);
      if (size == SIZE_MAX) {
        wt_ctx->result =
            tsci_os_io_err(handle, TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                           TEK_SC_ERR_IO_TYPE_get_size);
        atomic_store_explicit(&vc_file->status_a,
                              TEK_SC_JOB_ENTRY_STATUS_pending,
                              memory_order_relaxed);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_file->status_a);
        tsci_os_close_handle(handle);
        return false;
      }
      if (file->size < (int64_t)size) {
        vc_file->file_status = TEK_SC_VC_FILE_STATUS_truncate;
      }
      // Check which chunks are eligible for verification
      int64_t progress = 0;
      auto const vc_chunks = &ctx->vcache.chunks[file->chunks - man->chunks];
      for (int i = 0; i < file->num_chunks; ++i) {
        auto const vc_chunk = &vc_chunks[i];
        if (vc_chunk->status == TEK_SC_JOB_ENTRY_STATUS_done) {
          continue;
        }
        auto const chunk = &file->chunks[i];
        if (chunk->offset + chunk->size > (int64_t)size) {
          // Mark all chunks past EOF as missing
          for (int j = i; j < file->num_chunks; ++j) {
            auto const vc_chunk = &vc_chunks[j];
            if (vc_chunk->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
              vc_chunk->status = TEK_SC_JOB_ENTRY_STATUS_done;
              --vc_file->num_rem_chunks;
              ++vc_file->num_dirty_chunks;
              progress += chunk->size;
            }
          }
          break;
        }
      }
      // Finalize entry setup and mark it as either active or done, notifying
      //    other threads
      const int ref_count = vc_file->num_rem_chunks;
      if (ref_count) {
        vc_file->handle = handle;
      }
      atomic_store_explicit(&vc_file->status_a,
                            ref_count ? TEK_SC_JOB_ENTRY_STATUS_active
                                      : TEK_SC_JOB_ENTRY_STATUS_done,
                            memory_order_release);
      tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_file->status_a);
      bool last_ref;
      if (!ref_count) {
        last_ref = tscp_amjv_finish_file(vc_file, dir, vc_dir, &ctx->vcache);
      }
      if (progress) {
        // Report progress gained by marking past-EOF chunks
        atomic_fetch_add_explicit(progress_current, progress,
                                  memory_order_relaxed);
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
      }
      if (!ref_count) {
        if (last_ref) {
          return true;
        }
        continue;
      }
    } else { // if (vc_file->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup)
      if (!file->num_chunks) {
        // No need to wait on this file
        continue;
      }
      switch (expected) {
      case TEK_SC_JOB_ENTRY_STATUS_setup:
        // Wait for another thread to finish file setup and check results
        tsci_os_futex_wait((const _Atomic(uint32_t) *)&vc_file->status_a,
                           TEK_SC_JOB_ENTRY_STATUS_setup, UINT32_MAX);
        switch (
            atomic_load_explicit(&vc_file->status_a, memory_order_acquire)) {
        case TEK_SC_JOB_ENTRY_STATUS_pending:
          // An error has occurred during file setup
          return false;
        case TEK_SC_JOB_ENTRY_STATUS_active:
          // Fallthrough to the same case in outer switch
          break;
        case TEK_SC_JOB_ENTRY_STATUS_done:
          // No chunks to process in this file
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
    } // if (vc_file->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup) else
    bool registered = false;
    // Iterate chunks
    auto const vc_chunks = &ctx->vcache.chunks[file->chunks - man->chunks];
    for (int j = 0; j < file->num_chunks; ++j) {
      auto const vc_chunk = &vc_chunks[j];
      // Attempt to claim the chunk
      expected = TEK_SC_JOB_ENTRY_STATUS_pending;
      if (!atomic_compare_exchange_strong_explicit(
              &vc_chunk->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_active,
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
        auto const errc =
            tsci_os_aio_register_file(&wt_ctx->aio_ctx, vc_file->handle);
        if (errc) {
          wt_ctx->result = tsci_os_io_err(vc_file->handle, TEK_SC_ERRC_am_io,
                                          errc, TEK_SC_ERR_IO_TYPE_aio_reg);
          return false;
        }
        registered = true;
      }
      auto const chunk = &file->chunks[j];
      // Read the chunk
      auto const errc = tsci_os_aio_read(&wt_ctx->aio_ctx, wt_ctx->buffer,
                                         chunk->size, chunk->offset);
      if (errc) {
        wt_ctx->result = tsci_os_io_err(vc_file->handle, TEK_SC_ERRC_am_io,
                                        errc, TEK_SC_ERR_IO_TYPE_read);
        return false;
      }
      // Verify chunk's SHA-1 hash
      if (!EVP_DigestInit_ex2(md_ctx, sha1, nullptr)) {
        wt_ctx->result = tsc_err_sub(TEK_SC_ERRC_am_wt, TEK_SC_ERRC_sha);
        return false;
      }
      if (!EVP_DigestUpdate(md_ctx, wt_ctx->buffer, chunk->size)) {
        wt_ctx->result = tsc_err_sub(TEK_SC_ERRC_am_wt, TEK_SC_ERRC_sha);
        return false;
      }
      tek_sc_sha1_hash hash;
      if (!EVP_DigestFinal_ex(md_ctx, hash.bytes, nullptr)) {
        wt_ctx->result = tsc_err_sub(TEK_SC_ERRC_am_wt, TEK_SC_ERRC_sha);
        return false;
      }
      // Update verification cache entries
      atomic_store_explicit(&vc_chunk->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                            memory_order_relaxed);
      vc_chunk->match =
          hash.high32 == chunk->sha.high32 && hash.low128 == chunk->sha.low128;
      if (!vc_chunk->match) {
        atomic_fetch_add_explicit(&vc_file->num_dirty_chunks_a, 1,
                                  memory_order_relaxed);
      }
      enum { NEXT_CHUNK, NEXT_FILE, NEXT_DIR } proceed_type;
      if (atomic_fetch_sub_explicit(&vc_file->num_rem_chunks_a, 1,
                                    memory_order_acq_rel) == 1) {
        atomic_store_explicit(&vc_file->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        tsci_os_close_handle(vc_file->handle);
        vc_file->handle = TSCI_OS_INVALID_HANDLE;
        proceed_type = tscp_amjv_finish_file(vc_file, dir, vc_dir, &ctx->vcache)
                           ? NEXT_DIR
                           : NEXT_FILE;
      } else {
        proceed_type = NEXT_CHUNK;
      }
      // Report progress
      atomic_fetch_add_explicit(progress_current, chunk->size,
                                memory_order_relaxed);
      if (upd_handler) {
        upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
      }
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
    auto const vc_subdir = &vc_subdirs[i];
    const bool is_empty = !subdir->num_files && !subdir->num_subdirs;
    // Attempt to claim the entry for subdirectory setup
    tek_sc_job_entry_status expected = TEK_SC_JOB_ENTRY_STATUS_pending;
    if (atomic_compare_exchange_strong_explicit(
            &vc_subdir->status_a, &expected, TEK_SC_JOB_ENTRY_STATUS_setup,
            memory_order_acquire, memory_order_acquire)) {
      // Setup the subdirectory
      if (is_empty) {
        // Only ensure that subdirectory exists
        auto const res = tsci_os_path_exists_at(vc_dir->handle, subdir->name);
        if (res && res != TSCI_OS_ERR_FILE_NOT_FOUND) {
          wt_ctx->result =
              tsci_os_io_err_at(vc_dir->handle, subdir->name, TEK_SC_ERRC_am_io,
                                res, TEK_SC_ERR_IO_TYPE_check_existence);
          return false;
        }
        if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(vc_dir->handle);
          vc_dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        if (res) {
          // The subdirectory does not exist in filesystem
          vc_subdir->num_dirty_subdirs = -1;
          atomic_fetch_add_explicit(&vc_dir->num_dirty_subdirs_a, 1,
                                    memory_order_relaxed);
        }
        atomic_store_explicit(&vc_subdir->status_a,
                              TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        if (atomic_fetch_sub_explicit(&vc_dir->num_rem_children_a, 1,
                                      memory_order_acq_rel) == 1) {
          tscp_amjv_finish_dir(dir, vc_dir, &ctx->vcache);
          return true;
        }
        continue;
      } // if (is_empty)
      auto const handle = tsci_os_dir_open_at(vc_dir->handle, subdir->name);
      if (handle == TSCI_OS_INVALID_HANDLE) {
        auto const errc = tsci_os_get_last_error();
        if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
          wt_ctx->result =
              tsci_os_io_err_at(vc_dir->handle, subdir->name, TEK_SC_ERRC_am_io,
                                errc, TEK_SC_ERR_IO_TYPE_open);
          atomic_store_explicit(&vc_subdir->status_a,
                                TEK_SC_JOB_ENTRY_STATUS_pending,
                                memory_order_relaxed);
          tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_subdir->status_a);
          return false;
        }
        // The subdirectory does not exist in filesystem
        if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                      memory_order_relaxed) == 1) {
          tsci_os_close_handle(vc_dir->handle);
          vc_dir->handle = TSCI_OS_INVALID_HANDLE;
        }
        vc_subdir->num_dirty_subdirs = -1;
        atomic_store_explicit(&vc_subdir->status_a,
                              TEK_SC_JOB_ENTRY_STATUS_done,
                              memory_order_relaxed);
        tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_subdir->status_a);
        atomic_fetch_add_explicit(&vc_dir->num_dirty_subdirs_a, 1,
                                  memory_order_relaxed);
        bool last_ref = false;
        if (atomic_fetch_sub_explicit(&vc_dir->num_rem_children_a, 1,
                                      memory_order_acq_rel) == 1) {
          tscp_amjv_finish_dir(dir, vc_dir, &ctx->vcache);
          last_ref = true;
        }
        atomic_fetch_add_explicit(progress_current,
                                  tscp_amjv_get_dir_size(subdir),
                                  memory_order_relaxed);
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
        if (last_ref) {
          return true;
        }
        continue;
      } // if (handle == TSCI_OS_INVALID_HANDLE)
      if (atomic_fetch_sub_explicit(&vc_dir->ref_count, 1,
                                    memory_order_relaxed) == 1) {
        tsci_os_close_handle(vc_dir->handle);
        vc_dir->handle = TSCI_OS_INVALID_HANDLE;
      }
      // Finalize entry setup and mark it as active, notifying other threads
      vc_subdir->handle = handle;
      atomic_store_explicit(&vc_subdir->status_a,
                            TEK_SC_JOB_ENTRY_STATUS_active,
                            memory_order_release);
      tsci_os_futex_wake((_Atomic(uint32_t) *)&vc_subdir->status_a);
    } else { // if (vc_subdir->status_a changed to
             // TEK_SC_JOB_ENTRY_STATUS_setup)
      if (is_empty) {
        // No need to wait on this subdirectory
        continue;
      }
      switch (expected) {
      case TEK_SC_JOB_ENTRY_STATUS_setup:
        // Wait for another thread to finish subdirectory setup and check
        //    results
        tsci_os_futex_wait((const _Atomic(uint32_t) *)&vc_subdir->status_a,
                           TEK_SC_JOB_ENTRY_STATUS_setup, UINT32_MAX);
        switch (
            atomic_load_explicit(&vc_subdir->status_a, memory_order_acquire)) {
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
    } // if (vc_subdir->status_a changed to TEK_SC_JOB_ENTRY_STATUS_setup) else
    // Recurse to subdirectory
    if (!tscp_amjv_process_dir(ctx, wt_ctx, subdir, vc_subdir)) {
      return false;
    }
  } // for (int i = 0; i < dir->num_subdirs; ++i)
  return true;
}

/// Verification worker thread procedure.
///
/// @param [in, out] arg
///    Pointer to a @ref tscp_amjv_wt_ctx.
/// @return `nullptr`.
[[gnu::nonnull(1), gnu::accress(read_write, 1)]] static void
    *_Nullable tscp_amjv_wt_proc(void *_Nonnull arg) {
  tscp_amjv_wt_ctx *const wt_ctx = arg;
  auto const ctx = wt_ctx->ctx;
  const int ind = wt_ctx - ctx->wt_ctxs;
  tek_sc_os_char name[16];
  TSCI_OS_SNPRINTF(name, sizeof name / sizeof *name,
                   TEK_SC_OS_STR("tsc worker #%u"), ind);
  tsci_os_set_thread_name(name);
  auto const state = &ctx->desc->desc.job.state;
  wt_ctx->buffer = ctx->buffer + 0x100000 * ind;
  wt_ctx->md_ctx = EVP_MD_CTX_new();
  if (!wt_ctx->md_ctx) {
    atomic_store_explicit(state, TEK_SC_AM_JOB_STATE_pause_pending,
                          memory_order_relaxed);
    wt_ctx->result = tsc_err_sub(TEK_SC_ERRC_am_wt, TEK_SC_ERRC_sha);
    return nullptr;
  }
  auto const errc =
      tsci_os_aio_ctx_init(&wt_ctx->aio_ctx, wt_ctx->buffer, 0x100000);
  if (errc) {
    EVP_MD_CTX_free(wt_ctx->md_ctx);
    atomic_store_explicit(state, TEK_SC_AM_JOB_STATE_pause_pending,
                          memory_order_relaxed);
    wt_ctx->result = tsci_err_os(TEK_SC_ERRC_aio_init, errc);
    return nullptr;
  }
  wt_ctx->result = tsc_err_ok();
  if (!tscp_amjv_process_dir(ctx, wt_ctx, ctx->vcache.manifest->dirs,
                             ctx->vcache.dirs)) {
    atomic_store_explicit(state, TEK_SC_AM_JOB_STATE_pause_pending,
                          memory_order_relaxed);
  }
  tsci_os_aio_ctx_destroy(&wt_ctx->aio_ctx);
  EVP_MD_CTX_free(wt_ctx->md_ctx);
  return nullptr;
}

/// Get current verification progress for specified directory.
///
/// @param [in] dir
///    Pointer to the manifest entry for the directory to process.
/// @param [in] vc
///    Pointer to the verification cache.
/// @return Current verification progress for the directory, in bytes.
[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_only, 2)]]
static int64_t
tscp_amjv_get_progress(const tek_sc_dm_dir *_Nonnull dir,
                       const tek_sc_verification_cache *_Nonnull vc) {
  int64_t progress = 0;
  auto const man = vc->manifest;
  auto const vc_files = &vc->files[dir->files - man->files];
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!file->num_chunks) {
      continue;
    }
    auto const vc_file = &vc_files[i];
    if (vc_file->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      progress += file->size;
      continue;
    }
    auto const vc_chunks = &vc->chunks[file->chunks - man->chunks];
    for (int j = 0; j < file->num_chunks; ++j) {
      if (vc_chunks[j].status == TEK_SC_JOB_ENTRY_STATUS_done) {
        progress += file->chunks[j].size;
      }
    }
  }
  auto const vc_subdirs = &vc->dirs[dir->subdirs - man->dirs];
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (vc_subdirs[i].status == TEK_SC_JOB_ENTRY_STATUS_done) {
      progress += tscp_amjv_get_dir_size(subdir);
      continue;
    }
    progress += tscp_amjv_get_progress(subdir, vc);
  }
  return progress;
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_job_verify(tek_sc_am *am, tsci_am_item_desc *desc,
                              tsci_am_job_ctx *ctx) {
  tscp_amjv_ctx vctx;
  vctx.desc = desc;
  // Load or create verification cache
  static const tek_sc_os_char vc_file_name[] = TEK_SC_OS_STR("vcache");
  auto vc_file_handle = tsci_os_file_open_at(ctx->dir_handle, vc_file_name,
                                             TSCI_OS_FILE_ACCESS_read);
  if (vc_file_handle == TSCI_OS_INVALID_HANDLE) {
    auto const errc = tsci_os_get_last_error();
    if (errc == TSCI_OS_ERR_FILE_NOT_FOUND) {
      vctx.vcache = tek_sc_vc_create(&ctx->target_manifest);
    } else {
      return tsci_os_io_err_at(ctx->dir_handle, vc_file_name, TEK_SC_ERRC_am_io,
                               errc, TEK_SC_ERR_IO_TYPE_open);
    }
  } else {
    auto const file_size = tsci_os_file_get_size(vc_file_handle);
    if (file_size == SIZE_MAX) {
      auto const err =
          tsci_os_io_err(vc_file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
      tsci_os_close_handle(vc_file_handle);
      return err;
    }
    auto const file_buf = malloc(file_size);
    if (!file_buf) {
      tsci_os_close_handle(vc_file_handle);
      return tsc_err_basic(TEK_SC_ERRC_mem_alloc);
    }
    if (!tsci_os_file_read(vc_file_handle, file_buf, file_size)) {
      auto const err =
          tsci_os_io_err(vc_file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
      free(file_buf);
      tsci_os_close_handle(vc_file_handle);
      return err;
    }
    tsci_os_close_handle(vc_file_handle);
    auto const res = tek_sc_vc_deserialize(file_buf, file_size,
                                           &ctx->target_manifest, &vctx.vcache);
    free(file_buf);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
  } // if (vc_file_handle == TSCI_OS_INVALID_HANDLE) else
  // Setup progress and notify update handler
  auto const job = &desc->desc.job;
  job->stage = TEK_SC_AM_JOB_STAGE_verifying;
  job->progress_current =
      tscp_amjv_get_progress(vctx.vcache.manifest->dirs, &vctx.vcache);
  job->progress_total = vctx.vcache.manifest->data_size;
  tek_sc_err res;
  auto const upd_handler = desc->job_upd_handler;
  if (upd_handler) {
    upd_handler(&desc->desc,
                TEK_SC_AM_UPD_TYPE_stage | TEK_SC_AM_UPD_TYPE_progress);
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      res = tsc_err_basic(TEK_SC_ERRC_paused);
      goto free_vc;
    }
  }
  // Open/set item's root installation directory handle
  auto const ws_item_id = desc->desc.id.ws_item_id;
  if (ws_item_id) {
    tek_sc_os_char dir_name[21];
    TSCI_OS_SNPRINTF(dir_name, sizeof dir_name / sizeof *dir_name,
                     TEK_SC_OS_STR("%" PRIu64), ws_item_id);
    vctx.vcache.dirs[0].handle =
        tsci_os_dir_create_at(am->ws_dir_handle, dir_name);
    if (vctx.vcache.dirs[0].handle == TSCI_OS_INVALID_HANDLE) {
      res =
          tsci_os_io_err_at(am->ws_dir_handle, dir_name, TEK_SC_ERRC_am_io,
                            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
      goto free_vc;
    }
  } else {
    vctx.vcache.dirs[0].handle = am->inst_dir_handle;
  }
  // Initialize the rest of verification context
  vctx.sha1 = EVP_sha1();
  const int num_threads = ctx->nproc;
  const size_t buf_size = 0x100000 * num_threads;
  vctx.buffer = tsci_os_mem_alloc(buf_size);
  if (!vctx.buffer) {
    res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
    goto close_root_dir;
  }
  vctx.wt_ctxs =
      malloc((sizeof *vctx.wt_ctxs + sizeof *vctx.threads) * num_threads);
  if (!vctx.wt_ctxs) {
    res = tsc_err_basic(TEK_SC_ERRC_mem_alloc);
    goto free_buffer;
  }
  vctx.threads = (pthread_t *)(vctx.wt_ctxs + num_threads);
  for (int i = 0; i < num_threads; ++i) {
    vctx.wt_ctxs[i].ctx = &vctx;
  }
  // Start worker threads
  for (int i = 0; i < num_threads; ++i) {
    if (pthread_create(&vctx.threads[i], nullptr, tscp_amjv_wt_proc,
                       &vctx.wt_ctxs[i])) {
      atomic_store_explicit(&job->state, TEK_SC_AM_JOB_STATE_pause_pending,
                            memory_order_relaxed);
      for (int j = 0; j < i; ++j) {
        pthread_join(vctx.threads[j], nullptr);
        free((void *)vctx.wt_ctxs[j].result.uri);
      }
      res = tsc_err_basic(TEK_SC_ERRC_wt_start);
      goto free_arrs;
    }
  }
  // Wait for worker threads to exit and gather their results
  res = tsc_err_ok();
  for (int i = 0; i < num_threads; ++i) {
    pthread_join(vctx.threads[i], nullptr);
    auto const wt_res = &vctx.wt_ctxs[i].result;
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
  for (int i = 0; i < vctx.vcache.manifest->num_files; ++i) {
    auto const handle = vctx.vcache.files[i].handle;
    if (handle != TSCI_OS_INVALID_HANDLE) {
      tsci_os_close_handle(handle);
    }
  }
  for (int i = 1; i < vctx.vcache.manifest->num_dirs; ++i) {
    auto const handle = vctx.vcache.dirs[i].handle;
    if (handle != TSCI_OS_INVALID_HANDLE) {
      tsci_os_close_handle(handle);
    }
  }
  if (tek_sc_err_success(&res)) {
    // Create delta from the verification cache if there are any mismatches
    if (vctx.vcache.dirs->num_dirty_files ||
        vctx.vcache.dirs->num_dirty_subdirs) {
      ctx->delta = tek_sc_dd_compute_from_vc(&vctx.vcache);
    } else {
      res.primary = TEK_SC_ERRC_up_to_date;
    }
  } else { // if (tek_sc_err_success(&res))
    // Save verification cache to file
    vc_file_handle = tsci_os_file_create_at(ctx->dir_handle, vc_file_name,
                                            TSCI_OS_FILE_ACCESS_write);
    if (vc_file_handle == TSCI_OS_INVALID_HANDLE) {
      if (res.primary == TEK_SC_ERRC_paused) {
        res = tsci_os_io_err_at(ctx->dir_handle, vc_file_name,
                                TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                                TEK_SC_ERR_IO_TYPE_open);
      }
      goto free_arrs;
    }
    const int ser_size = tek_sc_vc_serialize(&vctx.vcache, nullptr, 0);
    auto const ser_buf = tsci_os_mem_alloc(ser_size);
    if (!ser_buf) {
      if (res.primary == TEK_SC_ERRC_paused) {
        res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
      }
      tsci_os_close_handle(vc_file_handle);
      goto free_arrs;
    }
    tek_sc_vc_serialize(&vctx.vcache, ser_buf, ser_size);
    if (!tsci_os_file_write(vc_file_handle, ser_buf, ser_size)) {
      if (res.primary == TEK_SC_ERRC_paused) {
        res =
            tsci_os_io_err(vc_file_handle, TEK_SC_ERRC_am_io,
                           tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_write);
      }
      tsci_os_file_delete_at(ctx->dir_handle, vc_file_name);
    }
    tsci_os_mem_free(ser_buf, ser_size);
    tsci_os_close_handle(vc_file_handle);
  } // if (tek_sc_err_success(&res)) else
  // Cleanup
free_arrs:
  free(vctx.wt_ctxs);
free_buffer:
  tsci_os_mem_free(vctx.buffer, buf_size);
close_root_dir:
  if (ws_item_id) {
    tsci_os_close_handle(vctx.vcache.dirs[0].handle);
  }
free_vc:
  tek_sc_vc_free(&vctx.vcache);
  return res;
}
