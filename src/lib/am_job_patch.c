//===-- am_job_patch.c - job patching stage implementation ----------------===//
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
/// Implementation of @ref tsci_am_job_patch.
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

#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>

//===-- Private type ------------------------------------------------------===//

/// Patching context, shared across recursion levels of
///    @ref tscp_amjp_process_dir.
typedef struct tscp_amjp_ctx tscp_amjp_ctx;
/// @copydoc tscp_amjp_ctx
struct tscp_amjp_ctx {
  /// Pointer to the state descriptor of the item that the job is operating on.
  tsci_am_item_desc *_Nonnull desc;
  /// Handle for the transfer buffer file.
  tek_sc_os_handle tb_handle;
  /// Pointer to the chunk decoding context instance.
  tek_sc_sp_dec_ctx *_Nonnull dec_ctx;
};

//===-- Private functions -------------------------------------------------===//

/// Patch files in specified directory.
///
/// @param [in, out] ctx
///    Pointer to the patching context.
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @param dir_handle
///    OS handle for the directory.
/// @param [in, out] copy_args
///    Pointer to the thread's copy arguments structure.
/// @param [out] err
///    Address of variable that receives the error object on failure.
/// @return Value indicating whether the operation was successful.
[[gnu::nonnull(1, 2, 4, 5), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_write, 4),
  gnu::access(write_only, 5)]]
static bool tscp_amjp_process_dir(tscp_amjp_ctx *_Nonnull ctx,
                                  tek_sc_dd_dir *_Nonnull dir,
                                  tek_sc_os_handle dir_handle,
                                  tsci_os_copy_args *_Nonnull copy_args,
                                  tek_sc_err *_Nonnull err) {
  auto const desc = &ctx->desc->desc;
  auto const job = &desc->job;
  auto const state = &job->state;
  auto const upd_handler = ctx->desc->job_upd_handler;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags &
          (TEK_SC_DD_FILE_FLAG_patch | TEK_SC_DD_FILE_FLAG_truncate)) ||
        file->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      continue;
    }
    // Open the file for writing if only truncation is needed, for reading and
    //    writing otherwise
    auto const handle =
        tsci_os_file_open_at(dir_handle, file->file->name,
                             (file->flags & (TEK_SC_DD_FILE_FLAG_patch |
                                             TEK_SC_DD_FILE_FLAG_truncate)) ==
                                     TEK_SC_DD_FILE_FLAG_truncate
                                 ? TSCI_OS_FILE_ACCESS_write
                                 : TSCI_OS_FILE_ACCESS_rdwr,
                             TSCI_OS_FILE_OPT_sync);
    if (handle == TSCI_OS_INVALID_HANDLE) {
      *err =
          tsci_os_io_err_at(dir_handle, file->file->name, TEK_SC_ERRC_am_io,
                            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
      return false;
    }
    const bool is_patching = file->flags & TEK_SC_DD_FILE_FLAG_patch;
    // Iterate transfer operations (stage 1)
    if (is_patching && file->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      for (int j = 0; j < file->num_transfer_ops; ++j) {
        auto const transfer_op = &file->transfer_ops[j];
        if (transfer_op->status != TEK_SC_JOB_ENTRY_STATUS_pending) {
          continue;
        }
        // Pause if requested
        if (atomic_load_explicit(state, memory_order_relaxed) ==
            TEK_SC_AM_JOB_STATE_pause_pending) {
          *err = tsc_err_basic(TEK_SC_ERRC_paused);
          tsci_os_close_handle(handle);
          return false;
        }
        const bool is_direct = transfer_op->transfer_buf_offset < 0;
        switch (transfer_op->type) {
        case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
          // Simply copy the data to its destination or transfer buffer file
          copy_args->src_handle = handle;
          copy_args->tgt_handle = is_direct ? handle : ctx->tb_handle;
          if (is_direct) {
            copy_args->not_same_dev = false;
          }
          if (!tsci_os_file_copy_chunk(
                  copy_args, transfer_op->data.relocation.source_offset,
                  is_direct ? transfer_op->data.relocation.target_offset
                            : transfer_op->transfer_buf_offset,
                  transfer_op->data.relocation.size)) {
            *err = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                  tsci_os_get_last_error(),
                                  TEK_SC_ERR_IO_TYPE_copy);
            tsci_os_close_handle(handle);
            return false;
          }
          break;
        case TEK_SC_DD_TRANSFER_OP_TYPE_patch:
          auto const pchunk = transfer_op->data.patch_chunk;
          auto const src_chunk = pchunk->source_chunk;
          auto const tgt_chunk = pchunk->target_chunk;
          if (is_direct || tgt_chunk->size <= src_chunk->size) {
            auto const src_buf = copy_args->buf;
            auto const tgt_buf = src_buf + src_chunk->size;
            // Read the source chunk
            if (!tsci_os_file_read_at(handle, src_buf, src_chunk->size,
                                      src_chunk->offset)) {
              *err = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_read);
              tsci_os_close_handle(handle);
              return false;
            }
            // Patch the chunk
            auto const res =
                tek_sc_sp_patch_chunk(ctx->dec_ctx, src_buf, tgt_buf, pchunk);
            if (!tek_sc_err_success(&res)) {
              *err = res;
              tsci_os_close_handle(handle);
              return false;
            }
            // Write target chunk to the file
            auto const write_handle = is_direct ? handle : ctx->tb_handle;
            if (!tsci_os_file_write_at(
                    write_handle, tgt_buf, tgt_chunk->size,
                    is_direct ? tgt_chunk->offset
                              : transfer_op->transfer_buf_offset)) {
              *err = tsci_os_io_err(write_handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_write);
              tsci_os_close_handle(handle);
              return false;
            }
          } else { // if (is_direct || tgt_chunk->size <= src_chunk->size)
            // Simply copy the chunk to the transfer buffer file
            copy_args->src_handle = handle;
            copy_args->tgt_handle = ctx->tb_handle;
            if (!tsci_os_file_copy_chunk(copy_args, src_chunk->offset,
                                         transfer_op->transfer_buf_offset,
                                         src_chunk->size)) {
              *err = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_copy);
              tsci_os_close_handle(handle);
              return false;
            }
          } // if (is_direct || tgt_chunk->size <= src_chunk->size) else
          break;
        } // switch (transfer_op->type)
        transfer_op->status = is_direct ? TEK_SC_JOB_ENTRY_STATUS_done
                                        : TEK_SC_JOB_ENTRY_STATUS_active;
        ++job->progress_current;
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
      } // for (int j = 0; j < file->num_transfer_ops; ++j)
      file->status = TEK_SC_JOB_ENTRY_STATUS_setup;
    } // if (is_patching && file->status == TEK_SC_JOB_ENTRY_STATUS_pending)
    // Iterate transfer operations (stage 2)
    if (is_patching && file->status == TEK_SC_JOB_ENTRY_STATUS_setup) {
      for (int j = 0; j < file->num_transfer_ops; ++j) {
        auto const transfer_op = &file->transfer_ops[j];
        if (transfer_op->status == TEK_SC_JOB_ENTRY_STATUS_done) {
          continue;
        }
        // Pause if requested
        if (atomic_load_explicit(state, memory_order_relaxed) ==
            TEK_SC_AM_JOB_STATE_pause_pending) {
          *err = tsc_err_basic(TEK_SC_ERRC_paused);
          tsci_os_close_handle(handle);
          return false;
        }
        switch (transfer_op->type) {
        case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
          // Copy the data from the transfer buffer file
          copy_args->src_handle = ctx->tb_handle;
          copy_args->tgt_handle = handle;
          if (!tsci_os_file_copy_chunk(
                  copy_args, transfer_op->transfer_buf_offset,
                  transfer_op->data.relocation.target_offset,
                  transfer_op->data.relocation.size)) {
            *err = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                  tsci_os_get_last_error(),
                                  TEK_SC_ERR_IO_TYPE_copy);
            tsci_os_close_handle(handle);
            return false;
          }
          break;
        case TEK_SC_DD_TRANSFER_OP_TYPE_patch:
          auto const pchunk = transfer_op->data.patch_chunk;
          auto const src_chunk = pchunk->source_chunk;
          auto const tgt_chunk = pchunk->target_chunk;
          if (tgt_chunk->size <= src_chunk->size) {
            // The chunk was patched earlier, simply copy it from the
            //    transfer buffer file
            copy_args->src_handle = ctx->tb_handle;
            copy_args->tgt_handle = handle;
            if (!tsci_os_file_copy_chunk(copy_args,
                                         transfer_op->transfer_buf_offset,
                                         tgt_chunk->offset, tgt_chunk->size)) {
              *err = tsci_os_io_err(ctx->tb_handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_copy);
              tsci_os_close_handle(handle);
              return false;
            }
          } else { // if (tgt_chunk->size <= src_chunk->size)
            auto const src_buf = copy_args->buf;
            auto const tgt_buf = src_buf + src_chunk->size;
            // Read the source chunk
            if (!tsci_os_file_read_at(ctx->tb_handle, src_buf, src_chunk->size,
                                      transfer_op->transfer_buf_offset)) {
              *err = tsci_os_io_err(ctx->tb_handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_read);
              tsci_os_close_handle(handle);
              return false;
            }
            // Patch the chunk
            auto const res =
                tek_sc_sp_patch_chunk(ctx->dec_ctx, src_buf, tgt_buf, pchunk);
            if (!tek_sc_err_success(&res)) {
              *err = res;
              tsci_os_close_handle(handle);
              return false;
            }
            // Write target chunk to the file
            if (!tsci_os_file_write_at(handle, tgt_buf, tgt_chunk->size,
                                       tgt_chunk->offset)) {
              *err = tsci_os_io_err(handle, TEK_SC_ERRC_am_io,
                                    tsci_os_get_last_error(),
                                    TEK_SC_ERR_IO_TYPE_write);
              tsci_os_close_handle(handle);
              return false;
            }
          } // if (tgt_chunk->size <= src_chunk->size) else
          break;
        } // switch (transfer_op->type)
        transfer_op->status = TEK_SC_JOB_ENTRY_STATUS_done;
        ++job->progress_current;
        if (upd_handler) {
          upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
        }
      } // for (int j = 0; j < file->num_transfer_ops; ++j)
      file->status = TEK_SC_JOB_ENTRY_STATUS_active;
    } // if (is_patching && file->status == TEK_SC_JOB_ENTRY_STATUS_active)
    if (file->flags & TEK_SC_DD_FILE_FLAG_truncate) {
      // Pause if requested
      if (atomic_load_explicit(state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        *err = tsc_err_basic(TEK_SC_ERRC_paused);
        tsci_os_close_handle(handle);
        return false;
      }
      // Truncate the file
      if (!tsci_os_file_truncate(handle, file->file->size)) {
        *err =
            tsci_os_io_err(handle, TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                           TEK_SC_ERR_IO_TYPE_truncate);
        tsci_os_close_handle(handle);
        return false;
      }
      ++job->progress_current;
      if (upd_handler) {
        upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
      }
    }
    tsci_os_close_handle(handle);
    file->status = TEK_SC_JOB_ENTRY_STATUS_done;
  } // for (int i = 0; i < dir->num_files; ++i)
  // Iterate subdirectories
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags & TEK_SC_DD_DIR_FLAG_children_patch) ||
        subdir->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      continue;
    }
    auto const handle = tsci_os_dir_open_at(dir_handle, subdir->dir->name);
    if (handle == TSCI_OS_INVALID_HANDLE) {
      *err =
          tsci_os_io_err_at(dir_handle, subdir->dir->name, TEK_SC_ERRC_am_io,
                            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
      return false;
    }
    const bool res = tscp_amjp_process_dir(ctx, subdir, handle, copy_args, err);
    tsci_os_close_handle(handle);
    if (!res) {
      return false;
    }
  }
  dir->status = TEK_SC_JOB_ENTRY_STATUS_done;
  return true;
}

/// Get current patching progress for specified directory.
///
/// @param [in] dir
///    Pointer to the delta directory entry to process.
/// @return Current patching progress for the directory, in bytes.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int64_t tscp_amjp_init_dir(const tek_sc_dd_dir *_Nonnull dir) {
  int64_t progress = 0;
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags &
          (TEK_SC_DD_FILE_FLAG_patch | TEK_SC_DD_FILE_FLAG_truncate))) {
      continue;
    }
    if ((file->flags & TEK_SC_DD_FILE_FLAG_truncate) &&
        file->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      ++progress;
    }
    for (int j = 0; j < file->num_transfer_ops; ++j) {
      auto const transfer_op = &file->transfer_ops[j];
      if (transfer_op->transfer_buf_offset >= 0 &&
          transfer_op->status != TEK_SC_JOB_ENTRY_STATUS_pending) {
        ++progress;
      }
      if (transfer_op->status == TEK_SC_JOB_ENTRY_STATUS_done) {
        ++progress;
      }
    }
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags & TEK_SC_DD_DIR_FLAG_children_patch)) {
      continue;
    }
    progress += tscp_amjp_init_dir(subdir);
  }
  return progress;
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_job_patch(tek_sc_am *am, tsci_am_item_desc *desc,
                             tsci_am_job_ctx *ctx) {
  tscp_amjp_ctx pctx;
  pctx.desc = desc;
  auto const root_delta_dir = ctx->delta.dirs;
  // Setup progress and notify update handler
  auto const job = &desc->desc.job;
  job->stage = TEK_SC_AM_JOB_STAGE_patching;
  job->progress_current = tscp_amjp_init_dir(root_delta_dir);
  job->progress_total = ctx->delta.num_io_ops;
  auto const upd_handler = desc->job_upd_handler;
  if (upd_handler) {
    upd_handler(&desc->desc,
                TEK_SC_AM_UPD_TYPE_stage | TEK_SC_AM_UPD_TYPE_progress);
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
  }
  // Open/set item's root installation directory handle
  tek_sc_os_handle root_handle;
  auto const ws_item_id = desc->desc.id.ws_item_id;
  if (ws_item_id) {
    tek_sc_os_char dir_name[21];
    TSCI_OS_SNPRINTF(dir_name, sizeof dir_name / sizeof *dir_name,
                     TEK_SC_OS_STR("%" PRIu64), ws_item_id);
    root_handle = tsci_os_dir_create_at(am->ws_dir_handle, dir_name);
    if (root_handle == TSCI_OS_INVALID_HANDLE) {
      return tsci_os_io_err_at(am->ws_dir_handle, dir_name, TEK_SC_ERRC_am_io,
                               tsci_os_get_last_error(),
                               TEK_SC_ERR_IO_TYPE_open);
    }
  } else {
    root_handle = am->inst_dir_handle;
  }
  tek_sc_err res;
  // Scan all transfer operations to determine if transfer buffer file is needed
  pctx.tb_handle = TSCI_OS_INVALID_HANDLE;
  for (int i = 0; i < ctx->delta.num_transfer_ops; ++i) {
    if (ctx->delta.transfer_ops[i].transfer_buf_offset >= 0) {
      // Create/open the transfer buffer file right here
      pctx.tb_handle = tsci_os_file_create_at(
          ctx->dir_handle, TEK_SC_OS_STR("transfer_buf"),
          TSCI_OS_FILE_ACCESS_rdwr, TSCI_OS_FILE_OPT_sync);
      if (pctx.tb_handle == TSCI_OS_INVALID_HANDLE) {
        res = tsci_os_io_err_at(ctx->dir_handle, TEK_SC_OS_STR("transfer_buf"),
                                TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                                TEK_SC_ERR_IO_TYPE_open);
        goto close_root_dir;
      }
      break;
    }
  }
  // Setup chunk decoding context only if depot patch is used
  if (ctx->delta.patch) {
    pctx.dec_ctx = tek_sc_sp_dec_ctx_create(nullptr);
    if (!pctx.dec_ctx) {
      res = tsc_err_basic(TEK_SC_ERRC_sp_dec_ctx);
      goto close_tb_file;
    }
  }
  tsci_os_copy_args copy_args;
  copy_args.not_same_dev = false;
  copy_args.buf_size = ctx->delta.transfer_buf_size > 0x100000
                           ? ctx->delta.transfer_buf_size
                           : 0x100000;
  copy_args.buf = tsci_os_mem_alloc(copy_args.buf_size);
  if (!copy_args.buf) {
    res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
    goto destroy_dec_ctx;
  };
  // Run patching
  res = tsc_err_ok();
  if (tscp_amjp_process_dir(&pctx, root_delta_dir, root_handle, &copy_args,
                            &res)) {
    // Reset delta progress and set the next stage if available
    const bool install_available =
        root_delta_dir->flags & (TEK_SC_DD_DIR_FLAG_children_new |
                                 TEK_SC_DD_DIR_FLAG_children_download);
    if (install_available || ctx->delta.num_deletions) {
      // Chunk entries are not used at this stage and transfer operation
      //    entries are not used on later stages.
      for (int i = 0; i < ctx->delta.num_files; ++i) {
        ctx->delta.files[i].status = TEK_SC_JOB_ENTRY_STATUS_pending;
      }
      for (int i = 0; i < ctx->delta.num_dirs; ++i) {
        ctx->delta.dirs[i].status = TEK_SC_JOB_ENTRY_STATUS_pending;
      }
      ctx->delta.stage = install_available ? TEK_SC_DD_STAGE_installing
                                           : TEK_SC_DD_STAGE_deleting;
    }
  }
  // Cleanup
  tsci_os_mem_free(copy_args.buf, copy_args.buf_size);
destroy_dec_ctx:
  if (ctx->delta.patch) {
    tek_sc_sp_dec_ctx_destroy(pctx.dec_ctx);
  }
close_tb_file:
  if (pctx.tb_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(pctx.tb_handle);
  }
close_root_dir:
  if (ws_item_id) {
    tsci_os_close_handle(root_handle);
  }
  return res;
}
