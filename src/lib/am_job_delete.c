//===-- am_job_delete.c - job deletion stage implementation ---------------===//
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
/// Implementation of @ref tsci_am_job_delete.
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
#include <stdatomic.h>
#include <stdint.h>

//===-- Private functions -------------------------------------------------===//

/// Delete delisted files in specified directory.
///
/// @param [in, out] item_desc
///    Pointer to the current item state descriptor.
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
/// @param dir_handle
///    OS handle for the directory.
/// @param [out] err
///    Address of variable that receives the error object on failure.
/// @return Value indicating whether the operation was successful.
[[gnu::nonnull(1, 2, 4), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(write_only, 4)]]
static bool tscp_amjdel_process_dir(tsci_am_item_desc *_Nonnull item_desc,
                                    tek_sc_dd_dir *_Nonnull dir,
                                    tek_sc_os_handle dir_handle,
                                    tek_sc_err *_Nonnull err) {
  auto const desc = &item_desc->desc;
  auto const job = &desc->job;
  auto const state = &job->state;
  auto const upd_handler = item_desc->job_upd_handler;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if (!(file->flags & TEK_SC_DD_FILE_FLAG_delete) ||
        file->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      continue;
    }
    // Pause if requested
    if (atomic_load_explicit(state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      *err = tsc_err_basic(TEK_SC_ERRC_paused);
      return false;
    }
    if (!tsci_os_file_delete_at(dir_handle, file->file->name)) {
      auto const errc = tsci_os_get_last_error();
      if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
        *err =
            tsci_os_io_err_at(dir_handle, file->file->name, TEK_SC_ERRC_am_io,
                              errc, TEK_SC_ERR_IO_TYPE_delete);
        return false;
      }
    }
    file->status = TEK_SC_JOB_ENTRY_STATUS_done;
    ++job->progress_current;
    if (upd_handler) {
      upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
    }
  } // for (int i = 0; i < dir->num_files; ++i)
  // Iterate subdirectories
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (!(subdir->flags &
          (TEK_SC_DD_DIR_FLAG_delete | TEK_SC_DD_DIR_FLAG_children_delete)) ||
        subdir->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      continue;
    }
    if (subdir->flags & TEK_SC_DD_DIR_FLAG_children_delete) {
      auto const handle = tsci_os_dir_open_at(dir_handle, subdir->dir->name);
      if (handle == TSCI_OS_INVALID_HANDLE) {
        auto const errc = tsci_os_get_last_error();
        if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
          *err = tsci_os_io_err_at(dir_handle, subdir->dir->name,
                                   TEK_SC_ERRC_am_io, errc,
                                   TEK_SC_ERR_IO_TYPE_open);
          return false;
        }
      } else {
        const bool res =
            tscp_amjdel_process_dir(item_desc, subdir, handle, err);
        tsci_os_close_handle(handle);
        if (!res) {
          return false;
        }
      }
    }
    if (subdir->flags & TEK_SC_DD_DIR_FLAG_delete) {
      if (!tsci_os_dir_delete_at(dir_handle, subdir->dir->name)) {
        auto const errc = tsci_os_get_last_error();
        if (errc != TSCI_OS_ERR_FILE_NOT_FOUND &&
            errc != TSCI_OS_ERR_DIR_NOT_EMPTY) {
          *err = tsci_os_io_err_at(dir_handle, subdir->dir->name,
                                   TEK_SC_ERRC_am_io, errc,
                                   TEK_SC_ERR_IO_TYPE_delete);
          return false;
        }
      }
      ++job->progress_current;
      if (upd_handler) {
        upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
      }
    }
    subdir->status = TEK_SC_JOB_ENTRY_STATUS_done;
  } // for (int i = 0; i < dir->num_subdirs; ++i)
  return true;
}

/// Get current deletion progress for specified directory.
///
/// @param [in] dir
///    Pointer to the delta directory entry to process.
/// @return Current deletion progress for the directory, in bytes.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int64_t tscp_amjdel_init_dir(const tek_sc_dd_dir *_Nonnull dir) {
  int64_t progress = (dir->flags & TEK_SC_DD_DIR_FLAG_delete) &&
                             dir->status == TEK_SC_JOB_ENTRY_STATUS_done
                         ? 1
                         : 0;
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    if ((file->flags & TEK_SC_DD_FILE_FLAG_delete) &&
        file->status == TEK_SC_JOB_ENTRY_STATUS_done) {
      ++progress;
    }
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    if (subdir->flags &
        (TEK_SC_DD_DIR_FLAG_delete | TEK_SC_DD_DIR_FLAG_children_delete)) {
      progress += tscp_amjdel_init_dir(subdir);
    }
  }
  return progress;
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_job_delete(tek_sc_am *am, tsci_am_item_desc *desc,
                              tsci_am_job_ctx *ctx) {
  auto const root_delta_dir = ctx->delta.dirs;
  // Setup progress and notify update handler
  auto const job = &desc->desc.job;
  job->stage = TEK_SC_AM_JOB_STAGE_deleting;
  job->progress_current = tscp_amjdel_init_dir(root_delta_dir);
  job->progress_total = ctx->delta.num_deletions;
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
  // Run deletion
  auto res = tsc_err_ok();
  tscp_amjdel_process_dir(desc, root_delta_dir, root_handle, &res);
  // Cleanup
  if (ws_item_id) {
    tsci_os_close_handle(root_handle);
  }
  return res;
}
