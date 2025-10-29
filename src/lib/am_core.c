//===-- am_core.c - Steam application manager core implementation ---------===//
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
/// Implementation of application manager core functionality.
///
//===----------------------------------------------------------------------===//
#include "common/am.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"
#include "tek-steamclient/sp.h"

#include <inttypes.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//===-- Private function --------------------------------------------------===//

/// Create an I/O error object for specified pathname.
///
/// @param [in] path
///    Path to the file/directory that was subject to failed I/O operation,
///    as a null-terminated string.
/// @param prim
///    Primary error code.
/// @param io_type
///    Type of the I/O operation that failed.
/// @return A @ref tek_sc_err describing the I/O error.
[[gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
static inline tek_sc_err tscp_am_io_err(const tek_sc_os_char *_Nonnull path,
                                        tek_sc_errc prim,
                                        tek_sc_err_io_type io_type) {
  auto const errc = tsci_os_get_last_error();
  char *const buf = malloc(tsci_os_pstr_strlen(path) + 1);
  if (buf) {
    buf[tsci_os_pstr_to_str(path, buf)] = '\0';
  }
  return (tek_sc_err){.type = TEK_SC_ERR_TYPE_os,
                      .primary = prim,
                      .auxiliary = errc,
                      .extra = io_type,
                      .uri = buf};
}

//===-- Internal function -------------------------------------------------===//

tek_sc_err tsci_am_clean_job_dir(tek_sc_os_handle data_dir_handle,
                                 const tek_sc_item_id *item_id) {
  tek_sc_os_char dir_path[40];
  if (item_id->ws_item_id) {
    TSCI_OS_SNPRINTF(dir_path, sizeof dir_path / sizeof *dir_path,
                     TEK_SC_OS_STR("jobs" TSCI_OS_PATH_SEP_CHAR_STR "%" PRIx32
                                   "-%" PRIx32 "-%" PRIx64),
                     item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  } else {
    TSCI_OS_SNPRINTF(
        dir_path, sizeof dir_path / sizeof *dir_path,
        TEK_SC_OS_STR("jobs" TSCI_OS_PATH_SEP_CHAR_STR "%" PRIx32 "-%" PRIx32),
        item_id->app_id, item_id->depot_id);
  }
  auto const dir_handle = tsci_os_dir_open_at(data_dir_handle, dir_path);
  if (dir_handle == TSCI_OS_INVALID_HANDLE) {
    auto const errc = tsci_os_get_last_error();
    return errc == TSCI_OS_ERR_FILE_NOT_FOUND
               ? tsc_err_ok()
               : tsci_os_io_err_at(data_dir_handle, dir_path, TEK_SC_ERRC_am_io,
                                   errc, TEK_SC_ERR_IO_TYPE_open);
  }
  auto res = tsci_os_dir_delete_at_rec(dir_handle, TEK_SC_OS_STR("img"),
                                       TEK_SC_ERRC_am_io);
  if (!tek_sc_err_success(&res)) {
    goto close_dir_handle;
  }
  static const tek_sc_os_char *const filenames[] = {
      TEK_SC_OS_STR("transfer_buf"), TEK_SC_OS_STR("chunk_buf"),
      TEK_SC_OS_STR("delta"), TEK_SC_OS_STR("vcache"), TEK_SC_OS_STR("patch")};
  for (size_t i = 0; i < sizeof filenames / sizeof *filenames; ++i) {
    if (!tsci_os_file_delete_at(dir_handle, filenames[i])) {
      auto const errc = tsci_os_get_last_error();
      if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
        res = tsci_os_io_err_at(dir_handle, filenames[i], TEK_SC_ERRC_am_io,
                                errc, TEK_SC_ERR_IO_TYPE_delete);
        goto close_dir_handle;
      }
    }
  }
  res = tsci_os_dir_delete_at(data_dir_handle, dir_path)
            ? tsc_err_ok()
            : tsci_os_io_err_at(data_dir_handle, dir_path, TEK_SC_ERRC_am_io,
                                tsci_os_get_last_error(),
                                TEK_SC_ERR_IO_TYPE_delete);
close_dir_handle:
  tsci_os_close_handle(dir_handle);
  return res;
}

//===-- Public functions --------------------------------------------------===//

tek_sc_am *tek_sc_am_create(tek_sc_lib_ctx *lib_ctx, const tek_sc_os_char *dir,
                            tek_sc_err *err) {
  tek_sc_am *am = malloc(sizeof *am);
  if (!am) {
    *err = tsc_err_sub(TEK_SC_ERRC_am_create, TEK_SC_ERRC_mem_alloc);
    return nullptr;
  }
  am->lib_ctx = lib_ctx;
  // Open/create directories
  am->inst_dir_handle = tsci_os_dir_create(dir);
  if (am->inst_dir_handle == TSCI_OS_INVALID_HANDLE) {
    *err = tscp_am_io_err(dir, TEK_SC_ERRC_am_create, TEK_SC_ERR_IO_TYPE_open);
    goto cleanup_am;
  }
  am->data_dir_handle =
      tsci_os_dir_create_at(am->inst_dir_handle, TEK_SC_OS_STR("tek-sc-data"));
  if (am->data_dir_handle == TSCI_OS_INVALID_HANDLE) {
    *err = tsci_os_io_err_at(am->inst_dir_handle, TEK_SC_OS_STR("tek-sc-data"),
                             TEK_SC_ERRC_am_create, tsci_os_get_last_error(),
                             TEK_SC_ERR_IO_TYPE_open);
    goto cleanup_idh;
  }
  am->ws_dir_handle = TSCI_OS_INVALID_HANDLE;
  // Create CM client instance
  am->cm_client = tek_sc_cm_client_create(lib_ctx, am);
  if (!am->cm_client) {
    *err = tsc_err_sub(TEK_SC_ERRC_am_create, TEK_SC_ERRC_cm_create);
    goto cleanup_ddh;
  }
  // Build state file path and open the database connection
  static const char state_rel_path[] = TSCI_OS_PATH_SEP_CHAR_STR
      "tek-sc-data" TSCI_OS_PATH_SEP_CHAR_STR "state.sqlite3";
  char *const state_path =
      malloc(tsci_os_pstr_strlen(dir) + sizeof state_rel_path);
  if (!state_path) {
    *err = tsc_err_sub(TEK_SC_ERRC_am_create, TEK_SC_ERRC_mem_alloc);
    goto cleanup_cm;
  }
  memcpy(&state_path[tsci_os_pstr_to_str(dir, state_path)], state_rel_path,
         sizeof state_rel_path);
  int res = sqlite3_open_v2(
      state_path, &am->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
  if (res != SQLITE_OK) {
    if (am->db) {
      sqlite3_close_v2(am->db);
    }
    *err = (tek_sc_err){.type = TEK_SC_ERR_TYPE_sqlite,
                        .primary = TEK_SC_ERRC_am_create,
                        .auxiliary = res,
                        .uri = state_path};
    goto cleanup_cm;
  }
  free(state_path);
  res = sqlite3_exec(am->db, "BEGIN", nullptr, nullptr, nullptr);
  // Create tables if they don't exist
  if (res == SQLITE_OK) {
    res = sqlite3_exec(am->db,
                       "CREATE TABLE IF NOT EXISTS state (changenum INTEGER)",
                       nullptr, nullptr, nullptr);
  }
  if (res == SQLITE_OK) {
    res = sqlite3_exec(
        am->db,
        "CREATE TABLE IF NOT EXISTS items (app_id INTEGER, depot_id INTEGER, "
        "ws_item_id INTEGER, status INTEGER, current_manifest_id INTEGER, "
        "latest_manifest_id INTEGER, job_stage INTEGER, job_progress_current "
        "INTEGER, job_progress_total INTEGER, job_src_man_id INTEGER, "
        "job_tgt_man_id INTEGER, job_patch_status INTEGER, UNIQUE(app_id, "
        "depot_id, ws_item_id))",
        nullptr, nullptr, nullptr);
  }
  // Load state variables
  if (res == SQLITE_OK) {
    static const char query[] = "SELECT changenum FROM state";
    sqlite3_stmt *stmt;
    res = sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
    if (res == SQLITE_OK) {
      res = sqlite3_step(stmt);
      if (res == SQLITE_ROW) {
        am->changenum = (uint32_t)sqlite3_column_int(stmt, 0);
        res = SQLITE_OK;
      } else if (res == SQLITE_DONE) {
        am->changenum = 0;
        res = sqlite3_exec(am->db, "INSERT INTO state (changenum) VALUES (0)",
                           nullptr, nullptr, nullptr);
      }
      sqlite3_finalize(stmt);
    }
  }
  // Load item state descriptors
  am->item_descs = nullptr;
  if (res == SQLITE_OK) {
    static const char query[] =
        "SELECT app_id, depot_id, ws_item_id, status, current_manifest_id, "
        "latest_manifest_id, job_stage, job_progress_current, "
        "job_progress_total, job_src_man_id, job_tgt_man_id, job_patch_status "
        "FROM items ORDER BY app_id, depot_id, ws_item_id";
    sqlite3_stmt *stmt;
    res = sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
    if (res == SQLITE_OK) {
      for (auto desc = &am->item_descs;;) {
        res = sqlite3_step(stmt);
        if (res != SQLITE_ROW) {
          break;
        }
        *desc = malloc(sizeof **desc);
        auto const item = *desc;
        if (!item) {
          *err = tsc_err_sub(TEK_SC_ERRC_am_create, TEK_SC_ERRC_mem_alloc);
          for (auto desc = am->item_descs; desc;) {
            auto const ptr = desc;
            desc = (tsci_am_item_desc *)desc->desc.next;
            free(ptr);
          }
          goto cleanup_db;
        }
        *item = (tsci_am_item_desc){
            .desc = {
                .id = {.app_id = (uint32_t)sqlite3_column_int(stmt, 0),
                       .depot_id = (uint32_t)sqlite3_column_int(stmt, 1),
                       .ws_item_id = (uint64_t)sqlite3_column_int64(stmt, 2)},
                .status = (tek_sc_am_item_status)sqlite3_column_int(stmt, 3),
                .current_manifest_id = (uint64_t)sqlite3_column_int64(stmt, 4),
                .latest_manifest_id = (uint64_t)sqlite3_column_int64(stmt, 5),
                .job = {
                    .stage = (tek_sc_am_job_stage)sqlite3_column_int(stmt, 6),
                    .progress_current = (int64_t)sqlite3_column_int64(stmt, 7),
                    .progress_total = (int64_t)sqlite3_column_int64(stmt, 8),
                    .source_manifest_id =
                        (uint64_t)sqlite3_column_int64(stmt, 9),
                    .target_manifest_id =
                        (uint64_t)sqlite3_column_int64(stmt, 10),
                    .patch_status = (tek_sc_am_job_patch_status)
                        sqlite3_column_int(stmt, 11)}}};
        desc = (tsci_am_item_desc **)&item->desc.next;
      } // for (auto desc = &am->item_descs;;)
      if (res == SQLITE_DONE) {
        res = SQLITE_OK;
      } else {
        for (auto desc = am->item_descs; desc;) {
          auto const ptr = desc;
          desc = (tsci_am_item_desc *)desc->desc.next;
          free(ptr);
        }
      }
      sqlite3_finalize(stmt);
    } // if (res == SQLITE_OK)
  } // if (res == SQLITE_OK)
  if (res == SQLITE_OK) {
    res = sqlite3_exec(am->db, "COMMIT", nullptr, nullptr, nullptr);
  }
  if (res != SQLITE_OK) {
    *err = (tek_sc_err){.type = TEK_SC_ERR_TYPE_sqlite,
                        .primary = TEK_SC_ERRC_am_create,
                        .auxiliary = res};
    goto cleanup_db;
  }
  pthread_mutex_init(&am->item_descs_mtx, nullptr);
  pthread_mutex_init(&am->cm_ctx.mtx, nullptr);
  *err = tsc_err_ok();
  return am;
cleanup_db:
  sqlite3_close_v2(am->db);
cleanup_cm:
  tek_sc_cm_client_destroy(am->cm_client);
cleanup_ddh:
  tsci_os_close_handle(am->data_dir_handle);
cleanup_idh:
  tsci_os_close_handle(am->inst_dir_handle);
cleanup_am:
  free(am);
  return nullptr;
}

void tek_sc_am_destroy(tek_sc_am *am) {
  pthread_mutex_lock(&am->item_descs_mtx);
  for (auto desc = am->item_descs; desc;
       desc = (tsci_am_item_desc *)desc->desc.next) {
    tek_sc_am_job_state expected = TEK_SC_AM_JOB_STATE_running;
    if (atomic_compare_exchange_strong_explicit(
            &desc->desc.job.state, &expected, TEK_SC_AM_JOB_STATE_pause_pending,
            memory_order_acquire, memory_order_relaxed)) {
      if (desc->dlr) {
        tek_sc_sp_multi_dlr_cancel(desc->dlr);
      }
      atomic_store_explicit(&desc->sp_cancel_flag, true, memory_order_relaxed);
      tsci_os_futex_wait((const _Atomic(uint32_t) *)&desc->desc.job.state,
                         TEK_SC_AM_JOB_STATE_pause_pending, UINT32_MAX);
    }
  }
  pthread_mutex_unlock(&am->item_descs_mtx);
  pthread_mutex_destroy(&am->cm_ctx.mtx);
  pthread_mutex_destroy(&am->item_descs_mtx);
  for (auto desc = am->item_descs; desc;) {
    auto const ptr = desc;
    desc = (tsci_am_item_desc *)desc->desc.next;
    free(ptr);
  }
  sqlite3_close_v2(am->db);
  tek_sc_cm_client_destroy(am->cm_client);
  if (am->ws_dir_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(am->ws_dir_handle);
  }
  tsci_os_close_handle(am->data_dir_handle);
  tsci_os_close_handle(am->inst_dir_handle);
  free(am);
}

tek_sc_err tek_sc_am_set_ws_dir(tek_sc_am *am, const tek_sc_os_char *ws_dir) {
  am->ws_dir_handle = tsci_os_dir_create(ws_dir);
  return am->ws_dir_handle == TSCI_OS_INVALID_HANDLE
             ? tscp_am_io_err(ws_dir, TEK_SC_ERRC_am_ws_dir,
                              TEK_SC_ERR_IO_TYPE_open)
             : tsc_err_ok();
}

tek_sc_am_item_desc *tek_sc_am_get_item_desc(tek_sc_am *am,
                                             const tek_sc_item_id *item_id) {
  if (!item_id) {
    return &am->item_descs->desc;
  }
  pthread_mutex_lock(&am->item_descs_mtx);
  auto desc = &am->item_descs->desc;
  while (desc) {
    const int res = tsci_am_cmp_item_id(&desc->id, item_id);
    if (!res) {
      break;
    }
    desc = res > 0 ? nullptr : desc->next;
  }
  pthread_mutex_unlock(&am->item_descs_mtx);
  return desc;
}

void tek_sc_am_item_descs_lock(tek_sc_am *am) {
  pthread_mutex_lock(&am->item_descs_mtx);
}

void tek_sc_am_item_descs_unlock(tek_sc_am *am) {
  pthread_mutex_unlock(&am->item_descs_mtx);
}

void tek_sc_am_pause_job(tek_sc_am_item_desc *item_desc) {
  tek_sc_am_job_state expected = TEK_SC_AM_JOB_STATE_running;
  if (!atomic_compare_exchange_strong_explicit(
          &item_desc->job.state, &expected, TEK_SC_AM_JOB_STATE_pause_pending,
          memory_order_acquire, memory_order_relaxed)) {
    return;
  }
  auto const desc = (tsci_am_item_desc *)item_desc;
  if (desc->dlr) {
    tek_sc_sp_multi_dlr_cancel(desc->dlr);
  }
  atomic_store_explicit(&desc->sp_cancel_flag, true, memory_order_relaxed);
  if (desc->job_upd_handler) {
    desc->job_upd_handler(item_desc, TEK_SC_AM_UPD_TYPE_state);
  }
}

tek_sc_err tek_sc_am_cancel_job(tek_sc_am *am, tek_sc_am_item_desc *item_desc) {
  if (!(item_desc->status & TEK_SC_AM_ITEM_STATUS_job)) {
    return tsc_err_basic(TEK_SC_ERRC_am_no_job);
  }
  if (atomic_load_explicit(&item_desc->job.state, memory_order_relaxed) !=
      TEK_SC_AM_JOB_STATE_stopped) {
    return tsc_err_basic(TEK_SC_ERRC_am_job_alr_running);
  }
  // Clean job directory
  auto res = tsci_am_clean_job_dir(am->data_dir_handle, &item_desc->id);
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  item_desc->status &= ~TEK_SC_AM_ITEM_STATUS_job;
  // Clean job state descriptor fields
  auto const job = &item_desc->job;
  job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
  job->progress_current = 0;
  job->progress_total = 0;
  job->source_manifest_id = 0;
  job->target_manifest_id = 0;
  job->patch_status = TEK_SC_AM_JOB_PATCH_STATUS_unknown;
  int sqlite_res;
  if (item_desc->current_manifest_id) {
    // Commit changes to the state database
    static const char query[] =
        "UPDATE items SET status = ?, job_stage = 0, job_progress_current = 0, "
        "job_progress_total = 0, job_src_man_id = 0, job_tgt_man_id = 0, "
        "job_patch_status = 0 WHERE app_id = ? AND depot_id = ? AND ws_item_id "
        "= ?";
    sqlite3_stmt *stmt;
    sqlite_res =
        sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
    if (sqlite_res == SQLITE_OK) {
      sqlite_res = sqlite3_bind_int(stmt, 1, item_desc->status);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_upd_stmt;
      }
      sqlite_res = sqlite3_bind_int(stmt, 2, (int)item_desc->id.app_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_upd_stmt;
      }
      sqlite_res = sqlite3_bind_int(stmt, 3, (int)item_desc->id.depot_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_upd_stmt;
      }
      sqlite_res =
          sqlite3_bind_int64(stmt, 4, (sqlite3_int64)item_desc->id.ws_item_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_upd_stmt;
      }
      sqlite_res = sqlite3_step(stmt);
      if (sqlite_res == SQLITE_DONE) {
        sqlite_res = SQLITE_OK;
      }
    cleanup_upd_stmt:
      sqlite3_finalize(stmt);
    } // if (sqlite_res == SQLITE_OK)
  } else { // if (item_desc->current_manifest_id)
    // Delete item entry from the state database
    static const char query[] = "DELETE FROM items WHERE app_id = ? AND "
                                "depot_id = ? AND ws_item_id = ?";
    sqlite3_stmt *stmt;
    sqlite_res =
        sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
    if (sqlite_res == SQLITE_OK) {
      sqlite_res = sqlite3_bind_int(stmt, 1, (int)item_desc->id.app_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_del_stmt;
      }
      sqlite_res = sqlite3_bind_int(stmt, 2, (int)item_desc->id.depot_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_del_stmt;
      }
      sqlite_res =
          sqlite3_bind_int64(stmt, 3, (sqlite3_int64)item_desc->id.ws_item_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_del_stmt;
      }
      sqlite_res = sqlite3_step(stmt);
      if (sqlite_res == SQLITE_DONE) {
        sqlite_res = SQLITE_OK;
      }
    cleanup_del_stmt:
      sqlite3_finalize(stmt);
    } // if (sqlite_res == SQLITE_OK)
  } // if (item_desc->current_manifest_id) else
  if (sqlite_res != SQLITE_OK) {
    res = (tek_sc_err){.type = TEK_SC_ERR_TYPE_sqlite,
                       .primary = TEK_SC_ERRC_am_db_update,
                       .auxiliary = sqlite_res};
  }
  if (!item_desc->current_manifest_id &&
      !pthread_mutex_trylock(&am->item_descs_mtx)) {
    // Remove and free the item state descriptor
    if (&am->item_descs->desc == item_desc) {
      am->item_descs = (tsci_am_item_desc *)item_desc->next;
    } else {
      for (auto prev_desc = (tek_sc_am_item_desc *)am->item_descs; prev_desc;
           prev_desc = prev_desc->next) {
        if (prev_desc->next == item_desc) {
          prev_desc->next = item_desc->next;
          break;
        }
      }
    }
    free(item_desc);
    pthread_mutex_unlock(&am->item_descs_mtx);
  }
  return res;
}
