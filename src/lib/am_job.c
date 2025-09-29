//===-- am_job.c - Steam application manager job skeleton -----------------===//
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
/// Implementation of @ref tek_sc_am_run_job.
///
//===----------------------------------------------------------------------===//
#include "common/am.h"

#include "common/error.h"
#include "config.h" // IWYU pragma: keep
#include "os.h"
#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"
#include "tek-steamclient/sp.h"
#ifdef TEK_SCB_S3C
#include "tek-steamclient/s3c.h"
#endif // def TEK_SCB_S3C

#include <inttypes.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <zstd.h>

/// Singleton empty root directory entry used by fictional uninstallation
///    manifests.
static tek_sc_dm_dir tscp_am_empty_dir = {};

//===-- Private types -----------------------------------------------------===//

/// SteamPipe manifest download context.
typedef struct tscp_am_sp_ctx_dm tscp_am_sp_ctx_dm;
/// @copydoc tscp_am_sp_ctx_dm
struct tscp_am_sp_ctx_dm {
  /// Input/output data for SteamPipe downloader API.
  tek_sc_sp_data_dm data;
  /// Pointer to the item state descriptor.
  tek_sc_am_item_desc *_Nonnull item_desc;
  /// Optional pointer to the job state update handler function to use.
  tek_sc_am_job_upd_func *_Nullable upd_handler;
};

/// SteamPipe patch download context.
typedef struct tscp_am_sp_ctx_dp tscp_am_sp_ctx_dp;
/// @copydoc tscp_am_sp_ctx_dp
struct tscp_am_sp_ctx_dp {
  /// Input/output data for SteamPipe downloader API.
  tek_sc_sp_data_dp data;
  /// Pointer to the item state descriptor.
  tek_sc_am_item_desc *_Nonnull item_desc;
  /// Optional pointer to the job state update handler function to use.
  tek_sc_am_job_upd_func *_Nullable upd_handler;
};

//===-- Private functions -------------------------------------------------===//

/// Create a @ref tek_sc_err out of a @ref tek_sc_errc and an SQLite error code.
///
/// @param prim
///    Primary error code.
/// @param errc
///    SQLite error code.
/// @return A @ref tek_sc_err for specified error codes.
[[gnu::const]]
static inline tek_sc_err tscp_am_err_sqlite(tek_sc_errc prim, int errc) {
  return (tek_sc_err){
      .type = TEK_SC_ERR_TYPE_sqlite, .primary = prim, .auxiliary = errc};
}

/// Check if specified @ref tek_sc_err indicates an error condition or not.
///
/// @param [in] err
///    Pointer to the @ref tek_sc_err to examine.
/// @return Value indicating whether @p err indicates an error condition.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static inline bool tscp_am_is_err(const tek_sc_err *_Nonnull err) {
  switch (err->primary) {
  case TEK_SC_ERRC_ok:
  case TEK_SC_ERRC_paused:
  case TEK_SC_ERRC_up_to_date:
    return false;
  default:
    return true;
  }
}

/// Check if specified @ref tek_sc_err indicates that the job has finished or
///    not.
///
/// @param [in] err
///    Pointer to the @ref tek_sc_err to examine.
/// @return Value indicating whether @p err indicates that the job has finished.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static inline bool tscp_am_is_finished(const tek_sc_err *_Nonnull err) {
  return err->primary == TEK_SC_ERRC_ok ||
         err->primary == TEK_SC_ERRC_up_to_date;
}

/// SteamPipe manifest download progress handler.
///
/// @param [in] data
///    Pointer to the corresponding @ref tscp_am_sp_ctx_dm.
/// @param current
///    Current download progress value, in bytes.
/// @param total
///    Total size of the file being downloaded, in bytes.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static void tscp_am_sp_handle_progress_dm(void *_Nonnull data, int current,
                                          int total) {
  const tscp_am_sp_ctx_dm *const ctx = data;
  auto const desc = ctx->item_desc;
  auto const job = &desc->job;
  job->progress_current = current;
  job->progress_total = total;
  auto const upd_handler = ctx->upd_handler;
  if (upd_handler) {
    upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
  }
}

/// SteamPipe patch download progress handler.
///
/// @param [in] data
///    Pointer to the corresponding @ref tscp_am_sp_ctx_dp.
/// @param current
///    Current download progress value, in bytes.
/// @param total
///    Total size of the file being downloaded, in bytes.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static void tscp_am_sp_handle_progress_dp(void *_Nonnull data, int current,
                                          int total) {
  const tscp_am_sp_ctx_dp *const ctx = data;
  auto const desc = ctx->item_desc;
  auto const job = &desc->job;
  job->progress_current = current;
  job->progress_total = total;
  auto const upd_handler = ctx->upd_handler;
  if (upd_handler) {
    upd_handler(desc, TEK_SC_AM_UPD_TYPE_progress);
  }
}

/// Load specified manifest from the file if present, or download it from
///    SteamPipe if not.
///
/// @param [in, out] am
///    Pointer to the application manager instance loading the manifest.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item to load manifest for.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @param dir_handle
///    Handle for the "manifests" directory.
/// @param manifest_id
///    ID of the manifest to load.
/// @param [out] manifest
///    Address of variable that receives the manifest on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::nonnull(1, 2, 3, 6), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_write, 3),
  gnu::access(read_write, 6)]]
static tek_sc_err
tscp_am_load_manifest(tek_sc_am *_Nonnull am, tsci_am_item_desc *_Nonnull desc,
                      tsci_am_job_ctx *_Nonnull ctx,
                      tek_sc_os_handle dir_handle, uint64_t manifest_id,
                      tek_sc_depot_manifest *_Nonnull manifest) {
  tek_sc_os_char file_name[56];
  auto const item_id = &desc->desc.id;
  if (item_id->ws_item_id) {
    TSCI_OS_SNPRINTF(
        file_name, sizeof file_name / sizeof *file_name,
        TEK_SC_OS_STR("%" PRIx32 "-%" PRIx32 "-%" PRIx64 "_%" PRIx64 ".zst"),
        item_id->app_id, item_id->depot_id, item_id->ws_item_id, manifest_id);
  } else {
    TSCI_OS_SNPRINTF(file_name, sizeof file_name / sizeof *file_name,
                     TEK_SC_OS_STR("%" PRIx32 "-%" PRIx32 "_%" PRIx64 ".zst"),
                     item_id->app_id, item_id->depot_id, manifest_id);
  }
  auto file_handle =
      tsci_os_file_open_at(dir_handle, file_name, TSCI_OS_FILE_ACCESS_read);
  if (file_handle != TSCI_OS_INVALID_HANDLE) {
    // Load existing file
    auto const file_size = tsci_os_file_get_size(file_handle);
    if (file_size == SIZE_MAX) {
      auto const err =
          tsci_os_io_err(file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
      tsci_os_close_handle(file_handle);
      return err;
    }
    auto const file_buf = tsci_os_mem_alloc(file_size);
    if (!file_buf) {
      auto const errc = tsci_os_get_last_error();
      tsci_os_close_handle(file_handle);
      return tsci_err_os(TEK_SC_ERRC_mem_alloc, errc);
    }
    if (!tsci_os_file_read(file_handle, file_buf, file_size)) {
      auto const err =
          tsci_os_io_err(file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
      tsci_os_mem_free(file_buf, file_size);
      tsci_os_close_handle(file_handle);
      return err;
    }
    tsci_os_close_handle(file_handle);
    auto const uncomp_size = ZSTD_getFrameContentSize(file_buf, file_size);
    if (uncomp_size == ZSTD_CONTENTSIZE_UNKNOWN ||
        uncomp_size == ZSTD_CONTENTSIZE_ERROR) {
      tsci_os_mem_free(file_buf, file_size);
      tsci_os_file_delete_at(dir_handle, file_name);
      return tsc_err_sub(TEK_SC_ERRC_manifest_deserialize, TEK_SC_ERRC_zstd);
    }
    auto const uncomp_buf = tsci_os_mem_alloc(uncomp_size);
    if (!uncomp_buf) {
      auto const errc = tsci_os_get_last_error();
      tsci_os_mem_free(file_buf, file_size);
      return tsci_err_os(TEK_SC_ERRC_mem_alloc, errc);
    }
    auto const decomp_res =
        ZSTD_decompress(uncomp_buf, uncomp_size, file_buf, file_size);
    tsci_os_mem_free(file_buf, file_size);
    if (decomp_res != uncomp_size) {
      tsci_os_mem_free(uncomp_buf, uncomp_size);
      tsci_os_file_delete_at(dir_handle, file_name);
      return tsc_err_sub(TEK_SC_ERRC_manifest_deserialize, TEK_SC_ERRC_zstd);
    }
    auto const res = tek_sc_dm_deserialize(uncomp_buf, uncomp_size, manifest);
    tsci_os_mem_free(uncomp_buf, uncomp_size);
    if (!tek_sc_err_success(&res)) {
      tsci_os_file_delete_at(dir_handle, file_name);
    }
    return res;
  } // if (file_handle != TSCI_OS_INVALID_HANDLE)
  auto const errc = tsci_os_get_last_error();
  if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
    return tsci_os_io_err_at(dir_handle, file_name, TEK_SC_ERRC_am_io, errc,
                             TEK_SC_ERR_IO_TYPE_open);
  }
  // File doesn't exist, get manifest from SteamPipe
  auto const job = &desc->desc.job;
  auto const upd_handler = desc->job_upd_handler;
  if (job->stage != TEK_SC_AM_JOB_STAGE_fetching_data) {
    job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
    if (upd_handler) {
      upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
    }
  }
  if (!ctx->sp_srvs) {
    // Get SteamPipe server list
    auto const res = tsci_am_get_sp_servers(am, ctx);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
  }
  tek_sc_aes256_key key;
  if (!tek_sc_lib_get_depot_key(am->lib_ctx, item_id->depot_id, key)) {
    /// Get depot decryption key
    auto const res = tsci_am_get_depot_key(am, item_id);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
    tek_sc_lib_get_depot_key(am->lib_ctx, item_id->depot_id, key);
  }
  tscp_am_sp_ctx_dm sp_ctx;
  auto const sp_common = &sp_ctx.data.common;
  sp_common->srvs = ctx->sp_srvs;
  sp_common->num_srvs = ctx->num_sp_srvs;
  sp_common->progress_handler = tscp_am_sp_handle_progress_dm;
  sp_common->depot_id = item_id->depot_id;
  sp_ctx.data.manifest_id = manifest_id;
// Get manifest request code
#ifdef TEK_SCB_S3C
  auto s3_srv = tek_sc_s3c_get_srv_for_mrc(am->lib_ctx, item_id->app_id,
                                           item_id->depot_id);
  if (s3_srv) {
    tek_sc_cm_data_mrc data_mrc;
    data_mrc.app_id = item_id->app_id;
    data_mrc.depot_id = item_id->depot_id;
    data_mrc.manifest_id = manifest_id;
    /// Make up to 5 attempts to get MRC, so it uses different tek-s3 servers if
    ///    available
    for (int i = 0; i < 5; ++i) {
      tek_sc_s3c_get_mrc(s3_srv, 8000, &data_mrc);
      if (!tek_sc_err_success(&data_mrc.result)) {
        s3_srv = tek_sc_s3c_get_srv_for_mrc(am->lib_ctx, item_id->app_id,
                                            item_id->depot_id);
        continue;
      }
      if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        return tsc_err_basic(TEK_SC_ERRC_paused);
      }
      sp_ctx.data.request_code = data_mrc.request_code;
      break;
    }
    if (!tek_sc_err_success(&data_mrc.result)) {
      return data_mrc.result;
    }
  } else
#endif // def TEK_SCB_S3C
  {
    auto const res =
        tsci_am_get_mrc(am, item_id, manifest_id, &sp_ctx.data.request_code);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
  }
  sp_ctx.item_desc = &desc->desc;
  sp_ctx.upd_handler = upd_handler;
  // Run download
  job->progress_current = 0;
  job->progress_total = 0;
  job->stage = TEK_SC_AM_JOB_STAGE_dw_manifest;
  if (upd_handler) {
    upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
  }
  auto res = tek_sc_sp_download_dm(&sp_ctx.data, 600000, &desc->sp_cancel_flag);
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  // Parse downloaded file
  res = tek_sc_dm_parse(sp_common->data, sp_common->data_size, key, manifest);
  free(sp_common->data);
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  manifest->item_id = *item_id;
  // Serialize manifest data
  const int ser_size = tek_sc_dm_serialize(manifest, nullptr, 0);
  auto const ser_buf = tsci_os_mem_alloc(ser_size);
  if (!ser_buf) {
    return tsc_err_ok();
  }
  tek_sc_dm_serialize(manifest, ser_buf, ser_size);
  // Compress serialized data
  auto const comp_max_size = ZSTD_compressBound(ser_size);
  auto const comp_buf = tsci_os_mem_alloc(comp_max_size);
  if (!comp_buf) {
    tsci_os_mem_free(ser_buf, ser_size);
    return tsc_err_ok();
  }
  auto const comp_size =
      ZSTD_compress(comp_buf, comp_max_size, ser_buf, ser_size, 15);
  tsci_os_mem_free(ser_buf, ser_size);
  if (ZSTD_isError(comp_size)) {
    tsci_os_mem_free(comp_buf, comp_max_size);
    return tsc_err_ok();
  }
  // Write compressed data to file
  file_handle =
      tsci_os_file_create_at(dir_handle, file_name, TSCI_OS_FILE_ACCESS_write);
  if (file_handle != TSCI_OS_INVALID_HANDLE) {
    if (!tsci_os_file_write(file_handle, comp_buf, comp_size)) {
      tsci_os_file_delete_at(dir_handle, file_name);
    }
    tsci_os_close_handle(file_handle);
  }
  tsci_os_mem_free(comp_buf, comp_max_size);
  return tsc_err_ok();
}

/// Load patch needed by the job from the file if present, or download it from
///    SteamPipe if not.
///
/// @param [in, out] am
///    Pointer to the application manager instance loading the patch.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item to load patch for.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static tek_sc_err tscp_am_load_patch(tek_sc_am *_Nonnull am,
                                     tsci_am_item_desc *_Nonnull desc,
                                     tsci_am_job_ctx *_Nonnull ctx) {
  static const tek_sc_os_char file_name[] = TEK_SC_OS_STR("patch");
  auto file_handle = tsci_os_file_open_at(ctx->dir_handle, file_name,
                                          TSCI_OS_FILE_ACCESS_read);
  if (file_handle != TSCI_OS_INVALID_HANDLE) {
    // Load existing file
    auto const file_size = tsci_os_file_get_size(file_handle);
    if (file_size == SIZE_MAX) {
      auto const err =
          tsci_os_io_err(file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
      tsci_os_close_handle(file_handle);
      return err;
    }
    auto const file_buf = tsci_os_mem_alloc(file_size);
    if (!file_buf) {
      auto const errc = tsci_os_get_last_error();
      tsci_os_close_handle(file_handle);
      return tsci_err_os(TEK_SC_ERRC_mem_alloc, errc);
    }
    if (!tsci_os_file_read(file_handle, file_buf, file_size)) {
      auto const err =
          tsci_os_io_err(file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
      tsci_os_mem_free(file_buf, file_size);
      tsci_os_close_handle(file_handle);
      return err;
    }
    tsci_os_close_handle(file_handle);
    auto const res =
        tek_sc_dp_deserialize(file_buf, file_size, &ctx->source_manifest,
                              &ctx->target_manifest, &ctx->patch);
    tsci_os_mem_free(file_buf, file_size);
    if (!tek_sc_err_success(&res)) {
      tsci_os_file_delete_at(ctx->dir_handle, file_name);
    }
    return res;
  } // if (file_handle != TSCI_OS_INVALID_HANDLE)
  auto const errc = tsci_os_get_last_error();
  if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
    return tsci_os_io_err_at(ctx->dir_handle, file_name, TEK_SC_ERRC_am_io,
                             errc, TEK_SC_ERR_IO_TYPE_open);
  }
  // File doesn't exist, get patch from SteamPipe
  auto const job = &desc->desc.job;
  auto const upd_handler = desc->job_upd_handler;
  if (!ctx->sp_srvs) {
    if (job->stage != TEK_SC_AM_JOB_STAGE_fetching_data) {
      job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
      if (upd_handler) {
        upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
      }
    }
    // Get SteamPipe server list
    auto const res = tsci_am_get_sp_servers(am, ctx);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
  }
  auto const item_id = &desc->desc.id;
  tek_sc_aes256_key key;
  if (!tek_sc_lib_get_depot_key(am->lib_ctx, item_id->depot_id, key)) {
    if (job->stage != TEK_SC_AM_JOB_STAGE_fetching_data) {
      job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
      if (upd_handler) {
        upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
      }
    }
    /// Get depot decryption key
    auto const res = tsci_am_get_depot_key(am, item_id);
    if (!tek_sc_err_success(&res)) {
      return res;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      return tsc_err_basic(TEK_SC_ERRC_paused);
    }
    tek_sc_lib_get_depot_key(am->lib_ctx, item_id->depot_id, key);
  }
  tscp_am_sp_ctx_dp sp_ctx;
  auto const sp_common = &sp_ctx.data.common;
  sp_common->srvs = ctx->sp_srvs;
  sp_common->num_srvs = ctx->num_sp_srvs;
  sp_common->progress_handler = tscp_am_sp_handle_progress_dp;
  sp_common->depot_id = item_id->depot_id;
  sp_ctx.data.src_manifest_id = job->source_manifest_id;
  sp_ctx.data.tgt_manifest_id = job->target_manifest_id;
  sp_ctx.item_desc = &desc->desc;
  sp_ctx.upd_handler = upd_handler;
  // Run download
  job->progress_current = 0;
  job->progress_total = 0;
  job->stage = TEK_SC_AM_JOB_STAGE_dw_patch;
  if (upd_handler) {
    upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
  }
  auto res =
      tek_sc_sp_download_dp(&sp_ctx.data, 3600000, &desc->sp_cancel_flag);
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  // Parse downloaded file
  res = tek_sc_dp_parse(sp_common->data, sp_common->data_size, key,
                        &ctx->source_manifest, &ctx->target_manifest,
                        &ctx->patch);
  free(sp_common->data);
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  // Serialize patch data to file
  file_handle = tsci_os_file_create_at(ctx->dir_handle, file_name,
                                       TSCI_OS_FILE_ACCESS_write);
  if (file_handle != TSCI_OS_INVALID_HANDLE) {
    const int ser_size = tek_sc_dp_serialize(&ctx->patch, nullptr, 0);
    auto const ser_buf = tsci_os_mem_alloc(ser_size);
    if (!ser_buf) {
      tsci_os_close_handle(file_handle);
      return tsc_err_ok();
    }
    tek_sc_dp_serialize(&ctx->patch, ser_buf, ser_size);
    auto const res = tsci_os_file_write(file_handle, ser_buf, ser_size);
    tsci_os_mem_free(ser_buf, ser_size);
    if (!res) {
      tsci_os_file_delete_at(ctx->dir_handle, file_name);
    }
    tsci_os_close_handle(file_handle);
  }
  return tsc_err_ok();
}

//===-- Internal function -------------------------------------------------===//

void tsci_am_job_finish_dir(tek_sc_dd_dir *dir) {
  for (;;) {
    atomic_store_explicit(&dir->status_a, TEK_SC_JOB_ENTRY_STATUS_done,
                          memory_order_relaxed);
    auto const next_dir = dir->parent;
    if (!next_dir) {
      break;
    }
    if (atomic_fetch_sub_explicit(&next_dir->num_rem_children_a, 1,
                                  memory_order_relaxed) > 1) {
      break;
    }
    dir = next_dir;
  }
}

//===-- Public function ---------------------------------------------------===//

tek_sc_err tek_sc_am_run_job(tek_sc_am *am, const tek_sc_am_job_args *args,
                             tek_sc_am_item_desc **item_desc) {
  if (args->item_id->ws_item_id &&
      am->ws_dir_handle == TSCI_OS_INVALID_HANDLE) {
    return tsc_err_basic(TEK_SC_ERRC_am_no_ws_dir);
  }
  pthread_mutex_lock(&am->item_descs_mtx);
  auto desc_ptr = &am->item_descs;
  tsci_am_item_desc *desc = nullptr;
  // Find item's state descriptor or the position in the linked list to
  //    instert it to while maintaining sort order
  while (*desc_ptr) {
    const int res = tsci_am_cmp_item_id(&(*desc_ptr)->desc.id, args->item_id);
    if (!res) {
      desc = *desc_ptr;
      break;
    }
    if (res > 0) {
      break;
    }
    desc_ptr = (tsci_am_item_desc **)&(*desc_ptr)->desc.next;
  }
  auto res = tsc_err_ok();
  sqlite3_stmt *stmt;
  if (!desc) {
    // There was no state descriptor, allocate it and add to the database
    desc = calloc(1, sizeof *desc);
    if (!desc) {
      pthread_mutex_unlock(&am->item_descs_mtx);
      return tsc_err_basic(TEK_SC_ERRC_mem_alloc);
    }
    desc->desc.id = *args->item_id;
    desc->desc.next = *desc_ptr ? &(*desc_ptr)->desc : nullptr;
    *desc_ptr = desc;
    static const char query[] =
        "INSERT INTO items (app_id, depot_id, ws_item_id, status, "
        "current_manifest_id, latest_manifest_id, job_stage, "
        "job_progress_current, "
        "job_progress_total, job_src_man_id, job_tgt_man_id, job_patch_status) "
        "VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0)";
    int sqlite_res =
        sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
    if (sqlite_res == SQLITE_OK) {
      sqlite_res = sqlite3_bind_int(stmt, 1, (int)desc->desc.id.app_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_ins_stmt;
      }
      sqlite_res = sqlite3_bind_int(stmt, 2, (int)desc->desc.id.depot_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_ins_stmt;
      }
      sqlite_res =
          sqlite3_bind_int64(stmt, 3, (sqlite3_int64)desc->desc.id.ws_item_id);
      if (sqlite_res != SQLITE_OK) {
        goto cleanup_ins_stmt;
      }
      sqlite_res = sqlite3_step(stmt);
      if (sqlite_res == SQLITE_DONE) {
        sqlite_res = SQLITE_OK;
      }
    cleanup_ins_stmt:
      sqlite3_finalize(stmt);
    }
    if (sqlite_res != SQLITE_OK) {
      res = tscp_am_err_sqlite(TEK_SC_ERRC_am_db_insert, sqlite_res);
    }
  } // if (!desc)
  pthread_mutex_unlock(&am->item_descs_mtx);
  desc->job_upd_handler = args->upd_handler;
  *item_desc = &desc->desc;
  if (!tek_sc_err_success(&res)) {
    return res;
  }
  auto const job = &desc->desc.job;
  if (!(desc->desc.status & TEK_SC_AM_ITEM_STATUS_job)) {
    if (args->manifest_id == UINT64_MAX && !desc->desc.current_manifest_id) {
      return tsc_err_basic(TEK_SC_ERRC_am_uninst_unknown);
    }
    desc->desc.status |= TEK_SC_AM_ITEM_STATUS_job;
    // Set initial job parameters
    job->source_manifest_id =
        (args->force_verify && args->manifest_id != UINT64_MAX)
            ? 0
            : desc->desc.current_manifest_id;
    job->target_manifest_id = args->manifest_id;
  }
  auto const upd_handler = desc->job_upd_handler;
  // Notify that the job has started
  atomic_store_explicit(&job->state, TEK_SC_AM_JOB_STATE_running,
                        memory_order_release);
  if (upd_handler) {
    upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_state);
  }
  if (!job->target_manifest_id) {
    job->target_manifest_id = desc->desc.latest_manifest_id;
  }
  if (!job->target_manifest_id) {
    // Fetch latest manifest ID from Steam CM
    job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
    if (upd_handler) {
      upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
    }
    res = tsci_am_get_latest_man_id(am, &desc->desc.id);
    if (!tek_sc_err_success(&res)) {
      goto upd_db_item;
    }
    job->target_manifest_id = desc->desc.latest_manifest_id;
    if (!job->target_manifest_id) {
      res.primary = TEK_SC_ERRC_am_no_man_id;
      goto upd_db_item;
    }
    if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
        TEK_SC_AM_JOB_STATE_pause_pending) {
      res.primary = TEK_SC_ERRC_paused;
      goto upd_db_item;
    }
  }
  if (job->source_manifest_id == job->target_manifest_id) {
    res.primary = TEK_SC_ERRC_up_to_date;
    goto finalize;
  }
  if (job->patch_status == TEK_SC_AM_JOB_PATCH_STATUS_unknown) {
    if (job->source_manifest_id && job->target_manifest_id &&
        job->target_manifest_id != UINT64_MAX) {
      // Get patch availability information
      if (job->stage != TEK_SC_AM_JOB_STAGE_fetching_data) {
        job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
        if (upd_handler) {
          upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
        }
      }
      bool available;
      res = tsci_am_get_patch_info(am, &desc->desc.id, job->source_manifest_id,
                                   job->target_manifest_id, &available);
      if (!tek_sc_err_success(&res)) {
        goto upd_db_item;
      }
      job->patch_status = available ? TEK_SC_AM_JOB_PATCH_STATUS_used
                                    : TEK_SC_AM_JOB_PATCH_STATUS_unused;
      if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        res.primary = TEK_SC_ERRC_paused;
        goto upd_db_item;
      }
    } else {
      job->patch_status = TEK_SC_AM_JOB_PATCH_STATUS_unused;
    }
  } // if (job->patch_status == TEK_SC_AM_JOB_PATCH_STATUS_unknown)
  // Open manifests directory
  auto const manifests_dir_handle =
      tsci_os_dir_create_at(am->data_dir_handle, TEK_SC_OS_STR("manifests"));
  if (manifests_dir_handle == TSCI_OS_INVALID_HANDLE) {
    res = tsci_os_io_err_at(am->data_dir_handle, TEK_SC_OS_STR("manifests"),
                            TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                            TEK_SC_ERR_IO_TYPE_open);
    goto upd_db_item;
  }
  tsci_am_job_ctx ctx = {.nproc = tsci_os_get_nproc(),
                         .dir_handle = TSCI_OS_INVALID_HANDLE,
                         .img_dir_handle = TSCI_OS_INVALID_HANDLE};
  // Load manifest(s)
  if (job->source_manifest_id) {
    res = tscp_am_load_manifest(am, desc, &ctx, manifests_dir_handle,
                                job->source_manifest_id, &ctx.source_manifest);
    if (!tek_sc_err_success(&res)) {
      tsci_os_close_handle(manifests_dir_handle);
      goto free_ctx;
    }
  }
  if (job->target_manifest_id) {
    if (job->target_manifest_id == UINT64_MAX) {
      // Use fictional empty manifest
      ctx.target_manifest.item_id = desc->desc.id;
      ctx.target_manifest.id = UINT64_MAX;
      ctx.target_manifest.dirs = &tscp_am_empty_dir;
      ctx.target_manifest.num_dirs = 1;
    } else {
      res =
          tscp_am_load_manifest(am, desc, &ctx, manifests_dir_handle,
                                job->target_manifest_id, &ctx.target_manifest);
      if (!tek_sc_err_success(&res)) {
        tsci_os_close_handle(manifests_dir_handle);
        goto free_ctx;
      }
    }
  }
  tsci_os_close_handle(manifests_dir_handle);
  // Open the job directory
  {
    auto const jobs_dir_handle =
        tsci_os_dir_create_at(am->data_dir_handle, TEK_SC_OS_STR("jobs"));
    if (jobs_dir_handle == TSCI_OS_INVALID_HANDLE) {
      res = tsci_os_io_err_at(am->data_dir_handle, TEK_SC_OS_STR("jobs"),
                              TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                              TEK_SC_ERR_IO_TYPE_open);
      goto free_ctx;
    }
    tek_sc_os_char dir_name[35];
    auto const item_id = &desc->desc.id;
    if (item_id->ws_item_id) {
      TSCI_OS_SNPRINTF(dir_name, sizeof dir_name / sizeof *dir_name,
                       TEK_SC_OS_STR("%" PRIx32 "-%" PRIx32 "-%" PRIx64),
                       item_id->app_id, item_id->depot_id, item_id->ws_item_id);
    } else {
      TSCI_OS_SNPRINTF(dir_name, sizeof dir_name / sizeof *dir_name,
                       TEK_SC_OS_STR("%" PRIx32 "-%" PRIx32), item_id->app_id,
                       item_id->depot_id);
    }
    ctx.dir_handle = tsci_os_dir_create_at(jobs_dir_handle, dir_name);
    if (ctx.dir_handle == TSCI_OS_INVALID_HANDLE) {
      res =
          tsci_os_io_err_at(jobs_dir_handle, dir_name, TEK_SC_ERRC_am_io,
                            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
      tsci_os_close_handle(jobs_dir_handle);
      goto free_ctx;
    }
    tsci_os_close_handle(jobs_dir_handle);
  }
  if (job->patch_status == TEK_SC_AM_JOB_PATCH_STATUS_used) {
    // Load patch
    res = tscp_am_load_patch(am, desc, &ctx);
    if (!tek_sc_err_success(&res)) {
      goto free_ctx;
    }
  }
  static const tek_sc_os_char delta_file_name[] = TEK_SC_OS_STR("delta");
  // Load or create delta
  auto delta_file_handle = tsci_os_file_open_at(ctx.dir_handle, delta_file_name,
                                                TSCI_OS_FILE_ACCESS_read);
  if (delta_file_handle == TSCI_OS_INVALID_HANDLE) {
    auto const errc = tsci_os_get_last_error();
    if (errc != TSCI_OS_ERR_FILE_NOT_FOUND) {
      res =
          tsci_os_io_err_at(ctx.dir_handle, delta_file_name, TEK_SC_ERRC_am_io,
                            tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
      goto free_ctx;
    }
    if (job->source_manifest_id) {
      ctx.delta = tek_sc_dd_compute(
          &ctx.source_manifest, &ctx.target_manifest,
          job->patch_status == TEK_SC_AM_JOB_PATCH_STATUS_used ? &ctx.patch
                                                               : nullptr);
    } else {
      // Verify installation
      res = tsci_am_job_verify(am, desc, &ctx);
      if (!tek_sc_err_success(&res)) {
        goto free_ctx;
      }
    }
    job->delta = &ctx.delta;
    if (upd_handler) {
      upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_delta_created);
    }
  } else {
    // Load existing file
    auto const file_size = tsci_os_file_get_size(delta_file_handle);
    if (file_size == SIZE_MAX) {
      res =
          tsci_os_io_err(delta_file_handle, TEK_SC_ERRC_am_io,
                         tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
      tsci_os_close_handle(delta_file_handle);
      goto free_ctx;
    }
    auto const file_buf = tsci_os_mem_alloc(file_size);
    if (!file_buf) {
      res = tsci_err_os(TEK_SC_ERRC_mem_alloc, tsci_os_get_last_error());
      tsci_os_close_handle(delta_file_handle);
      goto free_ctx;
    }
    if (!tsci_os_file_read(delta_file_handle, file_buf, file_size)) {
      res = tsci_os_io_err(delta_file_handle, TEK_SC_ERRC_am_io,
                           tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
      tsci_os_mem_free(file_buf, file_size);
      tsci_os_close_handle(delta_file_handle);
      goto free_ctx;
    }
    tsci_os_close_handle(delta_file_handle);
    res = tek_sc_dd_deserialize(
        file_buf, file_size,
        job->source_manifest_id ? &ctx.source_manifest : nullptr,
        &ctx.target_manifest,
        job->patch_status == TEK_SC_AM_JOB_PATCH_STATUS_used ? &ctx.patch
                                                             : nullptr,
        &ctx.delta);
    tsci_os_mem_free(file_buf, file_size);
    if (!tek_sc_err_success(&res)) {
      goto free_ctx;
    }
  } // if (delta_file_handle == TSCI_OS_INVALID_HANDLE) else
  // Create/open img directory if needed
  if (ctx.delta.dirs->flags & TEK_SC_DD_DIR_FLAG_children_new &&
      ctx.delta.stage <= TEK_SC_DD_STAGE_installing) {
    ctx.img_dir_handle =
        tsci_os_dir_create_at(ctx.dir_handle, TEK_SC_OS_STR("img"));
    if (ctx.img_dir_handle == TSCI_OS_INVALID_HANDLE) {
      res = tsci_os_io_err_at(ctx.dir_handle, TEK_SC_OS_STR("img"),
                              TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                              TEK_SC_ERR_IO_TYPE_open);
      goto save_delta;
    }
  }
  if (ctx.delta.stage == TEK_SC_DD_STAGE_downloading) {
    if (!ctx.sp_srvs) {
      if (job->stage != TEK_SC_AM_JOB_STAGE_fetching_data) {
        job->stage = TEK_SC_AM_JOB_STAGE_fetching_data;
        if (upd_handler) {
          upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
        }
      }
      // Get SteamPipe server list
      res = tsci_am_get_sp_servers(am, &ctx);
      if (!tek_sc_err_success(&res)) {
        goto save_delta;
      }
      if (atomic_load_explicit(&job->state, memory_order_relaxed) ==
          TEK_SC_AM_JOB_STATE_pause_pending) {
        res = tsc_err_basic(TEK_SC_ERRC_paused);
        goto save_delta;
      }
    }
    // Run download stage
    res = tsci_am_job_download(am, desc, &ctx);
    if (!tek_sc_err_success(&res)) {
      goto save_delta;
    }
  }
  if (ctx.delta.stage == TEK_SC_DD_STAGE_patching) {
    // Run patching stage
    res = tsci_am_job_patch(am, desc, &ctx);
    if (!tek_sc_err_success(&res)) {
      goto save_delta;
    }
  }
  if (ctx.delta.stage == TEK_SC_DD_STAGE_installing) {
    // Run installing stage
    res = tsci_am_job_install(am, desc, &ctx);
    if (!tek_sc_err_success(&res)) {
      goto save_delta;
    }
  }
  if (ctx.delta.stage == TEK_SC_DD_STAGE_deleting) {
    // Run deletion stage
    res = tsci_am_job_delete(am, desc, &ctx);
    if (!tek_sc_err_success(&res)) {
      goto save_delta;
    }
  }
save_delta:
  if (!tek_sc_err_success(&res)) {
    delta_file_handle = tsci_os_file_create_at(ctx.dir_handle, delta_file_name,
                                               TSCI_OS_FILE_ACCESS_write);
    if (delta_file_handle == TSCI_OS_INVALID_HANDLE) {
      if (res.primary == TEK_SC_ERRC_paused) {
        res = tsci_os_io_err_at(ctx.dir_handle, delta_file_name,
                                TEK_SC_ERRC_am_io, tsci_os_get_last_error(),
                                TEK_SC_ERR_IO_TYPE_open);
      }
      goto free_ctx;
    }
    const int ser_size = tek_sc_dd_serialize(&ctx.delta, nullptr, 0);
    auto const ser_buf = tsci_os_mem_alloc(ser_size);
    if (!ser_buf) {
      tsci_os_close_handle(delta_file_handle);
      goto free_ctx;
    }
    tek_sc_dd_serialize(&ctx.delta, ser_buf, ser_size);
    if (!tsci_os_file_write(delta_file_handle, ser_buf, ser_size)) {
      if (res.primary == TEK_SC_ERRC_paused) {
        res =
            tsci_os_io_err(delta_file_handle, TEK_SC_ERRC_am_io,
                           tsci_os_get_last_error(), TEK_SC_ERR_IO_TYPE_write);
      }
      tsci_os_file_delete_at(ctx.dir_handle, delta_file_name);
    }
    tsci_os_mem_free(ser_buf, ser_size);
    tsci_os_close_handle(delta_file_handle);
  }
free_ctx:
  job->delta = nullptr;
  tek_sc_dd_free(&ctx.delta);
  tek_sc_dp_free(&ctx.patch);
  tek_sc_dm_free(&ctx.target_manifest);
  tek_sc_dm_free(&ctx.source_manifest);
  if (ctx.img_dir_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(ctx.img_dir_handle);
  }
  if (ctx.dir_handle != TSCI_OS_INVALID_HANDLE) {
    tsci_os_close_handle(ctx.dir_handle);
  }
  if (ctx.num_sp_srvs) {
    free(ctx.sp_srvs);
  }
  atomic_store_explicit(&desc->sp_cancel_flag, false, memory_order_relaxed);
finalize:
  if (tscp_am_is_finished(&res)) {
    job->stage = TEK_SC_AM_JOB_STAGE_finalizing;
    if (upd_handler) {
      upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_stage);
    }
    tsci_am_clean_job_dir(am->data_dir_handle, &desc->desc.id);
    if (job->target_manifest_id == UINT64_MAX) {
      desc->desc.status = 0;
      desc->desc.current_manifest_id = 0;
    } else {
      desc->desc.current_manifest_id = job->target_manifest_id;
      if (!desc->desc.latest_manifest_id) {
        desc->desc.latest_manifest_id = desc->desc.current_manifest_id;
      }
      if (desc->desc.current_manifest_id == desc->desc.latest_manifest_id) {
        desc->desc.status &= ~TEK_SC_AM_ITEM_STATUS_upd_available;
      } else {
        desc->desc.status |= TEK_SC_AM_ITEM_STATUS_upd_available;
      }
      desc->desc.status &= ~TEK_SC_AM_ITEM_STATUS_job;
    }
    job->stage = 0;
    job->progress_current = 0;
    job->progress_total = 0;
    job->source_manifest_id = 0;
    job->target_manifest_id = 0;
    job->patch_status = TEK_SC_AM_JOB_PATCH_STATUS_unknown;
  }
upd_db_item:
  // Save current item and job state to the state database
  static const char query[] =
      "UPDATE items SET status = ?, current_manifest_id = ?, job_stage = ?, "
      "job_progress_current = ?, job_progress_total = ?, job_src_man_id = ?, "
      "job_tgt_man_id = ?, job_patch_status = ? WHERE app_id = ? AND depot_id "
      "= ? AND ws_item_id = ?";
  int sqlite_res =
      sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr);
  if (sqlite_res == SQLITE_OK) {
    sqlite_res = sqlite3_bind_int(stmt, 1, desc->desc.status);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res = sqlite3_bind_int64(
        stmt, 2, (sqlite3_int64)desc->desc.current_manifest_id);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res = sqlite3_bind_int(stmt, 3, job->stage);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res =
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)job->progress_current);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res =
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)job->progress_total);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res =
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)job->source_manifest_id);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res =
        sqlite3_bind_int64(stmt, 7, (sqlite3_int64)job->target_manifest_id);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res = sqlite3_bind_int(stmt, 8, (int)job->patch_status);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res = sqlite3_bind_int(stmt, 9, (int)desc->desc.id.app_id);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res = sqlite3_bind_int(stmt, 10, (int)desc->desc.id.depot_id);
    if (sqlite_res != SQLITE_OK) {
      goto cleanup_upd_stmt;
    }
    sqlite_res =
        sqlite3_bind_int64(stmt, 11, (sqlite3_int64)desc->desc.id.ws_item_id);
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
  if (sqlite_res != SQLITE_OK && !tscp_am_is_err(&res)) {
    res = tscp_am_err_sqlite(TEK_SC_ERRC_am_db_update, sqlite_res);
  }
  // Notify that the job has stopped
  atomic_store_explicit(&job->state, TEK_SC_AM_JOB_STATE_stopped,
                        memory_order_release);
  tsci_os_futex_wake((_Atomic(uint32_t) *)&job->state);
  if (upd_handler) {
    upd_handler(&desc->desc, TEK_SC_AM_UPD_TYPE_state);
  }
  return res;
}
