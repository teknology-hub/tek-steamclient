//===-- am_cm.c - CM bridge for Steam application manager -----------------===//
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
/// Implementation of application manager functions that involve communication
///    with Steam CM.
///
//===----------------------------------------------------------------------===//
#include "common/am.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//===-- Private functions -------------------------------------------------===//

/// Find the entry for specified Steam Workshop item in the list of details.
///
/// @param [in] details
///    Pointer to the Steam Workshop item details array.
/// @param num_details
///    Number of details in the array.
/// @param ws_item_id
///    ID of the Steam Workshop item to search for.
/// @return Pointer to the application's change entry, or `nullptr` if not
///    found.
[[gnu::nonnull(1), gnu::access(read_only, 1, 2)]]
static inline const tek_sc_cm_ws_item_details
    *_Nullable tscp_am_find_ws_details(
        const tek_sc_cm_ws_item_details *_Nonnull details, int num_details,
        uint64_t ws_item_id) {
  for (int i = 0; i < num_details; ++i) {
    if (details[i].id == ws_item_id) {
      return &details[i];
    }
  }
  return nullptr;
}

/// Find the entry for specified application in the list of PICS changes.
///
/// @param [in] entries
///    Pointer to the PICS changes array.
/// @param num_entries
///    Number of PICS changes in the array.
/// @param app_id
///    Application ID to search for.
/// @return Pointer to the application's change entry, or `nullptr` if not
///    found.
[[gnu::nonnull(1), gnu::access(read_only, 1, 2)]]
static inline const tek_sc_cm_pics_change_entry *_Nullable tscp_am_find_change(
    const tek_sc_cm_pics_change_entry *_Nonnull entries, int num_entries,
    uint32_t app_id) {
  for (int i = 0; i < num_entries; ++i) {
    if (entries[i].id == app_id) {
      return &entries[i];
    }
  }
  return nullptr;
}

/// The callback for CM client signed in event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in] data
///    Pointer to @ref tek_sc_err indicating the result of the sign-in attempt.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_signed_in(tek_sc_cm_client *_Nonnull client,
                                 void *_Nonnull data, void *_Nonnull user_data);

/// The callback for CM client connected event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in] data
///    Pointer to @ref tek_sc_err indicating the result of connection.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_connected(tek_sc_cm_client *_Nonnull client,
                                 void *_Nonnull data,
                                 void *_Nonnull user_data) {
  const tek_sc_err *res = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (tek_sc_err_success(res)) {
    tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
  } else {
    ctx->result = *res;
    atomic_store_explicit(&ctx->completed, 1, memory_order_release);
    tsci_os_futex_wake(&ctx->completed);
  }
}

/// The callback for CM client disconnected event.
static void tscp_am_cb_disconnected(tek_sc_cm_client *, void *, void *) {}

/// The callback for CM client PICS app info received event.
///
/// @param [in, out] data
///    Pointer to the @ref tek_sc_cm_data_pics associated with the request.
/// @param [in, out] user_data
///    Pointer to the associated @ref tek_sc_am instance.
[[gnu::nonnull(2, 3), gnu::access(read_write, 2), gnu::access(read_write, 3)]]
static void tscp_am_cb_app_info(tek_sc_cm_client *, void *_Nonnull data,
                                void *_Nonnull user_data) {
  tek_sc_cm_data_pics *const data_pics = data;
  tek_sc_am *const am = user_data;
  auto const ctx = &am->cm_ctx;
  if (!tek_sc_err_success(&data_pics->result)) {
    if (ctx->num_rem_reqs >= 0) {
      ctx->num_rem_reqs = -1;
      ctx->result = data_pics->result;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    free(data_pics->app_entries);
    free(data_pics);
    return;
  }
  for (int i = 0; i < data_pics->num_app_entries; ++i) {
    auto const entry = &data_pics->app_entries[i];
    tek_sc_err err;
    if (!tek_sc_err_success(&entry->result)) {
      err = entry->result;
      goto failure;
    }
    if (!tsci_am_parse_app_info(am, entry->data, entry->data_size)) {
      err = tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_vdf_parse);
      goto failure;
    }
    free(entry->data);
    continue;
  failure:
    for (int j = i; j < data_pics->num_app_entries; ++j) {
      free(data_pics->app_entries[j].data);
    }
    free(data_pics->app_entries);
    free(data_pics);
    if (ctx->num_rem_reqs >= 0) {
      ctx->num_rem_reqs = -1;
      ctx->result = err;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    return;
  }
  free(data_pics->app_entries);
  free(data_pics);
  if (!--ctx->num_rem_reqs) {
    am->changenum = ctx->pending_changenum;
    ctx->result = tsc_err_ok();
    atomic_store_explicit(&ctx->completed, 1, memory_order_release);
    tsci_os_futex_wake(&ctx->completed);
  }
}

/// The callback for CM client PICS access tokens received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to the @ref tek_sc_cm_data_pics associated with the request.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_access_tokens(tek_sc_cm_client *_Nonnull client,
                                     void *_Nonnull data,
                                     void *_Nonnull user_data) {
  tek_sc_cm_data_pics *const data_pics = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (!tek_sc_err_success(&data_pics->result)) {
    if (data_pics->result.type == TEK_SC_ERR_TYPE_sub &&
        data_pics->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
      tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    } else if (ctx->num_rem_reqs >= 0) {
      ctx->num_rem_reqs = -1;
      ctx->result = data_pics->result;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    free(data_pics->app_entries);
    free(data_pics);
    return;
  }
  tek_sc_cm_get_product_info(client, data_pics, tscp_am_cb_app_info,
                             ctx->timeout);
}

/// The callback for CM client Steam Workshop item details received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to the @ref tek_sc_cm_data_ws associated with the request.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_ws_details(tek_sc_cm_client *_Nonnull client,
                                  void *_Nonnull data,
                                  void *_Nonnull user_data) {
  tek_sc_cm_data_ws *const data_ws = data;
  tek_sc_am *const am = user_data;
  auto const ctx = &am->cm_ctx;
  if (!tek_sc_err_success(&data_ws->result)) {
    if (data_ws->result.type == TEK_SC_ERR_TYPE_sub &&
        data_ws->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
      tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    } else if (ctx->num_rem_reqs >= 0) {
      ctx->num_rem_reqs = -1;
      ctx->result = data_ws->result;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    free(data_ws->details);
    free(data_ws);
    return;
  }
  sqlite3_exec(am->db, "BEGIN", nullptr, nullptr, nullptr);
  static const char query[] =
      "UPDATE items SET status = ?, latest_manifest_id = ? WHERE ws_item_id = ?";
  sqlite3_stmt *stmt;
  if (sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr) !=
      SQLITE_OK) {
    stmt = nullptr;
  }
  pthread_mutex_lock(&am->item_descs_mtx);
  for (auto desc = &am->item_descs->desc; desc; desc = desc->next) {
    auto const ws_item_id = desc->id.ws_item_id;
    if (!ws_item_id) {
      continue;
    }
    auto const ent = tscp_am_find_ws_details(data_ws->details,
                                             data_ws->num_details, ws_item_id);
    if (!ent) {
      continue;
    }
    desc->latest_manifest_id = ent->manifest_id;
    if (desc->current_manifest_id &&
        desc->latest_manifest_id != desc->current_manifest_id) {
      desc->status |= TEK_SC_AM_ITEM_STATUS_upd_available;
    }
    if (stmt) {
      sqlite3_bind_int(stmt, 1, (int)desc->status);
      sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ent->manifest_id);
      sqlite3_bind_int64(stmt, 3, (sqlite3_int64)ws_item_id);
      sqlite3_step(stmt);
      sqlite3_reset(stmt);
      sqlite3_clear_bindings(stmt);
    }
  }
  pthread_mutex_unlock(&am->item_descs_mtx);
  if (stmt) {
    sqlite3_finalize(stmt);
  }
  sqlite3_exec(am->db, "COMMIT", nullptr, nullptr, nullptr);
  free(data_ws->details);
  free(data_ws);
  if (!--ctx->num_rem_reqs) {
    am->changenum = ctx->pending_changenum;
    ctx->result = tsc_err_ok();
    atomic_store_explicit(&ctx->completed, 1, memory_order_release);
    tsci_os_futex_wake(&ctx->completed);
  }
}

/// The callback for CM client PICS changes received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in] data
///    Pointer to a @ref tek_sc_cm_data_pics_changes.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_changes(tek_sc_cm_client *_Nonnull client,
                               void *_Nonnull data, void *_Nonnull user_data) {
  const tek_sc_cm_data_pics_changes *const data_picsc = data;
  tek_sc_am *const am = user_data;
  auto const ctx = &am->cm_ctx;
  if (!tek_sc_err_success(&data_picsc->result)) {
    if (data_picsc->result.type == TEK_SC_ERR_TYPE_sub &&
        data_picsc->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
      tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    } else {
      ctx->result = data_picsc->result;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    return;
  }
  ctx->pending_changenum = data_picsc->changenumber;
  // Count the number of changed apps and the number of Steam Workshop items
  int num_apps = 0;
  int num_ws_items = 0;
  uint32_t last_app_id = 0;
  pthread_mutex_lock(&am->item_descs_mtx);
  for (auto desc = &am->item_descs->desc; desc; desc = desc->next) {
    auto const item_id = &desc->id;
    if (item_id->ws_item_id) {
      ++num_ws_items;
    } else if (item_id->app_id != last_app_id &&
               (data_picsc->num_entries < 0 ||
                tscp_am_find_change(data_picsc->entries,
                                    data_picsc->num_entries,
                                    item_id->app_id))) {
      ++num_apps;
      last_app_id = item_id->app_id;
    }
  }
  ctx->num_rem_reqs = 0;
  if (num_apps) {
    // Prepare and submit the PICS request
    ++ctx->num_rem_reqs;
    tek_sc_cm_data_pics *const data_pics = malloc(sizeof *data_pics);
    if (!data_pics) {
      pthread_mutex_unlock(&am->item_descs_mtx);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      return;
    }
    data_pics->app_entries = malloc(sizeof *data_pics->app_entries * num_apps);
    if (!data_pics->app_entries) {
      free(data_pics);
      pthread_mutex_unlock(&am->item_descs_mtx);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      return;
    }
    data_pics->package_entries = nullptr;
    data_pics->num_app_entries = num_apps;
    data_pics->num_package_entries = 0;
    data_pics->timeout_ms = ctx->timeout;
    auto cur_ent = data_pics->app_entries;
    last_app_id = 0;
    for (auto desc = &am->item_descs->desc; desc; desc = desc->next) {
      auto const item_id = &desc->id;
      if (item_id->ws_item_id || item_id->app_id == last_app_id) {
        continue;
      }
      if (data_picsc->num_entries < 0) {
        cur_ent++->id = item_id->app_id;
      } else {
        auto const ent = tscp_am_find_change(
            data_picsc->entries, data_picsc->num_entries, item_id->app_id);
        if (ent) {
          cur_ent++->id = ent->id;
        }
      }
      last_app_id = item_id->app_id;
    }
    tek_sc_cm_get_access_token(client, data_pics, tscp_am_cb_access_tokens,
                               ctx->timeout);
  } // if (num_apps)
  if (num_ws_items) {
    // Prepare and submit the Steam Workshop item details request
    ++ctx->num_rem_reqs;
    tek_sc_cm_data_ws *const data_ws = malloc(sizeof *data_ws);
    if (!data_ws) {
      pthread_mutex_unlock(&am->item_descs_mtx);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      return;
    }
    data_ws->details = malloc(sizeof *data_ws->details * num_ws_items);
    if (!data_ws->details) {
      free(data_ws);
      pthread_mutex_unlock(&am->item_descs_mtx);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      return;
    }
    data_ws->num_details = num_ws_items;
    auto cur_ent = data_ws->details;
    for (auto desc = &am->item_descs->desc; desc; desc = desc->next) {
      auto const ws_item_id = desc->id.ws_item_id;
      if (ws_item_id) {
        cur_ent++->id = ws_item_id;
      }
    }
    tek_sc_cm_ws_get_details(client, data_ws, tscp_am_cb_ws_details,
                             ctx->timeout);
  }
  pthread_mutex_unlock(&am->item_descs_mtx);
  if (!ctx->num_rem_reqs) {
    am->changenum = data_picsc->changenumber;
    ctx->result = tsc_err_ok();
    atomic_store_explicit(&ctx->completed, 1, memory_order_release);
    tsci_os_futex_wake(&ctx->completed);
  }
}

/// The callback for CM client SteamPipe server list received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to a @ref tek_sc_cm_data_sp_servers.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_sp_servers(tek_sc_cm_client *_Nonnull client,
                                  void *_Nonnull data,
                                  void *_Nonnull user_data) {
  const tek_sc_cm_data_sp_servers *const data_sp = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (tek_sc_err_success(&data_sp->result)) {
    ctx->job_ctx->sp_srvs = data_sp->entries;
    ctx->job_ctx->num_sp_srvs = data_sp->num_entries;
  } else if (data_sp->result.type == TEK_SC_ERR_TYPE_sub &&
             data_sp->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
    tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    return;
  }
  ctx->result = data_sp->result;
  atomic_store_explicit(&ctx->completed, 1, memory_order_release);
  tsci_os_futex_wake(&ctx->completed);
}

/// The callback for CM client depot decryption key received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to the @ref tek_sc_cm_data_depot_key associated with the request.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_depot_key(tek_sc_cm_client *_Nonnull client,
                                 void *_Nonnull data,
                                 void *_Nonnull user_data) {
  tek_sc_cm_data_depot_key *const data_dk = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (data_dk->result.type == TEK_SC_ERR_TYPE_sub &&
      data_dk->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
    free(data_dk);
    tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    return;
  }
  ctx->result = data_dk->result;
  free(data_dk);
  atomic_store_explicit(&ctx->completed, 1, memory_order_release);
  tsci_os_futex_wake(&ctx->completed);
}

/// The callback for CM client manifest request code received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to the @ref tek_sc_cm_data_mrc associated with the request.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_mrc(tek_sc_cm_client *_Nonnull client,
                           void *_Nonnull data, void *_Nonnull user_data) {
  tek_sc_cm_data_mrc *const data_mrc = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (tek_sc_err_success(&data_mrc->result)) {
    ctx->mrc = data_mrc->request_code;
  } else if (data_mrc->result.type == TEK_SC_ERR_TYPE_sub &&
             data_mrc->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
    free(data_mrc);
    tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    return;
  }
  ctx->result = data_mrc->result;
  free(data_mrc);
  atomic_store_explicit(&ctx->completed, 1, memory_order_release);
  tsci_os_futex_wake(&ctx->completed);
}

/// The callback for CM client patch availability information received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to a @ref tek_sc_cm_data_dp_info.
/// @param [in, out] user_data
///    Pointer to the @ref tek_sc_am instance associated with @p client.
[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_am_cb_patch_info(tek_sc_cm_client *_Nonnull client,
                                  void *_Nonnull data,
                                  void *_Nonnull user_data) {
  const tek_sc_cm_data_dp_info *const data_dpi = data;
  auto const ctx = &((tek_sc_am *)user_data)->cm_ctx;
  if (tek_sc_err_success(&data_dpi->result)) {
    ctx->patch_available = data_dpi->available;
  } else if (data_dpi->result.type == TEK_SC_ERR_TYPE_sub &&
             data_dpi->result.auxiliary == TEK_SC_ERRC_cm_not_signed_in) {
    tek_sc_cm_sign_in_anon(client, tscp_am_cb_signed_in, ctx->timeout);
    return;
  }
  ctx->result = data_dpi->result;
  atomic_store_explicit(&ctx->completed, 1, memory_order_release);
  tsci_os_futex_wake(&ctx->completed);
}

static void tscp_am_cb_signed_in(tek_sc_cm_client *client, void *data,
                                 void *user_data) {
  const tek_sc_err *const res = data;
  tek_sc_am *const am = user_data;
  auto const ctx = &am->cm_ctx;
  if (!tek_sc_err_success(res)) {
    if (res->type == TEK_SC_ERR_TYPE_sub &&
        res->auxiliary == TEK_SC_ERRC_cm_not_connected) {
      tek_sc_cm_connect(client, tscp_am_cb_connected, ctx->timeout,
                        tscp_am_cb_disconnected);
    } else {
      ctx->result = *res;
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
    }
    return;
  }
  /// Send the request based on the pending request type.
  switch (ctx->pending_req) {
  case TSCI_AM_PENDING_CM_REQ_changes:
    tek_sc_cm_get_changes(client, am->changenum, tscp_am_cb_changes,
                          ctx->timeout);
    break;
  case TSCI_AM_PENDING_CM_REQ_app_man_ids: {
    tek_sc_cm_data_pics *const data_pics = malloc(sizeof *data_pics);
    if (!data_pics) {
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_pics->app_entries = malloc(sizeof *data_pics->app_entries);
    if (!data_pics->app_entries) {
      free(data_pics);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_pics->app_entries->id = ctx->item_id->app_id;
    data_pics->package_entries = nullptr;
    data_pics->num_app_entries = 1;
    data_pics->num_package_entries = 0;
    data_pics->timeout_ms = ctx->timeout;
    tek_sc_cm_get_access_token(client, data_pics, tscp_am_cb_access_tokens,
                               ctx->timeout);
    break;
  }
  case TSCI_AM_PENDING_CM_REQ_ws_man_id: {
    tek_sc_cm_data_ws *const data_ws = malloc(sizeof *data_ws);
    if (!data_ws) {
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_ws->details = malloc(sizeof *data_ws->details);
    if (!data_ws->details) {
      free(data_ws);
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_ws->details->id = ctx->item_id->ws_item_id;
    data_ws->num_details = 1;
    tek_sc_cm_ws_get_details(client, data_ws, tscp_am_cb_ws_details,
                             ctx->timeout);
    break;
  }
  case TSCI_AM_PENDING_CM_REQ_sp_servers:
    tek_sc_cm_get_sp_servers(client, tscp_am_cb_sp_servers, ctx->timeout);
    break;
  case TSCI_AM_PENDING_CM_REQ_depot_key: {
    tek_sc_cm_data_depot_key *const data_dk = malloc(sizeof *data_dk);
    if (!data_dk) {
      ctx->result =
          tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_dk->app_id = ctx->item_id->app_id;
    data_dk->depot_id = ctx->item_id->depot_id;
    tek_sc_cm_get_depot_key(client, data_dk, tscp_am_cb_depot_key,
                            ctx->timeout);
    break;
  }
  case TSCI_AM_PENDING_CM_REQ_mrc: {
    tek_sc_cm_data_mrc *const data_mrc = malloc(sizeof *data_mrc);
    if (!data_mrc) {
      ctx->result = tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_mem_alloc);
      atomic_store_explicit(&ctx->completed, 1, memory_order_release);
      tsci_os_futex_wake(&ctx->completed);
      break;
    }
    data_mrc->app_id = ctx->item_id->app_id;
    data_mrc->depot_id = ctx->item_id->depot_id;
    data_mrc->manifest_id = ctx->manifest_id;
    tek_sc_cm_get_mrc(client, data_mrc, tscp_am_cb_mrc, ctx->timeout);
    break;
  }
  case TSCI_AM_PENDING_CM_REQ_patch_info:
    tek_sc_cm_get_dp_info(client, ctx->item_id, ctx->source_manifest_id,
                          ctx->target_manifest_id, tscp_am_cb_patch_info,
                          ctx->timeout);
  } // switch (ctx->pending_req)
}

//===-- Internal functions ------------------------------------------------===//

tek_sc_err tsci_am_get_latest_man_id(tek_sc_am *am,
                                     const tek_sc_item_id *item_id) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->num_rem_reqs = 1;
  cm_ctx->timeout = 5000;
  atomic_init(&cm_ctx->completed, 0);
  cm_ctx->item_id = item_id;
  if (item_id->ws_item_id) {
    cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_ws_man_id;
    tek_sc_cm_data_ws *const data_ws = malloc(sizeof *data_ws);
    if (!data_ws) {
      pthread_mutex_unlock(&cm_ctx->mtx);
      return tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
    }
    data_ws->details = malloc(sizeof *data_ws->details);
    if (!data_ws->details) {
      pthread_mutex_unlock(&cm_ctx->mtx);
      free(data_ws);
      return tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_mem_alloc);
    }
    data_ws->details->id = item_id->ws_item_id;
    data_ws->num_details = 1;
    tek_sc_cm_ws_get_details(am->cm_client, data_ws, tscp_am_cb_ws_details,
                             cm_ctx->timeout);
  } else {
    cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_app_man_ids;
    tek_sc_cm_data_pics *const data_pics = malloc(sizeof *data_pics);
    if (!data_pics) {
      pthread_mutex_unlock(&cm_ctx->mtx);
      return tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
    }
    data_pics->app_entries = malloc(sizeof *data_pics->app_entries);
    if (!data_pics->app_entries) {
      pthread_mutex_unlock(&cm_ctx->mtx);
      free(data_pics);
      return tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
    }
    data_pics->app_entries->id = item_id->app_id;
    data_pics->package_entries = nullptr;
    data_pics->num_app_entries = 1;
    data_pics->num_package_entries = 0;
    data_pics->timeout_ms = cm_ctx->timeout;
    tek_sc_cm_get_access_token(am->cm_client, data_pics,
                               tscp_am_cb_access_tokens, cm_ctx->timeout);
  }
  tsci_os_futex_wait(&cm_ctx->completed, 0, cm_ctx->timeout * 5);
  auto const res = cm_ctx->result;
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}

tek_sc_err tsci_am_get_sp_servers(tek_sc_am *am, tsci_am_job_ctx *ctx) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_sp_servers;
  cm_ctx->timeout = 5000;
  atomic_init(&cm_ctx->completed, 0);
  cm_ctx->job_ctx = ctx;
  tek_sc_cm_get_sp_servers(am->cm_client, tscp_am_cb_sp_servers,
                           cm_ctx->timeout);
  tsci_os_futex_wait(&cm_ctx->completed, 0, cm_ctx->timeout * 3 + 1000);
  auto const res = cm_ctx->result;
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}

tek_sc_err tsci_am_get_depot_key(tek_sc_am *am, const tek_sc_item_id *item_id) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_depot_key;
  cm_ctx->timeout = 5000;
  atomic_init(&cm_ctx->completed, 0);
  cm_ctx->item_id = item_id;
  tek_sc_cm_data_depot_key *const data_dk = malloc(sizeof *data_dk);
  if (!data_dk) {
    pthread_mutex_unlock(&cm_ctx->mtx);
    return tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_mem_alloc);
  }
  data_dk->app_id = item_id->app_id;
  data_dk->depot_id = item_id->depot_id;
  tek_sc_cm_get_depot_key(am->cm_client, data_dk, tscp_am_cb_depot_key,
                          cm_ctx->timeout);
  tsci_os_futex_wait(&cm_ctx->completed, 0, cm_ctx->timeout * 3 + 1000);
  auto const res = cm_ctx->result;
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}

tek_sc_err tsci_am_get_mrc(tek_sc_am *am, const tek_sc_item_id *item_id,
                           uint64_t manifest_id, uint64_t *mrc) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_mrc;
  cm_ctx->timeout = 5000;
  atomic_init(&cm_ctx->completed, 0);
  cm_ctx->item_id = item_id;
  cm_ctx->manifest_id = manifest_id;
  tek_sc_cm_data_mrc *const data_mrc = malloc(sizeof *data_mrc);
  if (!data_mrc) {
    pthread_mutex_unlock(&cm_ctx->mtx);
    return tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_mem_alloc);
  }
  data_mrc->app_id = item_id->app_id;
  data_mrc->depot_id = item_id->depot_id;
  data_mrc->manifest_id = manifest_id;
  tek_sc_cm_get_mrc(am->cm_client, data_mrc, tscp_am_cb_mrc, cm_ctx->timeout);
  tsci_os_futex_wait(&cm_ctx->completed, 0, cm_ctx->timeout * 3 + 1000);
  auto const res = cm_ctx->result;
  if (tek_sc_err_success(&res)) {
    *mrc = cm_ctx->mrc;
  }
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}

tek_sc_err tsci_am_get_patch_info(tek_sc_am *am, const tek_sc_item_id *item_id,
                                  uint64_t source_manifest_id,
                                  uint64_t target_manifest_id,
                                  bool *available) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_patch_info;
  cm_ctx->timeout = 5000;
  atomic_init(&cm_ctx->completed, 0);
  cm_ctx->item_id = item_id;
  cm_ctx->source_manifest_id = source_manifest_id;
  cm_ctx->target_manifest_id = target_manifest_id;
  tek_sc_cm_get_dp_info(am->cm_client, item_id, source_manifest_id,
                        target_manifest_id, tscp_am_cb_patch_info,
                        cm_ctx->timeout);
  tsci_os_futex_wait(&cm_ctx->completed, 0, cm_ctx->timeout * 3 + 1000);
  auto const res = cm_ctx->result;
  if (tek_sc_err_success(&res)) {
    *available = cm_ctx->patch_available;
  }
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}

//===-- Public function ---------------------------------------------------===//

tek_sc_err tek_sc_am_check_for_upds(tek_sc_am *am, long timeout_ms) {
  auto const cm_ctx = &am->cm_ctx;
  pthread_mutex_lock(&cm_ctx->mtx);
  cm_ctx->pending_req = TSCI_AM_PENDING_CM_REQ_changes;
  cm_ctx->timeout = timeout_ms;
  atomic_init(&cm_ctx->completed, 0);
  tek_sc_cm_get_changes(am->cm_client, am->changenum, tscp_am_cb_changes,
                        timeout_ms);
  tsci_os_futex_wait(&cm_ctx->completed, 0, timeout_ms * 5);
  auto const res = cm_ctx->result;
  if (tek_sc_err_success(&res)) {
    am->changenum = cm_ctx->pending_changenum;
    static const char query[] = "UPDATE state SET changenum = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(am->db, query, sizeof query, &stmt, nullptr) ==
        SQLITE_OK) {
      sqlite3_bind_int(stmt, 1, (int)cm_ctx->pending_changenum);
      sqlite3_step(stmt);
      sqlite3_finalize(stmt);
    }
  }
  pthread_mutex_unlock(&cm_ctx->mtx);
  return res;
}
