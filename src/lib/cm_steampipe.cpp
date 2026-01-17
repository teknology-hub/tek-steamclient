//===-- cm_steampipe.cpp - Steam CM client SteamPipe subsystem impl. ------===//
//
// Copyright (c) 2025-2026 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Implementation of Steam CM client functions related to SteamPipe (Steam
///    content distribution system).
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_depot_decryption_key.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_depot_patch_info.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_manifest_request_code.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_servers_for_steampipe.pb.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <string_view>
#include <utility>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private functions -------------------------------------------------===//

/// Handle a depot decryption key response message timeout.
static void timeout_ddk(cm_conn &conn, msg_await_entry &entry) {
  const auto data{
      reinterpret_cast<tek_sc_cm_data_depot_key *>(entry.inout_data)};
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, data, conn.user_data);
}

/// Handle a depot patch info response message timeout.
static void timeout_dpi(cm_conn &conn, msg_await_entry &entry) {
  tek_sc_cm_data_dp_info data;
  data.result =
      tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle a manifest request code response message timeout.
static void timeout_mrc(cm_conn &conn, msg_await_entry &entry) {
  const auto data{reinterpret_cast<tek_sc_cm_data_mrc *>(entry.inout_data)};
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, data, conn.user_data);
}

/// Handle a SteamPipe server list response message timeout.
static void timeout_gss(cm_conn &conn, msg_await_entry &entry) {
  tek_sc_cm_data_sp_servers data;
  data.result = tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle `EMSG_CLIENT_GET_DEPOT_DECRYPTION_KEY_RESPONSE` response message.
///
/// @param [in, out] conn
///    CM connection instance that received the message.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function.
/// @param [in, out] inout_data
///    Pointer to the @ref tek_sc_cm_data_depot_key.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_gddk(cm_conn &conn, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_dk{*reinterpret_cast<tek_sc_cm_data_depot_key *>(inout_data)};
  msg_payloads::GetDepotDecryptionKeyResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_dk.result =
        tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_dk, conn.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(payload.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_dk.result = err(TEK_SC_ERRC_cm_depot_key, eresult);
    cb(&conn, &data_dk, conn.user_data);
    return true;
  }
  data_dk.result = tsc_err_ok();
  std::ranges::copy(
      std::string_view{payload.decryption_key().data(), sizeof data_dk.key},
      data_dk.key);
  // Store the key into the cache
  tek_sc_lib_add_depot_key(&conn.ctx, payload.depot_id(), data_dk.key);
  //  Report results via callback
  cb(&conn, &data_dk, conn.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetDepotPatchInfo#1" response message.
///
/// @param [in, out] conn
///    CM connection instance that received the message.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function.
/// @return `true`.
[[gnu::nonnull(3, 5), gnu::access(read_only, 3, 4),
  clang::callback(cb, __, __, __)]]
static bool handle_gdpi(cm_conn &conn, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *) {
  tek_sc_cm_data_dp_info data_dpi;
  if (msg_payloads::GetDepotPatchInfoResponse payload;
      payload.ParseFromArray(data, size)) {
    data_dpi = {.available = payload.is_available(),
                .size = static_cast<std::int64_t>(payload.size()),
                .result{tsc_err_ok()}};
  } else {
    data_dpi.result = tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info,
                                  TEK_SC_ERRC_protobuf_deserialize);
  }
  cb(&conn, &data_dpi, conn.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetManifestRequestCode#1" response message.
///
/// @param [in, out] conn
///    CM connection instance that received the message.
/// @param [in] header
///    Header of the received message.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function.
/// @param [in, out] inout_data
///    Pointer to the @ref tek_sc_cm_data_mrc.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_gmrc(cm_conn &conn, const MessageHeader &header,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_mrc{*reinterpret_cast<tek_sc_cm_data_mrc *>(inout_data)};
  msg_payloads::GetManifestRequestCodeResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_mrc.result =
        tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_mrc, conn.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(header.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_mrc.result = err(TEK_SC_ERRC_cm_mrc, eresult);
    cb(&conn, &data_mrc, conn.user_data);
    return true;
  }
  data_mrc.request_code = payload.manifest_request_code();
  data_mrc.result = tsc_err_ok();
  //  Report results via callback
  cb(&conn, &data_mrc, conn.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetServersForSteamPipe#1" response message.
///
/// @param [in, out] conn
///    CM connection instance that received the message.
/// @param [in] header
///    Header of the received message.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function.
/// @return `true`.
[[gnu::nonnull(3, 5), gnu::access(read_only, 3, 4),
  clang::callback(cb, __, __, __)]]
static bool handle_gsfsp(cm_conn &conn, const MessageHeader &header,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GetServersForSteamPipeResponse payload;
  tek_sc_cm_data_sp_servers data_sp;
  if (!payload.ParseFromArray(data, size)) {
    data_sp.result = tsc_err_sub(TEK_SC_ERRC_cm_sp_servers,
                                 TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_sp, conn.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(header.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_sp.result = err(TEK_SC_ERRC_cm_sp_servers, eresult);
    cb(&conn, &data_sp, conn.user_data);
    return true;
  }
  std::vector<const msg_payloads::SteamPipeServer *> srvs;
  srvs.reserve(payload.servers_size());
  std::ranges::for_each(payload.servers().pointer_begin(),
                        payload.servers().pointer_end(),
                        [&srvs](auto ptr) { srvs.emplace_back(ptr); });
  std::erase_if(srvs, [](auto srv) {
    // There are no other known types that actually provide depot files
    return srv->type() != "CDN" && srv->type() != "SteamCache";
  });
  if (srvs.empty()) {
    data_sp.result =
        tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_cm_sp_servers_empty);
    cb(&conn, &data_sp, conn.user_data);
    return true;
  }
  const auto buf{
      std::malloc(std::ranges::fold_left(srvs, 0zu, [](auto acc, auto srv) {
        return acc + sizeof(tek_sc_cm_sp_srv_entry) + srv->vhost().length() + 1;
      }))};
  if (!buf) {
    data_sp.result =
        tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_mem_alloc);
    cb(&conn, &data_sp, conn.user_data);
    return true;
  }
  auto cur_entry{reinterpret_cast<tek_sc_cm_sp_srv_entry *>(buf)};
  for (auto cur_host{reinterpret_cast<char *>(&cur_entry[srvs.size()])};
       auto srv : srvs) {
    *cur_entry++ = {.host = cur_host,
                    .supports_https = srv->https_support() != "unavailable"};
    cur_host = std::ranges::copy(srv->vhost().begin(), srv->vhost().end() + 1,
                                 cur_host)
                   .out;
  }
  data_sp = {.entries = reinterpret_cast<tek_sc_cm_sp_srv_entry *>(buf),
             .num_entries = static_cast<int>(srvs.size()),
             .result{tsc_err_ok()}};
  //  Report results via callback
  cb(&conn, &data_sp, conn.user_data);
  return true;
}

} // namespace

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient::cm;

extern "C" {

void tek_sc_cm_get_depot_key(tek_sc_cm_client *client,
                             tek_sc_cm_data_depot_key *data,
                             tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Check if the key is present in the cache first
  if (tek_sc_lib_get_depot_key(&conn.ctx, data->depot_id, data->key)) {
    data->result = tsc_err_ok();
    cb(&conn, data, conn.user_data);
    return;
  }
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetDepotDecryptionKeyRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_GET_DEPOT_DECRYPTION_KEY;
  msg.header.set_source_job_id(job_id);
  msg.payload.set_depot_id(data->depot_id);
  msg.payload.set_app_id(data->app_id);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gddk, cb, timeout_ddk, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_depot_key>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    data->result = res;
    cb(&conn, data, conn.user_data);
  }
}

void tek_sc_cm_get_dp_info(tek_sc_cm_client *client,
                           const tek_sc_item_id *item_id,
                           uint64_t source_manifest_id,
                           uint64_t target_manifest_id,
                           tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    tek_sc_cm_data_dp_info data;
    data.result = tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info,
                              TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetDepotPatchInfoRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("ContentServerDirectory.GetDepotPatchInfo#1");
  msg.payload.set_app_id(item_id->app_id);
  msg.payload.set_depot_id(item_id->depot_id);
  msg.payload.set_source_manifest_id(source_manifest_id);
  msg.payload.set_target_manifest_id(target_manifest_id);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gdpi, cb, timeout_dpi)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_depot_patch_info>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    tek_sc_cm_data_dp_info data;
    data.result = res;
    cb(&conn, &data, conn.user_data);
  }
}

void tek_sc_cm_get_mrc(tek_sc_cm_client *client, tek_sc_cm_data_mrc *data,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  tek_sc_cm_get_mrc_branch(client, data, cb, timeout_ms, "public");
}

void tek_sc_cm_get_mrc_branch(tek_sc_cm_client *client,
                              tek_sc_cm_data_mrc *data,
                              tek_sc_cm_callback_func *cb, long timeout_ms,
                              const char *branch) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetManifestRequestCodeRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name(
      "ContentServerDirectory.GetManifestRequestCode#1");
  msg.payload.set_app_id(data->app_id);
  msg.payload.set_depot_id(data->depot_id);
  msg.payload.set_manifest_id(data->manifest_id);
  msg.payload.set_app_branch(branch);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gmrc, cb, timeout_mrc, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_mrc>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    data->result = res;
    cb(&conn, data, conn.user_data);
  }
}

void tek_sc_cm_get_sp_servers(tek_sc_cm_client *client,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    tek_sc_cm_data_sp_servers data;
    data.result =
        tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetServersForSteamPipeRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name(
      "ContentServerDirectory.GetServersForSteamPipe#1");
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gsfsp, cb, timeout_gss)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_sp_servers>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    tek_sc_cm_data_sp_servers data;
    data.result = res;
    cb(&conn, &data, conn.user_data);
  }
}

} // extern "C"
