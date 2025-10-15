//===-- cm_steampipe.cpp - Steam CM client SteamPipe subsystem impl. ------===//
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
/// Implementation of Steam CM client functions related to SteamPipe (Steam
///    content distribution system).
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "lib_ctx.hpp"
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
#include <libwebsockets.h>
#include <string_view>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private functions -------------------------------------------------===//

/// Handle a depot decryption key response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_ddk(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  const auto data{
      reinterpret_cast<tek_sc_cm_data_depot_key *>(a_entry.inout_data)};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_cm_timeout);
  cb(&client, data, client.user_data);
}

/// Handle a depot patch info response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_dpi(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  tek_sc_cm_data_dp_info data;
  data.result =
      tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info, TEK_SC_ERRC_cm_timeout);
  cb(&client, &data, client.user_data);
}

/// Handle a manifest request code response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_mrc(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  const auto data{reinterpret_cast<tek_sc_cm_data_mrc *>(a_entry.inout_data)};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_cm_timeout);
  cb(&client, data, client.user_data);
}

/// Handle a SteamPipe server list response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_gss(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  tek_sc_cm_data_sp_servers data;
  data.result = tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_cm_timeout);
  cb(&client, &data, client.user_data);
}

/// Handle `EMSG_CLIENT_GET_DEPOT_DECRYPTION_KEY_RESPONSE` response message.
///
/// @param [in, out] client
///    CM client instance that received the message.
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
  gnu::access(read_write, 6), clang::callback(cb, client, inout_data, __)]]
static bool handle_gddk(cm_client &client, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_dk{*reinterpret_cast<tek_sc_cm_data_depot_key *>(inout_data)};
  msg_payloads::GetDepotDecryptionKeyResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_dk.result =
        tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_dk, client.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(payload.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_dk.result = err(TEK_SC_ERRC_cm_depot_key, eresult);
    cb(&client, &data_dk, client.user_data);
    return true;
  }
  data_dk.result = tsc_err_ok();
  std::ranges::copy(
      std::string_view{payload.decryption_key().data(), sizeof data_dk.key},
      data_dk.key);
  // Store the key into the cache
  client.lib_ctx.depot_keys_mtx.lock();
  std::ranges::copy(data_dk.key, client.lib_ctx.depot_keys[payload.depot_id()]);
  client.lib_ctx.depot_keys_mtx.unlock();
  client.lib_ctx.dirty_flags.fetch_or(static_cast<int>(dirty_flag::depot_keys),
                                      std::memory_order::relaxed);
  //  Report results via callback
  cb(&client, &data_dk, client.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetDepotPatchInfo#1" response message.
///
/// @param [in, out] client
///    CM client instance that received the message.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function.
/// @return `true`.
[[gnu::nonnull(3, 5), gnu::access(read_only, 3, 4),
  clang::callback(cb, client, __, __)]]
static bool handle_gdpi(cm_client &client, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *) {
  tek_sc_cm_data_dp_info data_dpi;
  if (msg_payloads::GetDepotPatchInfoResponse payload;
      payload.ParseFromArray(data, size)) {
    data_dpi = {.available = payload.is_available(),
                .size = static_cast<std::int64_t>(payload.size()),
                .result = tsc_err_ok()};
  } else {
    data_dpi.result = tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info,
                                  TEK_SC_ERRC_protobuf_deserialize);
  }
  cb(&client, &data_dpi, client.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetManifestRequestCode#1" response message.
///
/// @param [in, out] client
///    CM client instance that received the message.
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
  gnu::access(read_write, 6), clang::callback(cb, client, inout_data, __)]]
static bool handle_gmrc(cm_client &client, const MessageHeader &header,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_mrc{*reinterpret_cast<tek_sc_cm_data_mrc *>(inout_data)};
  msg_payloads::GetManifestRequestCodeResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_mrc.result =
        tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_mrc, client.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(header.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_mrc.result = err(TEK_SC_ERRC_cm_mrc, eresult);
    cb(&client, &data_mrc, client.user_data);
    return true;
  }
  data_mrc.request_code = payload.manifest_request_code();
  data_mrc.result = tsc_err_ok();
  //  Report results via callback
  cb(&client, &data_mrc, client.user_data);
  return true;
}

/// Handle "ContentServerDirectory.GetServersForSteamPipe#1" response message.
///
/// @param [in, out] client
///    CM client instance that received the message.
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
  clang::callback(cb, client, __, __)]]
static bool handle_gsfsp(cm_client &client, const MessageHeader &header,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GetServersForSteamPipeResponse payload;
  tek_sc_cm_data_sp_servers data_sp;
  if (!payload.ParseFromArray(data, size)) {
    data_sp.result = tsc_err_sub(TEK_SC_ERRC_cm_sp_servers,
                                 TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_sp, client.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(header.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_sp.result = err(TEK_SC_ERRC_cm_sp_servers, eresult);
    cb(&client, &data_sp, client.user_data);
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
    cb(&client, &data_sp, client.user_data);
    return true;
  }
  const auto buf{
      std::malloc(std::ranges::fold_left(srvs, 0zu, [](auto acc, auto srv) {
        return acc + sizeof(tek_sc_cm_sp_srv_entry) + srv->vhost().length() + 1;
      }))};
  if (!buf) {
    data_sp.result =
        tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_mem_alloc);
    cb(&client, &data_sp, client.user_data);
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
             .result = tsc_err_ok()};
  //  Report results via callback
  cb(&client, &data_sp, client.user_data);
  return true;
}

} // namespace

//===-- Public functions --------------------------------------------------===//

extern "C" {

void tek_sc_cm_get_depot_key(tek_sc_cm_client *client,
                             tek_sc_cm_data_depot_key *data,
                             tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Check if the key is present in the cache first
  client->lib_ctx.depot_keys_mtx.lock();
  if (const auto it{client->lib_ctx.depot_keys.find(data->depot_id)};
      it != client->lib_ctx.depot_keys.cend()) {
    std::ranges::copy(it->second, data->key);
    client->lib_ctx.depot_keys_mtx.unlock();
    data->result = tsc_err_ok();
    cb(client, data, client->user_data);
    return;
  }
  client->lib_ctx.depot_keys_mtx.unlock();
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_depot_key, TEK_SC_ERRC_cm_not_signed_in);
    cb(client, data, client->user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetDepotDecryptionKeyRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_GET_DEPOT_DECRYPTION_KEY;
  msg.header.set_source_job_id(job_id);
  msg.payload.set_depot_id(data->depot_id);
  msg.payload.set_app_id(data->app_id);
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_ddk,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_gddk,
                                           .cb = cb,
                                           .inout_data = data})
          .first};
  auto &a_entry{a_entry_it->second};
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{
          client->send_message<TEK_SC_ERRC_cm_depot_key>(msg, &a_entry.sul)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Report error via callback
    data->result = res;
    cb(client, data, client->user_data);
  }
}

void tek_sc_cm_get_dp_info(tek_sc_cm_client *client,
                           const tek_sc_item_id *item_id,
                           uint64_t source_manifest_id,
                           uint64_t target_manifest_id,
                           tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    tek_sc_cm_data_dp_info data;
    data.result = tsc_err_sub(TEK_SC_ERRC_cm_depot_patch_info,
                              TEK_SC_ERRC_cm_not_signed_in);
    cb(client, &data, client->user_data);
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
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_dpi,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_gdpi,
                                           .cb = cb,
                                           .inout_data = nullptr})
          .first};
  auto &a_entry{a_entry_it->second};
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{client->send_message<TEK_SC_ERRC_cm_depot_patch_info>(
          msg, &a_entry.sul)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Report error via callback
    tek_sc_cm_data_dp_info data;
    data.result = res;
    cb(client, &data, client->user_data);
  }
}

void tek_sc_cm_get_mrc(tek_sc_cm_client *client, tek_sc_cm_data_mrc *data,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_mrc, TEK_SC_ERRC_cm_not_signed_in);
    cb(client, data, client->user_data);
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
  msg.payload.set_app_branch("public");
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_mrc,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_gmrc,
                                           .cb = cb,
                                           .inout_data = data})
          .first};
  auto &a_entry{a_entry_it->second};
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{
          client->send_message<TEK_SC_ERRC_cm_mrc>(msg, &a_entry.sul)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Report error via callback
    data->result = res;
    cb(client, data, client->user_data);
  }
}

void tek_sc_cm_get_sp_servers(tek_sc_cm_client *client,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    tek_sc_cm_data_sp_servers data;
    data.result =
        tsc_err_sub(TEK_SC_ERRC_cm_sp_servers, TEK_SC_ERRC_cm_not_signed_in);
    cb(client, &data, client->user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetServersForSteamPipeRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name(
      "ContentServerDirectory.GetServersForSteamPipe#1");
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_gss,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_gsfsp,
                                           .cb = cb,
                                           .inout_data = nullptr})
          .first};
  auto &a_entry{a_entry_it->second};
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{
          client->send_message<TEK_SC_ERRC_cm_sp_servers>(msg, &a_entry.sul)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Report error via callback
    tek_sc_cm_data_sp_servers data;
    data.result = res;
    cb(client, &data, client->user_data);
  }
}

} // extern "C"

} // namespace tek::steamclient::cm
