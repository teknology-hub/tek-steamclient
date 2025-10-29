//===-- cm_workshop.cpp - Steam CM client Workshop subsystem impl. --------===//
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
/// Implementation of Steam CM client functions working with "PublishedFile"
///    interface.
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_details.pb.h"
#include "tek/steamclient/cm/msg_payloads/query_files.pb.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <libwebsockets.h>
#include <ranges>
#include <span>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private functions -------------------------------------------------===//

/// Handle a Steam Workshop item details response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_gd(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  const auto data{reinterpret_cast<tek_sc_cm_data_ws *>(a_entry.inout_data)};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_cm_timeout);
  cb(&client, data, client.user_data);
}

/// Handle a Steam Workshop items query response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_qi(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry{*reinterpret_cast<const msg_await_entry *>(sul)};
  auto &client{a_entry.client};
  const auto cb{a_entry.cb};
  const auto data{reinterpret_cast<tek_sc_cm_data_ws *>(a_entry.inout_data)};
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  data->result = tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_cm_timeout);
  cb(&client, data, client.user_data);
}

/// Handle "PublishedFile.GetDetails#1" response message.
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
///    Pointer to the @ref tek_sc_cm_data_ws.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_gd(cm_client &client, const MessageHeader &,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nonnull inout_data) {
  auto &data_ws{*reinterpret_cast<tek_sc_cm_data_ws *>(inout_data)};
  msg_payloads::GetDetailsResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_ws.result = tsc_err_sub(TEK_SC_ERRC_cm_ws_details,
                                 TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ws, client.user_data);
    return true;
  }
  // Process details entries
  std::vector<std::uint64_t> children;
  children.reserve(std::ranges::fold_left(
      payload.details(), 0, [](int acc, const auto &payload_details) {
        return acc + payload_details.children_size();
      }));
  for (const std::span span{data_ws.details,
                            static_cast<std::size_t>(data_ws.num_details)};
       const auto &payload_details : payload.details()) {
    const auto details{std::ranges::find(span, payload_details.id(),
                                         &tek_sc_cm_ws_item_details::id)};
    if (details == span.end()) {
      continue;
    }
    if (const auto eresult{
            static_cast<tek_sc_cm_eresult>(payload_details.eresult())};
        eresult != TEK_SC_CM_ERESULT_ok) {
      details->result = err(TEK_SC_ERRC_cm_ws_details, eresult);
      continue;
    }
    details->manifest_id = payload_details.hcontent_file();
    details->last_updated = payload_details.last_updated();
    details->name =
        payload_details.has_title() ? payload_details.title().data() : nullptr;
    details->preview_url = payload_details.has_preview_url()
                               ? payload_details.preview_url().data()
                               : nullptr;
    if (payload_details.children_size()) {
      details->children = std::to_address(children.end());
      details->num_children = payload_details.children_size();
      for (auto id : payload_details.children() |
                         std::views::transform(
                             &msg_payloads::PublishedFileDetails::Child::id)) {
        children.emplace_back(id);
      }
    } else {
      details->children = nullptr;
      details->num_children = 0;
    }
    details->app_id = payload_details.app_id();
    details->result = tsc_err_ok();
  }
  // Report results via callback
  data_ws.result = tsc_err_ok();
  cb(&client, &data_ws, client.user_data);
  return true;
}

/// Handle "PublishedFile.QueryFiles#1" response message.
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
///    Pointer to the @ref tek_sc_cm_data_ws.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_qf(cm_client &client, const MessageHeader &,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nonnull inout_data) {
  auto &data_ws{*reinterpret_cast<tek_sc_cm_data_ws *>(inout_data)};
  msg_payloads::QueryFilesResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_ws.result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ws, client.user_data);
    return true;
  }
  data_ws.num_returned_details = payload.details_size();
  data_ws.total_items = payload.total();
  // Process details entries
  for (auto &&[payload_details, details] : std::views::zip(
           payload.details(),
           std::span{data_ws.details,
                     static_cast<std::size_t>(data_ws.num_returned_details)})) {
    if (const auto eresult =
            static_cast<tek_sc_cm_eresult>(payload_details.eresult());
        eresult != TEK_SC_CM_ERESULT_ok) {
      details.result = err(TEK_SC_ERRC_cm_ws_details, eresult);
      continue;
    }
    details.id = payload_details.id();
    details.manifest_id = payload_details.hcontent_file();
    details.last_updated = payload_details.last_updated();
    details.name =
        payload_details.has_title() ? payload_details.title().data() : nullptr;
    details.preview_url = payload_details.has_preview_url()
                              ? payload_details.preview_url().data()
                              : nullptr;
    details.children = nullptr;
    details.num_children = 0;
    details.app_id = payload_details.app_id();
    details.result = tsc_err_ok();
  }
  // Report results via callback
  data_ws.result = tsc_err_ok();
  cb(&client, &data_ws, client.user_data);
  return true;
}

} // namespace

//===-- Public functions --------------------------------------------------===//

extern "C" {

void tek_sc_cm_ws_get_details(tek_sc_cm_client *client, tek_sc_cm_data_ws *data,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  if (!data->num_details) {
    // No-op
    data->result = tsc_err_ok();
    cb(client, data, client->user_data);
    return;
  }
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_cm_not_signed_in);
    cb(client, data, client->user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GetDetailsRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("PublishedFile.GetDetails#1");
  std::ranges::for_each(
      std::span{data->details, static_cast<std::size_t>(data->num_details)},
      [&msg](auto id) { msg.payload.add_ids(id); },
      &tek_sc_cm_ws_item_details::id);
  msg.payload.set_include_children(true);
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_gd,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_gd,
                                           .cb = cb,
                                           .inout_data = data})
          .first};
  auto &a_entry = a_entry_it->second;
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{
          client->send_message<TEK_SC_ERRC_cm_ws_details>(msg, &a_entry.sul)};
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

void tek_sc_cm_ws_query_items(tek_sc_cm_client *client, tek_sc_cm_data_ws *data,
                              uint32_t app_id, int page,
                              const char *search_query,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_cm_not_signed_in);
    cb(client, data, client->user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::QueryFilesRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("PublishedFile.QueryFiles#1");
  msg.payload.set_page(page);
  msg.payload.set_num_per_page(data->num_details);
  msg.payload.set_app_id(app_id);
  if (search_query) {
    msg.payload.set_search_text(search_query);
  }
  msg.payload.set_return_metadata(true);
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it{
      client->a_entries
          .emplace(job_id, msg_await_entry{.sul = {.list = {},
                                                   .us = timeout_to_deadline(
                                                       timeout_ms),
                                                   .cb = timeout_qi,
                                                   .latency_us = 0},
                                           .client = *client,
                                           .job_id = job_id,
                                           .proc = handle_qf,
                                           .cb = cb,
                                           .inout_data = data})
          .first};
  auto &a_entry{a_entry_it->second};
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res{
          client->send_message<TEK_SC_ERRC_cm_ws_query>(msg, &a_entry.sul)};
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

} // extern "C"

} // namespace tek::steamclient::cm
