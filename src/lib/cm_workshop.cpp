//===-- cm_workshop.cpp - Steam CM client Workshop subsystem impl. --------===//
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
#include <mutex>
#include <ranges>
#include <span>
#include <utility>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private functions -------------------------------------------------===//

/// Handle a Steam Workshop item details response message timeout.
static void timeout_gd(cm_conn &conn, msg_await_entry &entry) {
  reinterpret_cast<tek_sc_cm_data_ws *>(entry.inout_data)->result =
      tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, entry.inout_data, conn.user_data);
}

/// Handle a Steam Workshop items query response message timeout.
static void timeout_qi(cm_conn &conn, msg_await_entry &entry) {
  reinterpret_cast<tek_sc_cm_data_ws *>(entry.inout_data)->result =
      tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, entry.inout_data, conn.user_data);
}

/// Handle "PublishedFile.GetDetails#1" response message.
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
///    Pointer to the @ref tek_sc_cm_data_ws.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_gd(cm_conn &conn, const MessageHeader &,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nonnull inout_data) {
  auto &data_ws{*reinterpret_cast<tek_sc_cm_data_ws *>(inout_data)};
  msg_payloads::GetDetailsResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_ws.result = tsc_err_sub(TEK_SC_ERRC_cm_ws_details,
                                 TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_ws, conn.user_data);
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
  cb(&conn, &data_ws, conn.user_data);
  return true;
}

/// Handle "PublishedFile.QueryFiles#1" response message.
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
///    Pointer to the @ref tek_sc_cm_data_ws.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_qf(cm_conn &conn, const MessageHeader &,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nonnull inout_data) {
  auto &data_ws{*reinterpret_cast<tek_sc_cm_data_ws *>(inout_data)};
  msg_payloads::QueryFilesResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_ws.result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_ws, conn.user_data);
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
  cb(&conn, &data_ws, conn.user_data);
  return true;
}

} // namespace

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient::cm;

extern "C" {

void tek_sc_cm_ws_get_details(tek_sc_cm_client *client, tek_sc_cm_data_ws *data,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  if (!data->num_details) {
    // No-op
    data->result = tsc_err_ok();
    cb(&conn, data, conn.user_data);
    return;
  }
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_details, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
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
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gd, cb, timeout_gd, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_ws_details>(
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

void tek_sc_cm_ws_query_items(tek_sc_cm_client *client, tek_sc_cm_data_ws *data,
                              uint32_t app_id, int page,
                              const char *search_query,
                              tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_ws_query, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
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
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_qf, cb, timeout_qi, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_ws_query>(
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

} // extern "C"
