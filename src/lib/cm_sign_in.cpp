//===-- cm_sign_in.cpp - Steam CM client sign-in implementation -----------===//
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
/// Implementation of @ref tek_sc_cm_client_sign_in,
///    @ref tek_sc_cm_client_sign_in_anon and their response message handling.
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/heartbeat.pb.h"
#include "tek/steamclient/cm/msg_payloads/logon.pb.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <mutex>
#include <utility>
#include <uv.h>

namespace tek::steamclient::cm {

namespace {

//===-- Private functions -------------------------------------------------===//

/// Timer handle close callback.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void close_cb(uv_handle_t *_Nonnull timer) {
  auto &entry{*reinterpret_cast<await_entry *>(uv_handle_get_data(timer))};
  auto &conn{entry.conn};
  delete &entry;
  if (!--conn.ref_count) {
    if (conn.delete_pending.load(std::memory_order::relaxed)) {
      delete &conn;
    } else {
      conn.safe_to_delete.store(true, std::memory_order::relaxed);
    }
  }
}

/// Handle a sign-in response message timeout.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void timeout(uv_timer_t *_Nonnull timer) {
  auto &entry{*reinterpret_cast<await_entry *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(timer)))};
  auto &conn{entry.conn};
  conn.sign_in_entry.store(nullptr, std::memory_order::relaxed);
  auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_timeout)};
  entry.cb(&conn, &res, conn.user_data);
  uv_close(reinterpret_cast<uv_handle_t *>(timer), close_cb);
}

} // namespace

//===-- Internal method ---------------------------------------------------===//

void cm_conn::handle_logon(const MessageHeader &header, const void *data,
                           int size) {
  const auto entry{sign_in_entry.exchange(nullptr, std::memory_order::relaxed)};
  if (!entry) {
    // This message is not expected at the moment
    return;
  }
  const auto cb{entry->cb};
  // Cancel the timeout
  switch (entry->state) {
  case timer_state::inactive:
    delete entry;
    break;
  case timer_state::closing:
    break;
  case timer_state::active:
    entry->state = timer_state::closing;
    uv_close(reinterpret_cast<uv_handle_t *>(&entry->timer), close_cb);
    break;
  }
  // Parse the payload
  msg_payloads::LogonResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto res{
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_protobuf_deserialize)};
    cb(&*this, &res, user_data);
    return;
  }
  // Report the result via callback
  const auto eresult{static_cast<tek_sc_cm_eresult>(payload.eresult())};
  if (eresult == TEK_SC_CM_ERESULT_ok) {
    steam_id = header.steam_id();
    session_id = header.session_id();
    if ((steam_id & 0x1A0000000000000) == 0x1A0000000000000) {
      // Anonymous account, won't provide any licenses
      const std::scoped_lock lock{lics_mtx};
      num_lics = 0;
    }
    state.store(conn_state::signed_in, std::memory_order::release);
    // Setup heartbeat timer
    if (uv_timer_init(&ctx.loop, &heartbeat_timer) == 0) {
      heartbeat_active = true;
      ++ref_count;
      uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&heartbeat_timer),
                         this);
      uv_timer_start(
          &heartbeat_timer,
          [](auto timer) {
            message<msg_payloads::HeartBeat> msg;
            msg.type = EMsg::EMSG_CLIENT_HEARTBEAT;
            msg.payload.set_send_reply(true);
            reinterpret_cast<cm_conn *>(
                uv_handle_get_data(
                    reinterpret_cast<const uv_handle_t *>(timer)))
                ->send_message<TEK_SC_ERRC_ok>(std::move(msg));
          },
          payload.heartbeat_seconds() * 1000,
          payload.heartbeat_seconds() * 1000);
    }
  }
  auto res{eresult == TEK_SC_CM_ERESULT_ok
               ? tsc_err_ok()
               : err(TEK_SC_ERRC_cm_sign_in, eresult)};
  cb(&*this, &res, user_data);
}

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient::cm;

extern "C" {

void tek_sc_cm_sign_in(tek_sc_cm_client *client, const char *token,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is connected
  const auto cur_conn_state{conn.state.load(std::memory_order::relaxed)};
  if (cur_conn_state == conn_state::signed_in) {
    // No-op
    return;
  }
  if (cur_conn_state < conn_state::connected) {
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_not_connected)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Check if the token is valid
  const auto token_info{tek_sc_cm_parse_auth_token(token)};
  if (!token_info.steam_id) {
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_token_invalid)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  if (token_info.expires <
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_token_expired)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Prepare the request message
  message<msg_payloads::LogonRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_LOG_ON;
  msg.header.set_steam_id(token_info.steam_id);
  msg.payload.set_protocol_version(protocol_ver);
  msg.payload.set_client_language("english");
  msg.payload.set_client_os_type(conn.ctx.os_type);
  msg.payload.set_should_remember_password(true);
  msg.payload.set_access_token(token);
  std::size_t msg_size;
  auto buf{conn.serialize_message(std::move(msg), msg_size)};
  if (!buf) {
    auto res{
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_protobuf_serialize)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Create and attempt to acquire the sign-in entry
  const auto entry{new await_entry{
      .conn{conn}, .cb = cb, .state = timer_state::inactive, .timer{}}};
  if (await_entry *expected{}; !conn.sign_in_entry.compare_exchange_strong(
          expected, entry, std::memory_order::release,
          std::memory_order::relaxed)) {
    delete entry;
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_another_auth)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Send the request message
  conn.send_msg({.buf{std::move(buf)},
                 .size = static_cast<int>(msg_size),
                 .frame_type = CURLWS_BINARY,
                 .timer = &entry->timer,
                 .state = &entry->state,
                 .timer_cb = timeout,
                 .timeout = static_cast<std::uint64_t>(timeout_ms),
                 .data = entry});
}

void tek_sc_cm_sign_in_anon(tek_sc_cm_client *client,
                            tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is connected
  const auto cur_conn_state{conn.state.load(std::memory_order::relaxed)};
  if (cur_conn_state == conn_state::signed_in) {
    // No-op
    return;
  }
  if (cur_conn_state < conn_state::connected) {
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_not_connected)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Prepare the request message
  message<msg_payloads::LogonRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_LOG_ON;
  msg.header.set_steam_id(0x1A0000000000000);
  msg.payload.set_protocol_version(protocol_ver);
  msg.payload.set_client_language("english");
  msg.payload.set_client_os_type(conn.ctx.os_type);
  std::size_t msg_size;
  auto buf{conn.serialize_message(std::move(msg), msg_size)};
  if (!buf) {
    auto res{
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_protobuf_serialize)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Create and attempt to acquire the sign-in entry
  const auto entry{new await_entry{
      .conn{conn}, .cb = cb, .state = timer_state::inactive, .timer{}}};
  if (await_entry *expected{}; !conn.sign_in_entry.compare_exchange_strong(
          expected, entry, std::memory_order::release,
          std::memory_order::relaxed)) {
    delete entry;
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_another_auth)};
    cb(&conn, &res, conn.user_data);
    return;
  }
  // Send the request message
  conn.send_msg({.buf{std::move(buf)},
                 .size = static_cast<int>(msg_size),
                 .frame_type = CURLWS_BINARY,
                 .timer = &entry->timer,
                 .state = &entry->state,
                 .timer_cb = timeout,
                 .timeout = static_cast<std::uint64_t>(timeout_ms),
                 .data = entry});
}

} // extern "C"
