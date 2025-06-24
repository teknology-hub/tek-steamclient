//===-- cm_sign_in.cpp - Steam CM client sign-in implementation -----------===//
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
#include "tek/steamclient/cm/msg_payloads/logon.pb.h"

#include <atomic>
#include <chrono>
#include <libwebsockets.h>

namespace tek::steamclient::cm {

namespace {

//===-- Private function --------------------------------------------------===//

/// Handle a sign-in response message timeout.
///
/// @param [in, out] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void timeout(lws_sorted_usec_list_t *_Nonnull sul) {
  auto &a_entry = *reinterpret_cast<msg_await_entry_reduced *>(sul);
  auto &client = a_entry.client;
  auto res = tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_timeout);
  a_entry.cb(&client, &res, client.user_data);
  a_entry.cb = nullptr;
}

} // namespace

//===-- Internal method ---------------------------------------------------===//

} // namespace tek::steamclient::cm

void tek_sc_cm_client::handle_logon(
    const tek::steamclient::cm::MessageHeader &header, const void *data,
    int size) {
  if (!sign_in_entry.cb) {
    // This message is not expected at the moment
    return;
  }
  // Cancel the timeout
  lws_sul_cancel(&sign_in_entry.sul);
  // Parse the payload
  tek::steamclient::cm::msg_payloads::LogonResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto res =
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_protobuf_deserialize);
    sign_in_entry.cb(this, &res, user_data);
    return;
  }
  // Report the result via callback
  const auto eresult = static_cast<tek_sc_cm_eresult>(payload.eresult());
  if (eresult == TEK_SC_CM_ERESULT_ok) {
    steam_id = header.steam_id();
    session_id = header.session_id();
    if ((steam_id & 0x1A0000000000000) == 0x1A0000000000000) {
      // Anonymous account, won't provide any licenses
      num_lics = 0;
    }
    conn_state.store(tek::steamclient::cm::conn_state::signed_in,
                     std::memory_order::release);
  }
  auto res = eresult == TEK_SC_CM_ERESULT_ok
                 ? tsc_err_ok()
                 : tek::steamclient::cm::err(TEK_SC_ERRC_cm_sign_in, eresult);
  sign_in_entry.cb(this, &res, user_data);
  sign_in_entry.cb = nullptr;
}

namespace tek::steamclient::cm {

//===-- Public functions --------------------------------------------------===//

extern "C" {

void tek_sc_cm_sign_in(tek_sc_cm_client *client, const char *token,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is connected
  const auto cur_conn_state =
      client->conn_state.load(std::memory_order::relaxed);
  if (cur_conn_state == conn_state::signed_in) {
    // No-op
    return;
  }
  if (cur_conn_state < conn_state::connected) {
    auto res =
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_not_connected);
    cb(client, &res, client->user_data);
    return;
  }
  // Check if the token is valid
  const auto token_info = tek_sc_cm_parse_auth_token(token);
  if (!token_info.steam_id) {
    auto res =
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_token_invalid);
    cb(client, &res, client->user_data);
    return;
  }
  if (token_info.expires <
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {
    auto res =
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_token_expired);
    cb(client, &res, client->user_data);
    return;
  }
  // Prepare the request message
  message<msg_payloads::LogonRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_LOG_ON;
  msg.header.set_steam_id(token_info.steam_id);
  msg.payload.set_protocol_version(protocol_ver);
  msg.payload.set_client_language("english");
  msg.payload.set_client_os_type(client->lib_ctx.os_type);
  msg.payload.set_should_remember_password(true);
  msg.payload.set_access_token(token);
  // Setup the await entry
  client->sign_in_entry.sul.us = timeout_to_deadline(timeout_ms);
  client->sign_in_entry.sul.cb = timeout;
  client->sign_in_entry.cb = cb;
  // Send the request message
  if (auto res = client->send_message<TEK_SC_ERRC_cm_sign_in>(
          msg, &client->sign_in_entry.sul);
      !tek_sc_err_success(&res)) {
    client->sign_in_entry.cb = nullptr;
    cb(client, &res, client->user_data);
  }
}

void tek_sc_cm_sign_in_anon(tek_sc_cm_client *client,
                            tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is connected
  const auto cur_conn_state =
      client->conn_state.load(std::memory_order::relaxed);
  if (cur_conn_state == conn_state::signed_in) {
    // No-op
    return;
  }
  if (cur_conn_state < conn_state::connected) {
    auto res =
        tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_not_connected);
    cb(client, &res, client->user_data);
    return;
  }
  // Prepare the request message
  message<msg_payloads::LogonRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_LOG_ON;
  msg.header.set_steam_id(0x1A0000000000000);
  msg.payload.set_protocol_version(protocol_ver);
  msg.payload.set_client_language("english");
  msg.payload.set_client_os_type(client->lib_ctx.os_type);
  // Setup the await entry
  client->sign_in_entry.sul.us = timeout_to_deadline(timeout_ms);
  client->sign_in_entry.sul.cb = timeout;
  client->sign_in_entry.cb = cb;
  // Send the request message
  if (auto res = client->send_message<TEK_SC_ERRC_cm_sign_in>(
          msg, &client->sign_in_entry.sul);
      !tek_sc_err_success(&res)) {
    client->sign_in_entry.cb = nullptr;
    cb(client, &res, client->user_data);
  }
}

} // extern "C"

} // namespace tek::steamclient::cm
