//===-- cm_auth.cpp - Steam CM client auth subsystem implementation -------===//
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
/// Implementation of Steam CM client functions working with "Authentication"
///    interface or otherwise related to user authentication.
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/auth_common.pb.h"
#include "tek/steamclient/cm/msg_payloads/begin_auth_session_via_credentials.pb.h"
#include "tek/steamclient/cm/msg_payloads/begin_auth_session_via_qr.pb.h"
#include "tek/steamclient/cm/msg_payloads/generate_access_token_for_app.pb.h"
#include "tek/steamclient/cm/msg_payloads/get_password_rsa_public_key.pb.h"
#include "tek/steamclient/cm/msg_payloads/poll_auth_session_status.pb.h"
#include "tek/steamclient/cm/msg_payloads/request_encrypted_app_ticket.pb.h"
#include "tek/steamclient/cm/msg_payloads/update_auth_session_with_steam_guard_code.pb.h"
#include "utils.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <memory>
#include <mutex>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/types.h>
#include <ranges>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <uv.h>

namespace tek::steamclient::cm {

using auth_data = tek_sc_cm_data_auth_polling;

namespace {

//===-- Private functions -------------------------------------------------===//

static constexpr tek_sc_cm_auth_confirmation_type &
operator|=(tek_sc_cm_auth_confirmation_type &left,
           tek_sc_cm_auth_confirmation_type right) noexcept {
  return left = static_cast<tek_sc_cm_auth_confirmation_type>(
             static_cast<int>(left) | static_cast<int>(right));
}

/// Create a @ref auth_data with specified error.
///
/// @param [in] err
///    A @ref tek_sc_err to include into data.
/// @return A @ref auth_data with specified error.
static constexpr auth_data auth_data_err(const tek_sc_err &&err) noexcept {
  return {.status = TEK_SC_CM_AUTH_STATUS_completed,
          .confirmation_types{},
          .url{},
          .token{},
          .result{err}};
}

/// Create a @ref auth_data for an error code.
///
/// @param errc
///    The error code indicating failed operation.
/// @return A @ref auth_data for specified error code.
static constexpr auth_data auth_data_errc(tek_sc_errc errc) noexcept {
  return auth_data_err(tsc_err_sub(TEK_SC_ERRC_cm_auth, errc));
}

/// Create a @ref tek_sc_cm_data_renew_token with specified error.
///
/// @param [in] err
///    A @ref tek_sc_err to include into data.
/// @return A @ref tek_sc_cm_data_renew_token with specified error.
static constexpr tek_sc_cm_data_renew_token
renew_data_err(const tek_sc_err &&err) noexcept {
  return {.new_token{}, .result{err}};
}

/// Create a @ref tek_sc_cm_data_renew_token for an error code.
///
/// @param errc
///    The error code indicating failed operation.
/// @return A @ref tek_sc_cm_data_renew_token for specified error code.
static constexpr tek_sc_cm_data_renew_token
renew_data_errc(tek_sc_errc errc) noexcept {
  return renew_data_err(tsc_err_sub(TEK_SC_ERRC_cm_token_renew, errc));
}

/// Release and destroy CM connections's authentication session context.
///
/// @param [in, out] conn
///    CM connection instance to destroy auth session context for.
static void release_auth_ctx(cm_conn &conn) {
  const auto actx{conn.auth_ctx.exchange(nullptr, std::memory_order::relaxed)};
  if (!actx) {
    return;
  }
  if (actx->status_timer.timer_active) {
    uv_close(reinterpret_cast<uv_handle_t *>(&actx->status_timer.timer),
             [](auto timer) {
               auto &actx{*reinterpret_cast<auth_session_ctx *>(
                   uv_handle_get_data(timer))};
               auto &conn{actx.status_timer.conn};
               delete &actx;
               if (!--conn.ref_count &&
                   conn.delete_pending.load(std::memory_order::relaxed)) {
                 delete &conn;
               }
             });
  } else {
    delete actx;
  }
}

/// Handle an authentication session response message timeout.
static void timeout_auth(cm_conn &conn, msg_await_entry &entry) {
  release_auth_ctx(conn);
  auto data{auth_data_errc(TEK_SC_ERRC_cm_timeout)};
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle a renew token response message timeout.
static void timeout_renew(cm_conn &conn, msg_await_entry &entry) {
  auto data{renew_data_errc(TEK_SC_ERRC_cm_timeout)};
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle an encrypted app ticket response message timeout.
static void timeout_eat(cm_conn &conn, msg_await_entry &entry) {
  reinterpret_cast<tek_sc_cm_data_enc_app_ticket *>(entry.inout_data)->result =
      tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, entry.inout_data, conn.user_data);
}

/// Send an auth session status request.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void send_status_req(uv_timer_t *_Nonnull timer);

/// Handle "Authentication.BeginAuthSessionViaCredentials#1" response message.
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
static bool handle_basvc(cm_conn &conn, const MessageHeader &header,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(header.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_err(err(TEK_SC_ERRC_cm_auth, eresult))};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  msg_payloads::BeginAuthSessionViaCredentialsResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_protobuf_deserialize)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  const auto actx{conn.auth_ctx.load(std::memory_order::acquire)};
  if (!actx) {
    return true;
  }
  actx->client_id.store(payload.client_id(), std::memory_order::relaxed);
  actx->request_id = payload.request_id();
  actx->polling_interval = payload.interval() * 1000;
  actx->steam_id = payload.steam_id();
  // Schedule the first status request
  if (uv_timer_init(&conn.ctx.loop, &actx->status_timer.timer) != 0) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_mem_alloc)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  ++conn.ref_count;
  actx->status_timer.timer_active = true;
  uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&actx->status_timer.timer),
                     actx);
  if (uv_timer_start(&actx->status_timer.timer, send_status_req,
                     actx->polling_interval, 0) != 0) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_mem_alloc)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  // Report available confirmation types via callback
  auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_awaiting_confirmation,
                    .confirmation_types = TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
                    .url{},
                    .token{},
                    .result{}};
  for (auto type :
       payload.allowed_confirmations() |
           std::views::transform(
               &msg_payloads::AllowedConfirmation::confirmation_type)) {
    using msg_payloads::GuardType;
    switch (type) {
    case GuardType::GUARD_TYPE_EMAIL_CODE:
      data_ap.confirmation_types |= TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email;
      break;
    case GuardType::GUARD_TYPE_DEVICE_CODE:
      data_ap.confirmation_types |= TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code;
      break;
    case GuardType::GUARD_TYPE_DEVICE_CONFIRMATION:
      data_ap.confirmation_types |= TEK_SC_CM_AUTH_CONFIRMATION_TYPE_device;
      break;
    default:
      break;
    }
  }
  cb(&conn, &data_ap, conn.user_data);
  return true;
}

/// Handle "Authentication.BeginAuthSessionViaQR#1" response message.
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
static bool handle_basvq(cm_conn &conn, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::BeginAuthSessionViaQrResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap{auth_data_errc(TEK_SC_ERRC_protobuf_deserialize)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  const auto actx{conn.auth_ctx.load(std::memory_order::acquire)};
  if (!actx) {
    return true;
  }
  actx->client_id.store(payload.client_id(), std::memory_order::relaxed);
  actx->request_id = payload.request_id();
  actx->polling_interval = payload.interval() * 1000;
  // Schedule the first status request
  if (uv_timer_init(&conn.ctx.loop, &actx->status_timer.timer) != 0) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_mem_alloc)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  ++conn.ref_count;
  actx->status_timer.timer_active = true;
  if (uv_timer_start(&actx->status_timer.timer, send_status_req,
                     actx->polling_interval, 0) != 0) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_mem_alloc)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  // Report challenge URL via callback
  auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_new_url,
                    .confirmation_types{},
                    .url = payload.challenge_url().data(),
                    .token{},
                    .result{}};
  cb(&conn, &data_ap, conn.user_data);
  return true;
}

/// Handle "Authentication.GenerateAccessTokenForApp#1" response message.
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
static bool handle_gatfa(cm_conn &conn, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GenerateAccessTokenForAppResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_renew{renew_data_errc(TEK_SC_ERRC_protobuf_deserialize)};
    cb(&conn, &data_renew, conn.user_data);
    return true;
  }
  tek_sc_cm_data_renew_token data_renew{
      .new_token = payload.has_token() ? payload.token().data() : nullptr,
      .result{tsc_err_ok()}};
  cb(&conn, &data_renew, conn.user_data);
  return true;
}

/// Handle "Authentication.GetPasswordRSAPublicKey#1" response message.
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
static bool handle_gprpk(cm_conn &conn, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GetPasswordRsaPublicKeyResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap{auth_data_errc(TEK_SC_ERRC_protobuf_deserialize)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  const auto actx{conn.auth_ctx.load(std::memory_order::acquire)};
  if (!actx) {
    return true;
  }
  // For 512-byte input (maximum possible RSA block size)
  std::array<char, 684> b64_buf;
  int b64_len;
  {
    // Build the RSA public key via received parameters
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> param_build{
        OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free};
    if (!param_build) {
      goto encrypt_err;
    }
    BIGNUM *bn_ptr{};
    if (!BN_hex2bn(&bn_ptr, payload.modulus().data())) {
      goto encrypt_err;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n{bn_ptr, BN_free};
    if (!OSSL_PARAM_BLD_push_BN(param_build.get(), OSSL_PKEY_PARAM_RSA_N,
                                n.get())) {
      goto encrypt_err;
    }
    if (bn_ptr = nullptr; !BN_hex2bn(&bn_ptr, payload.exponent().data())) {
      goto encrypt_err;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e{bn_ptr, BN_free};
    if (!OSSL_PARAM_BLD_push_BN(param_build.get(), OSSL_PKEY_PARAM_RSA_E,
                                e.get())) {
      goto encrypt_err;
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> param{
        OSSL_PARAM_BLD_to_param(param_build.get()), OSSL_PARAM_free};
    if (!param) {
      goto encrypt_err;
    }
    n.reset();
    e.reset();
    param_build.reset();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx{
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free};
    if (!ctx) {
      goto encrypt_err;
    }
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
      goto encrypt_err;
    }
    EVP_PKEY *pkey_ptr{};
    if (EVP_PKEY_fromdata(ctx.get(), &pkey_ptr, EVP_PKEY_PUBLIC_KEY,
                          param.get()) != 1) {
      goto encrypt_err;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey{pkey_ptr,
                                                             EVP_PKEY_free};
    param.reset();
    ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (!ctx) {
      goto encrypt_err;
    }
    if (EVP_PKEY_encrypt_init_ex(ctx.get(), nullptr) != 1) {
      goto encrypt_err;
    }
    // Encrypt the password with the public key
    std::array<unsigned char, 512> enc_pass; // Maximum possible block size
    auto enc_pass_len{enc_pass.size()};
    if (EVP_PKEY_encrypt(
            ctx.get(), enc_pass.data(), &enc_pass_len,
            reinterpret_cast<const unsigned char *>(actx->password.data()),
            actx->password.length()) != 1) {
      goto encrypt_err;
    }
    std::ranges::fill(actx->password, '\0');
    actx->password = {};
    pkey.reset();
    ctx.reset();
    // Encode encrypted password into a base64 string
    b64_len =
        tsci_u_base64_encode(enc_pass.data(), enc_pass_len, b64_buf.data());
    goto encrypt_success;
  } // Password encryption scope
encrypt_err:;
  {
    auto data_ap{auth_data_errc(TEK_SC_ERRC_cm_pass_encryption)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
encrypt_success:;
  const auto job_id{gen_job_id()};
  // Prepare the begin auth session request message
  message<msg_payloads::BeginAuthSessionViaCredentialsRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name(
      "Authentication.BeginAuthSessionViaCredentials#1");
  msg.payload.set_account_name(actx->account_name);
  std::ranges::fill(actx->account_name, '\0');
  actx->account_name = {};
  msg.payload.set_encrypted_password(b64_buf.data(), b64_len);
  msg.payload.set_encryption_timestamp(payload.timestamp());
  msg.payload.set_persistence(
      msg_payloads::SessionPersistence::SESSION_PERSISTENCE_PERSISTENT);
  msg.payload.set_website_id("Client");
  auto &device_details = *msg.payload.mutable_device_details();
  device_details.set_device_friendly_name(actx->device_name);
  actx->device_name = {};
  device_details.set_platform_type(
      msg_payloads::PlatformType::PLATFORM_TYPE_STEAM_CLIENT);
  device_details.set_os_type(conn.ctx.os_type);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_basvc, cb, timeout_auth)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_auth>(
          std::move(msg), it->second, actx->timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    release_auth_ctx(conn);
    // Report error via callback
    auto data_ap{auth_data_err(std::move(res))};
    cb(&conn, &data_ap, conn.user_data);
  }
  return true;
}

/// Handle "Authentication.PollAuthSessionStatus#1" response message.
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
static bool handle_pass(cm_conn &conn, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *) {
  const auto actx{conn.auth_ctx.load(std::memory_order::acquire)};
  if (!actx) {
    return true;
  }
  msg_payloads::PollAuthSessionStatusResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap{auth_data_errc(TEK_SC_ERRC_protobuf_deserialize)};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  if (payload.has_refresh_token()) {
    // End auth session and report received token via callback
    release_auth_ctx(conn);
    auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_completed,
                      .confirmation_types{},
                      .url{},
                      .token = payload.refresh_token().data(),
                      .result{tsc_err_ok()}};
    cb(&conn, &data_ap, conn.user_data);
    return true;
  }
  if (payload.has_new_client_id()) {
    actx->client_id = payload.new_client_id();
  }
  if (payload.has_new_challenge_url()) {
    // Report new challenge URL via callback
    auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_new_url,
                      .confirmation_types{},
                      .url = payload.new_challenge_url().data(),
                      .token{},
                      .result{}};
    cb(&conn, &data_ap, conn.user_data);
  }
  // Schedule the next status request
  if (uv_timer_start(&actx->status_timer.timer, send_status_req,
                     actx->polling_interval, 0) != 0) {
    release_auth_ctx(conn);
    auto data_ap{auth_data_errc(TEK_SC_ERRC_mem_alloc)};
    cb(&conn, &data_ap, conn.user_data);
  }
  return true;
}

/// Handle `EMSG_CLIENT_REQUEST_ENCRYPTED_APP_TICKET_RESPONSE` response message.
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
///    Pointer to the @ref tek_sc_cm_data_enc_app_ticket.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_reat(cm_conn &conn, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  const auto data_eat{
      reinterpret_cast<tek_sc_cm_data_enc_app_ticket *>(inout_data)};
  msg_payloads::RequestEncryptedAppTicketResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_eat->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                                   TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, data_eat, conn.user_data);
    return true;
  }
  if (const auto eresult{static_cast<tek_sc_cm_eresult>(payload.eresult())};
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_eat->result = err(TEK_SC_ERRC_cm_enc_app_ticket, eresult);
    cb(&conn, data_eat, conn.user_data);
    return true;
  }
  std::unique_ptr<unsigned char[]> data_buf;
  data_eat->data_size = 0;
  if (payload.has_ticket()) {
    const auto &ticket{payload.ticket()};
    data_eat->data_size = ticket.ByteSizeLong();
    data_buf.reset(new unsigned char[data_eat->data_size]);
    if (!ticket.SerializeToArray(data_buf.get(), data_eat->data_size)) {
      data_eat->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                                     TEK_SC_ERRC_protobuf_serialize);
      cb(&conn, data_eat, conn.user_data);
      return true;
    }
    data_eat->data = data_buf.get();
  } else {
    data_eat->data_size = 0;
    data_eat->data = nullptr;
  }
  data_eat->result = tsc_err_ok();
  //  Report results via callback
  cb(&conn, data_eat, conn.user_data);
  return true;
}

static void send_status_req(uv_timer_t *timer) {
  auto &actx{*reinterpret_cast<auth_session_ctx *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(timer)))};
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::PollAuthSessionStatusRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.PollAuthSessionStatus#1");
  msg.payload.set_client_id(actx.client_id);
  msg.payload.set_request_id(actx.request_id);
  // Send the request message
  auto &conn{actx.status_timer.conn};
  const auto cb{actx.status_timer.cb};
  const auto it{conn.setup_a_entry(job_id, handle_pass, cb, timeout_auth)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_auth>(
          std::move(msg), it->second, actx.polling_interval)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    release_auth_ctx(conn);
    // Report error via callback
    auto data{auth_data_err(std::move(res))};
    cb(&conn, &data, conn.user_data);
  }
}

} // namespace

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient::cm;

extern "C" {

tek_sc_cm_auth_token_info tek_sc_cm_parse_auth_token(const char *token) {
  // This string copy also provides a mutable buffer for in-situ Base64
  //    decoding and JSON parsing
  std::string token_str{token};
  // The token should contain 3 Base64 strings separated by a dot, we need the
  //    second one
  if (std::ranges::count(token_str, '.') != 2) {
    return {};
  }
  const auto start_pos{token_str.find('.') + 1};
  const int json_len{tsci_u_base64_decode(
      &token_str[start_pos], token_str.rfind('.') - start_pos,
      reinterpret_cast<unsigned char *>(token_str.data()))};
  token_str[json_len] = '\0'; // Null terminator required for in-situ parsing
  rapidjson::Document doc;
  doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(token_str.data());
  if (doc.HasParseError() || !doc.IsObject()) {
    return {};
  }
  const auto sub{doc.FindMember("sub")};
  if (sub == doc.MemberEnd() || !sub->value.IsString()) {
    return {};
  }
  tek_sc_cm_auth_token_info res;
  if (const std::string_view view{sub->value.GetString(),
                                  sub->value.GetStringLength()};
      std::from_chars(view.begin(), view.end(), res.steam_id).ec !=
      std::errc{}) {
    return {};
  }
  const auto exp{doc.FindMember("exp")};
  if (exp == doc.MemberEnd() || !exp->value.IsUint64()) {
    return {};
  }
  res.expires = exp->value.GetUint64();
  const auto per{doc.FindMember("per")};
  if (per == doc.MemberEnd() || !per->value.IsInt()) {
    return {};
  }
  res.renewable = per->value.GetInt() == 1;
  return res;
}

void tek_sc_cm_auth_credentials(tek_sc_cm_client *client,
                                const char *device_name,
                                const char *account_name, const char *password,
                                tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is connected
  if (conn.conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data{auth_data_errc(TEK_SC_ERRC_cm_not_connected)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  // Setup the auth context
  const auto actx{new auth_session_ctx{
      .client_id{},
      .request_id{},
      .polling_interval{},
      .steam_id{},
      .device_name{device_name},
      .account_name{account_name},
      .password{password},
      .timeout_ms = static_cast<std::uint64_t>(timeout_ms),
      .status_timer{.conn{conn}, .cb = cb, .timer{}, .timer_active{}}}};
  // Report an error if there is already another incomplete auth session
  if (auth_session_ctx *expected{}; !conn.auth_ctx.compare_exchange_strong(
          expected, actx, std::memory_order::release,
          std::memory_order::relaxed)) {
    delete actx;
    auto data{auth_data_errc(TEK_SC_ERRC_cm_another_auth)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the RSA public key request message
  message<msg_payloads::GetPasswordRsaPublicKeyRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.GetPasswordRSAPublicKey#1");
  msg.payload.set_account_name(account_name);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gprpk, cb, timeout_auth)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_auth>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    release_auth_ctx(conn);
    // Report error via callback
    auto data{auth_data_err(std::move(res))};
    cb(&conn, &data, conn.user_data);
  }
}

void tek_sc_cm_auth_qr(tek_sc_cm_client *client, const char *device_name,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is connected
  if (conn.conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data{auth_data_errc(TEK_SC_ERRC_cm_not_connected)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  // Setup the auth context
  const auto actx{new auth_session_ctx{
      .client_id{},
      .request_id{},
      .polling_interval{},
      .steam_id{},
      .device_name{},
      .account_name{},
      .password{},
      .timeout_ms{},
      .status_timer{.conn{conn}, .cb = cb, .timer{}, .timer_active{}}}};
  // Report an error if there is already another incomplete auth session
  if (auth_session_ctx *expected{}; !conn.auth_ctx.compare_exchange_strong(
          expected, actx, std::memory_order::release,
          std::memory_order::relaxed)) {
    delete actx;
    auto data{auth_data_errc(TEK_SC_ERRC_cm_another_auth)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::BeginAuthSessionViaQrRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.BeginAuthSessionViaQR#1");
  auto &device_details{*msg.payload.mutable_device_details()};
  device_details.set_device_friendly_name(device_name);
  device_details.set_platform_type(
      msg_payloads::PlatformType::PLATFORM_TYPE_STEAM_CLIENT);
  device_details.set_os_type(conn.ctx.os_type);
  msg.payload.set_website_id("Client");
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_basvq, cb, timeout_auth)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_auth>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    release_auth_ctx(conn);
    // Report error via callback
    auto data{auth_data_err(std::move(res))};
    cb(&conn, &data, conn.user_data);
  }
}

tek_sc_err
tek_sc_cm_auth_submit_code(tek_sc_cm_client *client,
                           tek_sc_cm_auth_confirmation_type code_type,
                           const char *code) {
  auto &conn{client->conn};
  // Ensure that there is an active auth session
  const auto actx{conn.auth_ctx.load(std::memory_order::acquire)};
  if (!actx) {
    return tsc_err_sub(TEK_SC_ERRC_cm_submit_code,
                       TEK_SC_ERRC_cm_not_connected);
  }
  // Prepare the message
  message<msg_payloads::UpdateAuthSessionWithSteamGuardCodeRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(gen_job_id());
  msg.header.set_target_job_name(
      "Authentication.UpdateAuthSessionWithSteamGuardCode#1");
  msg.payload.set_client_id(actx->client_id.load(std::memory_order::relaxed));
  msg.payload.set_steam_id(actx->steam_id);
  msg.payload.set_code(code);
  switch (code_type) {
  case TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code:
    msg.payload.set_code_type(msg_payloads::GuardType::GUARD_TYPE_DEVICE_CODE);
    break;
  case TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email:
    msg.payload.set_code_type(msg_payloads::GuardType::GUARD_TYPE_EMAIL_CODE);
    break;
  default:
    break;
  }
  // Send the message
  return conn.send_message<TEK_SC_ERRC_cm_submit_code>(std::move(msg));
}

void tek_sc_cm_auth_renew_token(tek_sc_cm_client *client, const char *token,
                                tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is connected
  if (conn.conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data{renew_data_errc(TEK_SC_ERRC_cm_not_connected)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  // Check if the token is valid
  const auto token_info{tek_sc_cm_parse_auth_token(token)};
  if (!token_info.steam_id) {
    auto data{renew_data_errc(TEK_SC_ERRC_cm_token_invalid)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  if (token_info.expires <
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {
    auto data{renew_data_errc(TEK_SC_ERRC_cm_token_expired)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  if (!token_info.renewable) {
    auto data{renew_data_errc(TEK_SC_ERRC_cm_token_not_renewable)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::GenerateAccessTokenForAppRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.GenerateAccessTokenForApp#1");
  msg.payload.set_token(token);
  msg.payload.set_steam_id(token_info.steam_id);
  msg.payload.set_renewal_type(
      msg_payloads::TokenRenewalType::TOKEN_RENEWAL_TYPE_ALLOW);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_gatfa, cb, timeout_renew)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_token_renew>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    auto data{renew_data_err(std::move(res))};
    cb(&conn, &data, conn.user_data);
  }
}

void tek_sc_cm_get_enc_app_ticket(tek_sc_cm_client *client,
                                  tek_sc_cm_data_enc_app_ticket *data,
                                  tek_sc_cm_callback_func *cb,
                                  long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                               TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::RequestEncryptedAppTicketRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_REQUEST_ENCRYPTED_APP_TICKET;
  msg.header.set_source_job_id(job_id);
  msg.payload.set_app_id(data->app_id);
  if (data->data && data->data_size) {
    msg.payload.set_user_data(data->data, data->data_size);
  }
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_reat, cb, timeout_eat, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_enc_app_ticket>(
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
