//===-- cm_auth.cpp - Steam CM client auth subsystem implementation -------===//
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
#include <atomic>
#include <charconv>
#include <cstdint>
#include <libwebsockets.h>
#include <memory>
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
          .confirmation_types = TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
          .url = nullptr,
          .token = nullptr,
          .result = err};
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
  return {.new_token = nullptr, .result = err};
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

/// Handle an authentication session response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_auth(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry = *reinterpret_cast<const msg_await_entry *>(sul);
  auto &client = a_entry.client;
  const auto cb = a_entry.cb;
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Reset auth session fields
  client.auth_client_id.store(0, std::memory_order::relaxed);
  client.auth_request_id.clear();
  client.auth_request_id.shrink_to_fit();
  client.auth_polling_interval = 0;
  client.auth_steam_id = 0;
  client.cred_auth_ctx.reset();
  // Report timeout via callback
  auto data = auth_data_errc(TEK_SC_ERRC_cm_timeout);
  cb(&client, &data, client.user_data);
}

/// Handle a renew token response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_renew(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry = *reinterpret_cast<const msg_await_entry *>(sul);
  auto &client = a_entry.client;
  const auto cb = a_entry.cb;
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  auto data = renew_data_errc(TEK_SC_ERRC_cm_timeout);
  cb(&client, &data, client.user_data);
}

/// Handle an encrypted app ticket response message timeout.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_eat(lws_sorted_usec_list_t *_Nonnull sul) {
  const auto &a_entry = *reinterpret_cast<const msg_await_entry *>(sul);
  auto &client = a_entry.client;
  const auto cb = a_entry.cb;
  const auto data =
      reinterpret_cast<tek_sc_cm_data_enc_app_ticket *>(a_entry.inout_data);
  // Remove the await entry
  client.a_entries_mtx.lock();
  client.a_entries.erase(a_entry.job_id);
  client.a_entries_mtx.unlock();
  // Report timeout via callback
  data->result =
      tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket, TEK_SC_ERRC_cm_timeout);
  cb(&client, data, client.user_data);
}

/// Send an auth session status request.
///
/// @param [in] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void send_status_req(lws_sorted_usec_list_t *_Nonnull sul);

/// Handle "Authentication.BeginAuthSessionViaCredentials#1" response message.
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
static bool handle_basvc(cm_client &client, const MessageHeader &header,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  if (const auto eresult = static_cast<tek_sc_cm_eresult>(header.eresult());
      eresult != TEK_SC_CM_ERESULT_ok) {
    client.auth_client_id.store(0, std::memory_order::relaxed);
    auto data_ap = auth_data_err(err(TEK_SC_ERRC_cm_auth, eresult));
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  msg_payloads::BeginAuthSessionViaCredentialsResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    client.auth_client_id.store(0, std::memory_order::relaxed);
    auto data_ap = auth_data_errc(TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  client.auth_client_id.store(payload.client_id(), std::memory_order::relaxed);
  client.auth_request_id = payload.request_id();
  client.auth_polling_interval = payload.interval() * LWS_US_PER_SEC;
  client.auth_steam_id = payload.steam_id();
  // Schedule the first status request
  client.status_req.reset(new status_request{
      .sul = {.list = {},
              .us = lws_now_usecs() + client.auth_polling_interval,
              .cb = send_status_req,
              .latency_us = 0},
      .client = client,
      .cb = cb});
  lws_sul2_schedule(client.lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                    &client.status_req->sul);
  // Report available confirmation types via callback
  auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_awaiting_confirmation,
                    .confirmation_types = TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
                    .url = nullptr,
                    .token = nullptr,
                    .result = {}};
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
  cb(&client, &data_ap, client.user_data);
  return true;
}

/// Handle "Authentication.BeginAuthSessionViaQR#1" response message.
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
static bool handle_basvq(cm_client &client, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::BeginAuthSessionViaQrResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap = auth_data_errc(TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  client.auth_client_id.store(payload.client_id(), std::memory_order::relaxed);
  client.auth_request_id = payload.request_id();
  client.auth_polling_interval = payload.interval() * LWS_US_PER_SEC;
  // Schedule the first status request
  client.status_req.reset(new status_request{
      .sul = {.list = {},
              .us = lws_now_usecs() + client.auth_polling_interval,
              .cb = send_status_req,
              .latency_us = 0},
      .client = client,
      .cb = cb});
  lws_sul2_schedule(client.lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                    &client.status_req->sul);
  // Report challenge URL via callback
  auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_new_url,
                    .confirmation_types = TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
                    .url = payload.challenge_url().data(),
                    .token = nullptr,
                    .result = {}};
  cb(&client, &data_ap, client.user_data);
  return true;
}

/// Handle "Authentication.GenerateAccessTokenForApp#1" response message.
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
static bool handle_gatfa(cm_client &client, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GenerateAccessTokenForAppResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_renew = renew_data_errc(TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_renew, client.user_data);
    return true;
  }
  tek_sc_cm_data_renew_token data_renew{
      .new_token = payload.has_token() ? payload.token().data() : nullptr,
      .result = tsc_err_ok()};
  cb(&client, &data_renew, client.user_data);
  return true;
}

/// Handle "Authentication.GetPasswordRSAPublicKey#1" response message.
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
static bool handle_gprpk(cm_client &client, const MessageHeader &,
                         const void *_Nonnull data, int size,
                         cb_func *_Nonnull cb, void *) {
  msg_payloads::GetPasswordRsaPublicKeyResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap = auth_data_errc(TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  // For 512-byte input (maximum possible RSA block size)
  char b64_buf[684];
  int b64_len;
  {
    // Build the RSA public key via received parameters
    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> param_build(
        OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!param_build) {
      goto encrypt_err;
    }
    BIGNUM *bn_ptr = nullptr;
    if (!BN_hex2bn(&bn_ptr, payload.modulus().data())) {
      goto encrypt_err;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n(bn_ptr, BN_free);
    if (!OSSL_PARAM_BLD_push_BN(param_build.get(), OSSL_PKEY_PARAM_RSA_N,
                                n.get())) {
      goto encrypt_err;
    }
    if (bn_ptr = nullptr; !BN_hex2bn(&bn_ptr, payload.exponent().data())) {
      goto encrypt_err;
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e(bn_ptr, BN_free);
    if (!OSSL_PARAM_BLD_push_BN(param_build.get(), OSSL_PKEY_PARAM_RSA_E,
                                e.get())) {
      goto encrypt_err;
    }
    std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> param(
        OSSL_PARAM_BLD_to_param(param_build.get()), OSSL_PARAM_free);
    if (!param) {
      goto encrypt_err;
    }
    n.reset();
    e.reset();
    param_build.reset();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
      goto encrypt_err;
    }
    if (EVP_PKEY_fromdata_init(ctx.get()) != 1) {
      goto encrypt_err;
    }
    EVP_PKEY *pkey_ptr = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &pkey_ptr, EVP_PKEY_PUBLIC_KEY,
                          param.get()) != 1) {
      goto encrypt_err;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(pkey_ptr,
                                                             EVP_PKEY_free);
    param.reset();
    ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (!ctx) {
      goto encrypt_err;
    }
    if (EVP_PKEY_encrypt_init_ex(ctx.get(), nullptr) != 1) {
      goto encrypt_err;
    }
    // Encrypt the password with the public key
    unsigned char enc_pass[512]; // Maximum possible block size
    auto enc_pass_len = sizeof enc_pass;
    if (EVP_PKEY_encrypt(ctx.get(), enc_pass, &enc_pass_len,
                         reinterpret_cast<const unsigned char *>(
                             client.cred_auth_ctx->password.data()),
                         client.cred_auth_ctx->password.length()) != 1) {
      goto encrypt_err;
    }
    pkey.reset();
    ctx.reset();
    // Encode encrypted password into a base64 string
    b64_len = tsci_u_base64_encode(enc_pass, enc_pass_len, b64_buf);
    goto encrypt_success;
  } // Password encryption scope
encrypt_err:;
  {
    auto data_ap = auth_data_errc(TEK_SC_ERRC_cm_pass_encryption);
    cb(&client, &data_ap, client.user_data);
    return true;
  }
encrypt_success:;
  const auto job_id = gen_job_id();
  // Prepare the begin auth session request message
  message<msg_payloads::BeginAuthSessionViaCredentialsRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name(
      "Authentication.BeginAuthSessionViaCredentials#1");
  msg.payload.set_account_name(client.cred_auth_ctx->account_name);
  msg.payload.set_encrypted_password(b64_buf, b64_len);
  msg.payload.set_encryption_timestamp(payload.timestamp());
  msg.payload.set_persistence(
      msg_payloads::SessionPersistence::SESSION_PERSISTENCE_PERSISTENT);
  msg.payload.set_website_id("Client");
  auto &device_details = *msg.payload.mutable_device_details();
  device_details.set_device_friendly_name(client.cred_auth_ctx->device_name);
  device_details.set_platform_type(
      msg_payloads::PlatformType::PLATFORM_TYPE_STEAM_CLIENT);
  device_details.set_os_type(client.lib_ctx.os_type);
  const auto timeout_ms = client.cred_auth_ctx->timeout_ms;
  client.cred_auth_ctx.reset();
  // Setup the await entry
  client.a_entries_mtx.lock();
  const auto a_entry_it =
      client.a_entries
          .emplace(
              job_id,
              msg_await_entry{.sul = {.list = {},
                                      .us = timeout_to_deadline(timeout_ms),
                                      .cb = timeout_auth,
                                      .latency_us = 0},
                              .client = client,
                              .job_id = job_id,
                              .proc = handle_basvc,
                              .cb = cb,
                              .inout_data = nullptr})
          .first;
  auto &a_entry = a_entry_it->second;
  client.a_entries_mtx.unlock();
  // Send the request message
  if (const auto res =
          client.send_message<TEK_SC_ERRC_cm_auth>(msg, &a_entry.sul);
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client.a_entries_mtx.lock();
    client.a_entries.erase(a_entry_it);
    client.a_entries_mtx.unlock();
    // Reset auth_client_id to allow restarting the auth session
    client.auth_client_id.store(0, std::memory_order::relaxed);
    // Report error via callback
    auto data_ap = auth_data_err(std::move(res));
    cb(&client, &data_ap, client.user_data);
  }
  return true;
}

/// Handle "Authentication.PollAuthSessionStatus#1" response message.
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
static bool handle_pass(cm_client &client, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *) {
  // Ignore the message if there is no active auth session
  if (!client.auth_client_id.load(std::memory_order::relaxed)) {
    return true;
  }
  msg_payloads::PollAuthSessionStatusResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    auto data_ap = auth_data_errc(TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  if (payload.has_refresh_token()) {
    // End auth session and report received token via callback
    client.auth_client_id.store(0, std::memory_order::relaxed);
    client.auth_request_id.clear();
    client.auth_request_id.shrink_to_fit();
    client.auth_polling_interval = 0;
    client.auth_steam_id = 0;
    auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_completed,
                      .confirmation_types =
                          TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
                      .url = nullptr,
                      .token = payload.refresh_token().data(),
                      .result = tsc_err_ok()};
    cb(&client, &data_ap, client.user_data);
    return true;
  }
  if (payload.has_new_client_id()) {
    client.auth_client_id = payload.new_client_id();
  }
  if (payload.has_new_challenge_url()) {
    // Report new challenge URL via callback
    auth_data data_ap{.status = TEK_SC_CM_AUTH_STATUS_new_url,
                      .confirmation_types =
                          TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
                      .url = payload.new_challenge_url().data(),
                      .token = nullptr,
                      .result = {}};
    cb(&client, &data_ap, client.user_data);
  }
  // Schedule the next status request
  client.status_req.reset(new status_request{
      .sul = {.list = {},
              .us = lws_now_usecs() + client.auth_polling_interval,
              .cb = send_status_req,
              .latency_us = 0},
      .client = client,
      .cb = cb});
  lws_sul2_schedule(client.lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                    &client.status_req->sul);
  return true;
}

/// Handle `EMSG_CLIENT_REQUEST_ENCRYPTED_APP_TICKET_RESPONSE` response message.
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
///    Pointer to the @ref tek_sc_cm_data_enc_app_ticket.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, client, inout_data, __)]]
static bool handle_reat(cm_client &client, const MessageHeader &,
                        const void *_Nonnull data, int size,
                        cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  const auto data_eat =
      reinterpret_cast<tek_sc_cm_data_enc_app_ticket *>(inout_data);
  msg_payloads::RequestEncryptedAppTicketResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_eat->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                                   TEK_SC_ERRC_protobuf_deserialize);
    cb(&client, data_eat, client.user_data);
    return true;
  }
  if (const auto eresult = static_cast<tek_sc_cm_eresult>(payload.eresult());
      eresult != TEK_SC_CM_ERESULT_ok) {
    data_eat->result = err(TEK_SC_ERRC_cm_enc_app_ticket, eresult);
    cb(&client, data_eat, client.user_data);
    return true;
  }
  std::unique_ptr<unsigned char[]> data_buf;
  data_eat->data_size = 0;
  if (payload.has_ticket()) {
    const auto &ticket = payload.ticket();
    data_eat->data_size = ticket.ByteSizeLong();
    data_buf.reset(new unsigned char[data_eat->data_size]);
    if (!ticket.SerializeToArray(data_buf.get(), data_eat->data_size)) {
      data_eat->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                                     TEK_SC_ERRC_protobuf_serialize);
      cb(&client, data_eat, client.user_data);
      return true;
    }
    data_eat->data = data_buf.get();
  } else {
    data_eat->data_size = 0;
    data_eat->data = nullptr;
  }
  data_eat->result = tsc_err_ok();
  //  Report results via callback
  cb(&client, data_eat, client.user_data);
  return true;
}

static void send_status_req(lws_sorted_usec_list_t *sul) {
  auto &status_req = *reinterpret_cast<status_request *>(sul);
  auto &client = status_req.client;
  const auto cb = status_req.cb;
  client.status_req.reset();
  const auto job_id = gen_job_id();
  // Prepare the request message
  message<msg_payloads::PollAuthSessionStatusRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.PollAuthSessionStatus#1");
  msg.payload.set_client_id(client.auth_client_id);
  msg.payload.set_request_id(client.auth_request_id);
  // Setup the await entry
  client.a_entries_mtx.lock();
  const auto a_entry_it =
      client.a_entries
          .emplace(job_id,
                   msg_await_entry{.sul = {.list = {},
                                           .us = lws_now_usecs() +
                                                 client.auth_polling_interval,
                                           .cb = timeout_auth,
                                           .latency_us = 0},
                                   .client = client,
                                   .job_id = job_id,
                                   .proc = handle_pass,
                                   .cb = cb,
                                   .inout_data = nullptr})
          .first;
  auto &a_entry = a_entry_it->second;
  client.a_entries_mtx.unlock();
  // Send the request message
  if (const auto res =
          client.send_message<TEK_SC_ERRC_cm_auth>(msg, &a_entry.sul);
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client.a_entries_mtx.lock();
    client.a_entries.erase(a_entry_it);
    client.a_entries_mtx.unlock();
    // Report error via callback
    auto data = auth_data_err(std::move(res));
    cb(&client, &data, client.user_data);
  }
}

} // namespace

//===-- Public functions --------------------------------------------------===//

extern "C" {

tek_sc_cm_auth_token_info tek_sc_cm_parse_auth_token(const char *token) {
  // This string copy also provides a mutable buffer for in-situ Base64
  //    decoding and JSON parsing
  std::string token_str(token);
  // The token should contain 3 Base64 strings separated by a dot, we need the
  //    second one
  if (std::ranges::count(token_str, '.') != 2) {
    return {};
  }
  const auto start_pos = token_str.find('.') + 1;
  const int json_len = tsci_u_base64_decode(
      &token_str[start_pos], token_str.rfind('.') - start_pos,
      reinterpret_cast<unsigned char *>(token_str.data()));
  token_str[json_len] = '\0'; // Null terminator required for in-situ parsing
  rapidjson::Document doc;
  doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(token_str.data());
  if (doc.HasParseError() || !doc.IsObject()) {
    return {};
  }
  const auto sub = doc.FindMember("sub");
  if (sub == doc.MemberEnd() || !sub->value.IsString()) {
    return {};
  }
  tek_sc_cm_auth_token_info res;
  if (const std::string_view view(sub->value.GetString(),
                                  sub->value.GetStringLength());
      std::from_chars(view.begin(), view.end(), res.steam_id).ec !=
      std::errc{}) {
    return {};
  }
  const auto exp = doc.FindMember("exp");
  if (exp == doc.MemberEnd() || !exp->value.IsUint64()) {
    return {};
  }
  res.expires = exp->value.GetUint64();
  const auto per = doc.FindMember("per");
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
  // Ensure that the client is connected
  if (client->conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data = auth_data_errc(TEK_SC_ERRC_cm_not_connected);
    cb(client, &data, client->user_data);
    return;
  }
  // Report an error if there is already another incomplete auth session
  if (std::uint64_t expected = 0;
      !client->auth_client_id.compare_exchange_strong(
          expected, 1, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    auto data = auth_data_errc(TEK_SC_ERRC_cm_another_auth);
    cb(client, &data, client->user_data);
    return;
  }
  const auto job_id = gen_job_id();
  // Prepare the RSA public key request message
  message<msg_payloads::GetPasswordRsaPublicKeyRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.GetPasswordRSAPublicKey#1");
  msg.payload.set_account_name(account_name);
  // Setup the auth context
  client->cred_auth_ctx = std::make_unique<cred_auth_ctx>(
      device_name, account_name, password, timeout_ms);
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it =
      client->a_entries
          .emplace(
              job_id,
              msg_await_entry{.sul = {.list = {},
                                      .us = timeout_to_deadline(timeout_ms),
                                      .cb = timeout_auth,
                                      .latency_us = 0},
                              .client = *client,
                              .job_id = job_id,
                              .proc = handle_gprpk,
                              .cb = cb,
                              .inout_data = nullptr})
          .first;
  auto &a_entry = a_entry_it->second;
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res =
          client->send_message<TEK_SC_ERRC_cm_auth>(msg, &a_entry.sul);
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Reset the auth context
    client->cred_auth_ctx.reset();
    // Reset auth_client_id to allow restarting the auth session
    client->auth_client_id.store(0, std::memory_order::relaxed);
    // Report error via callback
    auto data = auth_data_err(std::move(res));
    cb(client, &data, client->user_data);
  }
}

void tek_sc_cm_auth_qr(tek_sc_cm_client *client, const char *device_name,
                       tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is connected
  if (client->conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data = auth_data_errc(TEK_SC_ERRC_cm_not_connected);
    cb(client, &data, client->user_data);
    return;
  }
  // Report an error if there is already another incomplete auth session
  if (std::uint64_t expected = 0;
      !client->auth_client_id.compare_exchange_strong(
          expected, 1, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    auto data = auth_data_errc(TEK_SC_ERRC_cm_another_auth);
    cb(client, &data, client->user_data);
    return;
  }
  const auto job_id = gen_job_id();
  // Prepare the request message
  message<msg_payloads::BeginAuthSessionViaQrRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.BeginAuthSessionViaQR#1");
  auto &device_details = *msg.payload.mutable_device_details();
  device_details.set_device_friendly_name(device_name);
  device_details.set_platform_type(
      msg_payloads::PlatformType::PLATFORM_TYPE_STEAM_CLIENT);
  device_details.set_os_type(client->lib_ctx.os_type);
  msg.payload.set_website_id("Client");
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it =
      client->a_entries
          .emplace(
              job_id,
              msg_await_entry{.sul = {.list = {},
                                      .us = timeout_to_deadline(timeout_ms),
                                      .cb = timeout_auth,
                                      .latency_us = 0},
                              .client = *client,
                              .job_id = job_id,
                              .proc = handle_basvq,
                              .cb = cb,
                              .inout_data = nullptr})
          .first;
  auto &a_entry = a_entry_it->second;
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res =
          client->send_message<TEK_SC_ERRC_cm_auth>(msg, &a_entry.sul);
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Reset auth_client_id to allow restarting the auth session
    client->auth_client_id.store(0, std::memory_order::relaxed);
    // Report error via callback
    auto data = auth_data_err(std::move(res));
    cb(client, &data, client->user_data);
  }
}

tek_sc_err
tek_sc_cm_auth_submit_code(tek_sc_cm_client *client,
                           tek_sc_cm_auth_confirmation_type code_type,
                           const char *code) {
  // Ensure that the client is connected
  if (client->conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    return tsc_err_sub(TEK_SC_ERRC_cm_submit_code,
                       TEK_SC_ERRC_cm_not_connected);
  }
  // Prepare the message
  message<msg_payloads::UpdateAuthSessionWithSteamGuardCodeRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(gen_job_id());
  msg.header.set_target_job_name(
      "Authentication.UpdateAuthSessionWithSteamGuardCode#1");
  msg.payload.set_client_id(
      client->auth_client_id.load(std::memory_order::relaxed));
  msg.payload.set_steam_id(client->auth_steam_id);
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
  return client->send_message<TEK_SC_ERRC_cm_submit_code>(msg, nullptr);
}

void tek_sc_cm_auth_renew_token(tek_sc_cm_client *client, const char *token,
                                tek_sc_cm_callback_func *cb, long timeout_ms) {
  // Ensure that the client is connected
  if (client->conn_state.load(std::memory_order::relaxed) <
      conn_state::connected) {
    auto data = renew_data_errc(TEK_SC_ERRC_cm_not_connected);
    cb(client, &data, client->user_data);
    return;
  }
  // Check if the token is valid
  const auto token_info = tek_sc_cm_parse_auth_token(token);
  if (!token_info.steam_id) {
    auto data = renew_data_errc(TEK_SC_ERRC_cm_token_invalid);
    cb(client, &data, client->user_data);
    return;
  }
  if (token_info.expires <
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) {
    auto data = renew_data_errc(TEK_SC_ERRC_cm_token_expired);
    cb(client, &data, client->user_data);
    return;
  }
  if (!token_info.renewable) {
    auto data = renew_data_errc(TEK_SC_ERRC_cm_token_not_renewable);
    cb(client, &data, client->user_data);
    return;
  }
  const auto job_id = gen_job_id();
  // Prepare the request message
  message<msg_payloads::GenerateAccessTokenForAppRequest> msg;
  msg.type = EMsg::EMSG_SERVICE_METHOD_CALL_FROM_CLIENT_NON_AUTHED;
  msg.header.set_source_job_id(job_id);
  msg.header.set_target_job_name("Authentication.GenerateAccessTokenForApp#1");
  msg.payload.set_token(token);
  msg.payload.set_steam_id(0);
  msg.payload.set_renewal_type(
      msg_payloads::TokenRenewalType::TOKEN_RENEWAL_TYPE_ALLOW);
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it =
      client->a_entries
          .emplace(
              job_id,
              msg_await_entry{.sul = {.list = {},
                                      .us = timeout_to_deadline(timeout_ms),
                                      .cb = timeout_renew,
                                      .latency_us = 0},
                              .client = *client,
                              .job_id = job_id,
                              .proc = handle_gatfa,
                              .cb = cb,
                              .inout_data = nullptr})
          .first;
  auto &a_entry = a_entry_it->second;
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res =
          client->send_message<TEK_SC_ERRC_cm_token_renew>(msg, &a_entry.sul);
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    client->a_entries_mtx.lock();
    client->a_entries.erase(a_entry_it);
    client->a_entries_mtx.unlock();
    // Report error via callback
    auto data = renew_data_err(std::move(res));
    cb(client, &data, client->user_data);
  }
}

void tek_sc_cm_get_enc_app_ticket(tek_sc_cm_client *client,
                                  tek_sc_cm_data_enc_app_ticket *data,
                                  tek_sc_cm_callback_func *cb,
                                  long timeout_ms) {
  // Ensure that the client is signed in
  if (client->conn_state.load(std::memory_order::relaxed) !=
      conn_state::signed_in) {
    data->result = tsc_err_sub(TEK_SC_ERRC_cm_enc_app_ticket,
                               TEK_SC_ERRC_cm_not_signed_in);
    cb(client, data, client->user_data);
    return;
  }
  const auto job_id = gen_job_id();
  // Prepare the request message
  message<msg_payloads::RequestEncryptedAppTicketRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_REQUEST_ENCRYPTED_APP_TICKET;
  msg.header.set_source_job_id(job_id);
  msg.payload.set_app_id(data->app_id);
  if (data->data && data->data_size) {
    msg.payload.set_user_data(data->data, data->data_size);
  }
  // Setup the await entry
  client->a_entries_mtx.lock();
  const auto a_entry_it =
      client->a_entries
          .emplace(
              job_id,
              msg_await_entry{.sul = {.list = {},
                                      .us = timeout_to_deadline(timeout_ms),
                                      .cb = timeout_eat,
                                      .latency_us = 0},
                              .client = *client,
                              .job_id = job_id,
                              .proc = handle_reat,
                              .cb = cb,
                              .inout_data = data})
          .first;
  auto &a_entry = a_entry_it->second;
  client->a_entries_mtx.unlock();
  // Send the request message
  if (const auto res = client->send_message<TEK_SC_ERRC_cm_enc_app_ticket>(
          msg, &a_entry.sul);
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
