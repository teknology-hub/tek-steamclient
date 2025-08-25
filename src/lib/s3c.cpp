//===-- s3c.cpp - tek-s3 client interface implementation ------------------===//
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
/// Implementation of tek_sc_s3c_* functions.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/s3c.h"

#include "common/error.h"
#include "config.h"
#include "lib_ctx.hpp"
#include "s3c.hpp"
#include "tek-steamclient/base.h"
#include "utils.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <curl/curl.h>
#include <format>
#include <libwebsockets.h>
#include <limits>
#include <locale>
#include <memory>
#include <mutex>
#include <ranges>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace tek::steamclient::s3c {

namespace {

//===-- Private types -----------------------------------------------------===//

/// Download context for curl.
struct tsc_curl_ctx {
  /// curl easy handle that performs the download.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl =
      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(),
                                                          curl_easy_cleanup);
  /// Buffer storing downloaded content.
  std::string buf;
};

//===-- Private functions -------------------------------------------------===//

static constexpr tek_sc_cm_auth_confirmation_type &
operator|=(tek_sc_cm_auth_confirmation_type &left,
           tek_sc_cm_auth_confirmation_type right) noexcept {
  return left = static_cast<tek_sc_cm_auth_confirmation_type>(
             static_cast<int>(left) | static_cast<int>(right));
}

/// Report authentication session error via callback
///
/// @param [in, out] ctx
///    WebSocket connection context.
/// @param [in] err
///    The error to report.
static void auth_err(ws_ctx &ctx, const tek_sc_err &&err) noexcept {
  tek_sc_cm_data_auth_polling data;
  data.status = TEK_SC_CM_AUTH_STATUS_completed;
  data.result = err;
  ctx.busy.store(false, std::memory_order::relaxed);
  ctx.cb(nullptr, &data, ctx.user_data);
}

/// Handle an authentication session response message timeout.
///
/// @param [in, out] sul
///    Pointer to the scheduling element.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void timeout(lws_sorted_usec_list_t *_Nonnull sul) noexcept {
  auto &ctx = *reinterpret_cast<ws_ctx *>(sul);
  ctx.sul_scheduled = false;
  ctx.result = tsc_err_basic(TEK_SC_ERRC_s3c_ws_timeout);
  lws_set_timeout(ctx.wsi, static_cast<pending_timeout>(1), LWS_TO_KILL_ASYNC);
}

/// curl write data callback for manifest fetching, that copies downloaded data
///    to the context buffer.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk in bytes.
/// @param [in, out] ctx
///    Download context.
/// @return @p size.
[[using gnu: nonnull(1), access(read_only, 1, 3)]]
static std::size_t tsc_curl_write_manifest(const char *_Nonnull buf,
                                           std::size_t, std::size_t size,
                                           tsc_curl_ctx &ctx) {
  if (ctx.buf.empty()) {
    // This block is called only once, on first write
    // Get content length to do initial allocation
    if (curl_off_t content_len;
        curl_easy_getinfo(ctx.curl.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                          &content_len) == CURLE_OK &&
        content_len >= 0) {
      ctx.buf.reserve(content_len);
    }
  }
  ctx.buf.append(buf, size);
  return size;
}

/// curl write data callback for manifest request code fetching, that copies
///    curl data to specified stack buffer.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content.
/// @param size
///    Size of the content in bytes.
/// @param [out] out_buf
///    Pointer to the stack buffer that should receive the content.
/// @return @p size, or `CURL_WRITEFUNC_ERROR` on error.
[[using gnu: nonnull(1, 4), access(read_only, 1, 3), access(write_only, 4, 3)]]
static std::size_t tsc_curl_write_mrc(const char *_Nonnull buf, std::size_t,
                                      std::size_t size,
                                      char out_buf[_Nonnull 20]) {
  if (size > 20) {
    return CURL_WRITEFUNC_ERROR;
  }
  std::ranges::copy_n(buf, size, out_buf);
  return size;
}

/// Process a libwebsockets protocol callback.
///
/// @param wsi
///    Pointer to the WebSocket instance that emitted the callback.
/// @param reason
///    Reason for the callback.
/// @param user
///    For wsi-scoped callbacks, pointer to the associated CM client instance.
/// @param [in] in
///    Pointer to the data associated with the callback.
/// @param len
///    Size of the data pointed to by @p in, in bytes.
/// @return `0` on success, or a non-zero value to close connection.
[[gnu::access(read_only, 4, 5)]]
static int tsc_lws_cb(lws *_Nullable wsi, lws_callback_reasons reason,
                      void *_Nullable user, void *_Nullable in,
                      std::size_t len) {
  switch (reason) {
  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(user);
    auto res = tsc_err_basic(TEK_SC_ERRC_s3c_ws_connect);
    const auto url = std::format(
        std::locale::classic(), "{}://{}:{}{}",
        lib_ctx.s3_auth_ctx.use_tls ? "wss" : "ws", lib_ctx.s3_auth_ctx.host,
        lib_ctx.s3_auth_ctx.port, lib_ctx.s3_auth_ctx.path);
    curl_free(lib_ctx.s3_auth_ctx.host);
    curl_free(lib_ctx.s3_auth_ctx.path);
    const auto url_buf =
        reinterpret_cast<char *>(std::malloc(url.length() + 1));
    if (url_buf) {
      std::ranges::move(url.begin(), url.end() + 1, url_buf);
    }
    res.uri = url_buf;
    auth_err(lib_ctx.s3_auth_ctx, std::move(res));
    return 0;
  }
  case LWS_CALLBACK_CLIENT_ESTABLISHED: {
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(user);
    curl_free(lib_ctx.s3_auth_ctx.host);
    curl_free(lib_ctx.s3_auth_ctx.path);
    lib_ctx.s3_auth_ctx.pending.store(pending_msg_type::init,
                                      std::memory_order::relaxed);
    lib_ctx.s3_auth_ctx.wsi = wsi;
    lws_callback_on_writable(wsi);
    return 0;
  }
  case LWS_CALLBACK_CLIENT_RECEIVE: {
    if (lws_frame_is_binary(wsi)) {
      break;
    }
    if (lws_remaining_packet_payload(wsi) || !lws_is_final_fragment(wsi)) {
      // Incoming messages over 4 KiB would mean that something is really wrong
      //    with the server
      return 1;
    }
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(user);
    const auto msg = reinterpret_cast<char *>(in);
    msg[len] = '\0';
    rapidjson::Document doc;
    doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(msg);
    if (doc.HasParseError() || !doc.IsObject()) {
      return 1;
    }
    const auto error = doc.FindMember("error");
    if (error != doc.MemberEnd() && error->value.IsObject()) {
      lib_ctx.s3_auth_ctx.result = {};
      const auto &error_obj = error->value.GetObject();
      const auto type = error_obj.FindMember("type");
      if (type == error_obj.MemberEnd() || !type->value.IsInt()) {
        return 1;
      }
      lib_ctx.s3_auth_ctx.result.type =
          static_cast<tek_sc_err_type>(type->value.GetInt());
      const auto primary = error_obj.FindMember("primary");
      if (primary == error_obj.MemberEnd() || !primary->value.IsInt()) {
        return 1;
      }
      lib_ctx.s3_auth_ctx.result.primary =
          static_cast<tek_sc_errc>(primary->value.GetInt());
      if (lib_ctx.s3_auth_ctx.result.type != TEK_SC_ERR_TYPE_basic) {
        const auto auxiliary = error_obj.FindMember("auxiliary");
        if (auxiliary == error_obj.MemberEnd() || !auxiliary->value.IsInt()) {
          return 1;
        }
        lib_ctx.s3_auth_ctx.result.auxiliary = auxiliary->value.GetInt();
      }
      return 1;
    }
    const auto renewable = doc.FindMember("renewable");
    if (renewable != doc.MemberEnd() && renewable->value.IsBool()) {
      lib_ctx.s3_auth_ctx.result = tsc_err_ok();
      if (!renewable->value.GetBool()) {
        const auto expires = doc.FindMember("expires");
        if (expires == doc.MemberEnd() || !expires->value.IsUint64()) {
          return 1;
        }
        const auto exp_time = expires->value.GetUint64();
        lib_ctx.s3_auth_ctx.result.auxiliary =
            static_cast<int>(exp_time & std::numeric_limits<unsigned>::max());
        lib_ctx.s3_auth_ctx.result.extra = static_cast<int>(
            (exp_time >> 32) & std::numeric_limits<unsigned>::max());
      }
      return 1;
    }
    const auto url = doc.FindMember("url");
    if (url != doc.MemberEnd() && url->value.IsString()) {
      tek_sc_cm_data_auth_polling data;
      data.status = TEK_SC_CM_AUTH_STATUS_new_url;
      data.url = url->value.GetString();
      lib_ctx.s3_auth_ctx.cb(nullptr, &data, lib_ctx.s3_auth_ctx.user_data);
      break;
    }
    const auto confirmations = doc.FindMember("confirmations");
    if (confirmations != doc.MemberEnd() && confirmations->value.IsArray()) {
      tek_sc_cm_data_auth_polling data;
      data.status = TEK_SC_CM_AUTH_STATUS_awaiting_confirmation;
      data.confirmation_types = TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none;
      for (const auto &type : confirmations->value.GetArray()) {
        if (!type.IsString()) {
          continue;
        }
        if (const std::string_view view(type.GetString(),
                                        type.GetStringLength());
            view == "device") {
          data.confirmation_types |= TEK_SC_CM_AUTH_CONFIRMATION_TYPE_device;
        } else if (view == "guard_code") {
          data.confirmation_types |=
              TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code;
        } else if (view == "email") {
          data.confirmation_types |= TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email;
        }
      }
      lib_ctx.s3_auth_ctx.cb(nullptr, &data, lib_ctx.s3_auth_ctx.user_data);
      break;
    }
    break;
  }
  case LWS_CALLBACK_CLIENT_WRITEABLE: {
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(user);
    switch (lib_ctx.s3_auth_ctx.pending.exchange(pending_msg_type::none,
                                                 std::memory_order::acquire)) {
    case pending_msg_type::init: {
      rapidjson::StringBuffer buf;
      buf.Push(LWS_PRE);
      rapidjson::Writer writer(buf);
      writer.StartObject();
      std::string_view str = "type";
      writer.Key(str.data(), str.length());
      switch (lib_ctx.s3_auth_ctx.type) {
      case auth_type::credentials:
        str = "credentials";
        writer.String(str.data(), str.length());
        str = "account_name";
        writer.Key(str.data(), str.length());
        writer.String(lib_ctx.s3_auth_ctx.account_name.data(),
                      lib_ctx.s3_auth_ctx.account_name.length());
        lib_ctx.s3_auth_ctx.account_name = {};
        str = "password";
        writer.Key(str.data(), str.length());
        writer.String(lib_ctx.s3_auth_ctx.password.data(),
                      lib_ctx.s3_auth_ctx.password.length());
        lib_ctx.s3_auth_ctx.password = {};
        break;
      case auth_type::qr:
        str = "qr";
        writer.String(str.data(), str.length());
      }
      writer.EndObject();
      if (const int len = buf.GetSize() - LWS_PRE;
          lws_write(wsi,
                    reinterpret_cast<unsigned char *>(
                        const_cast<char *>(buf.GetString() + LWS_PRE)),
                    len, LWS_WRITE_TEXT) < len) {
        return 1;
      }
      lib_ctx.s3_auth_ctx.sul.us =
          lws_now_usecs() + lib_ctx.s3_auth_ctx.timeout_ms * LWS_US_PER_MS;
      lib_ctx.s3_auth_ctx.sul.cb = timeout;
      lws_sul2_schedule(lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                        &lib_ctx.s3_auth_ctx.sul);
      lib_ctx.s3_auth_ctx.sul_scheduled = true;
      return 0;
    } // case pending_msg_type::init
    case pending_msg_type::code: {
      rapidjson::StringBuffer buf;
      buf.Push(LWS_PRE);
      rapidjson::Writer writer(buf);
      writer.StartObject();
      std::string_view str = "type";
      writer.Key(str.data(), str.length());
      switch (lib_ctx.s3_auth_ctx.code_type) {
      case TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code:
        str = "guard_code";
        writer.String(str.data(), str.length());
        break;
      case TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email:
        str = "email";
        writer.String(str.data(), str.length());
        break;
      default:
        str = "unsupported";
        writer.String(str.data(), str.length());
      }
      str = "code";
      writer.Key(str.data(), str.length());
      writer.String(lib_ctx.s3_auth_ctx.code.data(),
                    lib_ctx.s3_auth_ctx.code.length());
      lib_ctx.s3_auth_ctx.code = {};
      writer.EndObject();
      if (const int len = buf.GetSize() - LWS_PRE;
          lws_write(wsi,
                    reinterpret_cast<unsigned char *>(
                        const_cast<char *>(buf.GetString() + LWS_PRE)),
                    len, LWS_WRITE_TEXT) < len) {
        return 1;
      }
      return 0;
    } // case pending_msg_type::code
    default:
      break;
    } // switch (lib_ctx.s3_auth_ctx.pending previous value)
    break;
  } // case LWS_CALLBACK_CLIENT_WRITEABLE
  case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
    if (!wsi) {
      break;
    }
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(
        lws_context_user(lws_get_context(wsi)));
    if (!lib_ctx.s3_auth_ctx.busy.load(std::memory_order::relaxed)) {
      break;
    }
    switch (lib_ctx.s3_auth_ctx.pending.load(std::memory_order::relaxed)) {
    case pending_msg_type::code:
      lws_callback_on_writable(lib_ctx.s3_auth_ctx.wsi);
      break;
    case pending_msg_type::disconnect:
      lib_ctx.s3_auth_ctx.result = tsc_err_basic(TEK_SC_ERRC_paused);
      lws_set_timeout(lib_ctx.s3_auth_ctx.wsi, static_cast<pending_timeout>(1),
                      LWS_TO_KILL_ASYNC);
      break;
    default:
      break;
    }
    if (bool expected = true;
        !lib_ctx.s3_auth_ctx.ready.compare_exchange_strong(
            expected, false, std::memory_order::acquire,
            std::memory_order::relaxed)) {
      break;
    }
    // Start connecting
    lws_client_connect_info info{};
    info.context = lib_ctx.lws_ctx;
    info.address = lib_ctx.s3_auth_ctx.host;
    info.port = lib_ctx.s3_auth_ctx.port;
    info.ssl_connection = lib_ctx.s3_auth_ctx.use_tls ? LCCSCF_USE_SSL : 0;
    info.path = lib_ctx.s3_auth_ctx.path;
    info.host = info.address;
    info.origin = info.address;
    info.protocol = "tek-s3";
    info.userdata = &lib_ctx;
    if (!lws_client_connect_via_info(&info) &&
        lib_ctx.s3_auth_ctx.busy.load(std::memory_order::relaxed)) {
      auto res = tsc_err_basic(TEK_SC_ERRC_s3c_ws_connect);
      const auto url = std::format(
          std::locale::classic(), "{}://{}:{}{}",
          lib_ctx.s3_auth_ctx.use_tls ? "wss" : "ws", lib_ctx.s3_auth_ctx.host,
          lib_ctx.s3_auth_ctx.port, lib_ctx.s3_auth_ctx.path);
      curl_free(lib_ctx.s3_auth_ctx.host);
      curl_free(lib_ctx.s3_auth_ctx.path);
      const auto url_buf =
          reinterpret_cast<char *>(std::malloc(url.length() + 1));
      if (url_buf) {
        std::ranges::move(url.begin(), url.end() + 1, url_buf);
      }
      res.uri = url_buf;
      auth_err(lib_ctx.s3_auth_ctx, std::move(res));
    }
    break;
  } // case LWS_CALLBACK_EVENT_WAIT_CANCELLED
  case LWS_CALLBACK_CLIENT_CLOSED: {
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(user);
    if (lib_ctx.s3_auth_ctx.sul_scheduled) {
      lib_ctx.s3_auth_ctx.sul_scheduled = false;
      lws_sul_cancel(&lib_ctx.s3_auth_ctx.sul);
    }
    tek_sc_cm_data_auth_polling data;
    data.status = TEK_SC_CM_AUTH_STATUS_completed;
    data.result = lib_ctx.s3_auth_ctx.result;
    lib_ctx.s3_auth_ctx.busy.store(false, std::memory_order::relaxed);
    lib_ctx.s3_auth_ctx.cb(nullptr, &data, lib_ctx.s3_auth_ctx.user_data);
    return 0;
  }
  default:
    break;
  } // switch (reason)
  return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/// Begin an authentication session to submit a Steam account to a tek-s3
/// server.
///
/// @param [in, out] lib_ctx
///    Library context that will host the WebSocket connection.
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3".
/// @param timeout_ms
///    The maximum amount of time the session is allowed to take, in
///    milliseconds.
[[using gnu: nonnull(2), access(read_only, 2), null_terminated_string_arg(2)]]
static void begin_auth(tek_sc_lib_ctx &lib_ctx, const char *_Nonnull url,
                       long timeout_ms) {
  auto &auth_ctx = lib_ctx.s3_auth_ctx;
  const std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> curlu(
      curl_url(), curl_url_cleanup);
  if (!curlu) {
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_curl_url));
    return;
  }
  curl_url_set(curlu.get(), CURLUPART_URL,
               (std::string(url).append("/signin")).data(), 0);
  char *part;
  if (curl_url_get(curlu.get(), CURLUPART_SCHEME, &part, 0) != CURLUE_OK) {
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_invalid_url));
    return;
  }
  auth_ctx.use_tls = std::string_view(part) == "https";
  curl_free(part);
  if (curl_url_get(curlu.get(), CURLUPART_PORT, &part, CURLU_DEFAULT_PORT) !=
      CURLUE_OK) {
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_invalid_url));
    return;
  }
  const std::string_view part_view(part);
  const bool success =
      std::from_chars(part_view.begin(), part_view.end(), auth_ctx.port).ec ==
      std::errc{};
  curl_free(part);
  if (!success) {
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_invalid_url));
    return;
  }
  auth_ctx.pending.store(pending_msg_type::none, std::memory_order::relaxed);
  if (curl_url_get(curlu.get(), CURLUPART_HOST, &auth_ctx.host, 0) !=
      CURLUE_OK) {
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_invalid_url));
    return;
  }
  if (curl_url_get(curlu.get(), CURLUPART_PATH, &auth_ctx.path, 0) !=
      CURLUE_OK) {
    curl_free(auth_ctx.host);
    auth_err(auth_ctx, tsc_err_basic(TEK_SC_ERRC_invalid_url));
    return;
  }
  auth_ctx.timeout_ms = timeout_ms;
  auth_ctx.result = tsc_err_basic(TEK_SC_ERRC_s3c_ws_disconnect);
  auth_ctx.ready.store(true, std::memory_order::release);
  lws_cancel_service(lib_ctx.lws_ctx);
}

} // namespace

//===-- Internal variable -------------------------------------------------===//

constexpr lws_protocols protocol{.name = "tek-s3",
                                 .callback = tsc_lws_cb,
                                 .per_session_data_size = 0,
                                 .rx_buffer_size = 4096,
                                 .id = 0,
                                 .user = nullptr,
                                 .tx_packet_size = 4096};

//===-- Public functions --------------------------------------------------===//

extern "C" {

tek_sc_err tek_sc_s3c_fetch_manifest(tek_sc_lib_ctx *lib_ctx, const char *url,
                                     long timeout_ms) {
  tsc_curl_ctx curl_ctx;
  if (!curl_ctx.curl) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_manifest, TEK_SC_ERRC_curle_init);
  }
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMECONDITION,
                   CURL_TIMECOND_IFMODSINCE);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_FILETIME, 1L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_HTTP_VERSION,
                   CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEDATA, &curl_ctx);
  const std::string_view url_view(url);
  const auto req_url = std::string(url_view).append("/manifest");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEFUNCTION,
                   tsc_curl_write_manifest);
  lib_ctx->s3_mtx.lock_shared();
  const auto srv =
      std::ranges::find(lib_ctx->s3_servers, url_view, &server::url);
  const curl_off_t timestamp = srv == lib_ctx->s3_servers.end()
                                   ? 0
                                   : static_cast<curl_off_t>(srv->timestamp);
  lib_ctx->s3_mtx.unlock_shared();
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMEVALUE_LARGE, timestamp);
  auto res = curl_easy_perform(curl_ctx.curl.get());
  if (res == CURLE_COULDNT_RESOLVE_HOST) {
    curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_DNS_SERVERS, "1.1.1.1,1.0.0.1");
    res = curl_easy_perform(curl_ctx.curl.get());
  }
  if (res != CURLE_OK) {
    const auto url_buf =
        reinterpret_cast<char *>(std::malloc(req_url.length() + 1));
    if (url_buf) {
      std::ranges::move(req_url.begin(), req_url.end() + 1, url_buf);
    }
    long status = 0;
    if (res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_RESPONSE_CODE, &status);
    }
    return {.type = TEK_SC_ERR_TYPE_curle,
            .primary = TEK_SC_ERRC_s3c_manifest,
            .auxiliary = res,
            .extra = static_cast<int>(status),
            .uri = url_buf};
  }
  long cond_unmet = 0;
  curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_CONDITION_UNMET, &cond_unmet);
  if (cond_unmet) {
    return tsc_err_ok();
  }
  curl_off_t last_mod;
  curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_FILETIME_T, &last_mod);
  curl_ctx.curl.reset();
  // Parse downloaded data
  rapidjson::Document doc;
  doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(curl_ctx.buf.data());
  if (doc.HasParseError() || !doc.IsObject()) {
    goto json_parse_err;
  }
  lib_ctx->dirty_flags.fetch_or(static_cast<int>(dirty_flag::s3),
                                std::memory_order::relaxed);
  {
    std::unique_lock lock(lib_ctx->s3_mtx);
    const auto srv_it =
        std::ranges::find(lib_ctx->s3_servers, url_view, &server::url);
    if (srv_it != lib_ctx->s3_servers.end()) {
      srv_it->timestamp = static_cast<std::time_t>(last_mod);
      // Clear all server references, in case some apps/depots have been removed
      //    from the manifest
      for (auto addr = std::to_address(srv_it);
           auto &app : lib_ctx->s3_cache | std::views::values) {
        for (auto &depot : app | std::views::values) {
          if (std::erase(depot.servers, addr)) {
            depot.it = depot.servers.cbegin();
          }
        }
        std::erase_if(app, [](const auto &depot) {
          return depot.second.servers.empty();
        });
      }
      std::erase_if(lib_ctx->s3_cache,
                    [](const auto &app) { return app.second.empty(); });
    }
    const auto srv =
        srv_it == lib_ctx->s3_servers.end()
            ? &lib_ctx->s3_servers.emplace_back(
                  std::string(url_view), static_cast<std::time_t>(last_mod))
            : std::to_address(srv_it);
    const auto apps = doc.FindMember("apps");
    if (apps == doc.MemberEnd() || !apps->value.IsObject()) {
      goto json_parse_err;
    }
    const auto depot_keys = doc.FindMember("depot_keys");
    if (depot_keys == doc.MemberEnd() || !depot_keys->value.IsObject()) {
      goto json_parse_err;
    }
    for (const auto &[id, value] : apps->value.GetObject()) {
      if (!value.IsObject()) {
        continue;
      }
      std::uint32_t app_id;
      if (const std::string_view view(id.GetString(), id.GetStringLength());
          std::from_chars(view.begin(), view.end(), app_id).ec != std::errc{}) {
        continue;
      }
      const auto depots = value.FindMember("depots");
      if (depots == value.MemberEnd() || !depots->value.IsArray()) {
        continue;
      }
      for (auto &cache_app = lib_ctx->s3_cache[app_id];
           const auto &depot : depots->value.GetArray()) {
        if (!depot.IsUint()) {
          continue;
        }
        auto &cache_depot =
            cache_app[static_cast<std::uint32_t>(depot.GetUint())];
        cache_depot.servers.emplace_back(srv);
        cache_depot.it = cache_depot.servers.cbegin();
      }
    }
    lock.unlock();
    for (const std::scoped_lock lock(lib_ctx->depot_keys_mtx);
         const auto &[id, value] : depot_keys->value.GetObject()) {
      if (!value.IsString()) {
        continue;
      }
      if (value.GetStringLength() != 44) {
        continue;
      }
      std::uint32_t depot_id;
      if (const std::string_view view(id.GetString(), id.GetStringLength());
          std::from_chars(view.begin(), view.end(), depot_id).ec !=
          std::errc{}) {
        continue;
      }
      const auto [it, emplaced] = lib_ctx->depot_keys.try_emplace(depot_id);
      if (emplaced) {
        lib_ctx->dirty_flags.fetch_or(static_cast<int>(dirty_flag::depot_keys),
                                      std::memory_order::relaxed);
      }
      tsci_u_base64_decode(value.GetString(), 44, it->second);
    }
  } // JSON parsing scope
  return tsc_err_ok();
json_parse_err:
  return tsc_err_sub(TEK_SC_ERRC_s3c_manifest, TEK_SC_ERRC_json_parse);
}

const char *tek_sc_s3c_get_srv_for_mrc(tek_sc_lib_ctx *lib_ctx, uint32_t app_id,
                                       uint32_t depot_id) {
  const std::shared_lock lock(lib_ctx->s3_mtx);
  const auto app_it = lib_ctx->s3_cache.find(app_id);
  if (app_it == lib_ctx->s3_cache.end()) {
    return nullptr;
  }
  const auto depot_it = app_it->second.find(depot_id);
  if (depot_it == app_it->second.end()) {
    return nullptr;
  }
  auto &entry = depot_it->second;
  if (entry.servers.empty()) {
    return nullptr;
  }
  const auto res = (*entry.it)->url.data();
  if (++entry.it == entry.servers.cend()) {
    entry.it = entry.servers.cbegin();
  }
  return res;
}

void tek_sc_s3c_get_mrc(const char *url, long timeout_ms,
                        tek_sc_cm_data_mrc *data) {
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl =
      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(),
                                                          curl_easy_cleanup);
  if (!curl) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_curle_init);
    return;
  }
  curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  char buf[20];
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, buf);
  const auto req_url = std::format(
      std::locale::classic(), "{}/mrc?app_id={}&depot_id={}&manifest_id={}",
      url, data->app_id, data->depot_id, data->manifest_id);
  curl_easy_setopt(curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write_mrc);
  auto res = curl_easy_perform(curl.get());
  if (res == CURLE_COULDNT_RESOLVE_HOST) {
    curl_easy_setopt(curl.get(), CURLOPT_DNS_SERVERS, "1.1.1.1,1.0.0.1");
    res = curl_easy_perform(curl.get());
  }
  if (res != CURLE_OK) {
    const auto url_buf =
        reinterpret_cast<char *>(std::malloc(req_url.length() + 1));
    if (url_buf) {
      std::ranges::move(req_url.begin(), req_url.end() + 1, url_buf);
    }
    long status = 0;
    if (res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    }
    data->result = {.type = TEK_SC_ERR_TYPE_curle,
                    .primary = TEK_SC_ERRC_s3c_mrc,
                    .auxiliary = res,
                    .extra = static_cast<int>(status),
                    .uri = url_buf};
    return;
  }
  curl_off_t content_len;
  if (curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                        &content_len) != CURLE_OK ||
      content_len <= 0 || content_len > 20) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_invalid_data);
    return;
  };
  curl.reset();
  if (const std::string_view mrc(buf, content_len);
      std::from_chars(mrc.begin(), mrc.end(), data->request_code).ec !=
      std::errc{}) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_invalid_data);
    return;
  }
  data->result = tsc_err_ok();
}

void tek_sc_s3c_auth_credentials(tek_sc_lib_ctx *lib_ctx, const char *url,
                                 const char *account_name, const char *password,
                                 tek_sc_cm_callback_func *cb, void *user_data,
                                 long timeout_ms) {
  auto &auth_ctx = lib_ctx->s3_auth_ctx;
  if (bool expected = false; !auth_ctx.busy.compare_exchange_strong(
          expected, true, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    tek_sc_cm_data_auth_polling data;
    data.status = TEK_SC_CM_AUTH_STATUS_completed;
    data.result = tsc_err_basic(TEK_SC_ERRC_cm_another_auth);
    cb(nullptr, &data, user_data);
    return;
  }
  auth_ctx.type = auth_type::credentials;
  auth_ctx.account_name = account_name;
  auth_ctx.password = password;
  auth_ctx.cb = cb;
  auth_ctx.user_data = user_data;
  begin_auth(*lib_ctx, url, timeout_ms);
}

void tek_sc_s3c_auth_qr(tek_sc_lib_ctx *lib_ctx, const char *url,
                        tek_sc_cm_callback_func *cb, void *user_data,
                        long timeout_ms) {
  auto &auth_ctx = lib_ctx->s3_auth_ctx;
  if (bool expected = false; !auth_ctx.busy.compare_exchange_strong(
          expected, true, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    tek_sc_cm_data_auth_polling data;
    data.status = TEK_SC_CM_AUTH_STATUS_completed;
    data.result = tsc_err_basic(TEK_SC_ERRC_cm_another_auth);
    cb(nullptr, &data, user_data);
    return;
  }
  auth_ctx.type = auth_type::qr;
  auth_ctx.cb = cb;
  auth_ctx.user_data = user_data;
  begin_auth(*lib_ctx, url, timeout_ms);
}

void tek_sc_s3c_auth_submit_code(tek_sc_lib_ctx *lib_ctx,
                                 tek_sc_cm_auth_confirmation_type code_type,
                                 const char *code) {
  auto &auth_ctx = lib_ctx->s3_auth_ctx;
  if (!auth_ctx.busy.load(std::memory_order::relaxed)) {
    return;
  }
  auth_ctx.code = code;
  auth_ctx.code_type = code_type;
  auth_ctx.pending.store(pending_msg_type::code, std::memory_order::release);
  lws_cancel_service(lib_ctx->lws_ctx);
}

void tek_sc_s3c_auth_cancel(tek_sc_lib_ctx *lib_ctx) {
  auto &auth_ctx = lib_ctx->s3_auth_ctx;
  if (!auth_ctx.busy.load(std::memory_order::relaxed)) {
    return;
  }
  auth_ctx.pending.store(pending_msg_type::disconnect,
                         std::memory_order::relaxed);
  lws_cancel_service(lib_ctx->lws_ctx);
}

} // extern "C"

} // namespace tek::steamclient::s3c
