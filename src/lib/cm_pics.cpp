//===-- cm_pics.cpp - Steam CM client PICS subsystem implementation -------===//
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
/// Implementation of Steam CM client functions working with Product Info Cache
///    Server (PICS).
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "config.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/license_list.pb.h"
#include "tek/steamclient/cm/msg_payloads/pics_access_token.pb.h"
#include "tek/steamclient/cm/msg_payloads/pics_changes_since.pb.h"
#include "tek/steamclient/cm/msg_payloads/pics_product_info.pb.h"
#include "utils.h"
#include "zlib_api.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <format>
#include <functional>
#include <locale>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <uv.h>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private type ------------------------------------------------------===//

/// Download context for curl.
struct tsc_curl_ctx {
  /// curl easy handle that performs the download.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  /// URL being downloaded.
  std::string url;
  /// Buffer storing downloaded content.
  std::vector<unsigned char> buf;
  /// Pointer to the corresponding product info entry.
  tek_sc_cm_pics_entry *_Nonnull entry;
};

//===-- Private functions -------------------------------------------------===//

/// Create a @ref tek_sc_cm_data_licenses for an error code.
///
/// @param errc
///    The error code indicating failed operation.
/// @return A @ref tek_sc_cm_data_licenses for specified error code.
static constexpr tek_sc_cm_data_lics lic_data_errc(tek_sc_errc errc) noexcept {
  return {.entries{},
          .num_entries{},
          .result{tsc_err_sub(TEK_SC_ERRC_cm_licenses, errc)}};
}

/// Create a @ref tek_sc_err for a libcurl-multi error code.
///
/// @param errc
///    The libcurl-multi error code to build error object for.
/// @return A @ref tek_sc_err for specified error code.
static constexpr tek_sc_err pi_err_curlm(CURLMcode errc) noexcept {
  return {.type = TEK_SC_ERR_TYPE_curlm,
          .primary = TEK_SC_ERRC_cm_product_info,
          .auxiliary = errc,
          .extra{},
          .uri{}};
}

/// curl write data callback that copies downloaded data to the context
/// buffer.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk, in bytes.
/// @param [in, out] ctx
///    Download context.
/// @return @p size, or `CURL_WRITEFUNC_ERROR` on error.
[[using gnu: nonnull(1), access(read_only, 1, 3)]]
static std::size_t tsc_curl_write(const unsigned char *_Nonnull buf,
                                  std::size_t, std::size_t size,
                                  tsc_curl_ctx &ctx) {
  if (ctx.buf.empty()) {
    // This branch is executed only once, on first write
    // Get content length to allocate the buffer
    if (curl_off_t content_len;
        curl_easy_getinfo(ctx.curl.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                          &content_len) == CURLE_OK &&
        content_len >= 0) {
      ctx.buf.reserve(content_len);
    }
  }
  ctx.buf.insert(ctx.buf.end(), buf, &buf[size]);
  return size;
}

/// Handle a licenses message timeout.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void timeout_lics(uv_timer_t *_Nonnull timer) {
  auto &entry{*reinterpret_cast<await_entry *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(timer)))};
  auto &conn{entry.conn};
  uv_close(reinterpret_cast<uv_handle_t *>(timer), [](auto timer) {
    auto &entry{*reinterpret_cast<await_entry *>(uv_handle_get_data(timer))};
    auto &conn{entry.conn};
    {
      const std::scoped_lock lock{conn.lics_mtx};
      for (auto it{conn.lics_a_entries.cbefore_begin()};;) {
        const auto prev_it{it++};
        if (it == conn.lics_a_entries.cend()) {
          break;
        }
        if (std::to_address(it) == &entry) {
          conn.lics_a_entries.erase_after(prev_it);
          break;
        }
      }
    }
    if (!--conn.ref_count) {
      if (conn.delete_pending.load(std::memory_order::relaxed)) {
        delete &conn;
      } else {
        conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
      }
    }
  });
  auto data{lic_data_errc(TEK_SC_ERRC_cm_timeout)};
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle a PICS access token response message timeout.
static void timeout_pics_at(cm_conn &conn, msg_await_entry &entry) {
  reinterpret_cast<tek_sc_cm_data_pics *>(entry.inout_data)->result =
      tsc_err_sub(TEK_SC_ERRC_cm_access_token, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, entry.inout_data, conn.user_data);
}

/// Handle a PICS changes since response message timeout.
static void timeout_pics_cs(cm_conn &conn, msg_await_entry &entry) {
  tek_sc_cm_data_pics_changes data;
  data.result = tsc_err_sub(TEK_SC_ERRC_cm_changes, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, &data, conn.user_data);
}

/// Handle a PICS product info response message timeout.
static void timeout_pics_pi(cm_conn &conn, msg_await_entry &entry) {
  reinterpret_cast<tek_sc_cm_data_pics *>(entry.inout_data)->result =
      tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_cm_timeout);
  entry.cb(&conn, entry.inout_data, conn.user_data);
}

/// Handle `EMSG_CLIENT_PICS_ACCESS_TOKEN_RESPONSE` response message.
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
///    Pointer to the @ref tek_sc_cm_data_pics.
/// @return `true`.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_pat(cm_conn &conn, const MessageHeader &,
                       const void *_Nonnull data, int size,
                       cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_pics{*reinterpret_cast<tek_sc_cm_data_pics *>(inout_data)};
  msg_payloads::PicsAccessTokenResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_pics.result = tsc_err_sub(TEK_SC_ERRC_cm_access_token,
                                   TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_pics, conn.user_data);
    return true;
  }
  // Process application tokens
  const std::span apps{data_pics.app_entries,
                       static_cast<std::size_t>(data_pics.num_app_entries)};
  for (const auto &app_token : payload.app_tokens()) {
    if (app_token.access_token()) {
      // Store the token into the cache
      tek_sc_lib_add_pics_at(&conn.ctx, app_token.app_id(),
                             app_token.access_token());
    }
    const auto app{
        std::ranges::find(apps, app_token.app_id(), &tek_sc_cm_pics_entry::id)};
    if (app == apps.end()) {
      continue;
    }
    app->access_token = app_token.access_token();
    app->result = tsc_err_ok();
  }
  for (auto app_id : payload.denied_apps()) {
    const auto app{std::ranges::find(apps, app_id, &tek_sc_cm_pics_entry::id)};
    if (app != apps.end()) {
      app->result = tsc_err_sub(TEK_SC_ERRC_cm_access_token,
                                TEK_SC_ERRC_cm_access_token_denied);
    }
  }
  // Process package tokens
  const std::span packages{
      data_pics.package_entries,
      static_cast<std::size_t>(data_pics.num_package_entries)};
  for (const auto &package_token : payload.package_tokens()) {
    const auto package{std::ranges::find(packages, package_token.package_id(),
                                         &tek_sc_cm_pics_entry::id)};
    if (package == packages.end()) {
      continue;
    }
    package->access_token = package_token.access_token();
    package->result = tsc_err_ok();
  }
  for (auto package_id : payload.denied_packages()) {
    const auto package{
        std::ranges::find(packages, package_id, &tek_sc_cm_pics_entry::id)};
    if (package != packages.end()) {
      package->result = tsc_err_sub(TEK_SC_ERRC_cm_access_token,
                                    TEK_SC_ERRC_cm_access_token_denied);
    }
  }
  // Report results via callback
  data_pics.result = tsc_err_ok();
  cb(&conn, &data_pics, conn.user_data);
  return true;
}

/// Handle `EMSG_CLIENT_PICS_CHANGES_SINCE_RESPONSE` response message.
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
static bool handle_pcs(cm_conn &conn, const MessageHeader &,
                       const void *_Nonnull data, int size,
                       cb_func *_Nonnull cb, void *) {
  msg_payloads::PicsChangesSinceResponse payload;
  tek_sc_cm_data_pics_changes data_pics_chngs;
  if (!payload.ParseFromArray(data, size)) {
    data_pics_chngs.result =
        tsc_err_sub(TEK_SC_ERRC_cm_changes, TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_pics_chngs, conn.user_data);
    return true;
  }
  std::vector<tek_sc_cm_pics_change_entry> changes;
  changes.reserve(payload.app_changes_size());
  for (const auto &change : payload.app_changes()) {
    changes.emplace_back(change.app_id(), change.needs_token());
  }
  // Report results via callback
  data_pics_chngs = {.entries = changes.data(),
                     .num_entries =
                         (payload.full_upd() || payload.full_app_upd())
                             ? -1
                             : payload.app_changes_size(),
                     .changenumber = payload.current_changenumber(),
                     .result{tsc_err_ok()}};
  cb(&conn, &data_pics_chngs, conn.user_data);
  return true;
}

/// Handle `EMSG_CLIENT_PICS_PRODUCT_INFO_RESPONSE` response message.
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
///    Pointer to the @ref tek_sc_cm_data_pics.
/// @return Value indicating whether the response is final, or more messages
///    are coming.
[[gnu::nonnull(3, 5, 6), gnu::access(read_only, 3, 4),
  gnu::access(read_write, 6), clang::callback(cb, __, __, __)]]
static bool handle_ppi(cm_conn &conn, const MessageHeader &,
                       const void *_Nonnull data, int size,
                       cb_func *_Nonnull cb, void *_Nonnull inout_data) {
  auto &data_pics{*reinterpret_cast<tek_sc_cm_data_pics *>(inout_data)};
  msg_payloads::PicsProductInfoResponse payload;
  if (!payload.ParseFromArray(data, size)) {
    data_pics.result = tsc_err_sub(TEK_SC_ERRC_cm_product_info,
                                   TEK_SC_ERRC_protobuf_deserialize);
    cb(&conn, &data_pics, conn.user_data);
    return true;
  }
  // Process apps
  const std::span apps{data_pics.app_entries,
                       static_cast<std::size_t>(data_pics.num_app_entries)};
  for (const auto &payload_app : payload.apps()) {
    // Find the corresponding entry in data_pics
    const auto app{std::ranges::find(apps, payload_app.app_id(),
                                     &tek_sc_cm_pics_entry::id)};
    if (app == apps.end()) {
      continue;
    }
    // Process the entry
    if (payload_app.missing_token()) {
      app->result = tsc_err_sub(TEK_SC_ERRC_cm_product_info,
                                TEK_SC_ERRC_cm_missing_token);
      continue;
    }
    app->data_size = payload_app.size();
    if (payload.has_http_min_size() &&
        payload_app.size() >= payload.http_min_size()) {
      continue;
    }
    app->data = std::malloc(payload_app.size());
    if (!app->data) {
      app->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      continue;
    }
    std::memcpy(app->data, payload_app.buffer().data(), payload_app.size());
    app->result = tsc_err_ok();
  }
  for (auto app_id : payload.unknown_app_ids()) {
    const auto app{std::ranges::find(apps, app_id, &tek_sc_cm_pics_entry::id)};
    if (app != apps.end()) {
      app->result = tsc_err_sub(TEK_SC_ERRC_cm_product_info,
                                TEK_SC_ERRC_cm_unknown_product);
    }
  }
  // Process packages
  const std::span packages{
      data_pics.package_entries,
      static_cast<std::size_t>(data_pics.num_package_entries)};
  for (const auto &payload_package : payload.packages()) {
    // Find the corresponding entry in data_pics
    const auto package{std::ranges::find(packages, payload_package.package_id(),
                                         &tek_sc_cm_pics_entry::id)};
    if (package == packages.end()) {
      continue;
    }
    // Process the entry
    if (payload_package.missing_token()) {
      package->result = tsc_err_sub(TEK_SC_ERRC_cm_product_info,
                                    TEK_SC_ERRC_cm_missing_token);
      continue;
    }
    package->data_size = payload_package.size();
    if (payload.has_http_min_size() &&
        payload_package.size() >= payload.http_min_size()) {
      continue;
    }
    package->data = std::malloc(payload_package.size());
    if (!package->data) {
      package->result =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
      continue;
    }
    std::memcpy(package->data, payload_package.buffer().data(),
                payload_package.size());
    package->result = tsc_err_ok();
  }
  for (auto package_id : payload.unknown_package_ids()) {
    const auto package_entry{
        std::ranges::find(packages, package_id, &tek_sc_cm_pics_entry::id)};
    if (package_entry != packages.end()) {
      package_entry->result = tsc_err_sub(TEK_SC_ERRC_cm_product_info,
                                          TEK_SC_ERRC_cm_unknown_product);
    }
  }
  if (payload.response_pending()) {
    return false;
  }
  const auto num_http{
      payload.has_http_min_size()
          ? static_cast<std::size_t>(
                std::ranges::count_if(
                    apps,
                    [min_size = static_cast<int>(payload.http_min_size())](
                        int data_size) { return data_size >= min_size; },
                    &tek_sc_cm_pics_entry::data_size) +
                std::ranges::count_if(
                    packages,
                    [min_size = static_cast<int>(payload.http_min_size())](
                        int data_size) { return data_size >= min_size; },
                    &tek_sc_cm_pics_entry::data_size))
          : 0};
  // Download buffers if any are stored on an HTTP host
  tek_sc_err http_error;
  if (num_http) {
    const std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> curlm{
        curl_multi_init(), curl_multi_cleanup};
    if (!curlm) {
      http_error =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_curlm_init);
      goto http_err;
    }
    std::vector<tsc_curl_ctx> ctxs{num_http};
    if (std::ranges::any_of(ctxs, std::logical_not{}, &tsc_curl_ctx::curl)) {
      http_error =
          tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_curle_init);
      goto http_err;
    }
    for (auto &ctx : ctxs) {
      curl_easy_setopt(ctx.curl.get(), CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_1_1);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_TIMEOUT_MS,
                       data_pics.timeout_ms);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 16000L);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_PIPEWAIT, 1L);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_WRITEDATA, &ctx);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_PRIVATE, &ctx);
      curl_easy_setopt(ctx.curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write);
    }
    auto next_ctx{ctxs.begin()};
    // Setup app info download contexts
    for (const auto &payload_app : payload.apps()) {
      if (payload_app.size() < payload.http_min_size()) {
        continue;
      }
      // Find the corresponding entry in data_pics
      const auto app{std::ranges::find(apps, payload_app.app_id(),
                                       &tek_sc_cm_pics_entry::id)};
      if (app == apps.end()) {
        continue;
      }
      auto &ctx{*next_ctx++};
      // Set curl options
      std::array<char, 40> sha;
      tsci_u_sha1_to_str(
          reinterpret_cast<const unsigned char *>(payload_app.sha().data()),
          sha.data());
      ctx.url = std::format(std::locale::classic(),
                            "http://{}/appinfo/{}/sha/{}.txt.gz",
                            payload.http_host(), payload_app.app_id(),
                            std::string_view{sha.data(), sha.size()});
      curl_easy_setopt(ctx.curl.get(), CURLOPT_URL, ctx.url.data());
      ctx.entry = std::to_address(app);
      // Submit curl easy handle to curlm
      if (const auto res{curl_multi_add_handle(curlm.get(), ctx.curl.get())};
          res != CURLM_OK) {
        std::ranges::for_each(
            ctxs.cbegin(), --next_ctx,
            [curlm{curlm.get()}](auto curl) {
              curl_multi_remove_handle(curlm, curl);
            },
            [](const auto &ctx) { return ctx.curl.get(); });
        http_error = pi_err_curlm(res);
        goto http_err;
      }
    } // App info download context setup
    // Setup package info download contexts
    for (const auto &payload_package : payload.packages()) {
      if (payload_package.size() < payload.http_min_size()) {
        continue;
      }
      // Find the corresponding entry in data_pics
      const auto package{std::ranges::find(
          packages, payload_package.package_id(), &tek_sc_cm_pics_entry::id)};
      if (package == packages.end()) {
        continue;
      }
      auto &ctx{*next_ctx++};
      // Set curl options
      std::array<char, 40> sha;
      tsci_u_sha1_to_str(
          reinterpret_cast<const unsigned char *>(payload_package.sha().data()),
          sha.data());
      ctx.url = std::format(std::locale::classic(),
                            "http://{}/appinfo/{}/sha/{}.txt.gz",
                            payload.http_host(), payload_package.package_id(),
                            std::string_view{sha.data(), sha.size()});
      curl_easy_setopt(ctx.curl.get(), CURLOPT_URL, ctx.url.data());
      ctx.entry = std::to_address(package);
      // Submit curl easy handle to curlm
      if (const auto res{curl_multi_add_handle(curlm.get(), ctx.curl.get())};
          res != CURLM_OK) {
        std::ranges::for_each(
            ctxs.cbegin(), --next_ctx,
            [curlm{curlm.get()}](auto curl) {
              curl_multi_remove_handle(curlm, curl);
            },
            [](const auto &ctx) { return ctx.curl.get(); });
        http_error = pi_err_curlm(res);
        goto http_err;
      }
    } // Package info download context setup
    // Process downloads
    int num_remaining;
    do {
      auto res{curl_multi_perform(curlm.get(), &num_remaining)};
      if (res == CURLM_OK && num_remaining) {
        res = curl_multi_poll(curlm.get(), nullptr, 0, data_pics.timeout_ms,
                              nullptr);
      }
      if (res != CURLM_OK) {
        std::ranges::for_each(
            ctxs,
            [curlm{curlm.get()}](auto curl) {
              curl_multi_remove_handle(curlm, curl);
            },
            [](const auto &ctx) { return ctx.curl.get(); });
        http_error = pi_err_curlm(res);
        goto http_err;
      }
    } while (num_remaining);
    // Process download results
    for (auto msg{curl_multi_info_read(curlm.get(), &num_remaining)}; msg;
         msg = curl_multi_info_read(curlm.get(), &num_remaining)) {
      if (msg->msg != CURLMSG_DONE) {
        continue;
      }
      curl_multi_remove_handle(curlm.get(), msg->easy_handle);
      tsc_curl_ctx *ctx;
      curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &ctx);
      auto &entry{*ctx->entry};
      if (msg->data.result == CURLE_OK) {
        entry.data = std::malloc(entry.data_size);
        if (!entry.data) {
          entry.result =
              tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_mem_alloc);
          continue;
        }
        // Inflate the data
        conn.zstream.next_in = ctx->buf.data();
        conn.zstream.avail_in = ctx->buf.size();
        conn.zstream.total_in = 0;
        conn.zstream.next_out = reinterpret_cast<unsigned char *>(entry.data);
        conn.zstream.avail_out = entry.data_size;
        conn.zstream.total_out = 0;
        auto res{tsci_z_inflate(&conn.zstream, Z_FINISH)};
        ctx->buf.clear();
        if (const auto reset_res{tsci_z_inflateReset2(&conn.zstream, 16)};
            res == Z_STREAM_END) {
          res = reset_res;
        }
        if (res != Z_OK) {
          std::free(entry.data);
          entry.result =
              tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_gzip);
          continue;
        }
        entry.result = tsc_err_ok();
      } else { // if (msg->data.result == CURLE_OK)
        ctx->buf.clear();
        entry.data = nullptr;
        entry.data_size = 0;
        long status = 0;
        if (msg->data.result == CURLE_HTTP_RETURNED_ERROR) {
          curl_easy_getinfo(ctx->curl.get(), CURLINFO_RESPONSE_CODE, &status);
        }
        const auto url_buf{
            reinterpret_cast<char *>(std::malloc(ctx->url.length() + 1))};
        if (url_buf) {
          std::ranges::move(ctx->url.begin(), ctx->url.end() + 1, url_buf);
        }
        entry.result = {.type = TEK_SC_ERR_TYPE_curle,
                        .primary = TEK_SC_ERRC_cm_product_info,
                        .auxiliary = msg->data.result,
                        .extra = static_cast<int>(status),
                        .uri = url_buf};
      } // if (msg->data.result == CURLE_OK) else
    } // for (curl messages)
    goto http_success;
  } // if (num_http)
  goto http_success;
http_err:
  for (auto &app : apps) {
    if (app.data_size >= static_cast<int>(payload.http_min_size())) {
      app.data = nullptr;
      app.data_size = 0;
      app.result = http_error;
    }
  }
  for (auto &package : packages) {
    if (package.data_size >= static_cast<int>(payload.http_min_size())) {
      package.data = nullptr;
      package.data_size = 0;
      package.result = http_error;
    }
  }
http_success:
  // Report results via callback
  data_pics.result = tsc_err_ok();
  cb(&conn, &data_pics, conn.user_data);
  return true;
}

} // namespace

//===-- Internal method ---------------------------------------------------===//

void cm_conn::handle_license_list(const void *data, int size) {
  msg_payloads::LicenseList payload;
  if (!payload.ParseFromArray(data, size)) {
    return;
  }
  if (payload.licenses_size()) {
    lics.reset(new tek_sc_cm_lic_entry[payload.licenses_size()]);
    const std::span span{lics.get(),
                         static_cast<std::size_t>(payload.licenses_size())};
    std::ranges::transform(
        payload.licenses(), span.begin(), [](const auto &lic) {
          return tek_sc_cm_lic_entry{.package_id = lic.package_id(),
                                     .access_token = lic.access_token()};
        });
    std::ranges::sort(span, {}, &tek_sc_cm_lic_entry::package_id);
  }
  const std::scoped_lock lock{lics_mtx};
  num_lics = payload.licenses_size();
  // Report licenses via callbacks if any
  for (tek_sc_cm_data_lics data_lics{.entries = lics.get(),
                                     .num_entries = num_lics,
                                     .result{tsc_err_ok()}};
       auto &lic_entry : lics_a_entries) {
    lic_entry.cb(&*this, &data_lics, user_data);
  }
  lics_a_entries.clear();
}

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient::cm;

extern "C" {

void tek_sc_cm_get_licenses(tek_sc_cm_client *client,
                            tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    auto data{lic_data_errc(TEK_SC_ERRC_cm_not_signed_in)};
    cb(&conn, &data, conn.user_data);
    return;
  }
  std::unique_lock lock{conn.lics_mtx};
  if (conn.num_lics >= 0) {
    tek_sc_cm_data_lics data{.entries = conn.lics.get(),
                             .num_entries = conn.num_lics,
                             .result{tsc_err_ok()}};
    lock.unlock();
    cb(&conn, &data, conn.user_data);
    return;
  }
  // Setup and submit the await entry
  auto &entry{
      conn.lics_a_entries.emplace_front(conn, cb, timer_state::inactive)};
  conn.send_msg({.buf{},
                 .size{},
                 .frame_type{},
                 .timer = &entry.timer,
                 .state = &entry.state,
                 .timer_cb = timeout_lics,
                 .timeout = static_cast<std::uint64_t>(timeout_ms),
                 .data = &entry});
}

void tek_sc_cm_get_access_token(tek_sc_cm_client *client,
                                tek_sc_cm_data_pics *data,
                                tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  if (!data->num_app_entries && !data->num_package_entries) {
    // No-op
    data->result = tsc_err_ok();
    cb(&conn, data, conn.user_data);
    return;
  }
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_access_token, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::PicsAccessTokenRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_PICS_ACCESS_TOKEN_REQUEST;
  msg.header.set_source_job_id(job_id);
  std::ranges::for_each(
      std::span{data->app_entries,
                static_cast<std::size_t>(data->num_app_entries)},
      [&msg](auto id) { msg.payload.add_app_ids(id); },
      &tek_sc_cm_pics_entry::id);
  std::ranges::for_each(
      std::span{data->package_entries,
                static_cast<std::size_t>(data->num_package_entries)},
      [&msg](auto id) { msg.payload.add_package_ids(id); },
      &tek_sc_cm_pics_entry::id);
  // Send the request message
  const auto it{
      conn.setup_a_entry(job_id, handle_pat, cb, timeout_pics_at, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_access_token>(
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

void tek_sc_cm_get_product_info(tek_sc_cm_client *client,
                                tek_sc_cm_data_pics *data,
                                tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  if (!data->num_app_entries && !data->num_package_entries) {
    // No-op
    data->result = tsc_err_ok();
    cb(&conn, data, conn.user_data);
    return;
  }
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    data->result =
        tsc_err_sub(TEK_SC_ERRC_cm_product_info, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::PicsProductInfoRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_PICS_PRODUCT_INFO_REQUEST;
  msg.header.set_source_job_id(job_id);
  for (const auto &app :
       std::span{data->app_entries,
                 static_cast<std::size_t>(data->num_app_entries)}) {
    auto &payload_app{*msg.payload.add_apps()};
    payload_app.set_app_id(app.id);
    if (app.access_token) {
      payload_app.set_access_token(app.access_token);
    }
  }
  for (const auto &package :
       std::span{data->package_entries,
                 static_cast<std::size_t>(data->num_package_entries)}) {
    auto &payload_package{*msg.payload.add_packages()};
    payload_package.set_package_id(package.id);
    if (package.access_token) {
      payload_package.set_access_token(package.access_token);
    }
  }
  // Send the request message
  const auto it{
      conn.setup_a_entry(job_id, handle_ppi, cb, timeout_pics_pi, data)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_product_info>(
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

void tek_sc_cm_get_changes(tek_sc_cm_client *client, uint32_t changenumber,
                           tek_sc_cm_callback_func *cb, long timeout_ms) {
  auto &conn{client->conn};
  // Ensure that the client is signed in
  if (conn.state.load(std::memory_order::relaxed) != conn_state::signed_in) {
    tek_sc_cm_data_pics_changes data;
    data.result =
        tsc_err_sub(TEK_SC_ERRC_cm_changes, TEK_SC_ERRC_cm_not_signed_in);
    cb(&conn, &data, conn.user_data);
    return;
  }
  const auto job_id{gen_job_id()};
  // Prepare the request message
  message<msg_payloads::PicsChangesSinceRequest> msg;
  msg.type = EMsg::EMSG_CLIENT_PICS_CHANGES_SINCE_REQUEST;
  msg.header.set_source_job_id(job_id);
  msg.payload.set_since_changenumber(changenumber);
  msg.payload.set_send_app_info_changes(true);
  msg.payload.set_send_package_info_changes(false);
  // Send the request message
  const auto it{conn.setup_a_entry(job_id, handle_pcs, cb, timeout_pics_cs)};
  if (const auto res{conn.send_message<TEK_SC_ERRC_cm_changes>(
          std::move(msg), it->second, timeout_ms)};
      !tek_sc_err_success(&res)) {
    // Remove the await entry
    {
      const std::scoped_lock lock{conn.a_entries_mtx};
      conn.a_entries.erase(it);
    }
    // Report error via callback
    tek_sc_cm_data_pics_changes data;
    data.result = res;
    cb(&conn, &data, conn.user_data);
  }
}

} // extern "C"
