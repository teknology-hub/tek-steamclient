//===-- s3c.cpp - tek-s3 client interface implementation ------------------===//
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
/// Implementation of tek_sc_s3c_* functions.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/s3c.h"

#include "common/error.h"
#include "config.h"
#include "lib_ctx.hpp"
#include "tek-steamclient/base.h"
#include "utils.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <curl/curl.h>
#include <format>
#include <locale>
#include <memory>
#include <mutex>
#include <ranges>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <shared_mutex>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <system_error>

namespace tek::steamclient::s3c {

namespace {

/// Hardcoded IP addresses to resolve cloudflare-dns.com to when using DOH
///    fallbacks.
static curl_slist cloudflare_dns_resolve{
    .data = const_cast<char *>(
        "cloudflare-dns.com:443:2606:4700:4700::1111,2606:4700:4700::1001,"
        "1.1.1.1,1.0.0.1"),
    .next{}};

//===-- Private type ------------------------------------------------------===//

/// Download context for curl.
struct tsc_curl_ctx {
  /// curl easy handle that performs the download.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  /// Buffer storing downloaded content.
  std::string buf;
};

//===-- Private functions -------------------------------------------------===//

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
///    Stack buffer that should receive the content.
/// @return @p size, or `CURL_WRITEFUNC_ERROR` on error.
[[using gnu: nonnull(1), access(read_only, 1, 3)]]
static std::size_t tsc_curl_write_mrc(const char *_Nonnull buf, std::size_t,
                                      std::size_t size,
                                      std::array<char, 20> &out_buf) {
  if (size > out_buf.size()) {
    return CURL_WRITEFUNC_ERROR;
  }
  std::ranges::copy_n(buf, size, out_buf.data());
  return size;
}

} // namespace

} // namespace tek::steamclient::s3c

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient;
using namespace tek::steamclient::s3c;

extern "C" {

tek_sc_err tek_sc_s3c_sync_manifest(tek_sc_lib_ctx *lib_ctx, const char *url,
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
  const std::string_view url_view{url};
  const auto req_url = std::string{url_view}.append("/manifest");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEFUNCTION,
                   tsc_curl_write_manifest);
  lib_ctx->s3_mtx.lock_shared();
  const auto srv{
      std::ranges::find(lib_ctx->s3_servers, url_view, &server::url)};
  const auto timestamp{srv == lib_ctx->s3_servers.end()
                           ? 0
                           : static_cast<curl_off_t>(srv->timestamp)};
  lib_ctx->s3_mtx.unlock_shared();
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMEVALUE_LARGE, timestamp);
  auto res{curl_easy_perform(curl_ctx.curl.get())};
  switch (res) {
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_PEER_FAILED_VERIFICATION:
    curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_RESOLVE,
                     &cloudflare_dns_resolve);
    curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");
    res = curl_easy_perform(curl_ctx.curl.get());
    break;
  default:
  }
  if (res != CURLE_OK) {
    const auto url_buf{
        reinterpret_cast<char *>(std::malloc(req_url.length() + 1))};
    if (url_buf) {
      std::ranges::copy(req_url.begin(), req_url.end() + 1, url_buf);
    }
    long status{};
    if (res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_RESPONSE_CODE, &status);
    }
    return {.type = TEK_SC_ERR_TYPE_curle,
            .primary = TEK_SC_ERRC_s3c_manifest,
            .auxiliary = res,
            .extra = static_cast<int>(status),
            .uri = url_buf};
  }
  long cond_unmet{};
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
    std::unique_lock lock{lib_ctx->s3_mtx};
    const auto srv_it{
        std::ranges::find(lib_ctx->s3_servers, url_view, &server::url)};
    if (srv_it != lib_ctx->s3_servers.end()) {
      srv_it->timestamp = static_cast<std::time_t>(last_mod);
      // Clear all server references, in case some apps/depots have been removed
      //    from the manifest
      for (auto addr{std::to_address(srv_it)};
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
    const auto srv{
        srv_it == lib_ctx->s3_servers.end()
            ? &lib_ctx->s3_servers.emplace_back(
                  std::string{url_view}, static_cast<std::time_t>(last_mod))
            : std::to_address(srv_it)};
    const auto apps{doc.FindMember("apps")};
    if (apps == doc.MemberEnd() || !apps->value.IsObject()) {
      goto json_parse_err;
    }
    const auto depot_keys{doc.FindMember("depot_keys")};
    if (depot_keys == doc.MemberEnd() || !depot_keys->value.IsObject()) {
      goto json_parse_err;
    }
    std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
        nullptr, sqlite3_finalize};
    const auto db{lib_ctx->cache.get()};
    const bool savepoint_created{sqlite3_exec(db, "SAVEPOINT s3", nullptr,
                                              nullptr, nullptr) == SQLITE_OK};
    if (savepoint_created) {
      sqlite3_stmt *stmt_ptr;
      constexpr std::string_view query{
          "INSERT INTO pics_access_tokens (app_id, token) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                             nullptr) == SQLITE_OK) {
        stmt.reset(stmt_ptr);
      }
    }
    for (const auto &[id, value] : apps->value.GetObject()) {
      if (!value.IsObject()) {
        continue;
      }
      std::uint32_t app_id;
      if (const std::string_view view{id.GetString(), id.GetStringLength()};
          std::from_chars(view.begin(), view.end(), app_id).ec != std::errc{}) {
        continue;
      }
      if (stmt) {
        const auto pics_at{value.FindMember("pics_at")};
        if (pics_at != value.MemberEnd() && pics_at->value.IsUint64()) {
          sqlite3_bind_int(stmt.get(), 1, static_cast<int>(app_id));
          sqlite3_bind_int64(
              stmt.get(), 2,
              static_cast<sqlite3_int64>(pics_at->value.GetUint64()));
          sqlite3_step(stmt.get());
          sqlite3_reset(stmt.get());
          sqlite3_clear_bindings(stmt.get());
        }
      }
      const auto depots{value.FindMember("depots")};
      if (depots == value.MemberEnd() || !depots->value.IsArray()) {
        continue;
      }
      for (auto &cache_app = lib_ctx->s3_cache[app_id];
           const auto &depot : depots->value.GetArray()) {
        if (!depot.IsUint()) {
          continue;
        }
        auto &cache_depot{
            cache_app[static_cast<std::uint32_t>(depot.GetUint())]};
        cache_depot.servers.emplace_back(srv);
        cache_depot.it = cache_depot.servers.cbegin();
      }
    }
    lock.unlock();
    stmt.reset();
    if (savepoint_created) {
      constexpr std::string_view query{
          "INSERT INTO depot_keys (depot_id, key) VALUES (?, ?)"};
      sqlite3_stmt *stmt_ptr;
      if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                             nullptr) == SQLITE_OK) {
        stmt.reset(stmt_ptr);
        for (const auto &[id, value] : depot_keys->value.GetObject()) {
          if (!value.IsString()) {
            continue;
          }
          if (value.GetStringLength() != 44) {
            continue;
          }
          std::uint32_t depot_id;
          if (const std::string_view view{id.GetString(), id.GetStringLength()};
              std::from_chars(view.begin(), view.end(), depot_id).ec !=
              std::errc{}) {
            continue;
          }
          tek_sc_aes256_key key;
          tsci_u_base64_decode(value.GetString(), 44, key);
          sqlite3_bind_int(stmt.get(), 1, static_cast<int>(depot_id));
          sqlite3_bind_blob(stmt.get(), 2, key, sizeof key, SQLITE_STATIC);
          sqlite3_step(stmt.get());
          sqlite3_reset(stmt.get());
          sqlite3_clear_bindings(stmt.get());
        }
      }
      stmt.reset();
      sqlite3_exec(db, "RELEASE s3", nullptr, nullptr, nullptr);
    }
  } // JSON parsing scope
  return tsc_err_ok();
json_parse_err:
  return tsc_err_sub(TEK_SC_ERRC_s3c_manifest, TEK_SC_ERRC_json_parse);
}

const char *tek_sc_s3c_get_srv_for_mrc(tek_sc_lib_ctx *lib_ctx, uint32_t app_id,
                                       uint32_t depot_id) {
  const std::shared_lock lock{lib_ctx->s3_mtx};
  const auto app_it{lib_ctx->s3_cache.find(app_id)};
  if (app_it == lib_ctx->s3_cache.end()) {
    return nullptr;
  }
  const auto depot_it{app_it->second.find(depot_id)};
  if (depot_it == app_it->second.end()) {
    return nullptr;
  }
  auto &entry{depot_it->second};
  if (entry.servers.empty()) {
    return nullptr;
  }
  const auto res{(*entry.it)->url.data()};
  if (++entry.it == entry.servers.cend()) {
    entry.it = entry.servers.cbegin();
  }
  return res;
}

void tek_sc_s3c_get_mrc(const char *url, long timeout_ms,
                        tek_sc_cm_data_mrc *data) {
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  if (!curl) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_curle_init);
    return;
  }
  curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  std::array<char, 20> buf;
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &buf);
  const auto req_url{std::format(
      std::locale::classic(), "{}/mrc?app_id={}&depot_id={}&manifest_id={}",
      url, data->app_id, data->depot_id, data->manifest_id)};
  curl_easy_setopt(curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write_mrc);
  auto res{curl_easy_perform(curl.get())};
  switch (res) {
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_PEER_FAILED_VERIFICATION:
    curl_easy_setopt(curl.get(), CURLOPT_RESOLVE, &cloudflare_dns_resolve);
    curl_easy_setopt(curl.get(), CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");
    res = curl_easy_perform(curl.get());
    break;
  default:
  }
  if (res != CURLE_OK) {
    const auto url_buf{
        reinterpret_cast<char *>(std::malloc(req_url.length() + 1))};
    if (url_buf) {
      std::ranges::copy(req_url.begin(), req_url.end() + 1, url_buf);
    }
    long status{};
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
  if (const std::string_view mrc{buf.data(),
                                 static_cast<std::size_t>(content_len)};
      std::from_chars(mrc.begin(), mrc.end(), data->request_code).ec !=
      std::errc{}) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_invalid_data);
    return;
  }
  data->result = tsc_err_ok();
}

} // extern "C"
