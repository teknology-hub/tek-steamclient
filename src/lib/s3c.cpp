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
#include "tek-steamclient/error.h"
#include "utils.h"
#include "zlib_api.h"

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
#include <span>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace tek::steamclient::s3c {

namespace {

/// Hardcoded IP addresses to resolve cloudflare-dns.com to when using DOH
///    fallbacks.
static curl_slist cloudflare_dns_resolve{
    .data = const_cast<char *>(
        "cloudflare-dns.com:443:2606:4700:4700::1111,2606:4700:4700::1001,"
        "1.1.1.1,1.0.0.1"),
    .next{}};

//===-- Private types -----------------------------------------------------===//

/// Download context for curl.
struct tsc_curl_ctx {
  /// curl easy handle that performs the download.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  /// Buffer storing downloaded content.
  std::vector<unsigned char> buf;
};

/// Stack buffer descriptor for downloads.
struct tsc_stack_buf {
  /// Pointer to the buffer to write data to.
  char *_Nonnull data;
  /// Size of the buffer pointed to by @ref data, in bytes.
  std::size_t size;
};

//===-- Binary manifest types ---------------------------------------------===//
//
// The structure of binary manifest is as following:
//    bmanifest_hdr
//    bmanifest_app[num_apps]
//    std::uint32_t[num_depots]
//    bmanifest_depot_key[num_depot_keys]

/// Binary manifest header.
struct bmanifest_hdr {
  /// CRC32 checksum for the remainder of serialized data (excluding itself).
  std::uint32_t crc;
  /// Total number of application entries in the manifest. A negative value
  ///    indcates that the server is "ultimate" variant that can provide
  ///    manifest request codes for every manifest in existence.
  std::int32_t num_apps;
  /// Total number of depot entries in the manifest.
  std::int32_t num_depots;
  /// Total number of depot decryption key entries in the manifest.
  std::int32_t num_depot_keys;
};

/// Binary manifest application entry.
struct bmanifest_app {
  /// ID of the application.
  std::uint32_t app_id;
  /// Number of depot IDs assigned to the application.
  std::int32_t num_depots;
  /// PICS access token for the application.
  std::uint64_t pics_access_token;
};

/// Binary manifest depot decryption key entry.
struct bmanifest_depot_key {
  /// ID of the depot.
  std::int32_t id;
  /// Decryption key for the depot.
  tek_sc_aes256_key key;
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
  ctx.buf.insert(ctx.buf.end(), buf, &buf[size]);
  return size;
}

/// curl write data callback that copies data to specified stack buffer.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content.
/// @param size
///    Size of the content in bytes.
/// @param [out] out_buf
///    Stack buffer receiving the content.
/// @return @p size, or `CURL_WRITEFUNC_ERROR` on error.
[[using gnu: nonnull(1), access(read_only, 1, 3)]]
static std::size_t tsc_curl_write_buf(const char *_Nonnull buf, std::size_t,
                                      std::size_t size,
                                      tsc_stack_buf &out_buf) {
  if (size > out_buf.size) {
    return CURL_WRITEFUNC_ERROR;
  }
  std::ranges::copy_n(buf, size, out_buf.data);
  return size;
}

/// Parse JSON variant of tek-s3 manifest.
///
/// @param [in, out] ctx
///    Library context that will cache the parsed data.
/// @param [in] url
///    tek-s3 server URL.
/// @param last_mod
///    Last manifest modification timestamp reported by the server.
/// @param [in, out] data
///    Buffer storing downloaded manifest data.
/// @return Value indicating whether parsing succeeded.
static bool parse_manifest_json(lib_ctx &ctx, const std::string_view &url,
                                curl_off_t last_mod,
                                std::vector<unsigned char> &data) {
  data.emplace_back(static_cast<unsigned char>('\0'));
  rapidjson::Document doc;
  doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(
      reinterpret_cast<char *>(data.data()));
  if (doc.HasParseError() || !doc.IsObject()) {
    return false;
  }
  ctx.dirty_flags.fetch_or(static_cast<int>(dirty_flag::s3),
                           std::memory_order::relaxed);
  std::unique_lock lock{ctx.s3_mtx};
  const auto srv_it{std::ranges::find(ctx.s3_servers, url, &server::url)};
  if (srv_it != ctx.s3_servers.end()) {
    srv_it->timestamp = static_cast<std::time_t>(last_mod);
    // Clear all server references, in case some apps/depots have been removed
    //    from the manifest
    for (auto addr{std::to_address(srv_it)};
         auto &app : ctx.s3_cache | std::views::values) {
      for (auto &depot : app | std::views::values) {
        if (std::erase(depot.servers, addr)) {
          depot.it = depot.servers.cbegin();
        }
      }
      std::erase_if(
          app, [](const auto &depot) { return depot.second.servers.empty(); });
    }
    std::erase_if(ctx.s3_cache,
                  [](const auto &app) { return app.second.empty(); });
  }
  const auto ultimate{doc.FindMember("ultimate")};
  if (ultimate != doc.MemberEnd() && ultimate->value.IsBool() &&
      ultimate->value.GetBool()) {
    if (srv_it != ctx.s3_servers.end()) {
      ctx.s3_servers.erase(srv_it);
    }
    ctx.s3u_servers.emplace_back(std::string{url});
    ctx.s3u_servers_it = ctx.s3u_servers.cbegin();
    return true;
  }
  const auto srv{srv_it == ctx.s3_servers.end()
                     ? &ctx.s3_servers.emplace_back(
                           std::string{url}, static_cast<std::time_t>(last_mod))
                     : std::to_address(srv_it)};
  const auto apps{doc.FindMember("apps")};
  if (apps == doc.MemberEnd() || !apps->value.IsObject()) {
    return false;
  }
  const auto depot_keys{doc.FindMember("depot_keys")};
  if (depot_keys == doc.MemberEnd() || !depot_keys->value.IsObject()) {
    return false;
  }
  std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
      nullptr, sqlite3_finalize};
  const auto db{ctx.cache.get()};
  const bool savepoint_created{
      sqlite3_exec(db, "SAVEPOINT s3", nullptr, nullptr, nullptr) == SQLITE_OK};
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
    for (auto &cache_app = ctx.s3_cache[app_id];
         const auto &depot : depots->value.GetArray()) {
      if (!depot.IsUint()) {
        continue;
      }
      auto &cache_depot{cache_app[static_cast<std::uint32_t>(depot.GetUint())]};
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
  return true;
}

/// Parse binary variant of tek-s3 manifest.
///
/// @param [in, out] ctx
///    Library context that will cache the parsed data.
/// @param [in] url
///    tek-s3 server URL.
/// @param last_mod
///    Last manifest modification timestamp reported by the server.
/// @param [in, out] data
///    Buffer storing downloaded manifest data.
/// @return Error code indicating the result of parsing.
static tek_sc_errc parse_manifest_bin(lib_ctx &ctx, const std::string_view &url,
                                      curl_off_t last_mod,
                                      std::vector<unsigned char> &data) {
  if (data.size() < sizeof(bmanifest_hdr)) {
    return TEK_SC_ERRC_invalid_data;
  }
  const auto &hdr{*reinterpret_cast<const bmanifest_hdr *>(data.data())};
  if (hdr.crc != tsci_z_crc32(tsci_z_crc32(0, nullptr, 0),
                              &data[sizeof hdr.crc],
                              data.size() - sizeof hdr.crc)) {
    return TEK_SC_ERRC_crc_mismatch;
  }
  const std::span apps{
      reinterpret_cast<const bmanifest_app *>(&hdr + 1),
      static_cast<std::size_t>(hdr.num_apps < 0 ? 0 : hdr.num_apps)};
  auto next_depot{
      reinterpret_cast<const std::uint32_t *>(std::to_address(apps.end()))};
  const std::span depot_keys{reinterpret_cast<const bmanifest_depot_key *>(
                                 &next_depot[hdr.num_depots]),
                             static_cast<std::size_t>(hdr.num_depot_keys)};
  if (static_cast<std::size_t>(reinterpret_cast<const unsigned char *>(
                                   std::to_address(depot_keys.end())) -
                               data.data()) > data.size()) {
    return TEK_SC_ERRC_invalid_data;
  }
  if (std::ranges::fold_left(apps, 0, [](int acc, const auto &app) {
        return acc + app.num_depots;
      }) != hdr.num_depots) {
    return TEK_SC_ERRC_invalid_data;
  }
  ctx.dirty_flags.fetch_or(static_cast<int>(dirty_flag::s3),
                           std::memory_order::relaxed);
  std::unique_lock lock{ctx.s3_mtx};
  const auto srv_it{std::ranges::find(ctx.s3_servers, url, &server::url)};
  if (srv_it != ctx.s3_servers.end()) {
    srv_it->timestamp = static_cast<std::time_t>(last_mod);
    // Clear all server references, in case some apps/depots have been removed
    //    from the manifest
    for (auto addr{std::to_address(srv_it)};
         auto &app : ctx.s3_cache | std::views::values) {
      for (auto &depot : app | std::views::values) {
        if (std::erase(depot.servers, addr)) {
          depot.it = depot.servers.cbegin();
        }
      }
      std::erase_if(
          app, [](const auto &depot) { return depot.second.servers.empty(); });
    }
    std::erase_if(ctx.s3_cache,
                  [](const auto &app) { return app.second.empty(); });
  }
  if (hdr.num_apps < 0) {
    if (srv_it != ctx.s3_servers.end()) {
      ctx.s3_servers.erase(srv_it);
    }
    ctx.s3u_servers.emplace_back(std::string{url});
    ctx.s3u_servers_it = ctx.s3u_servers.cbegin();
    return TEK_SC_ERRC_ok;
  }
  const auto srv{srv_it == ctx.s3_servers.end()
                     ? &ctx.s3_servers.emplace_back(
                           std::string{url}, static_cast<std::time_t>(last_mod))
                     : std::to_address(srv_it)};
  std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
      nullptr, sqlite3_finalize};
  const auto db{ctx.cache.get()};
  const bool savepoint_created{
      sqlite3_exec(db, "SAVEPOINT s3", nullptr, nullptr, nullptr) == SQLITE_OK};
  if (savepoint_created) {
    sqlite3_stmt *stmt_ptr;
    constexpr std::string_view query{
        "INSERT INTO pics_access_tokens (app_id, token) VALUES (?, ?)"};
    if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                           nullptr) == SQLITE_OK) {
      stmt.reset(stmt_ptr);
    }
  }
  for (const auto &app : apps) {
    if (stmt) {
      if (app.pics_access_token) {
        sqlite3_bind_int(stmt.get(), 1, static_cast<int>(app.app_id));
        sqlite3_bind_int64(stmt.get(), 2,
                           static_cast<sqlite3_int64>(app.pics_access_token));
        sqlite3_step(stmt.get());
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
      }
    }
    auto &cache_app = ctx.s3_cache[app.app_id];
    next_depot =
        std::ranges::for_each_n(next_depot, app.num_depots,
                                [&cache_app, srv](auto depot_id) {
                                  auto &cache_depot{cache_app[depot_id]};
                                  cache_depot.servers.emplace_back(srv);
                                  cache_depot.it = cache_depot.servers.cbegin();
                                })
            .in;
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
      for (const auto &dk : depot_keys) {
        sqlite3_bind_int(stmt.get(), 1, static_cast<int>(dk.id));
        sqlite3_bind_blob(stmt.get(), 2, dk.key, sizeof dk.key, SQLITE_STATIC);
        sqlite3_step(stmt.get());
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
      }
    }
    stmt.reset();
    sqlite3_exec(db, "RELEASE s3", nullptr, nullptr, nullptr);
  }
  return TEK_SC_ERRC_ok;
}

} // namespace

} // namespace tek::steamclient::s3c

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient;
using namespace tek::steamclient::s3c;

extern "C" {

tek_sc_err tek_sc_s3c_sync_manifest(tek_sc_lib_ctx *lib_ctx, const char *url,
                                    long timeout_ms) {
  if (const std::scoped_lock lock{lib_ctx->s3_mtx};
      std::ranges::contains(lib_ctx->s3u_servers, url)) {
    return tsc_err_ok();
  }
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
  auto req_url{std::string{url_view}.append("/manifest-bin")};
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEFUNCTION,
                   tsc_curl_write_manifest);
  {
    const std::scoped_lock lock{lib_ctx->s3_mtx};
    const auto srv{
        std::ranges::find(lib_ctx->s3_servers, url_view, &server::url)};
    const auto timestamp{srv == lib_ctx->s3_servers.end()
                             ? 0
                             : static_cast<curl_off_t>(srv->timestamp)};
    curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMEVALUE_LARGE, timestamp);
  }
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
  if (res == CURLE_OK) {
    long cond_unmet{};
    curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_CONDITION_UNMET,
                      &cond_unmet);
    if (cond_unmet) {
      return tsc_err_ok();
    }
    curl_off_t last_mod;
    curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_FILETIME_T, &last_mod);
    if (parse_manifest_bin(*lib_ctx, url_view, last_mod, curl_ctx.buf) ==
        TEK_SC_ERRC_ok) {
      return tsc_err_ok();
    }
    curl_ctx.buf.clear();
    req_url = std::string{url_view}.append("/manifest");
    curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, req_url.data());
    res = curl_easy_perform(curl_ctx.curl.get());
    goto process_json_manifest;
  }
  if (res == CURLE_HTTP_RETURNED_ERROR) {
    long status{};
    curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_RESPONSE_CODE, &status);
    if (status == 404) {
      curl_ctx.buf.clear();
      req_url = std::string{url_view}.append("/manifest");
      curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, req_url.data());
      res = curl_easy_perform(curl_ctx.curl.get());
    }
  }
process_json_manifest:
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
  return parse_manifest_json(*lib_ctx, url_view, last_mod, curl_ctx.buf)
             ? tsc_err_ok()
             : tsc_err_sub(TEK_SC_ERRC_s3c_manifest, TEK_SC_ERRC_json_parse);
}

void tek_sc_s3c_remove_server(tek_sc_lib_ctx *lib_ctx, const char *url) {
  const std::string_view url_view{url};
  const std::scoped_lock lock{lib_ctx->s3_mtx};
  std::erase(lib_ctx->s3u_servers, url_view);
  const auto srv_it{
      std::ranges::find(lib_ctx->s3_servers, url_view, &server::url)};
  if (srv_it == lib_ctx->s3_servers.end()) {
    return;
  }
  for (auto addr{std::to_address(srv_it)};
       auto &app : lib_ctx->s3_cache | std::views::values) {
    for (auto &depot : app | std::views::values) {
      if (std::erase(depot.servers, addr)) {
        depot.it = depot.servers.cbegin();
      }
    }
    std::erase_if(
        app, [](const auto &depot) { return depot.second.servers.empty(); });
  }
  std::erase_if(lib_ctx->s3_cache,
                [](const auto &app) { return app.second.empty(); });
  lib_ctx->s3_servers.erase(srv_it);
}

const char *tek_sc_s3c_get_srv_for_mrc(tek_sc_lib_ctx *lib_ctx, uint32_t app_id,
                                       uint32_t depot_id) {
  const std::scoped_lock lock{lib_ctx->s3_mtx};
  if (!lib_ctx->s3u_servers.empty()) {
    const auto res{lib_ctx->s3u_servers_it->data()};
    if (++lib_ctx->s3u_servers_it == lib_ctx->s3u_servers.cend()) {
      lib_ctx->s3u_servers_it = lib_ctx->s3u_servers.cbegin();
    }
    return res;
  }
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
  tsc_stack_buf stack_buf{.data = buf.data(), .size = buf.size()};
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &stack_buf);
  const auto req_url{std::format(
      std::locale::classic(), "{}/mrc?app_id={}&depot_id={}&manifest_id={}",
      url, data->app_id, data->depot_id, data->manifest_id)};
  curl_easy_setopt(curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write_buf);
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
      content_len <= 0 || static_cast<std::size_t>(content_len) > buf.size()) {
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

tek_sc_err tek_sc_s3c_get_depot_key(const char *url, long timeout_ms,
                                    uint32_t depot_id, tek_sc_aes256_key key) {
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  if (!curl) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_depot_key, TEK_SC_ERRC_curle_init);
  }
  curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  std::array<char, 44> buf;
  tsc_stack_buf stack_buf{.data = buf.data(), .size = buf.size()};
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &stack_buf);
  const auto req_url{std::format(std::locale::classic(),
                                 "{}/depot_key?depot_id={}", url, depot_id)};
  curl_easy_setopt(curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write_buf);
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
    return {.type = TEK_SC_ERR_TYPE_curle,
            .primary = TEK_SC_ERRC_s3c_depot_key,
            .auxiliary = res,
            .extra = static_cast<int>(status),
            .uri = url_buf};
  }
  curl_off_t content_len;
  if (curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                        &content_len) != CURLE_OK ||
      static_cast<std::size_t>(content_len) != buf.size()) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_depot_key, TEK_SC_ERRC_invalid_data);
  };
  curl.reset();
  tsci_u_base64_decode(buf.data(), buf.size(), key);
  return tsc_err_ok();
}

tek_sc_err tek_sc_s3c_get_pics_at(const char *url, long timeout_ms,
                                  uint32_t app_id, uint64_t *token) {
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  if (!curl) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_pics_at, TEK_SC_ERRC_curle_init);
  }
  curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  std::array<char, 20> buf;
  tsc_stack_buf stack_buf{.data = buf.data(), .size = buf.size()};
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &stack_buf);
  const auto req_url{
      std::format(std::locale::classic(), "{}/pics_at?app_id={}", url, app_id)};
  curl_easy_setopt(curl.get(), CURLOPT_URL, req_url.data());
  curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write_buf);
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
    return {.type = TEK_SC_ERR_TYPE_curle,
            .primary = TEK_SC_ERRC_s3c_pics_at,
            .auxiliary = res,
            .extra = static_cast<int>(status),
            .uri = url_buf};
  }
  curl_off_t content_len;
  if (curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                        &content_len) != CURLE_OK ||
      content_len <= 0 || static_cast<std::size_t>(content_len) > buf.size()) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_pics_at, TEK_SC_ERRC_invalid_data);
  };
  curl.reset();
  if (const std::string_view at{buf.data(),
                                static_cast<std::size_t>(content_len)};
      std::from_chars(at.begin(), at.end(), *token).ec != std::errc{}) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_pics_at, TEK_SC_ERRC_invalid_data);
  }
  return tsc_err_ok();
}

void tek_sc_s3c_ctx_get_mrc(tek_sc_lib_ctx *lib_ctx, long timeout_ms,
                            tek_sc_cm_data_mrc *data) {
  data->result = tsc_err_ok();
  const std::scoped_lock lock{lib_ctx->s3_mtx};
  if (!lib_ctx->s3u_servers.empty()) {
    for (const auto start_it{lib_ctx->s3u_servers_it};;) {
      tek_sc_s3c_get_mrc(lib_ctx->s3u_servers_it->data(), timeout_ms, data);
      if (tek_sc_err_success(&data->result)) {
        return;
      }
      if (++lib_ctx->s3u_servers_it == lib_ctx->s3u_servers.cend()) {
        lib_ctx->s3u_servers_it = lib_ctx->s3u_servers.cbegin();
      }
      if (lib_ctx->s3u_servers_it == start_it) {
        break;
      } else if (data->result.uri) {
        std::free(const_cast<char *>(data->result.uri));
      }
    }
  }
  if (const auto app_it{lib_ctx->s3_cache.find(data->app_id)};
      app_it != lib_ctx->s3_cache.end()) {
    if (const auto depot_it{app_it->second.find(data->depot_id)};
        depot_it != app_it->second.end()) {
      auto &entry{depot_it->second};
      for (const auto start_it{entry.it};;) {
        tek_sc_s3c_get_mrc((*entry.it)->url.data(), timeout_ms, data);
        if (tek_sc_err_success(&data->result)) {
          return;
        }
        if (++entry.it == entry.servers.cend()) {
          entry.it = entry.servers.cbegin();
        }
        if (entry.it == start_it) {
          break;
        } else if (data->result.uri) {
          std::free(const_cast<char *>(data->result.uri));
        }
      }
    }
  }
  if (tek_sc_err_success(&data->result)) {
    data->result = tsc_err_sub(TEK_SC_ERRC_s3c_mrc, TEK_SC_ERRC_s3c_no_srv);
  }
}

tek_sc_err tek_sc_s3c_ctx_get_depot_key(tek_sc_lib_ctx *lib_ctx,
                                        long timeout_ms, uint32_t depot_id,
                                        tek_sc_aes256_key key) {
  tek_sc_err res;
  const std::scoped_lock lock{lib_ctx->s3_mtx};
  if (lib_ctx->s3u_servers.empty()) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_depot_key, TEK_SC_ERRC_s3c_no_srv);
  }
  for (const auto start_it{lib_ctx->s3u_servers_it};;) {
    res = tek_sc_s3c_get_depot_key(lib_ctx->s3u_servers_it->data(), timeout_ms,
                                   depot_id, key);
    if (tek_sc_err_success(&res)) {
      tek_sc_lib_add_depot_key(lib_ctx, depot_id, key);
      return res;
    }
    if (++lib_ctx->s3u_servers_it == lib_ctx->s3u_servers.cend()) {
      lib_ctx->s3u_servers_it = lib_ctx->s3u_servers.cbegin();
    }
    if (lib_ctx->s3u_servers_it == start_it) {
      break;
    } else if (res.uri) {
      std::free(const_cast<char *>(res.uri));
    }
  }
  return res;
}

tek_sc_err tek_sc_s3c_ctx_get_pics_at(tek_sc_lib_ctx *lib_ctx, long timeout_ms,
                                      uint32_t app_id, uint64_t *token) {
  tek_sc_err res;
  const std::scoped_lock lock{lib_ctx->s3_mtx};
  if (lib_ctx->s3u_servers.empty()) {
    return tsc_err_sub(TEK_SC_ERRC_s3c_pics_at, TEK_SC_ERRC_s3c_no_srv);
  }
  for (const auto start_it{lib_ctx->s3u_servers_it};;) {
    res = tek_sc_s3c_get_pics_at(lib_ctx->s3u_servers_it->data(), timeout_ms,
                                 app_id, token);
    if (tek_sc_err_success(&res)) {
      tek_sc_lib_add_pics_at(lib_ctx, app_id, *token);
      return res;
    }
    if (++lib_ctx->s3u_servers_it == lib_ctx->s3u_servers.cend()) {
      lib_ctx->s3u_servers_it = lib_ctx->s3u_servers.cbegin();
    }
    if (lib_ctx->s3u_servers_it == start_it) {
      break;
    } else if (res.uri) {
      std::free(const_cast<char *>(res.uri));
    }
  }
  return res;
}

} // extern "C"
