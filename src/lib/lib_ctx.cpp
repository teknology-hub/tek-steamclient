//===-- lib_ctx.cpp - library context implementation ----------------------===//
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
/// Implementation of library context functions.
///
//===----------------------------------------------------------------------===//
#include "lib_ctx.hpp"

#include "cm.hpp"
#include "config.h"
#include "os.h"
#ifdef TEK_SCB_S3C
#include "s3c.hpp"
#endif // def TEK_SCB_S3C
#include "tek-steamclient/base.h"
#include "tek/steamclient/cm/msg_payloads/os_type.pb.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <functional>
#include <libwebsockets.h>
#include <memory>
#include <new>
#include <ranges>
#include <shared_mutex>
#include <sqlite3.h>
#include <string>
#include <string_view>

namespace tek::steamclient {

namespace {

using cm::msg_payloads::OsType;

/// Path to the library cache file relative to the OS user cache directory.
static constexpr std::string_view cache_file_rel_path{
    TSCI_OS_PATH_SEP_CHAR_STR "tek-steamclient" TSCI_OS_PATH_SEP_CHAR_STR
                              "cache.sqlite3"};

/// permessage-deflate WebSocket extension object.
static constexpr lws_extension ws_pm_ext[]{
    {.name = "permessage-deflate",
     .callback = lws_extension_callback_pm_deflate,
     .client_offer = "client_no_context_takeover; server_no_context_takeover; "
                     "client_max_window_bits"},
    {}};

//===-- Private functions -------------------------------------------------===//

/// Determine Steam's OS type value based on fetched OS version.
/// @return An OS type value.
static OsType get_os_type() noexcept {
  const auto version{tsci_os_get_version()};
#ifdef _WIN32
  switch (version.major) {
  case 10:
    return version.build >= 22000 ? OsType::OS_TYPE_WIN_11
                                  : OsType::OS_TYPE_WINDOWS_10;
  default:
    return OsType::OS_TYPE_WIN_UNKNOWN;
  }
#elifdef __linux__
  switch (version.major) {
  case 4:
    switch (version.minor) {
    case 14:
      return OsType::OS_TYPE_LINUX_414;
    case 19:
      return OsType::OS_TYPE_LINUX_419;
    default:
      return OsType::OS_TYPE_LINUX_4X;
    }
  case 5:
    switch (version.minor) {
    case 10:
      return OsType::OS_TYPE_LINUX_510;
    default:
      return OsType::OS_TYPE_LINUX_5X;
    }
  case 6:
    return OsType::OS_TYPE_LINUX_6X;
  case 7:
    return OsType::OS_TYPE_LINUX_7X;
  default:
    return OsType::OS_TYPE_LINUX_UNKNOWN;
  }
#endif // ifdef _WIN32 elifdef __linux__
}

/// Initialize libwebsockets and run its event loop.
///
/// @param [in, out] lib_ctx
///    Library context owning the libwebsockets context.
static void tsc_lws_loop(tek_sc_lib_ctx &lib_ctx) noexcept {
  tsci_os_set_thread_name(TEK_SC_OS_STR("tsc lws loop"));
  lws_context_creation_info info{};
  info.extensions = ws_pm_ext;
  info.port = CONTEXT_PORT_NO_LISTEN;
  info.timeout_secs = 10;
  info.connect_timeout_secs = 5;
  // Try to use libuv for better event loop performance
  info.options = LWS_SERVER_OPTION_LIBUV | LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  info.user = &lib_ctx;
#ifdef TEK_SCB_S3C
  const lws_protocols *pprotocols[]{&cm::protocol, &s3c::protocol, nullptr};
#else  // #def TEK_SCB_S3C
  const lws_protocols *pprotocols[]{&cm::protocol, nullptr};
#endif // #def TEK_SCB_S3C else
  info.pprotocols = pprotocols;
  lib_ctx.lws_ctx = lws_create_context(&info);
  if (!lib_ctx.lws_ctx) {
    // Probably libwebsockets was compiled without libuv support, try
    //    disabling it
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    lib_ctx.lws_ctx = lws_create_context(&info);
  }
  lib_ctx.lws_init.store(1, std::memory_order::release);
  tsci_os_futex_wake(&lib_ctx.lws_init);
  if (!lib_ctx.lws_ctx) {
    return;
  }
  while (!lws_service(lib_ctx.lws_ctx, 0))
    ;
}

} // namespace

//===-- Public functions --------------------------------------------------===//

extern "C" {

tek_sc_lib_ctx *tek_sc_lib_init(bool use_file_cache, bool disable_lws_logs) {
  // Initialize libcurl, libwebsockets, and allocate the context
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    return nullptr;
  }
  if (disable_lws_logs) {
    lws_set_log_level(0, nullptr);
  }
  const auto ctx{new (std::nothrow) tek_sc_lib_ctx()};
  if (!ctx) {
    curl_global_cleanup();
    return nullptr;
  }
  ctx->lws_thread = std::thread{&tsc_lws_loop, std::ref(*ctx)};
  tsci_os_futex_wait(&ctx->lws_init, 0, 3000);
  if (!ctx->lws_ctx) {
    if (ctx->lws_thread.joinable()) {
      ctx->lws_thread.join();
    }
    delete ctx;
    curl_global_cleanup();
    return nullptr;
  }
  ctx->use_file_cache = use_file_cache;
  ctx->os_type = get_os_type();
  if (!use_file_cache) {
    return ctx;
  }
  // Get cache file path
  const auto cache_dir{tsci_os_get_cache_dir()};
  if (!cache_dir) {
    return ctx;
  }
  const int cache_dir_len{tsci_os_pstr_strlen(cache_dir)};
  std::string cache_file_path;
  cache_file_path.reserve(cache_dir_len + cache_file_rel_path.length());
  cache_file_path.resize(cache_dir_len);
  tsci_os_pstr_to_str(cache_dir, cache_file_path.data());
  std::free(cache_dir);
  cache_file_path.append(cache_file_rel_path);
  // Open the database connection
  sqlite3 *db_ptr;
  if (sqlite3_open_v2(cache_file_path.data(), &db_ptr, SQLITE_OPEN_READONLY,
                      nullptr) != SQLITE_OK) {
    if (db_ptr) {
      sqlite3_close_v2(db_ptr);
    }
    return ctx;
  }
  const std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> db{
      db_ptr, sqlite3_close_v2};
  if (sqlite3_exec(db.get(), "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
    return ctx;
  }
  sqlite3_stmt *stmt_ptr;
  // Get CM server list
  std::string_view query{"SELECT hostname, port FROM cm_servers"};
  if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1, &stmt_ptr,
                         nullptr) == SQLITE_OK) {
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
        stmt_ptr, sqlite3_finalize};
    for (int res{sqlite3_step(stmt.get())}; res == SQLITE_ROW;
         res = sqlite3_step(stmt.get())) {
      ctx->cm_servers.emplace_back(
          std::string{
              reinterpret_cast<const char *>(
                  sqlite3_column_text(stmt.get(), 0)),
              static_cast<std::size_t>(sqlite3_column_bytes(stmt.get(), 0))},
          sqlite3_column_int(stmt.get(), 1));
    }
    ctx->cm_servers.shrink_to_fit();
  }
  // Get depot keys
  query = "SELECT depot_id, key FROM depot_keys";
  if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1, &stmt_ptr,
                         nullptr) == SQLITE_OK) {
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
        stmt_ptr, sqlite3_finalize};
    for (int res{sqlite3_step(stmt.get())}; res == SQLITE_ROW;
         res = sqlite3_step(stmt.get())) {
      auto &key{ctx->depot_keys[static_cast<std::uint32_t>(
          sqlite3_column_int(stmt.get(), 0))]};
      std::memcpy(key, sqlite3_column_blob(stmt.get(), 1), sizeof key);
    }
  }
#ifdef TEK_SCB_S3C
  // Get tek-s3 servers
  query = "SELECT url, timestamp FROM s3_servers ORDER BY rowid";
  if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1, &stmt_ptr,
                         nullptr) == SQLITE_OK) {
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
        stmt_ptr, sqlite3_finalize};
    for (int res{sqlite3_step(stmt.get())}; res == SQLITE_ROW;
         res = sqlite3_step(stmt.get())) {
      ctx->s3_servers.emplace_back(
          std::string{
              reinterpret_cast<const char *>(
                  sqlite3_column_text(stmt.get(), 0)),
              static_cast<std::size_t>(sqlite3_column_bytes(stmt.get(), 0))},
          static_cast<std::time_t>(sqlite3_column_int64(stmt.get(), 1)));
    }
  }
  // Get tek-s3 cache
  query = "SELECT app_id, depot_id, srv_index FROM s3_cache";
  if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1, &stmt_ptr,
                         nullptr) == SQLITE_OK) {
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt{
        stmt_ptr, sqlite3_finalize};
    for (int res{sqlite3_step(stmt.get())}; res == SQLITE_ROW;
         res = sqlite3_step(stmt.get())) {
      ctx->s3_cache[static_cast<std::uint32_t>(sqlite3_column_int(
          stmt.get(),
          0))][static_cast<std::uint32_t>(sqlite3_column_int(stmt.get(), 1))]
          .servers.emplace_back(
              &ctx->s3_servers[sqlite3_column_int64(stmt.get(), 2)]);
    }
  }
  for (auto &app : ctx->s3_cache | std::views::values) {
    for (auto &depot : app | std::views::values) {
      depot.it = depot.servers.cbegin();
    }
  }
#endif // def TEK_SCB_S3C
  sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr);
  return ctx;
}

void tek_sc_lib_cleanup(tek_sc_lib_ctx *ctx) {
  ctx->cleanup_requested.store(true, std::memory_order::relaxed);
  lws_cancel_service(ctx->lws_ctx);
  if (ctx->lws_thread.joinable()) {
    ctx->lws_thread.join();
  }
  const auto dirty_flags{static_cast<dirty_flag>(
      ctx->dirty_flags.load(std::memory_order::relaxed))};
  if (ctx->use_file_cache && dirty_flags != dirty_flag::none) {
    // Get cache file path
    std::unique_ptr<tek_sc_os_char, decltype(&std::free)> cache_dir{
        tsci_os_get_cache_dir(), std::free};
    if (!cache_dir) {
      goto skip_file_cache;
    }
    const int cache_dir_len{tsci_os_pstr_strlen(cache_dir.get())};
    std::string cache_file_path;
    cache_file_path.reserve(cache_dir_len + cache_file_rel_path.length());
    cache_file_path.resize(cache_dir_len);
    tsci_os_pstr_to_str(cache_dir.get(), cache_file_path.data());
    cache_file_path.append(cache_file_rel_path);
    // Open the database connection
    sqlite3 *db_ptr;
    int res{sqlite3_open_v2(cache_file_path.data(), &db_ptr,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            nullptr)};
    if (res != SQLITE_OK) {
      if (db_ptr) {
        sqlite3_close_v2(db_ptr);
      }
      if (res != SQLITE_CANTOPEN) {
        goto skip_file_cache;
      }
      // Most likely the parent directory doesn't exist yet, create the cache
      //    directory and its tek-steamclient subdirectory if they are missing
      const auto cache_dir_handle{tsci_os_dir_create(cache_dir.get())};
      if (cache_dir_handle == TSCI_OS_INVALID_HANDLE) {
        goto skip_file_cache;
      }
      const auto tsc_subdir_handle{tsci_os_dir_create_at(
          cache_dir_handle, TEK_SC_OS_STR("tek-steamclient"))};
      tsci_os_close_handle(cache_dir_handle);
      if (tsc_subdir_handle == TSCI_OS_INVALID_HANDLE) {
        goto skip_file_cache;
      }
      tsci_os_close_handle(tsc_subdir_handle);
      // Try opening the database connection again
      if (sqlite3_open_v2(cache_file_path.data(), &db_ptr,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                          nullptr) != SQLITE_OK) {
        if (db_ptr) {
          sqlite3_close_v2(db_ptr);
        }
        goto skip_file_cache;
      }
    }
    cache_dir.reset();
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> db{
        db_ptr, sqlite3_close_v2};
    if (sqlite3_exec(db.get(), "BEGIN", nullptr, nullptr, nullptr) !=
        SQLITE_OK) {
      goto skip_file_cache;
    }
    sqlite3_stmt *stmt_ptr;
    if ((dirty_flags & dirty_flag::cm_servers) &&
        sqlite3_exec(db.get(),
                     "CREATE TABLE IF NOT EXISTS cm_servers (hostname TEXT NOT "
                     "NULL, port INTEGER, UNIQUE(hostname, port))",
                     nullptr, nullptr, nullptr) == SQLITE_OK) {
      // Write CM server list
      constexpr std::string_view query{
          "INSERT INTO cm_servers (hostname, port) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1,
                             &stmt_ptr, nullptr) == SQLITE_OK) {
        for (const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>
                 stmt{stmt_ptr, sqlite3_finalize};
             const auto &server : ctx->cm_servers) {
          if (sqlite3_bind_text(stmt.get(), 1, server.hostname.data(),
                                server.hostname.length(),
                                SQLITE_STATIC) != SQLITE_OK) {
            break;
          }
          if (sqlite3_bind_int(stmt.get(), 2, server.port) != SQLITE_OK) {
            break;
          }
          res = sqlite3_step(stmt.get());
          if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
            break;
          }
          sqlite3_reset(stmt.get());
          sqlite3_clear_bindings(stmt.get());
        }
      }
    }
    if ((dirty_flags & dirty_flag::depot_keys) &&
        sqlite3_exec(db.get(),
                     "CREATE TABLE IF NOT EXISTS depot_keys (depot_id INTEGER "
                     "PRIMARY KEY UNIQUE, key BLOB)",
                     nullptr, nullptr, nullptr) == SQLITE_OK) {
      // Write depot keys
      constexpr std::string_view query{
          "INSERT INTO depot_keys (depot_id, key) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1,
                             &stmt_ptr, nullptr) == SQLITE_OK) {
        for (const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>
                 stmt{stmt_ptr, sqlite3_finalize};
             const auto &[depot_id, key] : ctx->depot_keys) {
          if (sqlite3_bind_int(stmt.get(), 1, static_cast<int>(depot_id)) !=
              SQLITE_OK) {
            break;
          }
          if (sqlite3_bind_blob(stmt.get(), 2, key, sizeof key,
                                SQLITE_STATIC) != SQLITE_OK) {
            break;
          }
          res = sqlite3_step(stmt.get());
          if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
            break;
          }
          sqlite3_reset(stmt.get());
          sqlite3_clear_bindings(stmt.get());
        }
      }
    }
#ifdef TEK_SCB_S3C
    if ((dirty_flags & dirty_flag::s3) &&
        sqlite3_exec(db.get(),
                     "CREATE TABLE IF NOT EXISTS s3_servers (url TEXT UNIQUE, "
                     "timestamp INTEGER)",
                     nullptr, nullptr, nullptr) == SQLITE_OK &&
        sqlite3_exec(
            db.get(),
            "CREATE TABLE IF NOT EXISTS s3_cache (app_id INTEGER, "
            "depot_id INTEGER, srv_index INTEGER, UNIQUE(depot_id, srv_index))",
            nullptr, nullptr, nullptr) == SQLITE_OK) {
      sqlite3_exec(db.get(), "DELETE FROM s3_servers", nullptr, nullptr,
                   nullptr);
      sqlite3_exec(db.get(), "DELETE FROM s3_cache", nullptr, nullptr, nullptr);
      // Write tek-s3 servers and cache
      std::string_view query{
          "INSERT INTO s3_servers (url, timestamp) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1,
                             &stmt_ptr, nullptr) == SQLITE_OK) {
        for (const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>
                 srv_stmt{stmt_ptr, sqlite3_finalize};
             const auto &server : ctx->s3_servers) {
          if (sqlite3_bind_text(srv_stmt.get(), 1, server.url.data(),
                                server.url.length(),
                                SQLITE_STATIC) != SQLITE_OK) {
            break;
          }
          if (sqlite3_bind_int64(
                  srv_stmt.get(), 2,
                  static_cast<sqlite3_int64>(server.timestamp)) != SQLITE_OK) {
            break;
          }
          res = sqlite3_step(srv_stmt.get());
          if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
            break;
          }
          if (res == SQLITE_DONE) {
            const auto row_index{sqlite3_last_insert_rowid(db.get()) - 1};
            query = "INSERT INTO s3_cache (app_id, depot_id, srv_index) VALUES "
                    "(?, ?, ?)";
            if (sqlite3_prepare_v2(db.get(), query.data(), query.length() + 1,
                                   &stmt_ptr, nullptr) == SQLITE_OK) {
              for (const std::unique_ptr<sqlite3_stmt,
                                         decltype(&sqlite3_finalize)>
                       cache_stmt{stmt_ptr, sqlite3_finalize};
                   const auto &[app_id, depots] : ctx->s3_cache) {
                for (const auto &[depot_id, srvs] : depots) {
                  if (!std::ranges::contains(srvs.servers, &server)) {
                    continue;
                  }
                  if (sqlite3_bind_int(cache_stmt.get(), 1,
                                       static_cast<int>(app_id)) != SQLITE_OK) {
                    break;
                  }
                  if (sqlite3_bind_int(cache_stmt.get(), 2,
                                       static_cast<int>(depot_id)) !=
                      SQLITE_OK) {
                    break;
                  }
                  if (sqlite3_bind_int64(cache_stmt.get(), 3, row_index) !=
                      SQLITE_OK) {
                    break;
                  }
                  res = sqlite3_step(cache_stmt.get());
                  if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
                    break;
                  }
                  sqlite3_reset(cache_stmt.get());
                  sqlite3_clear_bindings(cache_stmt.get());
                }
              }
            }
          } // if (res == SQLITE_DONE)
          sqlite3_reset(srv_stmt.get());
          sqlite3_clear_bindings(srv_stmt.get());
        } // for (const auto &server : ctx->s3_servers)
      } // srv_stmt scope
    } // Writing s3_servers and s3_cache scope
#endif // TEK_SCB_S3C
    sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr);
  } // if (ctx->use_file_cache && dirty_flags != dirty_flag::none)
skip_file_cache:
  curl_global_cleanup();
  delete ctx;
}

const char *tek_sc_version(void) { return TEK_SC_VERSION; }

bool tek_sc_lib_get_depot_key(tek_sc_lib_ctx *lib_ctx, uint32_t depot_id,
                              tek_sc_aes256_key key) {
  const std::shared_lock lock{lib_ctx->depot_keys_mtx};
  const auto it{lib_ctx->depot_keys.find(depot_id)};
  if (it == lib_ctx->depot_keys.cend()) {
    return false;
  }
  std::ranges::copy(it->second, key);
  return true;
}

} // extern "C"

} // namespace tek::steamclient
