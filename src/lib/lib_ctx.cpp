//===-- lib_ctx.cpp - library context implementation ----------------------===//
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
/// Implementation of library context functions.
///
//===----------------------------------------------------------------------===//
#include "lib_ctx.hpp"

#include "config.h"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek/steamclient/cm/msg_payloads/os_type.pb.h"
#include "ws_conn.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <new>
#include <ranges>
#include <shared_mutex>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <utility>
#include <uv.h>

namespace tek::steamclient {

namespace {

using cm::msg_payloads::OsType;

class scope_exit {
  std::function<void()> func;

public:
  constexpr scope_exit(std::function<void()> &&func) noexcept : func{func} {}
  constexpr ~scope_exit() { func(); }
  constexpr void release() noexcept {
    func = {[] {}};
  }
};

//===-- Private functions -------------------------------------------------===//

/// WebSocket connection poll callback.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void ws_poll_cb(uv_poll_t *_Nonnull poll, int status, int events) {
  auto &conn{*reinterpret_cast<ws_conn *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(poll)))};
  if (status < 0) {
    if (status == UV_EBADF) {
      conn.handle_disconnection(TSCI_WS_CLOSE_CODE_ABNORMAL);
    }
    return;
  }
  if (events & (UV_READABLE | UV_DISCONNECT)) {
    if (conn.recv() != CURLE_OK) {
      conn.handle_disconnection(TSCI_WS_CLOSE_CODE_ABNORMAL);
      return;
    }
    if (!conn.connected || (events & UV_DISCONNECT)) {
      return;
    }
  }
  if (events & UV_WRITABLE) {
    if (conn.send() != CURLE_OK) {
      conn.handle_disconnection(TSCI_WS_CLOSE_CODE_ABNORMAL);
    } else if (!(events & UV_WRITABLE)) {
      uv_poll_start(poll, conn.poll_events, ws_poll_cb);
    }
  }
}

/// Process pending curl multi completion messages.
static void process_curl_msgs(lib_ctx &ctx) {
  int num_queued;
  do {
    const auto msg{curl_multi_info_read(ctx.curlm.get(), &num_queued)};
    if (!msg) {
      break;
    }
    ws_conn *conn;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &conn);
    scope_exit rm_handle{[curlm{ctx.curlm.get()}, curl{msg->easy_handle}] {
      curl_multi_remove_handle(curlm, curl);
    }};
    if (msg->data.result != CURLE_OK) {
      conn->handle_connection(msg->data.result);
      continue;
    }
    curl_socket_t sock;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_ACTIVESOCKET, &sock);
    const auto [it, emplaced]{ctx.poll_handles.try_emplace(sock)};
    if (emplaced) {
      if (uv_poll_init_socket(&ctx.loop, &it->second, sock) != 0) {
        conn->handle_connection(CURLE_OUT_OF_MEMORY);
        continue;
      }
    }
    uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&it->second), conn);
    conn->poll_events = UV_READABLE | UV_DISCONNECT;
    if (uv_poll_start(&it->second, conn->poll_events, ws_poll_cb) != 0) {
      conn->handle_connection(CURLE_OUT_OF_MEMORY);
      continue;
    }
    rm_handle.release();
    ++conn->ref_count;
    conn->connected = true;
    conn->handle_connection(CURLE_OK);
  } while (num_queued);
}

/// Libuv event loop async callback.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void async_cb(uv_async_t *_Nonnull async) {
  auto &ctx{*reinterpret_cast<lib_ctx *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(async)))};
  if (ctx.loop_state.load(std::memory_order::relaxed) == loop_state::stopped) {
    uv_stop(&ctx.loop);
    return;
  }
  const std::scoped_lock lock{ctx.conn_mtx};
  while (!ctx.writable_queue.empty()) {
    auto &conn{*ctx.writable_queue.front()};
    for (const std::scoped_lock msg_lock{conn.pending_msgs_mtx};
         auto &msg : conn.pending_msgs) {
      if (msg.timer && !*msg.timer_active) {
        if (uv_timer_init(&ctx.loop, msg.timer) == 0) {
          uv_handle_set_data(reinterpret_cast<uv_handle_t *>(msg.timer),
                             msg.data);
          uv_timer_start(msg.timer, msg.timer_cb, msg.timeout, 0);
          *msg.timer_active = true;
          ++conn.ref_count;
        }
      }
    }
    if (conn.send_expected.load(std::memory_order::relaxed) &&
        !(conn.poll_events & UV_WRITABLE)) {
      conn.poll_events |= UV_WRITABLE;
      curl_socket_t sock;
      curl_easy_getinfo(conn.curl.get(), CURLINFO_ACTIVESOCKET, &sock);
      const auto it{ctx.poll_handles.find(sock)};
      if (it != ctx.poll_handles.end()) {
        uv_poll_start(&it->second, conn.poll_events, ws_poll_cb);
      }
    }
    ctx.writable_queue.pop_front();
  }
  if (ctx.conn_queue.empty()) {
    return;
  }
  while (!ctx.conn_queue.empty()) {
    const scope_exit pop{[&queue{ctx.conn_queue}] { queue.pop_front(); }};
    auto &req{ctx.conn_queue.front()};
    auto &conn{req.conn};
    conn.url = std::move(req.url);
    if (!conn.curl) {
      conn.curl.reset(curl_easy_init());
      if (!conn.curl) {
        conn.handle_connection(CURLE_OUT_OF_MEMORY);
        continue;
      }
      curl_easy_setopt(conn.curl.get(), CURLOPT_PRIVATE, &conn);
      curl_easy_setopt(conn.curl.get(), CURLOPT_CONNECT_ONLY, 2L);
      curl_easy_setopt(conn.curl.get(), CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(conn.curl.get(), CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(conn.curl.get(), CURLOPT_TIMEOUT_MS, req.timeout_ms);
      curl_easy_setopt(conn.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
    }
    curl_easy_setopt(conn.curl.get(), CURLOPT_URL, conn.url.data());
    if (curl_multi_add_handle(ctx.curlm.get(), conn.curl.get()) != CURLM_OK) {
      conn.curl.reset();
      conn.handle_connection(CURLE_FAILED_INIT);
    }
  }
  int running_handles;
  curl_multi_socket_action(ctx.curlm.get(), CURL_SOCKET_TIMEOUT, 0,
                           &running_handles);
  process_curl_msgs(ctx);
}

/// Libuv callback for poll handles used by curl multi.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void poll_cb(uv_poll_t *_Nonnull poll, int status, int events) {
  auto &ctx{*reinterpret_cast<lib_ctx *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(poll)))};
  using val_type = decltype(ctx.poll_handles)::value_type;
  const auto sock{reinterpret_cast<const val_type *>(
                      reinterpret_cast<const unsigned char *>(poll) -
                      offsetof(val_type, second))
                      ->first};
  if (status < 0) {
    int running_handles;
    curl_multi_socket_action(ctx.curlm.get(), sock, CURL_CSELECT_ERR,
                             &running_handles);
    if (status == UV_EBADF) {
      uv_close(reinterpret_cast<uv_handle_t *>(poll), [](auto poll) {
        auto &ctx{*reinterpret_cast<lib_ctx *>(uv_handle_get_data(poll))};
        ctx.poll_handles.erase(
            reinterpret_cast<const val_type *>(
                reinterpret_cast<const unsigned char *>(poll) -
                offsetof(val_type, second))
                ->first);
      });
    }
    return;
  }
  int bitmask{};
  if (events & UV_READABLE) {
    bitmask |= CURL_CSELECT_IN;
  }
  if (events & UV_WRITABLE) {
    bitmask |= CURL_CSELECT_OUT;
  }
  int running_handles;
  curl_multi_socket_action(ctx.curlm.get(), sock, bitmask, &running_handles);
  process_curl_msgs(ctx);
}

/// Libuv callback for timer handle used by curl multi.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void timer_cb(uv_timer_t *_Nonnull timer) {
  auto &ctx{*reinterpret_cast<lib_ctx *>(
      uv_handle_get_data(reinterpret_cast<const uv_handle_t *>(timer)))};
  int running_handles;
  curl_multi_socket_action(ctx.curlm.get(), CURL_SOCKET_TIMEOUT, 0,
                           &running_handles);
  process_curl_msgs(ctx);
}

/// curl multi timer callback.
[[using gnu: nonnull(3), access(read_write, 3)]]
static int curltimer_cb(CURLM *, long timeout_ms, void *_Nonnull clientp) {
  auto &ctx{*reinterpret_cast<lib_ctx *>(clientp)};
  const int res{timeout_ms < 0 ? uv_timer_stop(&ctx.curlm_timer)
                               : uv_timer_start(&ctx.curlm_timer, timer_cb,
                                                timeout_ms, 0)};
  return res == 0 ? 0 : -1;
}

/// curl multi socket callback.
[[using gnu: nonnull(4), access(read_write, 4)]]
static int curlsocket_cb(CURL *, curl_socket_t sock, int what,
                         void *_Nonnull clientp, void *) {
  auto &ctx{*reinterpret_cast<lib_ctx *>(clientp)};
  if (what == CURL_POLL_REMOVE) {
    const auto it{ctx.poll_handles.find(sock)};
    if (it != ctx.poll_handles.end()) {
      const auto data{uv_handle_get_data(
          reinterpret_cast<const uv_handle_t *>(&it->second))};
      if (data == &ctx) {
        uv_poll_stop(&it->second);
      }
      // Otherwise the socket is managed by a ws_conn
    }
    return 0;
  }
  const auto [it, emplaced]{ctx.poll_handles.try_emplace(sock)};
  if (emplaced) {
    if (uv_poll_init_socket(&ctx.loop, &it->second, sock) != 0) {
      return -1;
    }
    uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&it->second), &ctx);
  }
  int events;
  switch (what) {
  case CURL_POLL_IN:
    events = UV_READABLE;
    break;
  case CURL_POLL_OUT:
    events = UV_WRITABLE;
    break;
  case CURL_POLL_INOUT:
    events = UV_READABLE | UV_WRITABLE;
    break;
  default:
    events = 0;
  }
  return uv_poll_start(&it->second, events, poll_cb) == 0 ? 0 : -1;
}

/// Initialize libuv event loop and run it.
///
/// @param [in, out] arg
///    Pointer to the library context to run event loop for.
[[using gnu: nonnull(1), access(read_write, 1)]]
static void event_loop(void *_Nonnull arg) noexcept {
  uv_thread_setname("tsc event loop");
  auto &ctx{*reinterpret_cast<lib_ctx *>(arg)};
  scope_exit fail{[&loop_state{ctx.loop_state}] {
    loop_state.store(loop_state::error, std::memory_order::relaxed);
    tsci_os_futex_wake(reinterpret_cast<std::atomic_uint32_t *>(&loop_state));
  }};
  if (uv_loop_init(&ctx.loop) != 0) {
    return;
  }
  const scope_exit loop_close{[&loop{ctx.loop}] {
    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
  }};
  if (uv_async_init(&ctx.loop, &ctx.loop_async, async_cb) != 0) {
    return;
  }
  const scope_exit async_close{[&async{ctx.loop_async}] {
    uv_close(reinterpret_cast<uv_handle_t *>(&async), nullptr);
  }};
  uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&ctx.loop_async), &ctx);
  if (uv_timer_init(&ctx.loop, &ctx.curlm_timer) != 0) {
    return;
  }
  const scope_exit timer_close{[&timer{ctx.curlm_timer}] {
    uv_close(reinterpret_cast<uv_handle_t *>(&timer), nullptr);
  }};
  uv_handle_set_data(reinterpret_cast<uv_handle_t *>(&ctx.curlm_timer), &ctx);
  ctx.curlm.reset(curl_multi_init());
  if (!ctx.curlm) {
    return;
  }
  curl_multi_setopt(ctx.curlm.get(), CURLMOPT_SOCKETDATA, &ctx);
  curl_multi_setopt(ctx.curlm.get(), CURLMOPT_TIMERDATA, &ctx);
  curl_multi_setopt(ctx.curlm.get(), CURLMOPT_SOCKETFUNCTION, curlsocket_cb);
  curl_multi_setopt(ctx.curlm.get(), CURLMOPT_TIMERFUNCTION, curltimer_cb);
  fail.release();
  ctx.loop_state.store(loop_state::running, std::memory_order::relaxed);
  tsci_os_futex_wake(reinterpret_cast<std::atomic_uint32_t *>(&ctx.loop_state));
  uv_run(&ctx.loop, UV_RUN_DEFAULT);
}

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
#elifdef __linux__ // def _WIN32
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
#elifdef __APPLE__ // def _WIN32 elifdef __linux__
  switch (version.major) {
  case 22:
    return OsType::OS_TYPE_MAC_OS_13;
  case 23:
    return OsType::OS_TYPE_MAC_OS_14;
  case 24:
    return OsType::OS_TYPE_MAC_OS_15;
  default:
    return OsType::OS_TYPE_MAC_OS_UNKNOWN;
  }
#endif             // def _WIN32 elifdef __linux__ elifdef __APPLE__
}

} // namespace

} // namespace tek::steamclient

//===-- Public functions --------------------------------------------------===//

using namespace tek::steamclient;

extern "C" {

tek_sc_lib_ctx *tek_sc_lib_init(bool, bool) {
  // Initialize libcurl and allocate the context
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    return nullptr;
  }
  scope_exit curl_cleanup{curl_global_cleanup};
  std::unique_ptr<tek_sc_lib_ctx> ctx{new (std::nothrow) tek_sc_lib_ctx()};
  if (!ctx) {
    return nullptr;
  }
  // Create the event loop thread
  if (uv_thread_create(&ctx->loop_thread, event_loop, ctx.get()) != 0) {
    return nullptr;
  }
  tsci_os_futex_wait(reinterpret_cast<std::atomic_uint32_t *>(&ctx->loop_state),
                     static_cast<std::uint32_t>(loop_state::stopped), 3000);
  if (ctx->loop_state.load(std::memory_order::relaxed) == loop_state::error) {
    uv_thread_join(&ctx->loop_thread);
    return nullptr;
  }
  scope_exit stop_loop{[&ctx{*ctx.get()}] {
    ctx.loop_state.store(loop_state::stopped, std::memory_order::relaxed);
    uv_async_send(&ctx.loop_async);
    uv_thread_join(&ctx.loop_thread);
  }};
  ctx->os_type = get_os_type();
  // Get cache file path
  std::unique_ptr<tek_sc_os_char, decltype(&std::free)> cache_dir{
      tsci_os_get_cache_dir(), std::free};
  if (!cache_dir) {
    return nullptr;
  }
  const int cache_dir_len{tsci_os_pstr_strlen(cache_dir.get())};
  std::string cache_file_path;
  constexpr std::string_view cache_file_rel_path{
      TSCI_OS_PATH_SEP_CHAR_STR "tek-steamclient" TSCI_OS_PATH_SEP_CHAR_STR
                                "cache.sqlite3"};
  cache_file_path.reserve(cache_dir_len + cache_file_rel_path.length());
  cache_file_path.resize(cache_dir_len);
  tsci_os_pstr_to_str(cache_dir.get(), cache_file_path.data());
  cache_file_path.append(cache_file_rel_path);
  // Open the database connection
  sqlite3 *db_ptr;
  int res{sqlite3_open_v2(cache_file_path.data(), &db_ptr,
                          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr)};
  if (res != SQLITE_OK) {
    if (db_ptr) {
      sqlite3_close_v2(db_ptr);
    }
    if (res != SQLITE_CANTOPEN) {
      return nullptr;
    }
    // Most likely the parent directory doesn't exist yet, create the cache
    //    directory and its tek-steamclient subdirectory if they are missing
    const auto cache_dir_handle{tsci_os_dir_create(cache_dir.get())};
    if (cache_dir_handle == TSCI_OS_INVALID_HANDLE) {
      return nullptr;
    }
    const auto tsc_subdir_handle{tsci_os_dir_create_at(
        cache_dir_handle, TEK_SC_OS_STR("tek-steamclient"))};
    tsci_os_close_handle(cache_dir_handle);
    if (tsc_subdir_handle == TSCI_OS_INVALID_HANDLE) {
      return nullptr;
    }
    tsci_os_close_handle(tsc_subdir_handle);
    // Try opening the database connection again
    if (sqlite3_open_v2(cache_file_path.data(), &db_ptr,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        nullptr) != SQLITE_OK) {
      if (db_ptr) {
        sqlite3_close_v2(db_ptr);
      }
      return nullptr;
    }
  }
  cache_dir.reset();
  ctx->cache.reset(db_ptr);
  const auto db{ctx->cache.get()};
  if (sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
    return ctx.release();
  }
  sqlite3_stmt *stmt_ptr;
  // Get CM server list
  std::string_view query{"SELECT hostname, port FROM cm_servers"};
  if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
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
    ctx->cm_servers_iter = ctx->cm_servers.cbegin();
  }
  // Get depot keys
  query = "SELECT depot_id, key FROM depot_keys";
  if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
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
  if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
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
  if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
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
  sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
  stop_loop.release();
  curl_cleanup.release();
  return ctx.release();
}

void tek_sc_lib_cleanup(tek_sc_lib_ctx *ctx) {
  ctx->loop_state.store(loop_state::stopped, std::memory_order::relaxed);
  uv_async_send(&ctx->loop_async);
  uv_thread_join(&ctx->loop_thread);
  const auto dirty_flags{static_cast<dirty_flag>(
      ctx->dirty_flags.load(std::memory_order::relaxed))};
  if (dirty_flags != dirty_flag::none) {
    const auto db{ctx->cache.get()};
    if (sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
      goto skip_file_cache;
    }
    sqlite3_stmt *stmt_ptr;
    if ((dirty_flags & dirty_flag::cm_servers) &&
        sqlite3_exec(db,
                     "CREATE TABLE IF NOT EXISTS cm_servers (hostname TEXT NOT "
                     "NULL, port INTEGER, UNIQUE(hostname, port))",
                     nullptr, nullptr, nullptr) == SQLITE_OK &&
        sqlite3_exec(db, "DELETE FROM cm_servers", nullptr, nullptr, nullptr) ==
            SQLITE_OK) {
      // Write CM server list
      constexpr std::string_view query{
          "INSERT INTO cm_servers (hostname, port) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                             nullptr) == SQLITE_OK) {
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
          const int res{sqlite3_step(stmt.get())};
          if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
            break;
          }
          sqlite3_reset(stmt.get());
          sqlite3_clear_bindings(stmt.get());
        }
      }
    }
    if ((dirty_flags & dirty_flag::depot_keys) &&
        sqlite3_exec(db,
                     "CREATE TABLE IF NOT EXISTS depot_keys (depot_id INTEGER "
                     "PRIMARY KEY UNIQUE, key BLOB)",
                     nullptr, nullptr, nullptr) == SQLITE_OK) {
      // Write depot keys
      constexpr std::string_view query{
          "INSERT INTO depot_keys (depot_id, key) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                             nullptr) == SQLITE_OK) {
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
          const int res{sqlite3_step(stmt.get())};
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
        sqlite3_exec(db,
                     "CREATE TABLE IF NOT EXISTS s3_servers (url TEXT UNIQUE, "
                     "timestamp INTEGER)",
                     nullptr, nullptr, nullptr) == SQLITE_OK &&
        sqlite3_exec(
            db,
            "CREATE TABLE IF NOT EXISTS s3_cache (app_id INTEGER, "
            "depot_id INTEGER, srv_index INTEGER, UNIQUE(depot_id, srv_index))",
            nullptr, nullptr, nullptr) == SQLITE_OK) {
      sqlite3_exec(db, "DELETE FROM s3_servers", nullptr, nullptr, nullptr);
      sqlite3_exec(db, "DELETE FROM s3_cache", nullptr, nullptr, nullptr);
      // Write tek-s3 servers and cache
      std::string_view query{
          "INSERT INTO s3_servers (url, timestamp) VALUES (?, ?)"};
      if (sqlite3_prepare_v2(db, query.data(), query.length() + 1, &stmt_ptr,
                             nullptr) == SQLITE_OK) {
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
          const int res{sqlite3_step(srv_stmt.get())};
          if (res != SQLITE_DONE && res != SQLITE_CONSTRAINT) {
            break;
          }
          if (res == SQLITE_DONE) {
            const auto row_index{sqlite3_last_insert_rowid(db) - 1};
            query = "INSERT INTO s3_cache (app_id, depot_id, srv_index) VALUES "
                    "(?, ?, ?)";
            if (sqlite3_prepare_v2(db, query.data(), query.length() + 1,
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
                  const int res{sqlite3_step(cache_stmt.get())};
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
    sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
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
