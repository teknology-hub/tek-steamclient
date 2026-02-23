//===-- lib_ctx.hpp - internal library context definitions ----------------===//
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
/// Definitions of @ref tek_sc_lib_ctx structure and related types to be used by
///    library implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h"

#include "config.h" // IWYU pragma: keep
#include "tek/steamclient/cm/msg_payloads/os_type.pb.h"
#include "ws_conn.hpp"

#include <atomic>
#include <cstdint>
#ifdef TEK_SCB_S3C
#include <ctime>
#endif // def TEK_SCB_S3C
#include <curl/curl.h>
#include <map>
#include <memory>
#include <mutex>
#include <sqlite3.h>
#include <string>
#include <uv.h>
#include <vector>

namespace tek::steamclient {

using lib_ctx = tek_sc_lib_ctx;

/// libuv event loop state values.
enum class loop_state : std::uint32_t {
  /// The event loop hasn't been started yet, or should be stopped ASAP.
  stopped,
  /// The event loop is currently running.
  running,
  /// An error has occurred when setting up the event loop.
  error
};

/// Flags indicating which cache fields have changed and should be written back
///    to the cache file.
enum class [[clang::flag_enum]] dirty_flag {
  /// No fields have changed.
  none,
  /// `cm_servers` has changed.
  cm_servers = 1 << 0,
#ifdef TEK_SCB_S3C
  /// `s3_servers` and/or `s3_cache` have changed.
  s3 = 1 << 2
#endif // def TEK_SCB_S3C
};

constexpr bool operator&(dirty_flag left, dirty_flag right) noexcept {
  return static_cast<int>(left) & static_cast<int>(right);
}

/// Steam CM server entry.
struct cm_server {
  /// UTF-8 hostname of the server.
  std::string hostname;
  /// Port number at which the server listens for WebSocket connections.
  int port;
};

/// WebSocket connection request.
struct ws_conn_request {
  /// Instance to connect.
  ws_conn &conn;
  /// UTF-8 URL of the WebSocket server to connect to.
  std::string url;
  /// Timeout for the connection attempt, in milliseconds.
  long timeout_ms;
};

#ifdef TEK_SCB_S3C
namespace s3c {

/// tek-s3 server entry.
struct server {
  /// UTF-8 URL of the server.
  std::string url;
  /// Timestamp of the last manifest update for the server.
  std::time_t timestamp;
};

/// tek-s3 cache entry.
struct cache_entry {
  /// Servers that can provide manifest request codes for given app and depot
  ///    ID.
  std::vector<server *> servers;
  /// Current interator into @ref servers.
  decltype(servers)::const_iterator it;
};

} // namespace s3c
#endif // def TEK_SCB_S3C

} // namespace tek::steamclient

using namespace tek::steamclient;

/// @copydoc tek_sc_lib_ctx
struct tek_sc_lib_ctx {
  /// Futex indicating current libuv event loop state.
  std::atomic<loop_state> state{loop_state::stopped};
  /// Cached OS type value.
  cm::msg_payloads::OsType os_type;
  /// curl multi handle used for establishing WebSocket connections.
  std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> curlm{
      nullptr, curl_multi_cleanup};
  /// Map of per-socket libuv poll handles.
  std::map<uv_os_sock_t, uv_poll_t> poll_handles;
  /// WebSocket connection request queue.
  std::deque<ws_conn_request> conn_queue;
  /// Queue of WebSocket connections that need to enable polling for writable
  ///    event
  std::deque<ws_conn *> writable_queue;
  /// Mutex locking concurrent access to @ref conn_queue and
  ///    @ref writable_queue.
  std::mutex conn_mtx;
  /// Cached list of Steam CM servers.
  std::vector<cm_server> cm_servers;
  /// Iterator pointing to the next CM server to use for connection
  decltype(cm_servers)::const_iterator cm_servers_iter;
  /// Mutex locking concurrent access to @ref cm_servers and
  ///    @ref cm_servers_iter.
  std::mutex cm_servers_mtx;
  /// Cache database connection handle.
  std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> cache{nullptr,
                                                              sqlite3_close_v2};
#ifdef TEK_SCB_S3C
  /// Known tek-s3u server URLs.
  std::vector<std::string> s3u_servers;
  /// Iterator pointing to the next tek-s3u server to use.
  decltype(s3u_servers)::const_iterator s3u_servers_it;
  /// Known tek-s3 servers.
  std::vector<s3c::server> s3_servers;
  /// Map of app and depot IDs to tek-s3 server entries that can provide
  ///    manifest request codes for the depot.
  std::map<std::uint32_t, std::map<std::uint32_t, s3c::cache_entry>> s3_cache;
  /// Mutex locking concurrent access to @ref s3u_servers, @ref s3u_servers_it,
  ///    @ref s3_servers and @ref s3_cache.
  std::mutex s3_mtx;
#endif // def TEK_SCB_S3C
  /// Flags indicating which cache fields have changed and should be written
  ///    back to the cache file. Holds a @ref tek::steamclient::dirty_flag
  ///    value.
  std::atomic_int dirty_flags;
  /// Pre-checked value indicating whether loaded libcurl supports WSS protocol.
  bool wss_supported;
  /// libuv event loop running CM clients.
  uv_loop_t loop;
  /// Async handle for interrupting @ref loop to stop it or initiate
  /// connections.
  uv_async_t loop_async;
  /// Timer that runs @ref curlm's timeouts.
  uv_timer_t curlm_timer;
  /// Thread that creates and runs the libuv event loop.
  uv_thread_t loop_thread;
};
