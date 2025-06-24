//===-- lib_ctx.hpp - internal library context definitions ----------------===//
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
/// Definitions of @ref tek_sc_lib_ctx structure and related types to be used by
///    library implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h"

#include "config.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "tek/steamclient/cm/msg_payloads/os_type.pb.h"

#include <atomic>
#include <cstdint>
#ifdef TEK_SCB_S3C
#include <ctime>
#endif // def TEK_SCB_S3C
#include <forward_list>
#include <libwebsockets.h>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace tek::steamclient {

/// Flags indicating which cache fields have changed and should be written back
///    to the cache file.
enum class [[clang::flag_enum]] dirty_flag {
  /// No fields have changed.
  none,
  /// `cm_servers` has changed.
  cm_servers = 1 << 0,
  /// `depot_keys` has changed.
  depot_keys = 1 << 1,
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

#ifdef TEK_SCB_S3C
namespace s3c {

/// tek-s3 authentication types.
enum class auth_type {
  /// Credentials-based authentication.
  credentials,
  /// QR code-based authentication.
  qr
};

/// Types of pedning outgoing messages.
enum class pending_msg_type {
  /// No messages are pending.
  none,
  /// Initial message specifying authentication type, and credentials for
  ///    credentials-based sessions.
  init,
  /// Confirmation code message.
  code,
  /// Disconnect from the server.
  disconnect
};

/// tek-s3 server entry.
struct server {
  /// UTF-8 URL of the server.
  std::string url;
  /// Timestamp of the last manifest update for the server.
  std::time_t timestamp;
};

/// tek-s3 authentication WebSocket connection context.
struct ws_ctx {
  /// Doubly linked list element for libwebsockets timeout scheduling.
  lws_sorted_usec_list_t sul;
  /// Value indicating whether @ref sul has been scheduled yet.
  bool sul_scheduled;
  /// Value indicating whether there is ongoing auth session.
  std::atomic_bool busy;
  /// Value indicating whether the connection parameters are ready for
  ///    submission.
  std::atomic_bool ready;
  /// Value indicating whether to use TLS security.
  bool use_tls;
  /// Authentication type to request.
  auth_type type;
  /// Hostname of the server to connect to, as a null-terminated UTF-8 string.
  char *_Nonnull host;
  /// URL path part, as a null-terminated UTF-8 string.
  char *_Nonnull path;
  /// Port number at which the server listens for WebSocket connections.
  int port;
  /// Type of currently pending message.
  std::atomic<pending_msg_type> pending;
  /// Steam account name (login), as a UTF-8 string.
  std::string account_name;
  /// Steam account password, as a UTF-8 string.
  std::string password;
  /// Steam Guard code to submit, as a UTF-8 string.
  std::string code;
  /// Steam Guard confirmation type that @ref code belongs to.
  tek_sc_cm_auth_confirmation_type code_type;
  /// The maximum amount of time the session is allowed to take, in
  ///     milliseconds.
  long timeout_ms;
  /// Pointer to the callback function.
  tek_sc_cm_callback_func *_Nullable cb;
  /// Pointer that will be passed to @p cb.
  void *_Nullable user_data;
  /// WebSocket instance pointer.
  lws *_Nullable wsi;
  /// Result codes of the auth session.
  tek_sc_err result;
};

} // namespace s3c
#endif // def TEK_SCB_S3C

} // namespace tek::steamclient

/// @copydoc tek_sc_lib_ctx
struct tek_sc_lib_ctx {
  /// libwebsockets context, responsible for all WebSocket connections related
  ///    to the library context.
  lws_context *_Nonnull lws_ctx;
  /// Value indicating whether @ref lws_thread should destroy @ref lws_ctx and
  ///    exit as soon as it can.
  std::atomic_bool cleanup_requested;
  /// Value indicating whether @ref tek_sc_lib_cleanup should attempt saving
  ///    cached data to a file.
  bool use_file_cache;
  /// CM client instances assinged to the context.
  std::forward_list<tek_sc_cm_client *> cm_clients;
  /// Mutex locking concurrent access to @ref cm_clients.
  std::recursive_mutex cm_clients_mtx;
  /// Cached list of Steam CM servers.
  std::vector<tek::steamclient::cm_server> cm_servers;
  /// Mutex locking concurrent access to @ref cm_servers.
  std::mutex cm_servers_mtx;
  /// Cached depot decryption keys.
  std::map<std::uint32_t, tek_sc_aes256_key> depot_keys;
  /// Mutex locking concurrent write access to @ref depot_keys.
  std::shared_mutex depot_keys_mtx;
#ifdef TEK_SCB_S3C
  /// Known tek-s3 servers.
  std::vector<tek::steamclient::s3c::server> s3_servers;
  /// Map of app and depot IDs to tek-s3 server entries that can provide
  ///    manifest request codes for the depot.
  std::map<
      std::uint32_t,
      std::map<std::uint32_t, std::vector<tek::steamclient::s3c::server *>>>
      s3_cache;
  /// Mutex locking concurrent access to @ref s3_servers and @ref s3_cache.
  std::shared_mutex s3_mtx;
  /// tek-s3 authentication WebSocket connection context.
  tek::steamclient::s3c::ws_ctx s3_auth_ctx;
#endif // def TEK_SCB_S3C
  /// Cached OS type value.
  tek::steamclient::cm::msg_payloads::OsType os_type;
  /// Flags indicating which cache fields have changed and should be written
  ///    back to the cache file. Holds a @ref tek::steamclient::dirty_flag
  ///    value.
  std::atomic_int dirty_flags;
  /// libwebsockets event loop processing thread.
  std::thread lws_thread;
};
