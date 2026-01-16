//===-- cm.hpp - Steam CM client common types and functions ---------------===//
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
/// Declarations of common types and functions to be used by CM client
///    implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "common/error.h"
#include "lib_ctx.hpp"
#include "os.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "ws_close_code.h"
#include "ws_conn.hpp"
#include "zlib_api.h"

#include <algorithm>
#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <forward_list>
#include <google/protobuf/message_lite.h>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <uv.h>

namespace tek::steamclient::cm {

/// Current Steam CM protocol version.
constexpr std::uint32_t protocol_ver{65580};

//===-- Types -------------------------------------------------------------===//

/// @copydoc tek_sc_cm_client
using cm_client = tek_sc_cm_client;
/// @copydoc tek_sc_cm_callback_func
using cb_func = tek_sc_cm_callback_func;

/// CM client connection states.
enum class conn_state {
  /// Not connected to a server.
  disconnected,
  /// Establishing connection to a server.
  connecting,
  /// Connected to a server but not signed in.
  connected,
  /// Connected to a server and signed into a Steam account.
  signed_in
};

/// Steam CM Protobuf message structure.
///
/// @tparam T
///    Message payload type.
template <typename T>
  requires std::derived_from<T, google::protobuf::MessageLite>
struct message {
  /// Type of the message.
  EMsg type;
  /// Message header.
  MessageHeader header;
  /// Message payload body.
  T payload;
};

/// WebSocket connection implementation for Steam CM client.
class [[gnu::visibility("internal")]] cm_conn;

/// Simple event await entry.
struct await_entry {
  /// CM connection instance owning the entry.
  cm_conn &conn;
  /// Pointer to the callback function.
  cb_func *_Nonnull cb;
  /// libuv timer handle for timeout.
  uv_timer_t timer;
  /// Value indicating whether @ref timer has been initialized.
  bool timer_active;
};

/// Prototype of CM response message processing function.
///
/// @param [in, out] conn
///    CM connection instance that received the message.
/// @param [in] header
///    Message header.
/// @param [in] data
///    Pointer to serialized message payload data.
/// @param size
///    Size of the message payload, in bytes.
/// @param cb
///    Pointer to the callback function associated with the message.
/// @param [in, out] inout_data
///    Input/output data pointer associated with the message.
/// @return Value indicating whether the response is final and the await entry
///    for it may be removed, or there are more response messages coming.
using msg_proc = bool(cm_conn &conn, const MessageHeader &header,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nullable inout_data);

/// Response message await entry.
struct msg_await_entry;

/// Prototype of CM response timeout function.
///
/// @param [in, out] conn
///    CM connection instance owning the await entry.
/// @param [in, out] entry
///    Response message await entry that timed out.
using timeout_proc = void(cm_conn &conn, msg_await_entry &entry);

struct msg_await_entry {
  /// CM connection instance owning the entry.
  cm_conn &conn;
  /// Pointer to the message processing function.
  msg_proc *_Nonnull proc;
  /// Pointer to the callback function associated with the message.
  cb_func *_Nonnull cb;
  /// Input/output data pointer associated with the message.
  void *_Nullable inout_data;
  /// Pointer to the timeout (or disconnection) handling function.
  timeout_proc *_Nonnull timeout_cb;
  /// libuv timer handle for timeout.
  uv_timer_t timer;
  /// Value indicating whether @ref timer has been initialized.
  bool timer_active;
};

/// Authentication session context.
struct auth_session_ctx {
  /// Session client ID.
  std::atomic_uint64_t client_id;
  /// Session request ID.
  std::string request_id;
  /// Session polling interval, in milliseconds.
  std::uint64_t polling_interval;
  /// Steam ID of the account being authenticated. Only used in
  ///    credentials-based authentication sessions.
  std::uint64_t steam_id;
  /// User-friendly device name to send to Steam, as a UTF-8 string. Only used
  ///    in credentials-based authentication sessions.
  std::string device_name;
  /// Steam account name (login) as a UTF-8 string. Only used in
  ///    credentials-based authentication sessions.
  std::string account_name;
  /// Steam account password as a UTF-8 string. Only used in
  ///    credentials-based authentication sessions.
  std::string password;
  /// Timeout for the message response, in milliseconds.
  std::uint64_t timeout_ms;
  /// Status request polling timer.
  await_entry status_timer;
};

/// Steam CM serialized message header.
struct [[gnu::visibility("internal")]] serialized_msg_hdr {
  /// Type of the message, with MSB set if it's Protobuf-encoded.
  std::uint32_t raw_emsg;
  /// Size of the Protobuf message header ,in bytes.
  std::int32_t header_size;

  /// Check if the message is Protobuf-encoded.
  /// @return Value indicating whether the message is Protobuf-encoded.
  constexpr bool is_proto() const noexcept { return raw_emsg & 0x80000000; }
  /// Get message type.
  /// @return Unmasked EMsg value.
  constexpr EMsg emsg() const noexcept {
    return static_cast<EMsg>(raw_emsg & ~0x80000000);
  }
  /// Set message type.
  ///
  /// @param emsg EMsg value to set.
  constexpr void set_emsg(EMsg emsg) noexcept {
    raw_emsg = static_cast<std::uint32_t>(emsg) | 0x80000000;
  }
};

class [[gnu::visibility("internal")]] cm_conn final : public ws_conn {
public:
  /// User data pointer that will be passed to all callbacks.
  void *_Nullable user_data;

private:
  /// Steam ID of the current account, `0` if not signed in.
  std::uint64_t steam_id{};
  /// ID of the current account session, `0` if not signed in.
  std::uint32_t session_id{};

public:
  /// Current connection state.
  std::atomic<conn_state> conn_state{};
  /// Active response message await entires by job ID.
  std::map<std::uint64_t, msg_await_entry> a_entries;
  /// Mutex locking concurrent access to @ref a_entries.
  std::mutex a_entries_mtx;
  /// Pointer to current authentication session context.
  std::atomic<auth_session_ctx *> auth_ctx{};
  /// Pointer to current response message await entry for sign-in.
  std::atomic<await_entry *> sign_in_entry{};
  /// License list for current Steam account.
  std::unique_ptr<tek_sc_cm_lic_entry[]> lics;
  /// Number of entries in @ref lics. A value of `-1` indicates that the
  ///    license list hasn't been received yet.
  int num_lics{-1};
  /// Active license list await entires.
  std::forward_list<await_entry> lics_a_entries;
  /// Mutex locking concurrent access to @ref lics and @ref lics_a_entries.
  std::mutex lics_mtx;
  /// GZip inflate stream.
  tsci_z_stream zstream{};

private:
  /// Pointer to the function to call on establishing connection or its failure.
  cb_func *_Nullable connection_cb{};
  /// Pointer to the function to call on disconnection.
  cb_func *_Nullable disconnection_cb{};
  /// Pointer to currently used CM server.
  const cm_server *_Nullable cur_server{};
  /// Number of consecutive connection retry attempts. Reset when successfully
  ///    established a connection. When reaches 5, the connection attempt fails.
  int num_conn_retries{};
  /// If a disconnection is initiated due to a CM server's response, this field
  ///    will contain it.
  tek_sc_errc disconnection_reason;
  /// Pointer to the futex that will be set to 1 and waken when destroying the
  ///    instance.
  std::atomic<std::atomic_uint32_t *> destroy_futex{};

public:
  /// Value indicating whether the instance should be deleted after being
  ///    disconnected.
  std::atomic_bool delete_pending{};

  constexpr cm_conn(lib_ctx &ctx, void *_Nullable user_data) noexcept
      : ws_conn{ctx}, user_data{user_data} {}
  constexpr ~cm_conn() {
    const auto futex{destroy_futex.load(std::memory_order::acquire)};
    if (futex) {
      futex->store(1, std::memory_order::release);
      tsci_os_futex_wake(futex);
    }
  }

  //===-- Methods ---------------------------------------------------------===//

private:
  void handle_connection(CURLcode code) override;
  void handle_disconnection(tsci_ws_close_code code) override;
  void handle_post_disconnection() override;
  void handle_msg(const std::span<const unsigned char> &&data,
                  int frame_type) override;

  /// Handle a `EMSG_CLIENT_LOG_ON_RESPONSE` message.
  ///
  /// @param [in] header
  ///    Response message header.
  /// @param [in] data
  ///    Pointer to serialized message payload data.
  /// @param size
  ///    Size of the message payload, in bytes.
  [[using gnu: nonnull(3), access(read_only, 3, 4)]]
  void handle_logon(const MessageHeader &header, const void *_Nonnull data,
                    int size);
  /// Handle a `EMSG_CLIENT_LICENSE_LIST` message.
  ///
  /// @param [in] data
  ///    Pointer to serialized message payload data.
  /// @param size
  ///    Size of the message payload, in bytes.
  [[using gnu: nonnull(2), access(read_only, 2, 3)]]
  void handle_license_list(const void *_Nonnull data, int size);

public:
  //===-- CM API methods --------------------------------------------------===//

  /// Request CM client instance to disconnect and free its memory afterwards.
  void destroy();
  /// Initiate WebSocket connection of CM client instance to a server.
  /// If CM server list is not present in the cache, this function will also
  ///    fetch it from Steam Web API. Fetching is a blocking operation, but you
  ///    may specify its timeout via @p fetch_timeout_ms.
  ///
  /// @param [in, out] client
  ///    Pointer to the CM client instance to connect.
  /// @param connection_cb
  ///    Pointer to the function that will be called when connection attempt
  ///    succeeds or fails. `data` will point to a @ref tek_sc_err indicating
  ///    the result.
  /// @param fetch_timeout_ms
  ///    Timeout for fetching the server list, in milliseconds.
  /// @param disconnection_cb
  ///    Pointer to the function that will be called after disconnection from
  ///    the server. `data` will point to a @ref tek_sc_err indicating the
  ///    disconnection reason.
  [[gnu::nonnull(2, 4), clang::callback(connection_cb, __, __, __)]]
  void connect(cb_func *_Nonnull connection_cb, long fetch_timeout_ms,
               cb_func *_Nonnull disconnection_cb);
  /// Initiate disconnection of CM client instance from the server.
  void disconnect();

  //===-- Helper methods --------------------------------------------------===//

  /// Serialize a message for sending it to CM server.
  ///
  /// @tparam T
  ///    Message payload type.
  /// @param [in, out] message
  ///    Message to serialize.
  /// @param [out] msg_size
  ///    Variable that receives the size of serialized message data, in bytes.
  /// @return Pointer to the buffer containing serialized message data, or null
  ///    pointer if a serialization error has occurred.
  template <typename T>
    requires std::derived_from<T, google::protobuf::MessageLite>
  std::unique_ptr<unsigned char[]>
  serialize_message(message<T> &&msg, std::size_t &msg_size) const {
    msg.header.set_realm(1); // SteamGlobal
    // Set header's Steam and session IDs if available
    if (steam_id) {
      msg.header.set_steam_id(steam_id);
    }
    if (session_id) {
      msg.header.set_session_id(session_id);
    }
    // Serialize the message
    const auto header_size{msg.header.ByteSizeLong()};
    const auto payload_size{msg.payload.ByteSizeLong()};
    msg_size = sizeof(serialized_msg_hdr) + header_size + payload_size;
    auto buf{std::make_unique_for_overwrite<unsigned char[]>(msg_size)};
    auto &hdr{*reinterpret_cast<serialized_msg_hdr *>(buf.get())};
    hdr.set_emsg(msg.type);
    hdr.header_size = header_size;
    auto data_ptr{&buf[sizeof hdr]};
    if (!msg.header.SerializeToArray(data_ptr, header_size)) {
      return {};
    }
    data_ptr += header_size;
    if (!msg.payload.SerializeToArray(data_ptr, payload_size)) {
      return {};
    }
    return buf;
  }

  /// Send a message to the CM server.
  ///
  /// @tparam errc
  ///    The primary error code to return in case of an error.
  /// @tparam T
  ///    Message payload type.
  /// @param [in, out] message
  ///    Message to send.
  /// @return A @ref tek_sc_err indicating the result of operation.
  template <tek_sc_errc errc, typename T>
    requires std::derived_from<T, google::protobuf::MessageLite>
  tek_sc_err send_message(message<T> &&msg) {
    std::size_t msg_size;
    auto buf{serialize_message(std::move(msg), msg_size)};
    if (!buf) {
      return tsc_err_sub(errc, TEK_SC_ERRC_protobuf_serialize);
    }
    // Submit the message to the queue
    send_msg({.buf{std::move(buf)},
              .size = static_cast<int>(msg_size),
              .frame_type = CURLWS_BINARY,
              .timer{},
              .timer_active{},
              .timer_cb{},
              .timeout{},
              .data{}});
    return tsc_err_ok();
  }

  /// Send a message to the CM server and register its response await entry.
  ///
  /// @tparam errc
  ///    The primary error code to return in case of an error.
  /// @tparam T
  ///    Message payload type.
  /// @param [in, out] message
  ///    Message to send.
  /// @param [in] entry
  ///    Response message await entry to register before sending the message.
  /// @param timeout_ms
  ///    Timeout for response message, in milliseconds.
  /// @return A @ref tek_sc_err indicating the result of operation.
  template <tek_sc_errc errc, typename T>
    requires std::derived_from<T, google::protobuf::MessageLite>
  tek_sc_err send_message(message<T> &&msg, msg_await_entry &entry,
                          std::uint64_t timeout_ms) {
    std::size_t msg_size;
    auto buf{serialize_message(std::move(msg), msg_size)};
    if (!buf) {
      return tsc_err_sub(errc, TEK_SC_ERRC_protobuf_serialize);
    }
    // Submit the message to the queue
    send_msg(
        {.buf{std::move(buf)},
         .size = static_cast<int>(msg_size),
         .frame_type = CURLWS_BINARY,
         .timer = &entry.timer,
         .timer_active = &entry.timer_active,
         .timer_cb =
             [](auto timer) {
               const auto handle{reinterpret_cast<uv_handle_t *>(timer)};
               auto &entry{*reinterpret_cast<msg_await_entry *>(
                   uv_handle_get_data(handle))};
               entry.timeout_cb(entry.conn, entry);
               uv_close(handle, [](auto handle) {
                 auto &entry{*reinterpret_cast<msg_await_entry *>(
                     uv_handle_get_data(handle))};
                 auto &conn{entry.conn};
                 {
                   const std::scoped_lock lock{conn.pending_msgs_mtx};
                   const auto msg{std::ranges::find(conn.pending_msgs, &entry,
                                                    &pending_msg::data)};
                   if (msg != conn.pending_msgs.end()) {
                     conn.pending_msgs.erase(msg);
                   }
                 }
                 {
                   const std::scoped_lock lock{conn.a_entries_mtx};
                   using val_type = decltype(conn.a_entries)::value_type;
                   conn.a_entries.erase(
                       reinterpret_cast<const val_type *>(
                           reinterpret_cast<const unsigned char *>(&entry) -
                           offsetof(val_type, second))
                           ->first);
                 }
                 --conn.ref_count;
               });
             },
         .timeout = timeout_ms,
         .data = &entry});
    return tsc_err_ok();
  }

  /// Setup a response message await entry.
  ///
  /// @param job_id
  ///    Job ID associated with the response message.
  /// @param proc
  ///    Pointer to the message processing function.
  /// @param cb
  ///    Pointer to the callback function associated with the message.
  /// @param timeout_cb
  ///    Pointer to the timeout (or disconnection) handling function.
  /// @param [in, out] inout_data
  ///    Optional input/output data pointer associated with the message.
  /// @return Iterator for the created response message await entry.
  decltype(a_entries)::iterator
  setup_a_entry(std::uint64_t job_id, msg_proc *_Nonnull proc,
                cb_func *_Nonnull cb, timeout_proc *_Nonnull timeout_cb,
                void *_Nullable inout_data = nullptr) {
    const std::scoped_lock lock{a_entries_mtx};
    return a_entries
        .emplace(job_id, msg_await_entry{.conn{*this},
                                         .proc = proc,
                                         .cb = cb,
                                         .inout_data = inout_data,
                                         .timeout_cb = timeout_cb,
                                         .timer{},
                                         .timer_active{}})
        .first;
  }

  constexpr cm_client *_Nonnull operator&() noexcept {
    return reinterpret_cast<cm_client *>(this);
  }
}; // class cm_conn final : public ws_conn

} // namespace tek::steamclient::cm

using namespace tek::steamclient;
using namespace tek::steamclient::cm;

/// @copydoc tek_sc_cm_client
struct tek_sc_cm_client {
  /// WebSocket connection instance that implements the CM client.
  cm_conn conn;
  constexpr tek_sc_cm_client(lib_ctx &ctx, void *_Nullable user_data) noexcept
      : conn{ctx, user_data} {}
};

namespace tek::steamclient::cm {

//===-- Functions ---------------------------------------------------------===//

/// Create a @ref tek_sc_err out of a @ref tek_sc_errc and a
///    @ref tek_sc_cm_eresult error codes.
///
/// @param prim
///    Primary error code.
/// @param errc
///    A EResult value.
/// @return A @ref tek_sc_err for specified error codes.
constexpr tek_sc_err err(tek_sc_errc prim, tek_sc_cm_eresult errc) noexcept {
  return {.type = TEK_SC_ERR_TYPE_steam_cm,
          .primary = prim,
          .auxiliary = errc,
          .extra{},
          .uri{}};
}

/// Generate next unique job ID.
///
/// @return The generated job ID.
[[gnu::visibility("internal")]]
std::uint64_t gen_job_id() noexcept;

} // namespace tek::steamclient::cm
