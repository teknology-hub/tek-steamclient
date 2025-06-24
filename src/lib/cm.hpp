//===-- cm.hpp - Steam CM client common types and functions ---------------===//
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
/// Declarations of common types and functions to be used by CM client
///    implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "common/error.h"
#include "lib_ctx.hpp"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "zlib_api.h"

#include <atomic>
#include <concepts>
#include <cstdint>
#include <deque>
#include <forward_list>
#include <google/protobuf/message_lite.h>
#include <libwebsockets.h>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace tek::steamclient::cm {

/// Current Steam CM protocol version.
constexpr std::uint32_t protocol_ver = 65580;

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

/// Prototype of CM response message processing function.
///
/// @param [in, out] client
///    CM client instance that received the message.
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
using msg_proc = bool(cm_client &client, const MessageHeader &header,
                      const void *_Nonnull data, int size, cb_func *_Nonnull cb,
                      void *_Nullable inout_data);

/// The context that stores credentials for authentication until the client is
///    ready to send the begin auth session message.
struct cred_auth_ctx {
  /// User-friendly device name to send to Steam, as a UTF-8 string.
  std::string device_name;
  /// Steam account name (login) as a UTF-8 string.
  std::string account_name;
  /// Steam account password as a UTF-8 string.
  std::string password;
  /// Timeout for the message response, in milliseconds.
  long timeout_ms;
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

/// Response message await entry.
struct msg_await_entry {
  /// Doubly linked list element for libwebsockets timeout scheduling.
  lws_sorted_usec_list_t sul;
  /// CM client instance that the entry belongs to. Used by timeout procedure to
  ///    remove the entry.
  cm_client &client;
  /// Job ID assigned to the message. Used by timeout procedure to remove the
  ///    entry.
  std::uint64_t job_id;
  /// Pointer to the message processing function.
  msg_proc *_Nonnull proc;
  /// Pointer to the callback function associated with the message.
  cb_func *_Nonnull cb;
  /// Input/output data pointer associated with the message.
  void *_Nullable inout_data;
};

/// Reduced response message await entry for sign-in and license list purposes.
struct msg_await_entry_reduced {
  /// Doubly linked list element for libwebsockets timeout scheduling.
  lws_sorted_usec_list_t sul;
  /// CM client instance that the entry belongs to. Used by timeout procedure to
  ///    remove the entry.
  cm_client &client;
  /// Pointer to the callback function.
  cb_func *_Nonnull cb;
};

/// Pending send message entry.
struct [[gnu::visibility("internal")]] pending_msg_entry {
  /// Pointer to the buffer containing serialized message data after `LWS_PRE`
  ///    bytes. Specifying `nullptr` indicates disconnection request.
  std::unique_ptr<unsigned char[]> buf;
  /// Size of serialized message data (excluding `LWS_PRE`), in bytes.
  int size;
  /// Pointer to the scheduling element, if the message is subject to a timeout.
  lws_sorted_usec_list_t *_Nullable sul;

  constexpr pending_msg_entry() noexcept : buf(), size(0), sul(nullptr) {}

  constexpr pending_msg_entry(std::unique_ptr<unsigned char[]> &buf, int size,
                              lws_sorted_usec_list_t *_Nullable sul) noexcept
      : buf(buf.release()), size(size), sul(sul) {}
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

/// Auth session status request context.
struct status_request {
  /// Doubly linked list element for libwebsockets scheduling.
  lws_sorted_usec_list_t sul;
  /// CM client instance issuing the request.
  cm_client &client;
  /// Pointer to the calback function associated with the auth session.
  cb_func *_Nonnull cb;
};

} // namespace tek::steamclient::cm

/// @copydoc tek_sc_cm_client
struct [[gnu::visibility("internal")]] tek_sc_cm_client {
  using msg_await_entry_reduced = tek::steamclient::cm::msg_await_entry_reduced;

  /// WebSocket instance pointer.
  lws *_Nullable wsi;
  /// Value indicating whether the libwebsockets event loop processing thread
  ///    should start connecting this instance to a server as soon as it can.
  std::atomic_bool conn_requested;
  /// Value indicating whether the libwebsockets event loop processing thread
  ///    should destroy this instance as soon as it's disconnected.
  std::atomic_bool destroy_requested;
  /// The library context that the client is attached to.
  tek_sc_lib_ctx &lib_ctx;
  /// Steam ID of the current account, `0` if not signed in.
  std::uint64_t steam_id;
  /// ID of the current account session, `0` if not signed in.
  std::uint32_t session_id;
  /// Error code indicating disconnection reason.
  tek_sc_errc disconnect_reason;
  /// User data pointer which will be passed to all callbacks.
  void *_Nullable user_data;
  /// Active response message await entires by job ID.
  std::unordered_map<std::uint64_t, tek::steamclient::cm::msg_await_entry>
      a_entries;
  /// Mutex locking concurrent access to @ref a_entries.
  std::recursive_mutex a_entries_mtx;
  /// Pending message queue.
  std::deque<tek::steamclient::cm::pending_msg_entry> pending_msgs;
  /// Mutex locking concurrent access to @ref pending_msgs.
  std::mutex pending_msgs_mtx;
  /// Current connection state.
  std::atomic<tek::steamclient::cm::conn_state> conn_state;
  /// Buffer for temporary storage of partially received WebSocket messages.
  std::vector<unsigned char> pending_recv_buf;
  /// GZip inflate stream.
  tsci_z_stream zstream;
  /// Pointer to the function to call on establishing connection or its failure.
  tek_sc_cm_callback_func *_Nullable connection_cb;
  /// Pointer to the function to call on disconnection.
  tek_sc_cm_callback_func *_Nullable disconnection_cb;
  /// The response message await entry for sign-in.
  msg_await_entry_reduced sign_in_entry;
  /// Authentication session client ID.
  std::atomic_uint64_t auth_client_id;
  /// Authentication session request ID.
  std::string auth_request_id;
  /// Authentication session polling interval, in microseconds.
  lws_usec_t auth_polling_interval;
  /// Steam ID of the account being authenticated. Only used in
  ///    credentials-based authentication sessions.
  std::uint64_t auth_steam_id;
  /// Pointer to the context for credentials-based authentication.
  std::unique_ptr<tek::steamclient::cm::cred_auth_ctx> cred_auth_ctx;
  /// Poiunter to the status request context for current auth session.
  std::unique_ptr<tek::steamclient::cm::status_request> status_req;
  /// Number of consecutive connection retry attempts.
  /// Connection retry counter. Reset when successfully established a
  ///    connection. When reaches 5, the connection fails.
  int num_conn_retries;
  /// Number of entries in @ref lics. A value of `-1` indicates that the
  ///    license list hasn't been received yet.
  int num_lics;
  /// License list for current Steam account.
  std::unique_ptr<tek_sc_cm_lic_entry[]> lics;
  /// Active license list await entires.
  std::forward_list<msg_await_entry_reduced> lics_a_entries;
  /// Mutex locking concurrent access to @ref num_lics and @ref lics_a_entries.
  std::recursive_mutex lics_mtx;
  /// Iterator for the currently used server in `lib_ctx.cm_servers`.
  std::vector<tek::steamclient::cm_server>::const_iterator cur_server;

  [[using gnu: nonnull(2), access(none, 2), access(none, 3)]]
  tek_sc_cm_client(tek_sc_lib_ctx *_Nonnull lib_ctx, void *_Nullable user_data)
      : wsi(nullptr), conn_requested(false), destroy_requested(false),
        lib_ctx(*lib_ctx), steam_id(0), session_id(0),
        disconnect_reason(TEK_SC_ERRC_ok), user_data(user_data), zstream({}),
        sign_in_entry({.sul = {}, .client = *this, .cb = nullptr}),
        auth_client_id(0), num_conn_retries(0), num_lics(-1) {}

  /// Handle a `EMSG_CLIENT_LOG_ON_RESPONSE` message.
  ///
  /// @param [in] header
  ///    Response message header.
  /// @param [in] data
  ///    Pointer to serialized message payload data.
  /// @param size
  ///    Size of the message payload, in bytes.
  [[using gnu: nonnull(3), access(read_only, 3, 4)]]
  void handle_logon(const tek::steamclient::cm::MessageHeader &header,
                    const void *_Nonnull data, int size);

  /// Handle a `EMSG_CLIENT_LICENSE_LIST` message.
  ///
  /// @param [in] data
  ///    Pointer to serialized message payload data.
  /// @param size
  ///    Size of the message payload, in bytes.
  [[using gnu: nonnull(2), access(read_only, 2, 3)]]
  void handle_license_list(const void *_Nonnull data, int size);

  /// Send a message to the CM server.
  ///
  /// @tparam errc
  ///    The primary error code to return in case of an error.
  /// @tparam T
  ///    Message payload type.
  /// @param [in, out] message
  ///    Message to send.
  /// @param sul
  ///    If message is subject to a timeout, pointer to the scheduling element.
  /// @return A @ref tek_sc_err indicating the result of operation.
  template <tek_sc_errc errc, typename T>
    requires std::derived_from<T, google::protobuf::MessageLite>
  [[gnu::access(none, 3)]]
  tek_sc_err send_message(tek::steamclient::cm::message<T> &msg,
                          lws_sorted_usec_list_t *_Nullable sul) {
    using serialized_msg_hdr = tek::steamclient::cm::serialized_msg_hdr;
    // Set header's Steam and sesion IDs if available
    if (steam_id) {
      msg.header.set_steam_id(steam_id);
    }
    if (session_id) {
      msg.header.set_session_id(session_id);
    }
    // Serialize the message
    const auto header_size = msg.header.ByteSizeLong();
    const auto payload_size = msg.payload.ByteSizeLong();
    const auto msg_size =
        sizeof(serialized_msg_hdr) + header_size + payload_size;
    auto msg_buf =
        std::make_unique_for_overwrite<unsigned char[]>(LWS_PRE + msg_size);
    auto &hdr =
        *reinterpret_cast<serialized_msg_hdr *>(msg_buf.get() + LWS_PRE);
    hdr.set_emsg(msg.type);
    hdr.header_size = header_size;
    auto data_ptr = msg_buf.get() + LWS_PRE + sizeof hdr;
    if (!msg.header.SerializeToArray(data_ptr, header_size)) {
      return tsc_err_sub(errc, TEK_SC_ERRC_protobuf_serialize);
    }
    data_ptr += header_size;
    if (!msg.payload.SerializeToArray(data_ptr, payload_size)) {
      return tsc_err_sub(errc, TEK_SC_ERRC_protobuf_serialize);
    }
    // Submit the message to the queue
    pending_msgs_mtx.lock();
    pending_msgs.emplace_back(msg_buf, msg_size, sul);
    pending_msgs_mtx.unlock();
    lws_cancel_service(lib_ctx.lws_ctx);
    return tsc_err_ok();
  }
}; // struct tek_sc_cm_client

namespace tek::steamclient::cm {

//===-- Variable ----------------------------------------------------------===//

/// libwebsockets protocol for Steam CM.
[[gnu::visibility("internal")]]
extern const lws_protocols protocol;

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
          .extra = 0,
          .uri = nullptr};
}

/// Generate next unique job ID.
///
/// @return The generated job ID.
[[gnu::visibility("internal")]]
std::uint64_t gen_job_id() noexcept;

/// Convert timeout value to libwebsockets' usec deadline value.
///
/// @param timeout_ms
///    Timeout value in milliseconds.
/// @return Deadline value in microseconds since Epoch.
static inline lws_usec_t timeout_to_deadline(long timeout_ms) noexcept {
  return lws_now_usecs() + LWS_US_PER_MS * timeout_ms;
}

} // namespace tek::steamclient::cm
