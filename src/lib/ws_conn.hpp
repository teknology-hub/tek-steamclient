//===-- ws_conn.hpp - WebSocket connection interface declaration ----------===//
//
// Copyright (c) 2026 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Declaraton of @ref tek::steamclient::ws_conn.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h"
#include "ws_close_code.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <curl/curl.h>
#include <deque>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <uv.h>
#include <vector>

namespace tek::steamclient {

/// libuv timer handle state values.
enum class timer_state {
  /// The timer is not attached to a libuv event loop and may safely be freed.
  inactive,
  /// The timer has been requested to be closed; neither freeing its memory not
  ///    requesting it to close again is allowed.
  closing,
  /// The timer is attach to a libuv loop and must be closed before its memory
  ///    can be freed.
  active
};

/// WebSocket connection interface.
class [[gnu::visibility("internal")]] ws_conn {
public:
  /// Pending outgoing message entry.
  struct pending_msg {
    /// Pointer to the buffer containing serialized message data. If null, no
    ///    message will be sent but @ref timer will be started.
    std::unique_ptr<unsigned char[]> buf;
    /// Size of serialized message data, in bytes.
    int size;
    /// WebSocket frame type. Must contain one of `CURLWS_` flags.
    unsigned frame_type;
    /// Optional pointer to the timer handle to initialize and start after
    ///    sending the message.
    uv_timer_t *_Nullable timer;
    /// If @ref timer is set, pointer to the value indicating its state.
    timer_state *_Nullable state;
    /// If @ref timer is set, pointer to the callback procedure that the timer
    ///    will invoke.
    uv_timer_cb _Nullable timer_cb;
    /// If @ref timer is set, the number of milliseconds after which the timer
    ///    will fire
    std::uint64_t timeout;
    /// If @ref timer is set, data pointer that will be set for it.
    void *_Nullable data;
  };

  /// Reference to the library context owning the connection.
  tek_sc_lib_ctx &ctx;
  /// curl easy handle representing WebSocket connection.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{nullptr,
                                                           curl_easy_cleanup};

private:
  /// Offset into the receive buffer to write next chunk of data to.
  std::size_t recv_offset{};
  /// Offset into the current pending message buffer to send next chunk of data
  ///    from.
  std::size_t send_offset{};
  /// Recieve buffer.
  std::vector<unsigned char> recv_buf;

public:
  /// Pending message queue.
  std::deque<pending_msg> pending_msgs;
  /// Mutex locking concurrent access to @ref pending_msgs.
  std::mutex pending_msgs_mtx;
  /// URL of the server that the instance is currently connected to.
  std::string url;
  /// Current event mask to poll socket for.
  int poll_events{};
  /// Number of active libuv handles referencing the connection.
  int ref_count{};
  /// Value indicating whether the connection is currently active.
  bool connected{};
  /// Value indicating whether connection has pending outgoing messages, so it's
  ///    waiting for socket to be writable.
  std::atomic_bool send_expected{};

protected:
  constexpr ws_conn(tek_sc_lib_ctx &ctx) noexcept : ctx{ctx} {}

public:
  /// Handler for the event of establishing WebSocket connection or failure to
  ///    do so.
  ///
  /// @param code
  ///    curl easy return code indicating the result of establishing connection.
  virtual void handle_connection(CURLcode code) = 0;
  /// Handler for the event of disconnection from the server.
  ///
  /// @param code
  ///    WebSocket close code received from the server.
  virtual void handle_disconnection(tsci_ws_close_code code);
  /// Handler for the event after the socket stops being polled. The instance
  ///    can safely be deleted here.
  virtual void handle_post_disconnection() = 0;
  /// Handler for incoming (complete) messages.
  ///
  /// @param [in] data
  ///    Buffer containing message data.
  /// @param frame_type
  ///    WebSocket frame type. Contains either `CURLWS_TEXT` or `CURLWS_BINARY`.
  virtual void handle_msg(const std::span<const unsigned char> &&data,
                          int frame_type) = 0;

  /// Perform non-blocking socket receive operation and process received data if
  ///    there is any.
  CURLcode recv();
  /// Perform non-blocking socket send operation to send pending outgoing data.
  CURLcode send();
  /// Enqueue a pending outgoing message.
  ///
  /// @param msg
  ///    Pennding message entry to submit.
  void send_msg(pending_msg &&msg);
  /// Send disconnection request.
  ///
  /// @param code
  ///    WebSocket close code to send to the server.
  void disconnect(tsci_ws_close_code code);
};

} // namespace tek::steamclient
