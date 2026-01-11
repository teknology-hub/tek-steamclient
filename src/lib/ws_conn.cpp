//===-- ws_conn.cpp - WebSocket connection interface implementation -------===//
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
/// Implementation of @ref tek::steamclient::ws_conn's methods.
///
//===----------------------------------------------------------------------===//
#include "ws_conn.hpp"

#include "lib_ctx.hpp" // IWYU pragma: keep
#include "ws_close_code.h"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <curl/curl.h>
#include <mutex>
#include <utility>
#include <uv.h>

namespace tek::steamclient {

void ws_conn::handle_disconnection(tsci_ws_close_code) {
  curl_socket_t sock;
  curl_easy_getinfo(curl.get(), CURLINFO_ACTIVESOCKET, &sock);
  const auto it{ctx.poll_handles.find(sock)};
  if (it != ctx.poll_handles.end()) {
    uv_close(reinterpret_cast<uv_handle_t *>(&it->second), [](auto poll) {
      auto &conn{*reinterpret_cast<ws_conn *>(uv_handle_get_data(poll))};
      using val_type = decltype(conn.ctx.poll_handles)::value_type;
      conn.ctx.poll_handles.erase(
          reinterpret_cast<const val_type *>(
              reinterpret_cast<const unsigned char *>(poll) -
              offsetof(val_type, second))
              ->first);
      curl_multi_remove_handle(conn.ctx.curlm.get(), conn.curl.get());
      --conn.ref_count;
      conn.handle_post_disconnection();
    });
  }
  send_expected.store(false, std::memory_order::relaxed);
  connected = false;
  const std::scoped_lock lock{pending_msgs_mtx};
  pending_msgs.clear();
}

CURLcode ws_conn::recv() {
  for (;;) {
    std::size_t recv;
    const curl_ws_frame *meta;
    const auto res{curl_ws_recv(
        curl.get(), recv_buf.empty() ? nullptr : &recv_buf[recv_offset],
        recv_buf.size() - recv_offset, &recv, &meta)};
    switch (res) {
    case CURLE_OK:
      if (!(meta->flags & (CURLWS_TEXT | CURLWS_BINARY))) {
        if (meta->flags == CURLWS_CLOSE) {
          tsci_ws_close_code code{TSCI_WS_CLOSE_CODE_NO_STATUS};
          if (recv >= sizeof code) {
            std::memcpy(&code, &recv_buf[recv_offset], sizeof code);
          }
          handle_disconnection(code);
          return CURLE_OK;
        }
        continue;
      }
      recv_offset += recv;
      if (meta->bytesleft) {
        const auto total_size{recv_offset + meta->bytesleft};
        if (recv_buf.size() < total_size) {
          recv_buf.resize(total_size);
        }
      } else {
        if (meta->flags & CURLWS_CONT) {
          break;
        } else {
          const auto size{recv_offset};
          recv_offset = 0;
          handle_msg({recv_buf.data(), size}, meta->flags);
        }
      }
      break;
    case CURLE_GOT_NOTHING:
      handle_disconnection(TSCI_WS_CLOSE_CODE_ABNORMAL);
      [[fallthrough]];
    case CURLE_AGAIN:
      return CURLE_OK;
    default:
      return res;
    }
  }
}

CURLcode ws_conn::send() {
  for (const std::scoped_lock lock{pending_msgs_mtx}; !pending_msgs.empty();) {
    const auto &msg{pending_msgs.front()};
    if (!msg.buf) {
      pending_msgs.pop_front();
      continue;
    }
    std::size_t sent;
    const auto res{curl_ws_send(curl.get(), &msg.buf[send_offset],
                                msg.size - send_offset, &sent, 0,
                                msg.frame_type)};
    switch (res) {
    case CURLE_OK:
      send_offset += sent;
      if (send_offset < static_cast<std::size_t>(msg.size)) {
        break;
      }
      send_offset = 0;
      pending_msgs.pop_front();
      break;
    case CURLE_AGAIN:
      return CURLE_OK;
    default:
      if (msg.frame_type == CURLWS_CLOSE) {
        handle_disconnection(TSCI_WS_CLOSE_CODE_ABNORMAL);
      }
      return res;
    }
  }
  send_expected.store(false, std::memory_order::relaxed);
  poll_events &= ~UV_WRITABLE;
  return CURLE_OK;
}

void ws_conn::send_msg(pending_msg &&msg) {
  const bool timer_only{!msg.buf};
  {
    const std::scoped_lock lock{pending_msgs_mtx};
    pending_msgs.emplace_back(std::move(msg));
  }
  if (bool expected{};
      timer_only || send_expected.compare_exchange_strong(
                        expected, true, std::memory_order::relaxed,
                        std::memory_order::relaxed)) {
    const std::scoped_lock lock{ctx.conn_mtx};
    ctx.writable_queue.emplace_back(this);
    uv_async_send(&ctx.loop_async);
  }
}

void ws_conn::disconnect(tsci_ws_close_code code) {
  {
    auto buf{std::make_unique_for_overwrite<unsigned char[]>(sizeof code)};
    *reinterpret_cast<tsci_ws_close_code *>(buf.get()) = code;
    const std::scoped_lock lock{pending_msgs_mtx};
    pending_msgs.emplace_back(std::move(buf), sizeof code, CURLWS_CLOSE);
  }
  if (bool expected{}; send_expected.compare_exchange_strong(
          expected, true, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    const std::scoped_lock lock{ctx.conn_mtx};
    ctx.writable_queue.emplace_back(this);
    uv_async_send(&ctx.loop_async);
  }
}

} // namespace tek::steamclient
