//===-- cm_core.cpp - Steam CM client core implementation -----------------===//
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
/// Implementation of CM client basic connection and message processing
///    functions.
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
#include "config.h"
#include "lib_ctx.hpp"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "tek/steamclient/cm/emsg.pb.h"
#include "tek/steamclient/cm/message_header.pb.h"
#include "tek/steamclient/cm/msg_payloads/hello.pb.h"
#include "tek/steamclient/cm/msg_payloads/logoff.pb.h"
#include "tek/steamclient/cm/msg_payloads/multi.pb.h"
#include "ws_close_code.h"
#include "ws_conn.hpp"
#include "zlib_api.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <format>
#include <limits>
#include <locale>
#include <memory>
#include <mutex>
#include <new>
#include <rapidjson/document.h>
#include <rapidjson/reader.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace tek::steamclient::cm {

namespace {

//===-- Private type ------------------------------------------------------===//

/// Download context for curl.
struct tsc_curl_ctx {
  /// curl easy handle that performs the download.
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl{curl_easy_init(),
                                                           curl_easy_cleanup};
  /// Buffer storing downloaded content.
  std::string buf;
};

//===-- Private variable --------------------------------------------------===//

/// Mask for job IDs, pre-generated with process start time.
static const std::uint64_t job_id_mask{
    0x3FF0000000000 |
    (((static_cast<std::uint64_t>(tsci_os_get_process_start_time()) -
       0x41D5E800) &
      0xFFFFF)
     << 20)};

//===-- Private functions -------------------------------------------------===//

/// curl write data callback that copies downloaded data to the context
/// buffer.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk, in bytes.
/// @param [in, out] ctx
///    Download context.
/// @return @p size.
[[using gnu: nonnull(1), access(read_only, 1, 3)]]
static std::size_t tsc_curl_write(const char *_Nonnull buf, std::size_t,
                                  std::size_t size, tsc_curl_ctx &ctx) {
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

/// Fetch CM server list from the Steam Web API.
///
/// @param [in, out] cm_servers
///    Reference to the library context's CM server list to populate.
/// @param timeout_ms
///    Timeout for the download, in milliseconds.
/// @return A @ref tek_sc_err indicating the result of operation.
static tek_sc_err fetch_server_list(std::vector<cm_server> &cm_servers,
                                    long timeout_ms) {
  // Download the list from the Steam Web API
  tsc_curl_ctx curl_ctx;
  if (!curl_ctx.curl) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_curle_init);
  }
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 16000L);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEDATA, &curl_ctx);
  constexpr std::string_view url{
      "https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/"
      "v1?cmtype=websockets&realm=steamglobal"};
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, url.data());
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write);
  if (const auto curl_res{curl_easy_perform(curl_ctx.curl.get())};
      curl_res != CURLE_OK) {
    const auto url_buf{reinterpret_cast<char *>(std::malloc(sizeof url))};
    if (url_buf) {
      std::ranges::copy(url, url_buf);
    }
    long status{};
    if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl_ctx.curl.get(), CURLINFO_RESPONSE_CODE, &status);
    }
    return {.type = TEK_SC_ERR_TYPE_curle,
            .primary = TEK_SC_ERRC_cm_server_list,
            .auxiliary = curl_res,
            .extra = static_cast<int>(status),
            .uri = url_buf};
  }
  curl_ctx.curl.reset();
  // Parse downloaded data
  rapidjson::Document doc;
  doc.ParseInsitu<rapidjson::kParseStopWhenDoneFlag>(curl_ctx.buf.data());
  if (doc.HasParseError() || !doc.IsObject()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_json_parse);
  }
  const auto response{doc.FindMember("response")};
  if (response == doc.MemberEnd() || !response->value.IsObject()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_json_parse);
  }
  const auto serverlist{response->value.FindMember("serverlist")};
  if (serverlist == response->value.MemberEnd() ||
      !serverlist->value.IsArray()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_json_parse);
  }
  const auto serverlist_arr{serverlist->value.GetArray()};
  cm_servers.reserve(serverlist_arr.Size());
  for (const auto &element : serverlist_arr) {
    const auto endpoint{element.FindMember("endpoint")};
    if (endpoint == element.MemberEnd() || !endpoint->value.IsString()) {
      continue;
    }
    const std::string_view view{endpoint->value.GetString(),
                                endpoint->value.GetStringLength()};
    const auto colon_pos{view.find(':')};
    if (colon_pos == std::string_view::npos) {
      continue;
    }
    int port;
    if (std::from_chars(&view[colon_pos + 1], view.end(), port).ec !=
        std::errc{}) {
      continue;
    }
    cm_servers.emplace_back(std::string{view.data(), colon_pos}, port);
  }
  if (cm_servers.empty()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list,
                       TEK_SC_ERRC_cm_server_list_empty);
  }
  // Some firewalls block TCP/TLS traffic to non-standard ports, so prefer
  //    endpoints with port 443 by putting them first in the list
  std::ranges::sort(
      cm_servers,
      [](int left, int right) { return left == 443 && right != 443; },
      &cm_server::port);
  return tsc_err_ok();
}

} // namespace

//===-- cm_conn internal methods ------------------------------------------===//

void cm_conn::handle_connection(CURLcode code) {
  if (code == CURLE_OK) {
    state.store(conn_state::connected, std::memory_order::relaxed);
    // Send hello message
    msg_payloads::Hello payload;
    payload.set_protocol_version(protocol_ver);
    const auto payload_size{payload.ByteSizeLong()};
    const auto msg_size{sizeof(serialized_msg_hdr) + payload_size};
    auto msg_buf{std::make_unique_for_overwrite<unsigned char[]>(msg_size)};
    auto &hdr{*reinterpret_cast<serialized_msg_hdr *>(msg_buf.get())};
    hdr.set_emsg(EMsg::EMSG_CLIENT_HELLO);
    hdr.header_size = 0;
    auto res{tsc_err_ok()};
    connection_cb(&*this, &res, user_data);
    if (tsci_z_inflateInit2(&zstream, 16) != Z_OK) {
      zstream = {};
      disconnection_reason = TEK_SC_ERRC_gzip;
      ws_conn::disconnect(TSCI_WS_CLOSE_CODE_NORMAL);
    } else if (!payload.SerializeToArray(&msg_buf[sizeof hdr], payload_size)) {
      zstream = {};
      disconnection_reason = TEK_SC_ERRC_protobuf_serialize;
      ws_conn::disconnect(TSCI_WS_CLOSE_CODE_NORMAL);
    } else {
      disconnection_reason = TEK_SC_ERRC_ok;
      send_msg({.buf{std::move(msg_buf)},
                .size = static_cast<int>(msg_size),
                .frame_type = CURLWS_BINARY,
                .timer{},
                .state{},
                .timer_cb{},
                .timeout{},
                .data{}});
    }
  } else { // if (code == CURLE_OK)
    bool retry{!delete_pending.load(std::memory_order::relaxed)};
    if (retry && code == CURLE_OPERATION_TIMEDOUT) {
      if (!num_conn_retries) {
        // Perhaps the server is dead, request a new list from web API
        std::unique_lock lock{ctx.cm_servers_mtx};
        ctx.cm_servers.clear();
        auto res{fetch_server_list(ctx.cm_servers, 5000)};
        if (!tek_sc_err_success(&res)) {
          lock.unlock();
          connection_cb(&*this, &res, user_data);
          return;
        }
        ++num_conn_retries;
        ctx.dirty_flags.fetch_or(static_cast<int>(dirty_flag::cm_servers),
                                 std::memory_order::relaxed);
        ctx.cm_servers_iter = ctx.cm_servers.cbegin();
        cur_server = std::to_address(ctx.cm_servers_iter);
        auto url{std::format(std::locale::classic(), "wss://{}:{}/cmsocket/",
                             cur_server->hostname.data(), cur_server->port)};
        const std::scoped_lock conn_lock{ctx.conn_mtx};
        ctx.conn_queue.emplace_back(ws_conn_request{
            .conn{*this}, .url{std::move(url)}, .timeout_ms = 5000});
        return;
      }
      if (num_conn_retries >= 3) {
        retry = false;
      }
    }
    // If retry counter is below 5, retry with another server
    if (retry && ++num_conn_retries < 5) {
      {
        const std::scoped_lock lock{ctx.cm_servers_mtx};
        if (++ctx.cm_servers_iter == ctx.cm_servers.cend()) {
          ctx.cm_servers_iter = ctx.cm_servers.cbegin();
        }
        cur_server = std::to_address(ctx.cm_servers_iter);
      }
      auto url{std::format(std::locale::classic(), "wss://{}:{}/cmsocket/",
                           cur_server->hostname.data(), cur_server->port)};
      const std::scoped_lock lock{ctx.conn_mtx};
      ctx.conn_queue.emplace_back(ws_conn_request{
          .conn{*this}, .url{std::move(url)}, .timeout_ms = 5000});
      return;
    }
    // Otherwise report the error via callback
    state.store(conn_state::disconnected, std::memory_order::relaxed);
    long status{};
    if (code == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    }
    const auto url_buf{reinterpret_cast<char *>(std::malloc(url.length() + 1))};
    if (url_buf) {
      std::ranges::copy(url.begin(), url.end() + 1, url_buf);
    }
    tek_sc_err res{.type = TEK_SC_ERR_TYPE_curle,
                   .primary = TEK_SC_ERRC_cm_connect,
                   .auxiliary = code,
                   .extra = static_cast<int>(status),
                   .uri = url_buf};
    connection_cb(&*this, &res, user_data);
    if (delete_pending.load(std::memory_order::relaxed)) {
      delete this;
    }
  } // if (code == CURLE_OK) else
}

void cm_conn::handle_disconnection(tsci_ws_close_code code) {
  ws_conn::handle_disconnection(code);
  state.store(conn_state::disconnected, std::memory_order::relaxed);
  steam_id = 0;
  session_id = 0;
  tsci_z_inflateEnd(&zstream);
  if (heartbeat_active) {
    heartbeat_active = false;
    uv_close(reinterpret_cast<uv_handle_t *>(&heartbeat_timer), [](auto timer) {
      auto &conn{*reinterpret_cast<cm_conn *>(uv_handle_get_data(timer))};
      if (!--conn.ref_count) {
        if (conn.delete_pending.load(std::memory_order::relaxed)) {
          delete &conn;
        } else {
          conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
        }
      }
    });
  }
  // Process all pending timeouts
  {
    const std::scoped_lock lock{a_entries_mtx};
    for (auto it{a_entries.begin()}; it != a_entries.end();) {
      auto &entry{it->second};
      if (entry.state == timer_state::closing) {
        ++it;
        continue;
      }
      entry.timeout_cb(entry.conn, entry);
      switch (entry.state) {
      case timer_state::inactive:
        it = a_entries.erase(it);
        break;
      case timer_state::active:
        entry.state = timer_state::closing;
        uv_close(reinterpret_cast<uv_handle_t *>(&entry.timer), [](auto timer) {
          auto &entry{
              *reinterpret_cast<msg_await_entry *>(uv_handle_get_data(timer))};
          auto &conn{entry.conn};
          {
            const std::scoped_lock lock{conn.a_entries_mtx};
            using val_type = decltype(conn.a_entries)::value_type;
            conn.a_entries.erase(
                reinterpret_cast<const val_type *>(
                    reinterpret_cast<const unsigned char *>(&entry) -
                    offsetof(val_type, second))
                    ->first);
          }
          if (!--conn.ref_count) {
            if (conn.delete_pending.load(std::memory_order::relaxed)) {
              delete &conn;
            } else {
              conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
            }
          }
        });
        [[fallthrough]];
      case timer_state::closing:
        ++it;
        break;
      }
    }
  }
  const auto actx{auth_ctx.exchange(nullptr, std::memory_order::relaxed)};
  if (actx) {
    tek_sc_cm_data_auth_polling data{
        .status = TEK_SC_CM_AUTH_STATUS_completed,
        .confirmation_types{},
        .url{},
        .token{},
        .result{tsc_err_sub(TEK_SC_ERRC_cm_auth, TEK_SC_ERRC_cm_timeout)}};
    actx->status_timer.cb(&*this, &data, user_data);
    switch (actx->status_timer.state) {
    case timer_state::inactive:
      delete actx;
      break;
    case timer_state::closing:
      break;
    case timer_state::active:
      actx->status_timer.state = timer_state::closing;
      uv_close(reinterpret_cast<uv_handle_t *>(&actx->status_timer.timer),
               [](auto timer) {
                 auto &actx{*reinterpret_cast<auth_session_ctx *>(
                     uv_handle_get_data(timer))};
                 auto &conn{actx.status_timer.conn};
                 delete &actx;
                 if (!--conn.ref_count) {
                   if (conn.delete_pending.load(std::memory_order::relaxed)) {
                     delete &conn;
                   } else {
                     conn.conn_ref_count.fetch_sub(1,
                                                   std::memory_order::relaxed);
                   }
                 }
               });
      break;
    }
  }
  const auto entry{sign_in_entry.exchange(nullptr, std::memory_order::relaxed)};
  if (entry) {
    auto res{tsc_err_sub(TEK_SC_ERRC_cm_sign_in, TEK_SC_ERRC_cm_timeout)};
    entry->cb(&*this, &res, user_data);
    switch (entry->state) {
    case timer_state::inactive:
      delete entry;
      break;
    case timer_state::closing:
      break;
    case timer_state::active:
      entry->state = timer_state::closing;
      uv_close(reinterpret_cast<uv_handle_t *>(&entry->timer), [](auto timer) {
        auto &entry{
            *reinterpret_cast<await_entry *>(uv_handle_get_data(timer))};
        auto &conn{entry.conn};
        delete &entry;
        if (!--conn.ref_count) {
          if (conn.delete_pending.load(std::memory_order::relaxed)) {
            delete &conn;
          } else {
            conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
          }
        }
      });
      break;
    }
  }
  {
    const std::scoped_lock lock{lics_mtx};
    for (auto it{lics_a_entries.before_begin()};;) {
      const auto prev_it{it++};
      if (it == lics_a_entries.end()) {
        break;
      }
      tek_sc_cm_data_lics data{.entries{},
                               .num_entries{},
                               .result = tsc_err_sub(TEK_SC_ERRC_cm_licenses,
                                                     TEK_SC_ERRC_cm_timeout)};
      it->cb(&*this, &data, user_data);
      switch (it->state) {
      case timer_state::inactive:
        it = lics_a_entries.erase_after(prev_it);
        break;
      case timer_state::closing:
        break;
      case timer_state::active:
        it->state = timer_state::closing;
        uv_close(reinterpret_cast<uv_handle_t *>(&it->timer), [](auto timer) {
          auto &entry{
              *reinterpret_cast<await_entry *>(uv_handle_get_data(timer))};
          auto &conn{entry.conn};
          {
            const std::scoped_lock lock{conn.lics_mtx};
            for (auto it{conn.lics_a_entries.cbefore_begin()};;) {
              const auto prev_it{it++};
              if (it == conn.lics_a_entries.cend()) {
                break;
              }
              if (std::to_address(it) == &entry) {
                conn.lics_a_entries.erase_after(prev_it);
                break;
              }
            }
          }
          if (!--conn.ref_count) {
            if (conn.delete_pending.load(std::memory_order::relaxed)) {
              delete &conn;
            } else {
              conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
            }
          }
        });
        break;
      }
      if (it == lics_a_entries.end()) {
        break;
      }
    } // for (auto it{lics_a_entries.before_begin()};;)
  } // license timeout processing scope
  tek_sc_err res;
  if ((code == TSCI_WS_CLOSE_CODE_NORMAL ||
       code == TSCI_WS_CLOSE_CODE_STEAM_NORMAL) &&
      disconnection_reason == TEK_SC_ERRC_ok) {
    res = tsc_err_ok();
  } else {
    const auto url_buf{reinterpret_cast<char *>(std::malloc(url.length() + 1))};
    if (url_buf) {
      std::ranges::copy(url.begin(), url.end() + 1, url_buf);
    }
    res = {.type = disconnection_reason == TEK_SC_ERRC_ok
                       ? TEK_SC_ERR_TYPE_basic
                       : TEK_SC_ERR_TYPE_sub,
           .primary = TEK_SC_ERRC_cm_disconnect,
           .auxiliary = static_cast<int>(disconnection_reason),
           .extra = static_cast<int>(code),
           .uri = url_buf};
  }
  disconnection_cb(&*this, &res, user_data);
}

void cm_conn::handle_post_disconnection() {
  if (!ref_count) {
    if (delete_pending.load(std::memory_order::relaxed)) {
      delete this;
    } else {
      conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
    }
  }
}

void cm_conn::handle_msg(const std::span<const unsigned char> &&data,
                         int frame_type) {
  if (frame_type != CURLWS_BINARY) {
    return;
  }
  serialized_msg_hdr hdr;
  std::memcpy(&hdr, data.data(), sizeof hdr);
  if (!hdr.is_proto()) {
    return;
  }
  auto data_ptr{reinterpret_cast<const unsigned char *>(data.data()) +
                sizeof hdr};
  MessageHeader header;
  if (!header.ParseFromArray(data_ptr, hdr.header_size)) {
    return;
  }
  data_ptr += hdr.header_size;
  const int payload_size{
      static_cast<int>(data.size() - sizeof hdr - hdr.header_size)};
  switch (hdr.emsg()) {
  case EMsg::EMSG_MULTI: {
    msg_payloads::Multi payload;
    if (!payload.ParseFromArray(data_ptr, payload_size)) {
      return;
    }
    bool msg_buf_allocated;
    const unsigned char *msg_buf;
    const unsigned char *msg_buf_end;
    if (payload.uncompressed_size()) {
      // Inner message buffer is GZip-compressed, inflate it
      msg_buf_allocated = true;
      const auto uncomp_buf{new unsigned char[payload.uncompressed_size()]};
      msg_buf = uncomp_buf;
      msg_buf_end = msg_buf + payload.uncompressed_size();
      zstream.next_in = reinterpret_cast<const unsigned char *>(
          payload.inner_messages().data());
      zstream.avail_in = payload.inner_messages().size();
      zstream.total_in = 0;
      zstream.next_out = uncomp_buf;
      zstream.avail_out = payload.uncompressed_size();
      zstream.total_out = 0;
      auto res{tsci_z_inflate(&zstream, Z_FINISH)};
      if (const auto reset_res{tsci_z_inflateReset2(&zstream, 16)};
          res == Z_STREAM_END) {
        res = reset_res;
      }
      if (res != Z_OK) {
        // Abort processing if inflate fails, to avoid further corruption
        return;
      }
    } else {
      // Inner message buffer can be used as-is
      msg_buf_allocated = false;
      msg_buf = reinterpret_cast<const unsigned char *>(
          payload.inner_messages().data());
      msg_buf_end = msg_buf + payload.inner_messages().size();
    }
    // Process inner messages one by one
    for (auto i{msg_buf}; i < msg_buf_end;) {
      std::uint32_t msg_size;
      std::memcpy(&msg_size, i, sizeof msg_size);
      i += sizeof msg_size;
      handle_msg({i, static_cast<std::size_t>(msg_size)}, CURLWS_BINARY);
      i += msg_size;
    }
    if (msg_buf_allocated) {
      delete[] msg_buf;
    }
    break;
  } // case EMsg::EMSG_MULTI
  case EMsg::EMSG_CLIENT_LOG_ON_RESPONSE:
    handle_logon(header, data_ptr, payload_size);
    break;
  case EMsg::EMSG_CLIENT_LICENSE_LIST:
    handle_license_list(data_ptr, payload_size);
    break;
  case EMsg::EMSG_CLIENT_SERVER_UNAVAILABLE:
    disconnection_reason = TEK_SC_ERRC_cm_server_unavailable;
    disconnect();
    break;
  default: {
    if (!header.has_target_job_id()) {
      break;
    }
    // Check if there is an await entry for this message and process it if
    //    there is
    decltype(a_entries)::iterator it;
    {
      const std::scoped_lock lock{a_entries_mtx};
      it = a_entries.find(header.target_job_id());
      if (it == a_entries.end()) {
        break;
      }
    }
    auto &entry{it->second};
    if (entry.state == timer_state::closing) {
      break;
    }
    // Process the response
    if (entry.proc(*this, header, data_ptr, payload_size, entry.cb,
                   entry.inout_data)) {
      // Cancel the timeout and remove the await entry afterwards
      switch (entry.state) {
      case timer_state::inactive: {
        const std::scoped_lock lock{a_entries_mtx};
        a_entries.erase(it);
        break;
      }
      case timer_state::closing:
        break;
      case timer_state::active:
        entry.state = timer_state::closing;
        uv_close(reinterpret_cast<uv_handle_t *>(&entry.timer), [](auto timer) {
          auto &entry{
              *reinterpret_cast<msg_await_entry *>(uv_handle_get_data(timer))};
          auto &conn{entry.conn};
          {
            const std::scoped_lock lock{conn.a_entries_mtx};
            using val_type = decltype(conn.a_entries)::value_type;
            conn.a_entries.erase(
                reinterpret_cast<const val_type *>(
                    reinterpret_cast<const unsigned char *>(&entry) -
                    offsetof(val_type, second))
                    ->first);
          }
          if (!--conn.ref_count) {
            if (conn.delete_pending.load(std::memory_order::relaxed)) {
              delete &conn;
            } else {
              conn.conn_ref_count.fetch_sub(1, std::memory_order::relaxed);
            }
          }
        });
        break;
      }
    } // if (entry.proc(...))
  } // default
  } // switch (hdr.emsg())
}

//===-- CM API methods ----------------------------------------------------===//

void cm_conn::destroy() {
  if (!conn_ref_count.load(std::memory_order::relaxed)) {
    delete this;
    return;
  }
  std::atomic_uint32_t futex{};
  destroy_futex.store(&futex, std::memory_order::release);
  delete_pending.store(true, std::memory_order::relaxed);
  if (state.load(std::memory_order::relaxed) != conn_state::disconnected) {
    disconnect();
  }
  tsci_os_futex_wait(&futex, 0, std::numeric_limits<std::uint32_t>::max());
}

void cm_conn::connect(cb_func *connection_cb, long fetch_timeout_ms,
                      cb_func *disconnection_cb) {
  if (auto expected{conn_state::disconnected}; !state.compare_exchange_strong(
          expected, conn_state::connecting, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    // Do nothing if there is already another connection
    return;
  }
  // Ensure that server list is not empty
  if (std::unique_lock lock{ctx.cm_servers_mtx}; ctx.cm_servers.empty()) {
    auto res{fetch_server_list(ctx.cm_servers, fetch_timeout_ms)};
    if (!tek_sc_err_success(&res)) {
      lock.unlock();
      state.store(conn_state::disconnected, std::memory_order::relaxed);
      connection_cb(&*this, &res, user_data);
      return;
    }
    ctx.dirty_flags.fetch_or(static_cast<int>(dirty_flag::cm_servers),
                             std::memory_order::relaxed);
    ctx.cm_servers_iter = ctx.cm_servers.cbegin();
    cur_server = std::to_address(ctx.cm_servers_iter);
  } else {
    if (++ctx.cm_servers_iter == ctx.cm_servers.cend()) {
      ctx.cm_servers_iter = ctx.cm_servers.cbegin();
    }
    cur_server = std::to_address(ctx.cm_servers_iter);
  }
  // Prepare and submit the connection request
  num_conn_retries = 0;
  this->connection_cb = connection_cb;
  this->disconnection_cb = disconnection_cb;
  conn_ref_count.fetch_add(1, std::memory_order::relaxed);
  {
    auto url{std::format(std::locale::classic(), "wss://{}:{}/cmsocket/",
                         cur_server->hostname.data(), cur_server->port)};
    const std::scoped_lock lock{ctx.conn_mtx};
    ctx.conn_queue.emplace_back(ws_conn_request{
        .conn{*this}, .url{std::move(url)}, .timeout_ms = 8000});
  }
  uv_async_send(&ctx.loop_async);
}

void cm_conn::disconnect() {
  switch (state.load(std::memory_order::relaxed)) {
  case conn_state::disconnected:
    // Already disonnected
    return;
  case conn_state::signed_in: {
    /// Send logoff request
    message<msg_payloads::LogoffRequest> msg;
    msg.type = EMsg::EMSG_CLIENT_LOG_OFF;
    if (const auto res{send_message<TEK_SC_ERRC_cm_disconnect>(std::move(msg))};
        tek_sc_err_success(&res)) {
      break;
    }
    // Fallback to closing the connection from client side
    [[fallthrough]];
  }
  case conn_state::connecting:
  case conn_state::connected:
    /// Submit disconnection request
    ws_conn::disconnect(TSCI_WS_CLOSE_CODE_NORMAL);
  }
}

//===-- Internal function -------------------------------------------------===//

std::uint64_t gen_job_id() noexcept {
  static std::atomic_uint64_t counter;
  return job_id_mask | counter.fetch_add(1, std::memory_order::relaxed);
}

} // namespace tek::steamclient::cm

//===-- Public functions --------------------------------------------------===//

extern "C" {

//===--- Create/destroy ---------------------------------------------------===//

tek_sc_cm_client *tek_sc_cm_client_create(tek_sc_lib_ctx *lib_ctx,
                                          void *user_data) {
  return new (std::nothrow) tek_sc_cm_client(*lib_ctx, user_data);
}

void tek_sc_cm_client_destroy(tek_sc_cm_client *client) {
  client->conn.destroy();
}

void tek_sc_cm_set_user_data(tek_sc_cm_client *client, void *user_data) {
  client->conn.user_data = user_data;
}

//===--- Connect/disconnect -----------------------------------------------===//

void tek_sc_cm_connect(tek_sc_cm_client *client,
                       tek_sc_cm_callback_func *connection_cb,
                       long fetch_timeout_ms,
                       tek_sc_cm_callback_func *disconnection_cb) {
  client->conn.connect(connection_cb, fetch_timeout_ms, disconnection_cb);
}

void tek_sc_cm_disconnect(tek_sc_cm_client *client) {
  client->conn.disconnect();
}

} // extern "C"
