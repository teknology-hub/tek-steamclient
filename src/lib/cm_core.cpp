//===-- cm_core.cpp - Steam CM client core implementation -----------------===//
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
/// Implementation of CM client basic connection and message processing
///    functions.
///
//===----------------------------------------------------------------------===//
#include "cm.hpp"

#include "common/error.h"
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
#include "zlib_api.h"

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <curl/curl.h>
#include <format>
#include <functional>
#include <libwebsockets.h>
#include <locale>
#include <memory>
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
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl =
      std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>(curl_easy_init(),
                                                          curl_easy_cleanup);
  /// Buffer storing downloaded content.
  std::string buf;
};

//===-- Private variable --------------------------------------------------===//

/// Mask for job IDs, pre-generated with process start time.
static const std::uint64_t job_id_mask =
    0x3FF0000000000 |
    (((static_cast<std::uint64_t>(tsci_os_get_process_start_time()) -
       0x41D5E800) &
      0xFFFFF)
     << 20);

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

/// Detach CM client instance from the library context and destroy it.
///
/// @param [in, out] client
///    CM client instance to destroy.
static void destroy(cm_client &client) {
  client.lib_ctx.cm_clients_mtx.lock();
  auto &cm_clients = client.lib_ctx.cm_clients;
  for (auto it = cm_clients.cbefore_begin();;) {
    const auto prev_it = it++;
    if (it == cm_clients.cend()) {
      break;
    }
    if (*it == &client) {
      cm_clients.erase_after(prev_it);
      break;
    }
  }
  client.lib_ctx.cm_clients_mtx.unlock();
  tsci_z_inflateEnd(&client.zstream);
  delete &client;
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
  constexpr char url[] = "https://api.steampowered.com/ISteamDirectory/"
                         "GetCMListForConnect/v1?cmtype=websockets";
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_URL, url);
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_ACCEPT_ENCODING, "");
  curl_easy_setopt(curl_ctx.curl.get(), CURLOPT_WRITEFUNCTION, tsc_curl_write);
  if (const auto curl_res = curl_easy_perform(curl_ctx.curl.get());
      curl_res != CURLE_OK) {
    const auto url_buf = reinterpret_cast<char *>(std::malloc(sizeof url));
    if (url_buf) {
      std::ranges::move(url, url_buf);
    }
    long status = 0;
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
  const auto response = doc.FindMember("response");
  if (response == doc.MemberEnd() || !response->value.IsObject()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_json_parse);
  }
  const auto serverlist = response->value.FindMember("serverlist");
  if (serverlist == response->value.MemberEnd() ||
      !serverlist->value.IsArray()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list, TEK_SC_ERRC_json_parse);
  }
  const auto serverlist_arr = serverlist->value.GetArray();
  cm_servers.reserve(serverlist_arr.Size());
  for (const auto &element : serverlist_arr) {
    const auto endpoint = element.FindMember("endpoint");
    if (endpoint == element.MemberEnd() || !endpoint->value.IsString()) {
      continue;
    }
    const std::string_view view(endpoint->value.GetString(),
                                endpoint->value.GetStringLength());
    const auto colon_pos = view.find(':');
    if (colon_pos == std::string_view::npos) {
      continue;
    }
    int port;
    if (std::from_chars(&view[colon_pos + 1], view.end(), port).ec !=
        std::errc{}) {
      continue;
    }
    cm_servers.emplace_back(std::string(view.data(), colon_pos), port);
  }
  if (cm_servers.empty()) {
    return tsc_err_sub(TEK_SC_ERRC_cm_server_list,
                       TEK_SC_ERRC_cm_server_list_empty);
  }
  return tsc_err_ok();
}

/// Process incoming message from the CM server.
///
/// @param [in, out] client
///    CM client that received the message.
/// @param [in] data
///    Pointer to serialized message data.
/// @param size
///    Size of the message data in bytes.
[[using gnu: nonnull(2), access(read_only, 2, 3)]]
static void process_msg(cm_client &client, const void *_Nonnull data,
                        int size) {
  serialized_msg_hdr hdr;
  std::memcpy(&hdr, data, sizeof hdr);
  if (!hdr.is_proto()) {
    return;
  }
  auto data_ptr = reinterpret_cast<const unsigned char *>(data) + sizeof hdr;
  MessageHeader header;
  if (!header.ParseFromArray(data_ptr, hdr.header_size)) {
    return;
  }
  data_ptr += hdr.header_size;
  const int payload_size = size - sizeof hdr - hdr.header_size;
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
      const auto uncomp_buf = new unsigned char[payload.uncompressed_size()];
      msg_buf = uncomp_buf;
      msg_buf_end = msg_buf + payload.uncompressed_size();
      client.zstream.next_in = reinterpret_cast<const unsigned char *>(
          payload.inner_messages().data());
      client.zstream.avail_in = payload.inner_messages().size();
      client.zstream.total_in = 0;
      client.zstream.next_out = uncomp_buf;
      client.zstream.avail_out = payload.uncompressed_size();
      client.zstream.total_out = 0;
      auto res = tsci_z_inflate(&client.zstream, Z_FINISH);
      if (const auto reset_res = tsci_z_inflateReset2(&client.zstream, 16);
          res == Z_STREAM_END) {
        res = reset_res;
      }
      if (res != Z_OK) {
        // Abort processing if inflate fails to avoid further corruption
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
    for (auto i = msg_buf; i < msg_buf_end;) {
      std::uint32_t msg_size;
      std::memcpy(&msg_size, i, sizeof msg_size);
      i += sizeof msg_size;
      process_msg(client, i, msg_size);
      i += msg_size;
    }
    if (msg_buf_allocated) {
      delete[] msg_buf;
    }
    break;
  } // case EMsg::EMSG_MULTI
  case EMsg::EMSG_CLIENT_LOG_ON_RESPONSE:
    client.handle_logon(header, data_ptr, payload_size);
    break;
  case EMsg::EMSG_CLIENT_LICENSE_LIST:
    client.handle_license_list(data_ptr, payload_size);
    break;
  case EMsg::EMSG_CLIENT_SERVER_UNAVAILABLE:
    client.disconnect_reason = TEK_SC_ERRC_cm_server_unavailable;
    tek_sc_cm_disconnect(&client);
    break;
  default: {
    if (!header.has_target_job_id()) {
      break;
    }
    // Check if there is an await entry for this message and process it if
    //    there is
    client.a_entries_mtx.lock();
    const auto a_entry = client.a_entries.find(header.target_job_id());
    if (a_entry == client.a_entries.end()) {
      client.a_entries_mtx.unlock();
      break;
    }
    client.a_entries_mtx.unlock();
    // Process the response
    if (a_entry->second.proc(client, header, data_ptr, payload_size,
                             a_entry->second.cb, a_entry->second.inout_data)) {
      // Cancel the timeout and remove the entry
      lws_sul_cancel(&a_entry->second.sul);
      client.a_entries_mtx.lock();
      client.a_entries.erase(a_entry);
      client.a_entries_mtx.unlock();
    }
  }
  } // switch (hdr.emsg())
}

/// Process a libwebsockets protocol callback.
///
/// @param wsi
///    Pointer to the WebSocket instance that emitted the callback.
/// @param reason
///    Reason for the callback.
/// @param user
///    For wsi-scoped callbacks, pointer to the associated CM client instance.
/// @param [in] in
///    Pointer to the data associated with the callback.
/// @param len
///    Size of the data pointed to by @p in, in bytes.
/// @return `0` on success, or a non-zero value to close connection.
[[gnu::access(read_only, 4, 5)]]
static int tsc_lws_cb(lws *_Nullable wsi, lws_callback_reasons reason,
                      void *_Nullable user, void *_Nullable in,
                      std::size_t len) {
  switch (reason) {
  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
    auto &client = *reinterpret_cast<cm_client *>(user);
    if (client.destroy_requested.load(std::memory_order::relaxed)) {
      destroy(client);
      return 0;
    }
    // If there's no error from established callback and retry counter is below
    //    5, retry with another server
    if (!client.disconnect_reason && ++client.num_conn_retries < 5) {
      if (++client.cur_server == client.lib_ctx.cm_servers.cend()) {
        client.cur_server = client.lib_ctx.cm_servers.cbegin();
      }
      lws_client_connect_info info{};
      info.context = client.lib_ctx.lws_ctx;
      info.address = client.cur_server->hostname.data();
      info.port = client.cur_server->port;
      info.ssl_connection = LCCSCF_USE_SSL;
      info.path = "/cmsocket/";
      info.host = info.address;
      info.origin = info.address;
      info.protocol = "";
      info.userdata = &client;
      if (lws_client_connect_via_info(&info)) {
        return 0;
      }
    }
    // Otherwise report the error via callback
    client.conn_state.store(conn_state::disconnected,
                            std::memory_order::relaxed);
    auto res = client.disconnect_reason ? tsc_err_sub(TEK_SC_ERRC_cm_connect,
                                                      client.disconnect_reason)
                                        : tsc_err_basic(TEK_SC_ERRC_cm_connect);
    client.disconnect_reason = TEK_SC_ERRC_ok;
    const auto url =
        std::format(std::locale::classic(), "wss://{}:{}/cmsocket/",
                    client.cur_server->hostname, client.cur_server->port);
    const auto url_buf =
        reinterpret_cast<char *>(std::malloc(url.length() + 1));
    if (url_buf) {
      std::ranges::move(url.begin(), url.end() + 1, url_buf);
    }
    res.uri = url_buf;
    client.connection_cb(&client, &res, client.user_data);
    return 0;
  } // case LWS_CALLBACK_CLIENT_CONNECTION_ERROR
  case LWS_CALLBACK_CLIENT_ESTABLISHED: {
    auto &client = *reinterpret_cast<tek_sc_cm_client *>(user);
    client.wsi = wsi;
    client.conn_state.store(conn_state::connected, std::memory_order::release);
    // Send hello message
    msg_payloads::Hello payload;
    payload.set_protocol_version(protocol_ver);
    const auto payload_size = payload.ByteSizeLong();
    const auto msg_size = sizeof(serialized_msg_hdr) + payload_size;
    auto msg_buf =
        std::make_unique_for_overwrite<unsigned char[]>(LWS_PRE + msg_size);
    auto &hdr = *reinterpret_cast<serialized_msg_hdr *>(&msg_buf[LWS_PRE]);
    hdr.set_emsg(EMsg::EMSG_CLIENT_HELLO);
    hdr.header_size = 0;
    if (!payload.SerializeToArray(&msg_buf[LWS_PRE + sizeof hdr],
                                  payload_size)) {
      client.wsi = nullptr;
      client.disconnect_reason = TEK_SC_ERRC_protobuf_serialize;
      return 1;
    }
    client.pending_msgs_mtx.lock();
    client.pending_msgs.emplace_back(msg_buf, msg_size, nullptr);
    client.pending_msgs_mtx.unlock();
    lws_callback_on_writable(wsi);
    // Call connection callback
    auto res = tsc_err_ok();
    client.connection_cb(&client, &res, client.user_data);
    return 0;
  }
  case LWS_CALLBACK_CLIENT_RECEIVE: {
    auto &client = *reinterpret_cast<cm_client *>(user);
    if (!lws_frame_is_binary(wsi)) {
      // Ignore non-binary frames
      client.pending_recv_buf.clear();
      break;
    }
    const auto uc_in = reinterpret_cast<const unsigned char *>(in);
    const auto rem_payload = lws_remaining_packet_payload(wsi);
    if (!rem_payload && lws_is_final_fragment(wsi)) {
      if (client.pending_recv_buf.empty()) {
        // Entire message received in one go
        if (len >= sizeof(serialized_msg_hdr)) {
          process_msg(client, in, len);
        }
      } else {
        // Receiving last chunk of fragmented message
        client.pending_recv_buf.insert(client.pending_recv_buf.end(), uc_in,
                                       &uc_in[len]);
        if (client.pending_recv_buf.size() >= sizeof(serialized_msg_hdr)) {
          process_msg(client, client.pending_recv_buf.data(),
                      client.pending_recv_buf.size());
        }
        client.pending_recv_buf.clear();
      }
      break;
    }
    // Receiving non-last chunk of a fragmented message
    client.pending_recv_buf.reserve(client.pending_recv_buf.size() + len +
                                    rem_payload);
    client.pending_recv_buf.insert(client.pending_recv_buf.end(), uc_in,
                                   &uc_in[len]);
    break;
  }
  case LWS_CALLBACK_CLIENT_WRITEABLE: {
    auto &client = *reinterpret_cast<cm_client *>(user);
    client.pending_msgs_mtx.lock();
    if (client.pending_msgs.empty()) {
      client.pending_msgs_mtx.unlock();
      break;
    }
    for (bool remaining = !client.pending_msgs.empty(); remaining;) {
      const auto msg = std::move(client.pending_msgs.front());
      client.pending_msgs.pop_front();
      if (!msg.buf) {
        break;
      }
      if (msg.sul && lws_dll2_is_detached(&msg.sul->list)) {
        lws_sul2_schedule(client.lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                          msg.sul);
      }
      if (lws_write(wsi, &msg.buf[LWS_PRE], msg.size, LWS_WRITE_BINARY) <
          msg.size) {
        client.pending_msgs_mtx.unlock();
        return 1;
      }
      remaining = !client.pending_msgs.empty();
      if (remaining && lws_partial_buffered(wsi)) {
        lws_callback_on_writable(wsi);
        break;
      }
    }
    client.pending_msgs_mtx.unlock();
    return 0;
  }
  case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
    if (!wsi) {
      break;
    }
    auto &lib_ctx = *reinterpret_cast<tek_sc_lib_ctx *>(
        lws_context_user(lws_get_context(wsi)));
    if (lib_ctx.cleanup_requested.load(std::memory_order::relaxed)) {
      // Destroy libwebsockets context
      const auto lws_ctx = lib_ctx.lws_ctx;
      lib_ctx.lws_ctx = nullptr;
      lws_context_destroy(lws_ctx);
      return 0;
    }
    // Check for any pending actions in clients
    for (const std::scoped_lock lock(lib_ctx.cm_clients_mtx);
         auto client : lib_ctx.cm_clients) {
      if (bool expected = true; client->conn_requested.compare_exchange_strong(
              expected, false, std::memory_order::acquire,
              std::memory_order::relaxed)) {
        // Start connecting
        lws_client_connect_info info{};
        info.context = client->lib_ctx.lws_ctx;
        info.address = client->cur_server->hostname.data();
        info.port = client->cur_server->port;
        info.ssl_connection = LCCSCF_USE_SSL;
        info.path = "/cmsocket/";
        info.host = info.address;
        info.origin = info.address;
        info.protocol = "";
        info.userdata = client;
        if (!lws_client_connect_via_info(&info) &&
            client->conn_state.load(std::memory_order::relaxed) ==
                conn_state::connecting) {
          auto res = tsc_err_basic(TEK_SC_ERRC_cm_connect);
          const auto url = std::format(
              std::locale::classic(), "wss://{}:{}/cmsocket/",
              client->cur_server->hostname, client->cur_server->port);
          const auto url_buf =
              reinterpret_cast<char *>(std::malloc(url.length() + 1));
          if (url_buf) {
            std::ranges::move(url.begin(), url.end() + 1, url_buf);
          }
          res.uri = url_buf;
          client->connection_cb(client, &res, client->user_data);
        }
        continue;
      }
      // Schedule pending timeouts
      client->pending_msgs_mtx.lock();
      bool pending_send = client->wsi && !client->pending_msgs.empty();
      // Check if there is a disconnection request, don't schedule timeouts if
      //    there is
      if (pending_send &&
          std::ranges::any_of(client->pending_msgs, std::logical_not{},
                              &pending_msg_entry::buf)) {
        lws_set_timeout(client->wsi, static_cast<pending_timeout>(1),
                        LWS_TO_KILL_ASYNC);
        client->pending_msgs_mtx.unlock();
        continue;
      }
      for (auto &msg : client->pending_msgs) {
        if (msg.sul && lws_dll2_is_detached(&msg.sul->list)) {
          lws_sul2_schedule(lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                            msg.sul);
        }
      }
      client->pending_msgs_mtx.unlock();
      client->lics_mtx.lock();
      for (auto &a_entry : client->lics_a_entries) {
        if (lws_dll2_is_detached(&a_entry.sul.list)) {
          lws_sul2_schedule(lib_ctx.lws_ctx, 0, LWSSULLI_MISS_IF_SUSPENDED,
                            &a_entry.sul);
        }
      }
      client->lics_mtx.unlock();
      if (pending_send) {
        lws_callback_on_writable(client->wsi);
      }
    } // for (auto client : lib_ctx.cm_clients)
    break;
  } // case LWS_CALLBACK_EVENT_WAIT_CANCELLED
  case LWS_CALLBACK_CLIENT_CLOSED: {
    auto &client = *reinterpret_cast<cm_client *>(user);
    client.conn_state.store(conn_state::disconnected,
                            std::memory_order::relaxed);
    client.wsi = nullptr;
    client.steam_id = 0;
    client.session_id = 0;
    // Cancel all scheduled suls and run timeout handlers
    client.a_entries_mtx.lock();
    while (!client.a_entries.empty()) {
      auto &a_entry = client.a_entries.begin()->second;
      lws_sul_cancel(&a_entry.sul);
      a_entry.sul.cb(&a_entry.sul);
    }
    client.a_entries_mtx.unlock();
    lws_sul_cancel(&client.sign_in_entry.sul);
    client.lics_mtx.lock();
    client.num_lics = -1;
    client.lics.reset();
    while (!client.lics_a_entries.empty()) {
      auto &a_entry = client.lics_a_entries.front();
      lws_sul_cancel(&a_entry.sul);
      a_entry.sul.cb(&a_entry.sul);
    }
    client.lics_mtx.unlock();
    if (client.status_req) {
      lws_sul_cancel(&client.status_req->sul);
      client.status_req.reset();
    }
    auto res = client.disconnect_reason ? tsc_err_sub(TEK_SC_ERRC_cm_disconnect,
                                                      client.disconnect_reason)
                                        : tsc_err_ok();
    client.disconnect_reason = TEK_SC_ERRC_ok;
    client.disconnection_cb(&client, &res, client.user_data);
    if (client.destroy_requested.load(std::memory_order::relaxed)) {
      destroy(client);
    }
    return 0;
  }
  default:
    break;
  } // switch (reason)
  return lws_callback_http_dummy(wsi, reason, user, in, len);
}

} // namespace

//===-- Internal variable -------------------------------------------------===//

constexpr lws_protocols protocol{.name = "",
                                 .callback = tsc_lws_cb,
                                 .per_session_data_size = 0,
                                 .rx_buffer_size = 32768,
                                 .id = 0,
                                 .user = nullptr,
                                 .tx_packet_size = 8192};

//===-- Internal function -------------------------------------------------===//

std::uint64_t gen_job_id() noexcept {
  static std::atomic_uint64_t counter;
  return job_id_mask | counter.fetch_add(1, std::memory_order::relaxed);
}

//===-- Public functions --------------------------------------------------===//

extern "C" {

//===--- Create/destroy ---------------------------------------------------===//

tek_sc_cm_client *tek_sc_cm_client_create(tek_sc_lib_ctx *lib_ctx,
                                          void *user_data) {
  const auto client = new (std::nothrow) cm_client(lib_ctx, user_data);
  if (!client) {
    return nullptr;
  }
  if (tsci_z_inflateInit2(&client->zstream, 16) != Z_OK) {
    delete client;
    return nullptr;
  }
  const std::scoped_lock lock(lib_ctx->cm_clients_mtx);
  lib_ctx->cm_clients.emplace_front(client);
  return client;
}

void tek_sc_cm_client_destroy(tek_sc_cm_client *client) {
  if (client->conn_state.load(std::memory_order::relaxed) ==
      conn_state::disconnected) {
    // Client can be destroyed immediately
    destroy(*client);
    return;
  }
  // Request disconnection and destruction afterwards
  client->destroy_requested.store(true, std::memory_order::relaxed);
  tek_sc_cm_disconnect(client);
}

void tek_sc_cm_set_user_data(tek_sc_cm_client *client, void *user_data) {
  client->user_data = user_data;
}

//===--- Connect/disconnect -----------------------------------------------===//

void tek_sc_cm_connect(tek_sc_cm_client *client,
                       tek_sc_cm_callback_func *connection_cb,
                       long fetch_timeout_ms,
                       tek_sc_cm_callback_func *disconnection_cb) {
  if (auto expected = conn_state::disconnected;
      !client->conn_state.compare_exchange_strong(
          expected, conn_state::connecting, std::memory_order::relaxed,
          std::memory_order::relaxed)) {
    // Don't do anything if there is already another connection
    return;
  }
  // Ensure that server list is not empty
  client->lib_ctx.cm_servers_mtx.lock();
  if (client->lib_ctx.cm_servers.empty()) {
    auto res = fetch_server_list(client->lib_ctx.cm_servers, fetch_timeout_ms);
    client->lib_ctx.cm_servers_mtx.unlock();
    if (tek_sc_err_success(&res)) {
      client->lib_ctx.dirty_flags.fetch_or(
          static_cast<int>(dirty_flag::cm_servers), std::memory_order::relaxed);
    } else {
      connection_cb(client, &res, client->user_data);
      return;
    }
  } else {
    client->lib_ctx.cm_servers_mtx.unlock();
  }
  // Prepare and submit the connection request
  client->cur_server = client->lib_ctx.cm_servers.cbegin();
  client->num_conn_retries = 0;
  client->connection_cb = connection_cb;
  client->disconnection_cb = disconnection_cb;
  client->conn_requested.store(true, std::memory_order::release);
  lws_cancel_service(client->lib_ctx.lws_ctx);
}

void tek_sc_cm_disconnect(tek_sc_cm_client *client) {
  switch (client->conn_state.load(std::memory_order::relaxed)) {
  case conn_state::disconnected:
    // Already disonnected
    return;
  case conn_state::signed_in: {
    /// Send logoff request
    message<msg_payloads::LogoffRequest> msg;
    msg.type = EMsg::EMSG_CLIENT_LOG_OFF;
    if (const auto res =
            client->send_message<TEK_SC_ERRC_cm_disconnect>(msg, nullptr);
        tek_sc_err_success(&res)) {
      break;
    }
    // Fallback to closing the connection from client side
    [[fallthrough]];
  }
  case conn_state::connecting:
  case conn_state::connected:
    /// Submit disconnection request
    client->pending_msgs_mtx.lock();
    client->pending_msgs.emplace_back();
    client->pending_msgs_mtx.unlock();
    lws_cancel_service(client->lib_ctx.lws_ctx);
  }
}

} // extern "C"

} // namespace tek::steamclient::cm
