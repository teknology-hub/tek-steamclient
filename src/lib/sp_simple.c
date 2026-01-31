//===-- sp_simple.c - SteamPipe simple downloader implementation ----------===//
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
/// Implementation of SteamPipe interface functions for downloading single
///    files.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "common/error.h"
#include "config.h"
#include "os.h"
#include "sp.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "tek-steamclient/error.h"
#include "utils.h"
#include "zlib_api.h"

#include <curl/curl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//===-- Private types -----------------------------------------------------===//

/// Download context for manifest and patch downloads.
typedef struct tscp_dw_ctx_dm_dp tscp_dw_ctx_dm_dp;
/// @copydoc tscp_dw_ctx_dm_dp
struct tscp_dw_ctx_dm_dp {
  /// curl easy handle that performs the download.
  CURL *_Nonnull curl;
  /// Optional pointer to the flag that may be set by another thread to cancel
  ///    the operation.
  const atomic_bool *_Nullable cancel_flag;
  /// Pointer to the common part of input/output data.
  tek_sc_sp_data *_Nonnull data;
  /// Offset into `data->data` to copy the next chunk of downloaded data to,
  ///    also the current progress.
  int next_offset;
};

/// Download context for chunk downloads.
typedef struct tscp_dw_ctx_chunk tscp_dw_ctx_chunk;
/// @copydoc tscp_dw_ctx_chunk
struct tscp_dw_ctx_chunk {
  /// curl easy handle that performs the download.
  CURL *_Nonnull curl;
  /// Optional pointer to the flag that may be set by another thread to cancel
  ///    the operation.
  const atomic_bool *_Nullable cancel_flag;
  /// Pointer to the input/output data.
  tek_sc_sp_data_chunk *_Nonnull data;
  /// Offset into `data->comp_data` to copy the next chunk of downloaded data
  ///    to, also the current progress.
  int next_offset;
};

//===-- Private functions -------------------------------------------------===//

/// Set common curl easy handle options.
///
/// @param curl
///    curl easy handle to set options for.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param writedata
///    `CURLOPT_WRITEDATA` value.
/// @param curlu
///    `CURLOPT_CURLU` value.
/// @param writefunc
///    `CURLOPT_WRITEFUNCTION` value.
[[gnu::nonnull(1, 3, 4, 5)]]
static void tscp_sp_set_curl_opts(CURL *_Nonnull curl, long timeout_ms,
                                  void *_Nonnull writedata,
                                  CURLU *_Nonnull curlu,
                                  curl_write_callback _Nonnull writefunc) {
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, writedata);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, TEK_SC_UA);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
}

/// Run download operation, retry with DoH fallback if necessary, and get CDN
///    auth token if necessary.
/// @param curl
///    curl easy handle that performs the download.
/// @param curlu
///    `CURLOPT_CURLU` value.
/// @param [in, out] srv
///    SteamPipe server entry to use.
/// @param depot_id
///    ID of the depot to download file from.
/// @param [in, out] cm_client
///    Pointer to CM client instance to use to get CDN auth token if @ref srv
///    requires it.
/// @param [out] code
///    Address of variable that receives CURL result code on success.
/// @return If @p cm_client is used to get a CDN auth token and it fails, its
///    result, otherwise `tsc_err_ok()`.
[[gnu::nonnull(1, 2, 3, 6), gnu::access(read_write, 3),
  gnu::access(write_only, 6)]]
static tek_sc_err
tscp_sp_run_download(CURL *_Nonnull curl, CURLU *_Nonnull curlu,
                     tek_sc_cm_sp_srv_entry *_Nonnull srv, uint32_t depot_id,
                     tek_sc_cm_client *_Nullable cm_client,
                     CURLcode *_Nonnull code) {
  auto res = curl_easy_perform(curl);
  switch (res) {
  case CURLE_COULDNT_RESOLVE_HOST:
  case CURLE_PEER_FAILED_VERIFICATION:
    curl_easy_setopt(curl, CURLOPT_RESOLVE, &tsci_sp_cf_dns_resolve);
    curl_easy_setopt(curl, CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");
    res = curl_easy_perform(curl);
    break;
  default:
  }
  if (res == CURLE_HTTP_RETURNED_ERROR && cm_client) {
    long status;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status == 403) {
      tsci_sp_cat_req req;
      req.data.depot_id = depot_id;
      req.data.hostname = srv->host;
      atomic_init(&req.futex, 0);
      tek_sc_cm_get_cdn_auth_token(cm_client, &req.data,
                                   tsci_sp_cb_cdn_auth_token, 5000);
      if (!tsci_os_futex_wait(&req.futex, 0, 6000)) {
        return tsc_err_sub(TEK_SC_ERRC_cm_cdn_auth_token,
                           TEK_SC_ERRC_cm_timeout);
      }
      if (!tek_sc_err_success(&req.data.result)) {
        return req.data.result;
      }
      if (req.data.token) {
        if (srv->auth_token) {
          free((void*)srv->auth_token);
        }
        srv->auth_token = req.data.token;
        // Skip first character because CURLUPART_QUERY prepends '?' on its own
        curl_url_set(curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
        res = curl_easy_perform(curl);
      }
    }
  }
  *code = res;
  return tsc_err_ok();
}

/// curl write data callback for manifest and patch downloads.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk, in bytes.
/// @param [in, out] userdata
///    Pointer to the corresponding @ref tscp_dw_ctx_dm_dp.
/// @return @p size.
[[gnu::nonnull(1), gnu::access(read_only, 1, 3), gnu::access(read_write, 4)]]
static size_t tscp_sp_curl_write_dm_dp(char *_Nonnull buf, size_t, size_t size,
                                       void *_Nonnull userdata) {
  tscp_dw_ctx_dm_dp *const ctx = userdata;
  if (ctx->cancel_flag &&
      atomic_load_explicit(ctx->cancel_flag, memory_order_relaxed)) {
    return CURL_WRITEFUNC_ERROR;
  }
  auto const data = ctx->data;
  if (!data->data) {
    // This block is called only once, on first write
    // Get content length and allocate the buffer
    curl_off_t content_len;
    if (curl_easy_getinfo(ctx->curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                          &content_len) != CURLE_OK ||
        content_len < 0) {
      return CURL_WRITEFUNC_ERROR;
    }
    data->data = malloc(content_len);
    if (!data->data) {
      return CURL_WRITEFUNC_ERROR;
    }
    data->data_size = content_len;
  }
  const int content_len = data->data_size;
  if (ctx->next_offset + (int)size > content_len) {
    return CURL_WRITEFUNC_ERROR;
  }
  memcpy(data->data + ctx->next_offset, buf, size);
  ctx->next_offset += size;
  auto const progress_handler = data->progress_handler;
  if (progress_handler) {
    progress_handler(data, ctx->next_offset, content_len);
  }
  return size;
}

/// curl write data callback for chunk downloads.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk, in bytes.
/// @param [in, out] userdata
///    Pointer to the corresponding @ref tscp_dw_ctx_chunk.
/// @return @p size.
[[gnu::nonnull(1), gnu::access(read_only, 1, 3), gnu::access(read_write, 4)]]
static size_t tscp_sp_curl_write_chunk(char *_Nonnull buf, size_t, size_t size,
                                       void *_Nonnull userdata) {
  tscp_dw_ctx_chunk *const ctx = userdata;
  if (ctx->cancel_flag &&
      atomic_load_explicit(ctx->cancel_flag, memory_order_relaxed)) {
    return CURL_WRITEFUNC_ERROR;
  }
  auto const data = ctx->data;
  const int content_len = data->chunk->comp_size;
  if (ctx->next_offset + (int)size > content_len) {
    return CURL_WRITEFUNC_ERROR;
  }
  memcpy(data->data + ctx->next_offset, buf, size);
  ctx->next_offset += size;
  auto const progress_handler = data->progress_handler;
  if (progress_handler) {
    progress_handler(data, ctx->next_offset, content_len);
  }
  return size;
}

//===-- Public functions --------------------------------------------------===//

tek_sc_err tek_sc_sp_download_dm(tek_sc_sp_data_dm *data, long timeout_ms,
                                 const atomic_bool *cancel_flag) {
  // Build the base URL
  auto const curlu = curl_url();
  if (!curlu) {
    return tsc_err_sub(TEK_SC_ERRC_sp_dm, TEK_SC_ERRC_curl_url);
  }
  char path[71];
  snprintf(path, sizeof path,
           "/depot/%" PRIu32 "/manifest/%" PRIu64 "/5/%" PRIu64,
           data->common.depot_id, data->manifest_id, data->request_code);
  curl_url_set(curlu, CURLUPART_PATH, path, 0);
  // Setup curl easy handle
  auto const curl = curl_easy_init();
  tek_sc_err res;
  if (!curl) {
    res = tsc_err_sub(TEK_SC_ERRC_sp_dm, TEK_SC_ERRC_curle_init);
    goto cleanup_curlu;
  }
  tscp_dw_ctx_dm_dp ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = &data->common};
  tscp_sp_set_curl_opts(curl, timeout_ms, &ctx, curlu,
                        tscp_sp_curl_write_dm_dp);
  // Try downloading from provided servers
  CURLcode curl_res = CURLE_URL_MALFORMAT;
  for (int i = 0; i < data->common.num_srvs; ++i) {
    auto const srv = &data->common.srvs[i];
    curl_url_set(curlu, CURLUPART_SCHEME,
                 srv->supports_https ? "https" : "http", 0);
    curl_url_set(curlu, CURLUPART_HOST, srv->host, 0);
    if (srv->auth_token) {
      curl_url_set(curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
    }
    data->common.data = nullptr;
    data->common.data_size = 0;
    res = tscp_sp_run_download(curl, curlu, srv, data->common.depot_id,
                               data->common.cm_client, &curl_res);
    if (cancel_flag &&
        atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
      res = tsc_err_basic(TEK_SC_ERRC_paused);
    }
    if (!tek_sc_err_success(&res)) {
      free(data->common.data);
      data->common.data = nullptr;
      data->common.data_size = 0;
      goto cleanup_curl;
    }
    switch (curl_res) {
    case CURLE_HTTP_RETURNED_ERROR: {
      long status;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
      switch (status) {
      case 429:
      case 502:
      case 503:
      case 504:
        free(data->common.data);
        continue;
      }
      break;
    }
    case CURLE_OPERATION_TIMEDOUT: {
      curl_off_t connect_time;
      curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &connect_time);
      if (connect_time <= 0) {
        continue;
      }
      break;
    }
    case CURLE_HTTP2_STREAM:
      continue;
    default:
    }
    break;
  }
  if (curl_res != CURLE_OK) {
    char *url_buf = nullptr;
    curl_url_get(curlu, CURLUPART_URL, &url_buf, 0);
    long status = 0;
    if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }
    free(data->common.data);
    data->common.data = nullptr;
    data->common.data_size = 0;
    res = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curle,
                       .primary = TEK_SC_ERRC_sp_dm,
                       .auxiliary = curl_res,
                       .extra = (int)status,
                       .uri = url_buf};
    goto cleanup_curl;
  }
  // Verify CRC32 checksum if it's provided by a header
  struct curl_header *crc_hdr;
  if (curl_easy_header(curl, "x-content-crc", 0, CURLH_HEADER, -1, &crc_hdr) ==
      CURLHE_OK) {
    if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), data->common.data,
                     data->common.data_size) !=
        strtoul(crc_hdr->value, nullptr, 10)) {
      free(data->common.data);
      data->common.data = nullptr;
      data->common.data_size = 0;
      res = tsc_err_sub(TEK_SC_ERRC_sp_dm, TEK_SC_ERRC_crc_mismatch);
      goto cleanup_curl;
    }
  }
  res = tsc_err_ok();
cleanup_curl:
  curl_easy_cleanup(curl);
cleanup_curlu:
  curl_url_cleanup(curlu);
  return res;
}

tek_sc_err tek_sc_sp_download_dp(tek_sc_sp_data_dp *data, long timeout_ms,
                                 const atomic_bool *cancel_flag) {
  // Build the base URL
  auto const curlu = curl_url();
  if (!curlu) {
    return tsc_err_sub(TEK_SC_ERRC_sp_dp, TEK_SC_ERRC_curl_url);
  }
  char path[66];
  snprintf(path, sizeof path, "/depot/%" PRIu32 "/patch/%" PRIu64 "/%" PRIu64,
           data->common.depot_id, data->src_manifest_id, data->tgt_manifest_id);
  curl_url_set(curlu, CURLUPART_PATH, path, 0);
  // Setup curl easy handle
  auto const curl = curl_easy_init();
  tek_sc_err res;
  if (!curl) {
    res = tsc_err_sub(TEK_SC_ERRC_sp_dm, TEK_SC_ERRC_curle_init);
    goto cleanup_curlu;
  }
  tscp_dw_ctx_dm_dp ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = &data->common};
  tscp_sp_set_curl_opts(curl, timeout_ms, &ctx, curlu,
                        tscp_sp_curl_write_dm_dp);
  // Try downloading from provided servers
  CURLcode curl_res = CURLE_URL_MALFORMAT;
  for (int i = 0; i < data->common.num_srvs; ++i) {
    auto const srv = &data->common.srvs[i];
    curl_url_set(curlu, CURLUPART_SCHEME,
                 srv->supports_https ? "https" : "http", 0);
    curl_url_set(curlu, CURLUPART_HOST, srv->host, 0);
    if (srv->auth_token) {
      curl_url_set(curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
    }
    data->common.data = nullptr;
    data->common.data_size = 0;
    res = tscp_sp_run_download(curl, curlu, srv, data->common.depot_id,
                               data->common.cm_client, &curl_res);
    if (cancel_flag &&
        atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
      res = tsc_err_basic(TEK_SC_ERRC_paused);
    }
    if (!tek_sc_err_success(&res)) {
      free(data->common.data);
      data->common.data = nullptr;
      data->common.data_size = 0;
      goto cleanup_curl;
    }
    switch (curl_res) {
    case CURLE_HTTP_RETURNED_ERROR: {
      long status;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
      switch (status) {
      case 429:
      case 502:
      case 503:
      case 504:
        free(data->common.data);
        continue;
      }
      break;
    }
    case CURLE_OPERATION_TIMEDOUT: {
      curl_off_t connect_time;
      curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &connect_time);
      if (connect_time <= 0) {
        continue;
      }
      break;
    }
    case CURLE_HTTP2_STREAM:
      continue;
    default:
    }
    break;
  }
  if (curl_res != CURLE_OK) {
    char *url_buf = nullptr;
    curl_url_get(curlu, CURLUPART_URL, &url_buf, 0);
    long status = 0;
    if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }
    free(data->common.data);
    data->common.data = nullptr;
    data->common.data_size = 0;
    res = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curle,
                       .primary = TEK_SC_ERRC_sp_dp,
                       .auxiliary = curl_res,
                       .extra = (int)status,
                       .uri = url_buf};
    goto cleanup_curl;
  }
  res = tsc_err_ok();
cleanup_curl:
  curl_easy_cleanup(curl);
cleanup_curlu:
  curl_url_cleanup(curlu);
  return res;
}

tek_sc_err tek_sc_sp_download_chunk(tek_sc_cm_sp_srv_entry *srv,
                                    tek_sc_sp_data_chunk *data, long timeout_ms,
                                    const atomic_bool *cancel_flag) {
  // Build the URL
  auto const curlu = curl_url();
  if (!curlu) {
    return tsc_err_sub(TEK_SC_ERRC_sp_chunk, TEK_SC_ERRC_curl_url);
  }
  curl_url_set(curlu, CURLUPART_SCHEME, srv->supports_https ? "https" : "http",
               0);
  curl_url_set(curlu, CURLUPART_HOST, srv->host, 0);
  {
    char path[65];
    const int len = snprintf(path, sizeof path, "/depot/%" PRIu32 "/chunk/",
                             data->depot_id);
    tsci_u_sha1_to_str(data->chunk->sha.bytes, &path[len]);
    path[len + 40] = '\0';
    curl_url_set(curlu, CURLUPART_PATH, path, 0);
  }
  if (srv->auth_token) {
    curl_url_set(curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
  }
  // Setup and run curl easy handle
  auto const curl = curl_easy_init();
  tek_sc_err res;
  if (!curl) {
    res = tsc_err_sub(TEK_SC_ERRC_sp_chunk, TEK_SC_ERRC_curle_init);
    goto cleanup_curlu;
  }
  tscp_dw_ctx_chunk ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = data};
  tscp_sp_set_curl_opts(curl, timeout_ms, &ctx, curlu,
                        tscp_sp_curl_write_chunk);
  CURLcode curl_res;
  res = tscp_sp_run_download(curl, curlu, srv, data->depot_id, data->cm_client,
                             &curl_res);
  if (cancel_flag && atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
    res = tsc_err_basic(TEK_SC_ERRC_paused);
  }
  if (!tek_sc_err_success(&res)) {
    goto cleanup_curl;
  }
  if (curl_res != CURLE_OK) {
    char *url_buf = nullptr;
    curl_url_get(curlu, CURLUPART_URL, &url_buf, 0);
    long status = 0;
    if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }
    res = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curle,
                       .primary = TEK_SC_ERRC_sp_chunk,
                       .auxiliary = curl_res,
                       .extra = (int)status,
                       .uri = url_buf};
    goto cleanup_curl;
  }
  res = tsc_err_ok();
cleanup_curl:
  curl_easy_cleanup(curl);
cleanup_curlu:
  curl_url_cleanup(curlu);
  return res;
}
