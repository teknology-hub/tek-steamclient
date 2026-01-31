//===-- sp_multi.c - SteamPipe multi downloader implementation ------------===//
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
/// Implementation of SteamPipe multi chunk downloader interface.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "common/error.h"
#include "config.h"
#include "os.h"
#include "sp.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"
#include "utils.h"

#include <curl/curl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// @def TSCP_MAX_NUM_RETRIES
/// The number of times the multi downloader is allowed to restart a download
///     after non-critical errors before failing the request.
#define TSCP_MAX_NUM_RETRIES 10

/// @def TSCP_TIMEOUT_MS
/// The number of milliseconds to wait before re-submitting a request after
///    receiving an HTTP status code indicating that the server is too busy.
#define TSCP_TIMEOUT_MS 1500

//===-- Private types -----------------------------------------------------===//

/// Individual chunk downloader instance.
typedef struct tscp_sp_dlr_inst tscp_sp_dlr_inst;
/// @copydoc tscp_sp_dlr_inst
struct tscp_sp_dlr_inst {
  /// curl easy handle that performs the download.
  CURL *_Nonnull curl;
  /// curl URL handle storing the URL of the chunk being downloaded.
  CURLU *_Nonnull curlu;
  /// Pointer to the multi downloader descriptor.
  tek_sc_sp_multi_dlr_desc *_Nonnull desc;
  /// Pointer to the request/response data currently being processed.
  tek_sc_sp_multi_chunk_req *_Nullable req;
  /// Offset into `req->comp_data` to copy the next chunk of downloaded data to.
  int next_offset;
  /// Download retry counter. Reset when scheduling a new request. When reaches
  ///    @ref TSCP_MAX_NUM_RETRIES, the request fails.
  int num_retries;
  /// The timestamp after which the request should be re-submitted.
  uint64_t timeout_timestamp;
  /// Pointer to the next instance with scheduled timeout.
  tscp_sp_dlr_inst *_Nullable next_timedout;
  /// Index of currently assigned SteamPipe server entry.
  int srv_ind;
  /// Buffer storing path part of the URL.
  char path[65];
};

/// Multi downloader thread context.
typedef struct tscp_sp_multi_thrd_ctx tscp_sp_multi_thrd_ctx;
/// @copydoc tscp_sp_multi_thrd_ctx
struct tscp_sp_multi_thrd_ctx {
  /// curl multi handle running the downloads.
  CURLM *_Nonnull curlm;
  /// Pointer to the array of chunk downloader instances.
  tscp_sp_dlr_inst *_Nonnull insts;
  /// Number of elements in @ref insts.
  int num_insts;
  /// Number of currently active chunk downloader instances.
  int num_active;
  /// Number of currently running chunk downloader instances.
  int num_running;
  /// Pointer to downloader instance with earliest scheduled timeout.
  tscp_sp_dlr_inst *_Nullable timedout;
  /// Chunk decoding context.
  tek_sc_sp_dec_ctx dec_ctx;
};

/// @copydoc tek_sc_sp_multi_dlr
struct tek_sc_sp_multi_dlr {
  /// Pointer to the assigned descriptor.
  const tek_sc_sp_multi_dlr_desc *_Nonnull desc;
  /// Pointer to the thread context array.
  tscp_sp_multi_thrd_ctx *_Nonnull thrd_ctxs;
  /// ID of the depot to download chunks from.
  uint32_t depot_id;
  /// Offset into `path` field of downloader instances where the SHA-1 hash
  ///    part begins.
  int path_sha_offset;
  /// Flag that may be set to cancel all ongoing downloads.
  atomic_bool cancel_flag;
  /// Mutex protecting concurrent access to CDN auth tokens of `desc->srvs`.
  pthread_mutex_t auth_token_mtx;
};

//===-- Private functions -------------------------------------------------===//

/// curl write data callback for multi downloader.
///
/// @param [in] buf
///    Pointer to the buffer containing downloaded content chunk.
/// @param size
///    Size of the content chunk, in bytes.
/// @param [in, out] userdata
///    Pointer to the corresponding @ref tscp_dlr_inst.
/// @return @p size.
[[gnu::nonnull(1), gnu::access(read_only, 1, 3), gnu::access(read_write, 4)]]
static size_t tscp_sp_curl_write_multi(char *_Nonnull buf, size_t, size_t size,
                                       void *_Nonnull userdata) {
  tscp_sp_dlr_inst *const inst = userdata;
  auto const req = inst->req;
  if (inst->next_offset + (int)size > req->chunk->comp_size) {
    return CURL_WRITEFUNC_ERROR;
  }
  memcpy(req->comp_data + inst->next_offset, buf, size);
  inst->next_offset += size;
  auto const desc = inst->desc;
  atomic_fetch_add_explicit(&desc->progress, size, memory_order_relaxed);
  auto const progress_handler = desc->progress_handler;
  if (progress_handler) {
    progress_handler(desc);
  }
  return size;
}

//===-- Public functions --------------------------------------------------===//

tek_sc_sp_multi_dlr *
tek_sc_sp_multi_dlr_create(tek_sc_sp_multi_dlr_desc *desc, uint32_t depot_id,
                           const tek_sc_aes256_key decryption_key,
                           tek_sc_err *err) {
  if (desc->num_threads > desc->num_srvs) {
    desc->num_threads = desc->num_srvs;
  }
  const int srvs_per_thread =
      (desc->num_srvs + desc->num_threads - 1) / desc->num_threads;
  desc->num_threads = (desc->num_srvs + srvs_per_thread - 1) / srvs_per_thread;
  desc->num_reqs_per_thread = srvs_per_thread * TEK_SCB_CHUNKS_PER_SRV;
  desc->num_reqs_last_thread =
      (desc->num_srvs % srvs_per_thread) * TEK_SCB_CHUNKS_PER_SRV;
  if (!desc->num_reqs_last_thread) {
    desc->num_reqs_last_thread = desc->num_reqs_per_thread;
  }
  const int num_insts = desc->num_srvs * TEK_SCB_CHUNKS_PER_SRV;
  tek_sc_sp_multi_dlr *dlr =
      malloc(sizeof *dlr + (sizeof *dlr->thrd_ctxs * desc->num_threads) +
             (sizeof(tscp_sp_dlr_inst) * num_insts));
  if (!dlr) {
    *err = tsc_err_sub(TEK_SC_ERRC_sp_multi_dlr, TEK_SC_ERRC_mem_alloc);
    return nullptr;
  }
  dlr->desc = desc;
  dlr->thrd_ctxs = (tscp_sp_multi_thrd_ctx *)(dlr + 1);
  dlr->depot_id = depot_id;
  dlr->path_sha_offset =
      snprintf(nullptr, 0, "/depot/%" PRIu32 "/chunk/", depot_id);
  atomic_init(&dlr->cancel_flag, false);
  auto const insts = (tscp_sp_dlr_inst *)(dlr->thrd_ctxs + desc->num_threads);
  // Initialize downloader instances
  for (int i = 0, srv_ind = 0; i < num_insts; ++i) {
    auto const inst = &insts[i];
    if (i) {
      if (i % TEK_SCB_CHUNKS_PER_SRV == 0) {
        ++srv_ind;
      }
      inst->curl = curl_easy_duphandle(insts[i - 1].curl);
      if (!inst->curl) {
        *err = tsc_err_sub(TEK_SC_ERRC_sp_multi_dlr, TEK_SC_ERRC_curle_init);
        goto handle_err_insts;
      }
    } else {
      inst->curl = curl_easy_init();
      if (!inst->curl) {
        *err = tsc_err_sub(TEK_SC_ERRC_sp_multi_dlr, TEK_SC_ERRC_curle_init);
        goto handle_err_insts;
      }
      curl_easy_setopt(inst->curl, CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(inst->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3);
      curl_easy_setopt(inst->curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(inst->curl, CURLOPT_TIMEOUT_MS, 180000L);
      curl_easy_setopt(inst->curl, CURLOPT_CONNECTTIMEOUT_MS, 16000L);
      curl_easy_setopt(inst->curl, CURLOPT_PIPEWAIT, 1L);
      curl_easy_setopt(inst->curl, CURLOPT_USERAGENT, TEK_SC_UA);
      curl_easy_setopt(inst->curl, CURLOPT_WRITEFUNCTION,
                       tscp_sp_curl_write_multi);
    }
    curl_easy_setopt(inst->curl, CURLOPT_WRITEDATA, inst);
    curl_easy_setopt(inst->curl, CURLOPT_PRIVATE, inst);
    inst->curlu = curl_url();
    if (!inst->curlu) {
      curl_easy_cleanup(inst->curl);
      *err = tsc_err_sub(TEK_SC_ERRC_sp_multi_dlr, TEK_SC_ERRC_curl_url);
      goto handle_err_insts;
    }
    curl_easy_setopt(inst->curl, CURLOPT_CURLU, inst->curlu);
    auto const srv = &desc->srvs[srv_ind];
    curl_url_set(inst->curlu, CURLUPART_SCHEME,
                 srv->supports_https ? "https" : "http", 0);
    curl_url_set(inst->curlu, CURLUPART_HOST, srv->host, 0);
    if (srv->auth_token) {
      curl_url_set(inst->curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
    }
    inst->desc = desc;
    inst->req = nullptr;
    inst->next_offset = 0;
    inst->num_retries = 0;
    inst->next_timedout = nullptr;
    inst->srv_ind = srv_ind;
    snprintf(inst->path, sizeof inst->path, "/depot/%" PRIu32 "/chunk/",
             depot_id);
    inst->path[dlr->path_sha_offset + 40] = '\0';
    continue;
  handle_err_insts:
    for (int j = 0; j < i; ++j) {
      auto const inst = &insts[j];
      curl_easy_cleanup(inst->curl);
      curl_url_cleanup(inst->curlu);
    }
    goto cleanup_dlr;
  } // (int i = 0; i < num_insts; ++i)
  // Initialize thread contexts
  for (int i = 0; i < desc->num_threads; ++i) {
    auto const thrd_ctx = &dlr->thrd_ctxs[i];
    thrd_ctx->curlm = curl_multi_init();
    if (!thrd_ctx->curlm) {
      *err = tsc_err_sub(TEK_SC_ERRC_sp_multi_dlr, TEK_SC_ERRC_curlm_init);
      for (int j = 0; j < i; ++j) {
        curl_multi_cleanup(dlr->thrd_ctxs[j].curlm);
      }
      goto cleanup_insts;
    }
    curl_multi_setopt(thrd_ctx->curlm, CURLMOPT_MAX_HOST_CONNECTIONS,
                      (long)TEK_SCB_CHUNKS_PER_SRV);
    thrd_ctx->insts = &insts[i * srvs_per_thread * TEK_SCB_CHUNKS_PER_SRV];
    thrd_ctx->num_insts = srvs_per_thread * TEK_SCB_CHUNKS_PER_SRV;
    thrd_ctx->num_active = 0;
    thrd_ctx->num_running = 0;
    thrd_ctx->timedout = 0;
    thrd_ctx->dec_ctx.flags = 0;
    thrd_ctx->dec_ctx.decryption_key =
        (const tek_sc_aes256_key *)decryption_key;
  }
  dlr->thrd_ctxs[desc->num_threads - 1].num_insts = desc->num_reqs_last_thread;
  pthread_mutex_init(&dlr->auth_token_mtx, nullptr);
  *err = tsc_err_ok();
  return dlr;
cleanup_insts:
  for (int i = 0; i < num_insts; ++i) {
    auto const inst = &insts[i];
    curl_easy_cleanup(inst->curl);
    curl_url_cleanup(inst->curlu);
  }
cleanup_dlr:
  free(dlr);
  return nullptr;
}

void tek_sc_sp_multi_dlr_destroy(tek_sc_sp_multi_dlr *_Nonnull dlr) {
  pthread_mutex_destroy(&dlr->auth_token_mtx);
  const int num_threads = dlr->desc->num_threads;
  for (int i = 0; i < num_threads; ++i) {
    auto const thrd_ctx = &dlr->thrd_ctxs[i];
    curl_multi_cleanup(thrd_ctx->curlm);
    tsci_chunk_dec_ctx_free(&thrd_ctx->dec_ctx);
  }
  auto const insts = (tscp_sp_dlr_inst *)(dlr->thrd_ctxs + num_threads);
  const int num_insts = dlr->desc->num_srvs * TEK_SCB_CHUNKS_PER_SRV;
  for (int i = 0; i < num_insts; ++i) {
    auto const inst = &insts[i];
    curl_easy_cleanup(inst->curl);
    curl_url_cleanup(inst->curlu);
  }
  free(dlr);
}

tek_sc_err tek_sc_sp_multi_dlr_submit_req(const tek_sc_sp_multi_dlr *dlr,
                                          int thrd_index,
                                          tek_sc_sp_multi_chunk_req *req) {
  auto const thrd_ctx = &dlr->thrd_ctxs[thrd_index];
  if (thrd_ctx->num_active >= thrd_ctx->num_insts) {
    return tsc_err_sub(TEK_SC_ERRC_sp_chunk, TEK_SC_ERRC_sp_max_reqs);
  }
  tscp_sp_dlr_inst *inst = nullptr;
  for (int i = 0; i < thrd_ctx->num_insts; ++i) {
    inst = &thrd_ctx->insts[i];
    if (!inst->req) {
      break;
    }
  }
  inst->req = req;
  tsci_u_sha1_to_str(req->chunk->sha.bytes, &inst->path[dlr->path_sha_offset]);
  curl_url_set(inst->curlu, CURLUPART_PATH, inst->path, 0);
  auto const res = curl_multi_add_handle(thrd_ctx->curlm, inst->curl);
  if (res != CURLM_OK) {
    inst->req = nullptr;
    return (tek_sc_err){.type = TEK_SC_ERR_TYPE_curlm,
                        .primary = TEK_SC_ERRC_sp_chunk,
                        .auxiliary = res};
  }
  ++thrd_ctx->num_active;
  ++thrd_ctx->num_running;
  return tsc_err_ok();
}

tek_sc_sp_multi_chunk_req *tek_sc_sp_multi_dlr_process(tek_sc_sp_multi_dlr *dlr,
                                                       int thrd_index,
                                                       bool poll,
                                                       tek_sc_err *err) {
  auto const thrd_ctx = &dlr->thrd_ctxs[thrd_index];
  if (!thrd_ctx->num_active) {
    *err = tsc_err_ok();
    return nullptr;
  }
  auto const curlm = thrd_ctx->curlm;
  // Poll until at least one request has completed.
  for (;;) {
    int num_handles;
    auto res = curl_multi_perform(curlm, &num_handles);
    if (res != CURLM_OK) {
      *err = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curlm,
                          .primary = TEK_SC_ERRC_sp_chunk,
                          .auxiliary = res};
      return nullptr;
    }
    int timeout = INT_MAX;
    if (thrd_ctx->timedout) {
      auto const timestamp = tsci_os_get_ticks();
      do {
        auto const inst = thrd_ctx->timedout;
        if (timestamp < inst->timeout_timestamp) {
          timeout = inst->timeout_timestamp - timestamp;
          break;
        }
        res = curl_multi_add_handle(curlm, inst->curl);
        if (res != CURLM_OK) {
          auto const req = inst->req;
          inst->req = nullptr;
          inst->num_retries = 0;
          --thrd_ctx->num_active;
          req->result = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curlm,
                                     .primary = TEK_SC_ERRC_sp_chunk,
                                     .auxiliary = res};
          *err = tsc_err_ok();
          return req;
        }
        ++thrd_ctx->num_running;
        thrd_ctx->timedout = inst->next_timedout;
        inst->next_timedout = nullptr;
      } while (thrd_ctx->timedout);
    }
    if (num_handles < thrd_ctx->num_running) {
      break;
    }
    if (!poll) {
      *err = tsc_err_ok();
      return nullptr;
    }
    res = curl_multi_poll(curlm, nullptr, 0, timeout, nullptr);
    if (atomic_load_explicit(&dlr->cancel_flag, memory_order_relaxed)) {
      *err = tsc_err_basic(TEK_SC_ERRC_paused);
      return nullptr;
    }
    if (res != CURLM_OK) {
      *err = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curlm,
                          .primary = TEK_SC_ERRC_sp_chunk,
                          .auxiliary = res};
      return nullptr;
    }
  }
  *err = tsc_err_ok();
  // Process the completed request, if it failed with non-critical error,
  //    re-submit it and process next one if available.
  for (int64_t timestamp = 0;;) {
    int num_queued;
    auto const msg = curl_multi_info_read(curlm, &num_queued);
    if (!msg) {
      return nullptr;
    }
    --thrd_ctx->num_running;
    curl_multi_remove_handle(curlm, msg->easy_handle);
    tscp_sp_dlr_inst *inst;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &inst);
    const int progress = inst->next_offset;
    inst->next_offset = 0;
    auto const req_res = msg->data.result;
    auto const req = inst->req;
    if (req_res == CURLE_OK) {
      auto const decode_res = tek_sc_sp_decode_chunk(
          &thrd_ctx->dec_ctx, req->comp_data, req->data, req->chunk);
      if (tek_sc_err_success(&decode_res) ||
          inst->num_retries >= TSCP_MAX_NUM_RETRIES - 1) {
        inst->req = nullptr;
        inst->num_retries = 0;
        --thrd_ctx->num_active;
        req->result = decode_res;
        return req;
      }
    }
    if (progress) {
      atomic_fetch_sub_explicit(&inst->desc->progress, progress,
                                memory_order_relaxed);
    }
    long status = 0;
    if (req_res == CURLE_HTTP_RETURNED_ERROR) {
      curl_easy_getinfo(inst->curl, CURLINFO_RESPONSE_CODE, &status);
    }
    bool change_srv = false;
    switch (status) {
    case 403: {
      auto const cm_client = dlr->desc->cm_client;
      if (!cm_client) {
        // Insta-fail
        inst->num_retries = TSCP_MAX_NUM_RETRIES;
        break;
      }
      auto const srv = &dlr->desc->srvs[inst->srv_ind];
      tsci_sp_cat_req cat_req;
      cat_req.data.depot_id = dlr->depot_id;
      cat_req.data.hostname = srv->host;
      atomic_init(&cat_req.futex, 0);
      tek_sc_cm_get_cdn_auth_token(cm_client, &cat_req.data,
                                   tsci_sp_cb_cdn_auth_token, 5000);
      if (!tsci_os_futex_wait(&cat_req.futex, 0, 6000)) {
        cat_req.data.result =
            tsc_err_sub(TEK_SC_ERRC_cm_cdn_auth_token, TEK_SC_ERRC_cm_timeout);
      }
      if (!tek_sc_err_success(&cat_req.data.result)) {
        inst->req = nullptr;
        inst->num_retries = 0;
        --thrd_ctx->num_active;
        req->result = cat_req.data.result;
        return req;
      }
      if (cat_req.data.token) {
        pthread_mutex_lock(&dlr->auth_token_mtx);
        if (srv->auth_token) {
          free((void *)srv->auth_token);
        }
        srv->auth_token = cat_req.data.token;
        curl_url_set(inst->curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
        pthread_mutex_unlock(&dlr->auth_token_mtx);
        goto add_handle;
      }
      break;
    }
    case 404:
    case 502:
    case 503:
      change_srv = true;
      break;
    }
    if (!change_srv && ++inst->num_retries >= TSCP_MAX_NUM_RETRIES) {
      inst->req = nullptr;
      inst->num_retries = 0;
      --thrd_ctx->num_active;
      char *url_buf = nullptr;
      curl_url_get(inst->curlu, CURLUPART_URL, &url_buf, 0);
      req->result = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curle,
                                 .primary = TEK_SC_ERRC_sp_chunk,
                                 .auxiliary = req_res,
                                 .extra = (int)status,
                                 .uri = url_buf};
      return req;
    }
    switch (status) {
    case 429:
    case 504:
      if (!timestamp) {
        timestamp = tsci_os_get_ticks() + TSCP_TIMEOUT_MS;
      }
      inst->timeout_timestamp = timestamp;
      auto ptr = &thrd_ctx->timedout;
      while (*ptr) {
        ptr = &(*ptr)->next_timedout;
      }
      *ptr = inst;
      continue;
    }
    switch (req_res) {
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_PEER_FAILED_VERIFICATION:
      curl_easy_setopt(inst->curl, CURLOPT_RESOLVE, &tsci_sp_cf_dns_resolve);
      curl_easy_setopt(inst->curl, CURLOPT_DOH_URL,
                       "https://cloudflare-dns.com/dns-query");
      break;
    default:
    }
    if (change_srv || req_res == CURLE_OPERATION_TIMEDOUT ||
        inst->num_retries % 4 == 0) {
      int srv_ind = inst->srv_ind;
      if (++srv_ind >= dlr->desc->num_srvs) {
        srv_ind = 0;
      }
      auto const srv = &dlr->desc->srvs[srv_ind];
      curl_url_set(inst->curlu, CURLUPART_SCHEME,
                   srv->supports_https ? "https" : "http", 0);
      curl_url_set(inst->curlu, CURLUPART_HOST, srv->host, 0);
      pthread_mutex_lock(&dlr->auth_token_mtx);
      if (srv->auth_token) {
        curl_url_set(inst->curlu, CURLUPART_QUERY, &srv->auth_token[1], 0);
      }
      pthread_mutex_unlock(&dlr->auth_token_mtx);
      inst->srv_ind = srv_ind;
    }
  add_handle:
    auto const res = curl_multi_add_handle(curlm, inst->curl);
    if (res != CURLM_OK) {
      inst->req = nullptr;
      inst->num_retries = 0;
      --thrd_ctx->num_active;
      req->result = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curlm,
                                 .primary = TEK_SC_ERRC_sp_chunk,
                                 .auxiliary = res};
      return req;
    }
    ++thrd_ctx->num_running;
    if (!num_queued) {
      return nullptr;
    }
  } // for (;;)
}

void tek_sc_sp_multi_dlr_cancel(tek_sc_sp_multi_dlr *dlr) {
  atomic_store_explicit(&dlr->cancel_flag, true, memory_order_relaxed);
  for (int i = 0; i < dlr->desc->num_threads; ++i) {
    curl_multi_wakeup(dlr->thrd_ctxs[i].curlm);
  }
}
