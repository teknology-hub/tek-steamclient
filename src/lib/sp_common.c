//===-- sp_common.c - SteamPipe common functions implementation ----------===//
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
/// Implementation of SteamPipe interface common internal functions used by
///    multiple implementation modules.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "os.h"
#include "sp.h"
#include "tek-steamclient/cm.h"

#include <curl/curl.h>
#include <lzma.h>
#include <openssl/evp.h>
#include <stdatomic.h>
#include <string.h>
#include <zstd.h>

struct curl_slist tsci_sp_cf_dns_resolve = {
    .data = "cloudflare-dns.com:443:2606:4700:4700::1111,2606:4700:4700::1001,"
            "1.1.1.1,1.0.0.1"};

void tsci_chunk_dec_ctx_free(tek_sc_sp_dec_ctx *ctx) {
  if (ctx->flags & TSCI_DEC_CTX_FLAG_aes) {
    EVP_CIPHER_CTX_free(ctx->cipher_ctx);
  }
  if (ctx->flags & TSCI_DEC_CTX_FLAG_lzma) {
    lzma_end(&ctx->lzma_strm);
  }
  if (ctx->flags & TSCI_DEC_CTX_FLAG_zstd) {
    ZSTD_freeDCtx(ctx->zstd_ctx);
  }
}

void tsci_sp_cb_cdn_auth_token(tek_sc_cm_client *, void *data, void *) {
  tsci_sp_cat_req *const req = data;
  if (req->data.token) {
#ifdef _WIN32
    req->data.token = _strdup(req->data.token);
#else  // def _WIN32
    req->data.token = strdup(req->data.token);
#endif // def _WIN32 else
  }
  atomic_store_explicit(&req->futex, 1, memory_order_relaxed);
  tsci_os_futex_wake(&req->futex);
}
