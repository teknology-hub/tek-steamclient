//===-- sp.h - SteamPipe downloader internal definitions ------------------===//
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
/// Definitions of structures and functions shared across multiple SteamPipe
///    interface implementation modules.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"

#include <curl/curl.h>
#include <lzma.h>
#include <openssl/types.h>
#include <stdatomic.h>
#include <stdint.h>
#include <zstd.h>

/// Hardcoded IP addresses to resolve cloudflare-dns.com to when using DoH
///    fallbacks.
[[gnu::visibility("internal")]]
extern struct curl_slist tsci_sp_cf_dns_resolve;

/// Flags indicating which decoders are currently initialized in a chunk
///    decoding context.
enum [[clang::flag_enum]] tsci_dec_ctx_flag {
  TSCI_DEC_CTX_FLAG_aes = 1 << 0,
  TSCI_DEC_CTX_FLAG_lzma = 1 << 1,
  TSCI_DEC_CTX_FLAG_zstd = 1 << 2
};
/// @copydoc tscp_dec_ctx_flag
typedef enum tsci_dec_ctx_flag tsci_dec_ctx_flag;

/// @copydoc tek_sc_sp_dec_ctx
struct tek_sc_sp_dec_ctx {
  /// Flags indicating which decoders are currently initialized.
  tsci_dec_ctx_flag flags;
  /// Pointer to the OpenSSL EVP AES-256-ECB cipher object.
  const EVP_CIPHER *_Nullable aes_ecb;
  /// Pointer to the OpenSSL EVP AES-256-CBC cipher object.
  const EVP_CIPHER *_Nullable aes_cbc;
  /// Pointer to the OpenSSL EVP cipher context.
  EVP_CIPHER_CTX *_Nullable cipher_ctx;
  /// Pointer to the AES-256 decryption key for the depot.
  const tek_sc_aes256_key *_Nullable decryption_key;
  /// Pointer to the Zstandard decompression context.
  ZSTD_DCtx *_Nullable zstd_ctx;
  /// LZMA decompression stream instance.
  lzma_stream lzma_strm;
  /// LZMA filter instance.
  lzma_filter lzma_filter[2];
  /// LZMA filter options storage.
  lzma_options_lzma lzma_opts;
  /// Allocator stub for LZMA filter options.
  lzma_allocator lzma_opts_alloc;
};

/// CDN auth token request structure.
typedef struct tsci_sp_cat_req tsci_sp_cat_req;
/// @copydoc tsci_sp_cat_req
struct tsci_sp_cat_req {
  /// Input/output data for CM request.
  tek_sc_cm_data_cdn_auth_token data;
  /// Futex that is set to 1 and woken up when CM response is received.
  _Atomic(uint32_t) futex;
};

/// Free resources allocated by a chunk decode context.
///
/// @param [in, out] ctx
///    Pointer to the chunk decode context to free.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_write, 1)]]
void tsci_chunk_dec_ctx_free(tek_sc_sp_dec_ctx *_Nonnull ctx);

/// The callback for CM client CDN auth token received event.
///
/// @param client
///    Pointer to the CM client instance that emitted the callback.
/// @param [in, out] data
///    Pointer to the @ref tsci_sp_cat_req associated with the request.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 2)]]
void tsci_sp_cb_cdn_auth_token(tek_sc_cm_client *_Nonnull, void *_Nonnull data, void *_Nullable);
