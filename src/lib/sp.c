//===-- sp.c - SteamPipe downloader interface implementation --------------===//
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
/// Implementation of tek_sc_sp_* functions and related private interfaces.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "common/error.h"
#include "config.h"
#include "delta_chunks.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "utils.h"
#include "zlib_api.h"

#include <curl/curl.h>
#include <inttypes.h>
#include <limits.h>
#include <lzma.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zip.h>
#include <zstd.h>

/// @def TSCP_MAX_NUM_RETRIES
/// The number of times the multi downloader is allowed to restart a download
///     after non-critical errors before failing the request.
#define TSCP_MAX_NUM_RETRIES 10

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

/// @def TSCP_VZ_HDR_MAGIC
/// Expected magic value for VZ header.
#define TSCP_VZ_HDR_MAGIC 0x615A56 // "VZa"
/// @def TSCP_VZ_FTR_MAGIC
/// Expected magic value for VZ footer.
#define TSCP_VZ_FTR_MAGIC 0x767A // "zv"

/// VZ header.
typedef struct tscp_vz_hdr tscp_vz_hdr;
/// @copydoc tscp_vz_hdr
struct [[gnu::packed]] tscp_vz_hdr {
  /// VZ header magic value, the integer representation must be
  ///    @ref TSCP_VZ_HDR_MAGIC.
  unsigned char magic[3];
  /// May be a timestamp or secondary CRC32 checksum depending on file.
  uint32_t unused;
};

/// VZ footer.
typedef struct tscp_vz_ftr tscp_vz_ftr;
/// @copydoc tscp_vz_ftr
struct [[gnu::packed]] tscp_vz_ftr {
  /// CRC32 checksum of uncompressed data.
  uint32_t crc;
  /// Size of uncompressed data, in bytes.
  uint32_t uncompressed_size;
  /// VZ footer magic value, must be @ref TSCP_VZ_FTR_MAGIC.
  uint16_t magic;
};

/// @def TSCP_VSZ_HDR_MAGIC
/// Expected magic value for VSZ header.
#define TSCP_VSZ_HDR_MAGIC 0x615A5356 // "VSZa"
/// @def TSCP_VSZ_FTR_MAGIC
/// Expected magic value for VSZ footer.
#define TSCP_VSZ_FTR_MAGIC 0x76737A // "zsv"

/// VSZ header.
typedef struct tscp_vsz_hdr tscp_vsz_hdr;
/// @copydoc tscp_vsz_hdr
struct [[gnu::packed]] tscp_vsz_hdr {
  /// VSZ header magic value, must be @ref TSCP_VSZ_HDR_MAGIC.
  uint32_t magic;
  /// CRC32 checksum of uncompressed data.
  uint32_t crc;
};

/// VSZ footer.
typedef struct tscp_vsz_ftr tscp_vsz_ftr;
/// @copydoc tscp_vsz_ftr
struct [[gnu::packed]] tscp_vsz_ftr {
  /// CRC32 checksum of uncompressed data.
  uint32_t crc;
  /// Size of uncompressed data, in bytes.
  uint32_t uncompressed_size;
  /// Reserved?
  uint32_t unknown;
  /// VSZ footer magic value, the integer representation must be
  ///    @ref TSCP_VSZ_FTR_MAGIC.
  unsigned char magic[3];
};

/// Flags indicating which decoders are currently initialized in a chunk
///    decoding context.
enum [[clang::flag_enum]] tscp_dec_ctx_flag {
  TSCP_DEC_CTX_FLAG_aes = 1 << 0,
  TSCP_DEC_CTX_FLAG_lzma = 1 << 1,
  TSCP_DEC_CTX_FLAG_zstd = 1 << 2
};
/// @copydoc tscp_dec_ctx_flag
typedef enum tscp_dec_ctx_flag tscp_dec_ctx_flag;

/// @copydoc tek_sc_sp_dec_ctx
struct tek_sc_sp_dec_ctx {
  /// Flags indicating which decoders are currently initialized.
  tscp_dec_ctx_flag flags;
  /// Pointer to the OpenSSL EVP AES-256-ECB cipher object.
  const EVP_CIPHER *_Nonnull aes_ecb;
  /// Pointer to the OpenSSL EVP AES-256-CBC cipher object.
  const EVP_CIPHER *_Nonnull aes_cbc;
  /// Pointer to the OpenSSL EVP cipher context.
  EVP_CIPHER_CTX *_Nonnull cipher_ctx;
  /// Pointer to the AES-256 decryption key for the depot.
  const tek_sc_aes256_key *_Nullable decryption_key;
  /// Pointer to the Zstandard decompression context.
  ZSTD_DCtx *_Nonnull zstd_ctx;
  /// LZMA decompression stream instance.
  lzma_stream lzma_strm;
  /// LZMA filter instance.
  lzma_filter lzma_filter[2];
  /// LZMA filter options storage.
  lzma_options_lzma lzma_opts;
  /// Allocator stub for LZMA filter options.
  lzma_allocator lzma_opts_alloc;
};

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
  /// Chunk decoding context.
  tek_sc_sp_dec_ctx dec_ctx;
};

/// @copydoc tek_sc_sp_multi_dlr
struct tek_sc_sp_multi_dlr {
  /// Pointer to the assigned descriptor.
  const tek_sc_sp_multi_dlr_desc *_Nonnull desc;
  /// Pointer to the thread context array.
  tscp_sp_multi_thrd_ctx *_Nonnull thrd_ctxs;
  /// Offset into `path` field of downloader instances where the SHA-1 hash
  ///    part begins.
  int path_sha_offset;
  /// Flag that may be set to cancel all ongoing downloads.
  atomic_bool cancel_flag;
};

//===-- Private functions -------------------------------------------------===//

//===--- curl write data callbacks ----------------------------------------===//

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

//===--- Chunk decoding functions -----------------------------------------===//

/// Get pointer to decode context's LZMA filter options storage.
///
/// @param opaque
///    Pointer to the @ref tek_sc_sp_dec_ctx.
/// @return Pointer to the `lzma_opts` field of the context.
[[gnu::returns_nonnull, gnu::nonnull(1), gnu::access(none, 1)]] static void
    *_Nonnull tscp_sp_lzma_opts_alloc(void *_Nonnull opaque, size_t, size_t) {
  return &((tek_sc_sp_dec_ctx *)opaque)->lzma_opts;
}

/// Do nothing.
static void tscp_sp_lzma_opts_free(void *, void *) {}

/// Ensure that chunk decoding context has specified decoders initialized.
///
/// @param [out] ctx
///    Pointer to the chunk decoding context to initialize.
/// @param flags
///    Flags specifying which decoders should be initialized.
/// @return A @ref tek_sc_errc indicating the result of operation.
[[gnu::nonnull(1), gnu::access(read_write, 1)]]
static tek_sc_errc tscp_chunk_dec_ctx_upd(tek_sc_sp_dec_ctx *_Nonnull ctx,
                                          tscp_dec_ctx_flag flags) {
  const tscp_dec_ctx_flag to_init = flags & ~ctx->flags;
  if (to_init & TSCP_DEC_CTX_FLAG_aes) {
    ctx->aes_ecb = EVP_aes_256_ecb();
    ctx->aes_cbc = EVP_aes_256_cbc();
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->cipher_ctx) {
      return TEK_SC_ERRC_aes_decryption;
    }
    ctx->flags |= TSCP_DEC_CTX_FLAG_aes;
  }
  if (to_init & TSCP_DEC_CTX_FLAG_lzma) {
    ctx->lzma_strm = (lzma_stream)LZMA_STREAM_INIT;
    ctx->lzma_filter[0].id = LZMA_FILTER_LZMA1;
    ctx->lzma_filter[1].id = LZMA_VLI_UNKNOWN;
    ctx->lzma_opts_alloc = (lzma_allocator){.alloc = tscp_sp_lzma_opts_alloc,
                                            .free = tscp_sp_lzma_opts_free,
                                            .opaque = ctx};
    ctx->flags |= TSCP_DEC_CTX_FLAG_lzma;
  }
  if (to_init & TSCP_DEC_CTX_FLAG_zstd) {
    ctx->zstd_ctx = ZSTD_createDCtx();
    if (!ctx->zstd_ctx) {
      return TEK_SC_ERRC_zstd;
    }
    ctx->flags |= TSCP_DEC_CTX_FLAG_zstd;
  }
  return TEK_SC_ERRC_ok;
}

/// Free resources allocated by a chunk decode context.
///
/// @param [in, out] ctx
///    Pointer to the chunk decode context to free.
[[gnu::nonnull(1), gnu::access(read_write, 1)]]
static void tscp_chunk_dec_ctx_free(tek_sc_sp_dec_ctx *_Nonnull ctx) {
  if (ctx->flags & TSCP_DEC_CTX_FLAG_aes) {
    EVP_CIPHER_CTX_free(ctx->cipher_ctx);
  }
  if (ctx->flags & TSCP_DEC_CTX_FLAG_lzma) {
    lzma_end(&ctx->lzma_strm);
  }
  if (ctx->flags & TSCP_DEC_CTX_FLAG_zstd) {
    ZSTD_freeDCtx(ctx->zstd_ctx);
  }
}

/// Decompress Zip-archived chunk.
///
/// @param [in] input
///    Pointer to the buffer containing archived chunk data.
/// @param input_size
///    Size of archived chunk data, in bytes.
/// @param [out] output
///    Pointer to the buffer that receives decompressed chunk data.
/// @return A @ref tek_sc_errc indicating the result of operation.
[[gnu::nonnull(1, 3), gnu::access(read_only, 1, 2), gnu::access(read_only, 3)]]
static tek_sc_errc tscp_decomp_chunk_zip(const void *_Nonnull input,
                                         int input_size,
                                         void *_Nonnull output) {
  auto const source = zip_source_buffer_create(input, input_size, 0, nullptr);
  if (!source) {
    return TEK_SC_ERRC_zip;
  }
  tek_sc_errc res;
  auto const archive = zip_open_from_source(source, ZIP_RDONLY, nullptr);
  if (!archive) {
    res = TEK_SC_ERRC_zip;
    goto cleanup_source;
  }
  zip_stat_t st;
  if (zip_stat_index(archive, 0, 0, &st) < 0) {
    res = TEK_SC_ERRC_zip;
    goto cleanup_archive;
  }
  if (!(st.valid & ZIP_STAT_SIZE)) {
    res = TEK_SC_ERRC_zip;
    goto cleanup_archive;
  }
  auto const file = zip_fopen_index(archive, 0, 0);
  if (!file) {
    res = TEK_SC_ERRC_zip;
    goto cleanup_archive;
  }
  if (zip_fread(file, output, st.size) != (zip_int64_t)st.size) {
    res = TEK_SC_ERRC_zip;
    goto cleanup_file;
  }
  res = TEK_SC_ERRC_ok;
cleanup_file:
  zip_fclose(file);
cleanup_archive:
  zip_close(archive);
cleanup_source:
  zip_source_close(source);
  return res;
}

/// Decompress VZ-archived chunk.
///
/// @param [in, out] ctx
///    Pointer to the chunk decoding context to use.
/// @param [in] input
///    Pointer to the buffer containing archived chunk data.
/// @param input_size
///    Size of archived chunk data, in bytes.
/// @param [out] output
///    Pointer to the buffer that receives decompressed chunk data.
/// @return A @ref tek_sc_errc indicating the result of operation.
[[gnu::nonnull(1, 2, 4), gnu::access(read_write, 1),
  gnu::access(read_only, 2, 3), gnu::access(read_write, 4)]]
static tek_sc_errc tscp_decomp_chunk_vz(tek_sc_sp_dec_ctx *_Nonnull ctx,
                                        const void *_Nonnull input,
                                        int input_size, void *_Nonnull output) {
  auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCP_DEC_CTX_FLAG_lzma);
  if (res != TEK_SC_ERRC_ok) {
    return res;
  }
  auto const content = input + sizeof(tscp_vz_hdr);
  const int content_size =
      input_size - sizeof(tscp_vz_hdr) - sizeof(tscp_vz_ftr);
  // Verify VZ footer
  auto const ftr = (const tscp_vz_ftr *)(content + content_size);
  if (ftr->magic != TSCP_VZ_FTR_MAGIC) {
    return TEK_SC_ERRC_magic_mismatch;
  }
  // Decompress the content
  if (lzma_properties_decode(ctx->lzma_filter, &ctx->lzma_opts_alloc, content,
                             5) != LZMA_OK) {
    return TEK_SC_ERRC_lzma;
  }
  if (lzma_raw_decoder(&ctx->lzma_strm, ctx->lzma_filter) != LZMA_OK) {
    return TEK_SC_ERRC_lzma;
  }
  ctx->lzma_strm.next_in = content + 5;
  ctx->lzma_strm.avail_in = content_size - 5;
  ctx->lzma_strm.total_in = 0;
  ctx->lzma_strm.next_out = output;
  ctx->lzma_strm.avail_out = ftr->uncompressed_size;
  ctx->lzma_strm.total_out = 0;
  if (lzma_code(&ctx->lzma_strm, LZMA_RUN) != LZMA_OK) {
    return TEK_SC_ERRC_lzma;
  }
  // Verify CRC32 checksum of data
  if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), output,
                   ftr->uncompressed_size) != ftr->crc) {
    return TEK_SC_ERRC_crc_mismatch;
  }
  return TEK_SC_ERRC_ok;
}

/// Decompress VSZ-archived chunk.
///
/// @param [in, out] ctx
///    Pointer to the chunk decoding context to use.
/// @param [in] input
///    Pointer to the buffer containing archived chunk data.
/// @param input_size
///    Size of archived chunk data, in bytes.
/// @param [out] output
///    Pointer to the buffer that receives decompressed chunk data.
/// @return A @ref tek_sc_errc indicating the result of operation.
[[gnu::nonnull(1, 2, 4), gnu::access(read_write, 1),
  gnu::access(read_only, 2, 3), gnu::access(read_write, 4)]]
static tek_sc_errc tscp_decomp_chunk_vsz(tek_sc_sp_dec_ctx *_Nonnull ctx,
                                         const void *_Nonnull input,
                                         int input_size,
                                         void *_Nonnull output) {
  auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCP_DEC_CTX_FLAG_zstd);
  if (res != TEK_SC_ERRC_ok) {
    return res;
  }
  auto const content = input + sizeof(tscp_vsz_hdr);
  const int content_size =
      input_size - sizeof(tscp_vsz_hdr) - sizeof(tscp_vsz_ftr);
  // Verify VSZ footer
  auto const ftr = (const tscp_vsz_ftr *)(content + content_size);
  if ((ftr->magic[0] | (ftr->magic[1] << 8) | (ftr->magic[2] << 16)) !=
      TSCP_VSZ_FTR_MAGIC) {
    return TEK_SC_ERRC_magic_mismatch;
  }
  // Decompress the content
  if (ZSTD_decompressDCtx(ctx->zstd_ctx, output, ftr->uncompressed_size,
                          content, content_size) != ftr->uncompressed_size) {
    return TEK_SC_ERRC_zstd;
  }
  return TEK_SC_ERRC_ok;
}

//===-- Public functions --------------------------------------------------===//

//===--- Simple download functions ----------------------------------------===//

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
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  tscp_dw_ctx_dm_dp ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = &data->common};
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tscp_sp_curl_write_dm_dp);
  // Try downloading from provided servers
  CURLcode curl_res = CURLE_URL_MALFORMAT;
  for (int i = 0; i < data->common.num_srvs; ++i) {
    auto const srv = &data->common.srvs[i];
    curl_url_set(curlu, CURLUPART_SCHEME,
                 srv->supports_https ? "https" : "http", 0);
    curl_url_set(curlu, CURLUPART_HOST, srv->host, 0);
    data->common.data = nullptr;
    data->common.data_size = 0;
    curl_res = curl_easy_perform(curl);
    if (cancel_flag &&
        atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
      free(data->common.data);
      data->common.data = nullptr;
      data->common.data_size = 0;
      res = tsc_err_basic(TEK_SC_ERRC_paused);
      goto cleanup_curl;
    }
    if (curl_res == CURLE_OK) {
      break;
    } else if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
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
    } else if (curl_res == CURLE_OPERATION_TIMEDOUT) {
      curl_off_t connect_time;
      curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &connect_time);
      if (connect_time <= 0) {
        continue;
      }
    } else if (curl_res == CURLE_HTTP2_STREAM) {
      continue;
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
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  tscp_dw_ctx_dm_dp ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = &data->common};
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tscp_sp_curl_write_dm_dp);
  // Try downloading from provided servers
  CURLcode curl_res = CURLE_URL_MALFORMAT;
  for (int i = 0; i < data->common.num_srvs; ++i) {
    auto const srv = &data->common.srvs[i];
    curl_url_set(curlu, CURLUPART_SCHEME,
                 srv->supports_https ? "https" : "http", 0);
    curl_url_set(curlu, CURLUPART_HOST, srv->host, 0);
    data->common.data = nullptr;
    data->common.data_size = 0;
    curl_res = curl_easy_perform(curl);
    if (cancel_flag &&
        atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
      free(data->common.data);
      data->common.data = nullptr;
      data->common.data_size = 0;
      res = tsc_err_basic(TEK_SC_ERRC_paused);
      goto cleanup_curl;
    }
    if (curl_res == CURLE_OK) {
      break;
    } else if (curl_res == CURLE_HTTP_RETURNED_ERROR) {
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
    } else if (curl_res == CURLE_OPERATION_TIMEDOUT) {
      curl_off_t connect_time;
      curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &connect_time);
      if (connect_time <= 0) {
        continue;
      }
    } else if (curl_res == CURLE_HTTP2_STREAM) {
      continue;
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

tek_sc_err tek_sc_sp_download_chunk(const tek_sc_cm_sp_srv_entry *srv,
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
  // Setup and run curl easy handle
  auto const curl = curl_easy_init();
  tek_sc_err res;
  if (!curl) {
    res = tsc_err_sub(TEK_SC_ERRC_sp_chunk, TEK_SC_ERRC_curle_init);
    goto cleanup_curlu;
  }
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 8000L);
  tscp_dw_ctx_chunk ctx = {
      .curl = curl, .cancel_flag = cancel_flag, .data = data};
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(curl, CURLOPT_CURLU, curlu);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, tscp_sp_curl_write_chunk);
  auto const curl_res = curl_easy_perform(curl);
  if (cancel_flag && atomic_load_explicit(cancel_flag, memory_order_relaxed)) {
    res = tsc_err_basic(TEK_SC_ERRC_paused);
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

//===--- Chunk decoding functions -----------------------------------------===//

tek_sc_sp_dec_ctx *
tek_sc_sp_dec_ctx_create(const tek_sc_aes256_key decryption_key) {
  tek_sc_sp_dec_ctx *const ctx = malloc(sizeof *ctx);
  if (ctx) {
    ctx->flags = 0;
    ctx->decryption_key = (const tek_sc_aes256_key *)decryption_key;
  }
  return ctx;
}

void tek_sc_sp_dec_ctx_destroy(tek_sc_sp_dec_ctx *ctx) {
  tscp_chunk_dec_ctx_free(ctx);
  free(ctx);
}

tek_sc_err tek_sc_sp_decode_chunk(tek_sc_sp_dec_ctx *ctx, void *enc_data,
                                  void *dec_data,
                                  const tek_sc_dm_chunk *chunk) {
  // Decrypt chunk
  auto res = tscp_chunk_dec_ctx_upd(ctx, TSCP_DEC_CTX_FLAG_aes);
  if (res != TEK_SC_ERRC_ok) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
  }
  if (!EVP_DecryptInit_ex2(ctx->cipher_ctx, ctx->aes_ecb, *ctx->decryption_key,
                           nullptr, nullptr)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  EVP_CIPHER_CTX_set_padding(ctx->cipher_ctx, 0);
  int decrypted_size;
  if (!EVP_DecryptUpdate(ctx->cipher_ctx, enc_data, &decrypted_size, enc_data,
                         16)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  int last_block_len;
  if (!EVP_DecryptFinal_ex(ctx->cipher_ctx, enc_data + decrypted_size,
                           &last_block_len)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  if (!EVP_DecryptInit_ex2(ctx->cipher_ctx, ctx->aes_cbc, *ctx->decryption_key,
                           enc_data, nullptr)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  EVP_CIPHER_CTX_set_padding(ctx->cipher_ctx, 1);
  if (!EVP_DecryptUpdate(ctx->cipher_ctx, enc_data, &decrypted_size,
                         enc_data + 16, chunk->comp_size - 16)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  if (!EVP_DecryptFinal_ex(ctx->cipher_ctx, enc_data + decrypted_size,
                           &last_block_len)) {
    return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_aes_decryption);
  }
  decrypted_size += last_block_len;
  // Determine chunk archive format and decompress it
  auto const magic = *((const uint32_t *)enc_data);
  if (magic == 0x04034B50) {
    // "PK\3\4" - Zip
    res = tscp_decomp_chunk_zip(enc_data, decrypted_size, dec_data);
  } else if ((magic & 0x00FFFFFF) == TSCP_VZ_HDR_MAGIC) {
    // "VZa" - VZ (ValveZip?)
    res = tscp_decomp_chunk_vz(ctx, enc_data, decrypted_size, dec_data);
  } else if (magic == TSCP_VSZ_HDR_MAGIC) {
    // "VSZa" - VSZ (Valve zStandard Zip?)
    res = tscp_decomp_chunk_vsz(ctx, enc_data, decrypted_size, dec_data);
  } else {
    res = TEK_SC_ERRC_sp_unknown_comp;
  }
  return res == TEK_SC_ERRC_ok ? tsc_err_ok()
                               : tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
}

tek_sc_err tek_sc_sp_patch_chunk(tek_sc_sp_dec_ctx *ctx, const void *src_chunk,
                                 void *tgt_chunk,
                                 const tek_sc_dp_chunk *pchunk) {
  switch (pchunk->type) {
  case TEK_SC_DP_CHUNK_TYPE_vzd: {
    auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCP_DEC_CTX_FLAG_lzma);
    if (res != TEK_SC_ERRC_ok) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
    }
    auto const content = pchunk->delta_chunk + sizeof(tsci_vzd_hdr);
    const int content_size =
        pchunk->delta_chunk_size - sizeof(tsci_vzd_hdr) - sizeof(tsci_vzd_ftr);
    const tsci_vzd_ftr *const ftr = content + content_size;
    // Decompress the content
    if (lzma_properties_decode(ctx->lzma_filter, &ctx->lzma_opts_alloc, content,
                               5) != LZMA_OK) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_lzma);
    }
    lzma_options_lzma *const lzma_opts = ctx->lzma_filter[0].options;
    lzma_opts->preset_dict = src_chunk;
    lzma_opts->preset_dict_size = pchunk->source_chunk->size;
    if (lzma_raw_decoder(&ctx->lzma_strm, ctx->lzma_filter) != LZMA_OK) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_lzma);
    }
    ctx->lzma_strm.next_in = content + 5;
    ctx->lzma_strm.avail_in = content_size - 5;
    ctx->lzma_strm.total_in = 0;
    ctx->lzma_strm.next_out = tgt_chunk;
    ctx->lzma_strm.avail_out = ftr->uncompressed_size;
    ctx->lzma_strm.total_out = 0;
    if (lzma_code(&ctx->lzma_strm, LZMA_RUN) != LZMA_OK) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_lzma);
    }
    // Verify CRC32 checksum of produced chunk
    if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), tgt_chunk,
                     ftr->uncompressed_size) != ftr->crc) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_crc_mismatch);
    }
    break;
  }
  case TEK_SC_DP_CHUNK_TYPE_vszd: {
    auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCP_DEC_CTX_FLAG_zstd);
    if (res != TEK_SC_ERRC_ok) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
    }
    auto const content = pchunk->delta_chunk + sizeof(tsci_vszd_hdr);
    const int content_size = pchunk->delta_chunk_size - sizeof(tsci_vszd_hdr) -
                             sizeof(tsci_vszd_ftr);
    const tsci_vszd_ftr *const ftr = content + content_size;
    // Decompress the content
    if (ZSTD_decompress_usingDict(ctx->zstd_ctx, tgt_chunk,
                                  ftr->uncompressed_size, content, content_size,
                                  src_chunk, pchunk->source_chunk->size) !=
        ftr->uncompressed_size) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_zstd);
    }
    // Verify CRC32 checksum of produced chunk
    if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), tgt_chunk,
                     ftr->uncompressed_size) != ftr->crc) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_crc_mismatch);
    }
  }
  } // switch (pchunk->type)
  return tsc_err_ok();
}

//===--- Multi downloader functions ---------------------------------------===//

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
  dlr->path_sha_offset =
      snprintf(nullptr, 0, "/depot/%" PRIu32 "/chunk/", depot_id);
  atomic_init(&dlr->cancel_flag, false);
  auto const insts = (tscp_sp_dlr_inst *)(dlr->thrd_ctxs + desc->num_threads);
  // Initialize downloader instances
  for (int i = 0, srv_ind = 0; i < num_insts; ++i) {
    auto const inst = &insts[i];
    if (i) {
      if (srv_ind % TEK_SCB_CHUNKS_PER_SRV == 0) {
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
      curl_easy_setopt(inst->curl, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(inst->curl, CURLOPT_TIMEOUT_MS, 180000L);
      curl_easy_setopt(inst->curl, CURLOPT_CONNECTTIMEOUT_MS, 16000L);
      curl_easy_setopt(inst->curl, CURLOPT_PIPEWAIT, 1L);
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
    inst->desc = desc;
    inst->req = nullptr;
    inst->next_offset = 0;
    inst->num_retries = 0;
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
    thrd_ctx->insts = &insts[i * srvs_per_thread * TEK_SCB_CHUNKS_PER_SRV];
    thrd_ctx->num_insts = srvs_per_thread * TEK_SCB_CHUNKS_PER_SRV;
    thrd_ctx->num_active = 0;
    thrd_ctx->dec_ctx.flags = 0;
    thrd_ctx->dec_ctx.decryption_key =
        (const tek_sc_aes256_key *)decryption_key;
  }
  dlr->thrd_ctxs[desc->num_threads - 1].num_insts = desc->num_reqs_last_thread;
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
  const int num_threads = dlr->desc->num_threads;
  for (int i = 0; i < num_threads; ++i) {
    auto const thrd_ctx = &dlr->thrd_ctxs[i];
    curl_multi_cleanup(thrd_ctx->curlm);
    tscp_chunk_dec_ctx_free(&thrd_ctx->dec_ctx);
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
  return tsc_err_ok();
}

tek_sc_sp_multi_chunk_req *
tek_sc_sp_multi_dlr_process(const tek_sc_sp_multi_dlr *dlr, int thrd_index,
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
    if (num_handles < thrd_ctx->num_active) {
      break;
    }
    res = curl_multi_poll(curlm, nullptr, 0, INT_MAX, nullptr);
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
  //     re-submit it and process next one if available.
  for (;;) {
    int num_queued;
    auto const msg = curl_multi_info_read(curlm, &num_queued);
    if (!msg) {
      *err = tsc_err_ok();
      return nullptr;
    }
    curl_multi_remove_handle(curlm, msg->easy_handle);
    tscp_sp_dlr_inst *inst;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &inst);
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
    if (++inst->num_retries >= TSCP_MAX_NUM_RETRIES) {
      inst->req = nullptr;
      inst->num_retries = 0;
      --thrd_ctx->num_active;
      char *url_buf = nullptr;
      curl_url_get(inst->curlu, CURLUPART_URL, &url_buf, 0);
      long status = 0;
      if (req_res == CURLE_HTTP_RETURNED_ERROR) {
        curl_easy_getinfo(inst->curl, CURLINFO_RESPONSE_CODE, &status);
      }
      req->result = (tek_sc_err){.type = TEK_SC_ERR_TYPE_curle,
                                 .primary = TEK_SC_ERRC_sp_chunk,
                                 .auxiliary = req_res,
                                 .extra = (int)status,
                                 .uri = url_buf};
      return req;
    }
    bool switch_srv = false;
    if (req_res == CURLE_HTTP_RETURNED_ERROR) {
      long status;
      curl_easy_getinfo(inst->curl, CURLINFO_RESPONSE_CODE, &status);
      switch (status) {
      case 429:
      case 502:
      case 503:
      case 504:
        switch_srv = true;
      }
    } else if (req_res == CURLE_OPERATION_TIMEDOUT) {
      switch_srv = true;
    }
    if (inst->num_retries % 4 == 0) {
      switch_srv = true;
    }
    if (switch_srv) {
      auto const srv_insts =
          inst - ((inst - thrd_ctx->insts) % TEK_SCB_CHUNKS_PER_SRV);
      int srv_ind = srv_insts->srv_ind;
      if (++srv_ind >= dlr->desc->num_srvs) {
        srv_ind = 0;
      }
      auto const srv = &dlr->desc->srvs[srv_ind];
      for (int i = 0; i < TEK_SCB_CHUNKS_PER_SRV; ++i) {
        auto const inst = &srv_insts[i];
        curl_url_set(inst->curlu, CURLUPART_SCHEME,
                     srv->supports_https ? "https" : "http", 0);
        curl_url_set(inst->curlu, CURLUPART_HOST, srv->host, 0);
        inst->srv_ind = srv_ind;
      }
    }
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
    if (!num_queued) {
      *err = tsc_err_ok();
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
