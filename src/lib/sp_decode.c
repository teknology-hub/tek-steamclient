//===-- sp_decode.c - SteamPipe chunk decoding and patching implementation ===//
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
/// Implementation of chunk decoding and patching functions from SteamPipe
///    interface.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/sp.h"

#include "common/error.h"
#include "delta_chunks.h"
#include "sp.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "zip_api.h"
#include "zlib_api.h"

#include <lzma.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

/// @def TSCP_VZ_HDR_MAGIC
/// Expected magic value for VZ header.
#define TSCP_VZ_HDR_MAGIC 0x615A56 // "VZa"
/// @def TSCP_VZ_FTR_MAGIC
/// Expected magic value for VZ footer.
#define TSCP_VZ_FTR_MAGIC 0x767A // "zv"

/// @def TSCP_VSZ_HDR_MAGIC
/// Expected magic value for VSZ header.
#define TSCP_VSZ_HDR_MAGIC 0x615A5356 // "VSZa"
/// @def TSCP_VSZ_FTR_MAGIC
/// Expected magic value for VSZ footer.
#define TSCP_VSZ_FTR_MAGIC 0x76737A // "zsv"

//===-- Private types -----------------------------------------------------===//

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

//===-- Private functions -------------------------------------------------===//

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
                                          tsci_dec_ctx_flag flags) {
  const tsci_dec_ctx_flag to_init = flags & ~ctx->flags;
  if (to_init & TSCI_DEC_CTX_FLAG_aes) {
    ctx->aes_ecb = EVP_aes_256_ecb();
    ctx->aes_cbc = EVP_aes_256_cbc();
    ctx->cipher_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->cipher_ctx) {
      return TEK_SC_ERRC_aes_decryption;
    }
    ctx->flags |= TSCI_DEC_CTX_FLAG_aes;
  }
  if (to_init & TSCI_DEC_CTX_FLAG_lzma) {
    ctx->lzma_strm = (lzma_stream)LZMA_STREAM_INIT;
    ctx->lzma_filter[0].id = LZMA_FILTER_LZMA1;
    ctx->lzma_filter[1].id = LZMA_VLI_UNKNOWN;
    ctx->lzma_opts_alloc = (lzma_allocator){.alloc = tscp_sp_lzma_opts_alloc,
                                            .free = tscp_sp_lzma_opts_free,
                                            .opaque = ctx};
    ctx->flags |= TSCI_DEC_CTX_FLAG_lzma;
  }
  if (to_init & TSCI_DEC_CTX_FLAG_zstd) {
    ctx->zstd_ctx = ZSTD_createDCtx();
    if (!ctx->zstd_ctx) {
      return TEK_SC_ERRC_zstd;
    }
    ctx->flags |= TSCI_DEC_CTX_FLAG_zstd;
  }
  return TEK_SC_ERRC_ok;
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
  int output_size;
  auto const handle = tsci_zip_open_get_size(input, input_size, &output_size);
  if (!handle) {
    return TEK_SC_ERRC_zip;
  }
  return tsci_zip_read_close(handle, output, output_size) ? TEK_SC_ERRC_ok
                                                          : TEK_SC_ERRC_zip;
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
  auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCI_DEC_CTX_FLAG_lzma);
  if (res != TEK_SC_ERRC_ok) {
    return res;
  }
  auto const content = input + sizeof(tscp_vz_hdr);
  const int content_size =
      input_size - sizeof(tscp_vz_hdr) - sizeof(tscp_vz_ftr);
  // Verify VZ footer
  tscp_vz_ftr ftr;
  memcpy(&ftr, content + content_size, sizeof ftr);
  if (ftr.magic != TSCP_VZ_FTR_MAGIC) {
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
  ctx->lzma_strm.avail_out = ftr.uncompressed_size;
  ctx->lzma_strm.total_out = 0;
  if (lzma_code(&ctx->lzma_strm, LZMA_RUN) != LZMA_OK) {
    return TEK_SC_ERRC_lzma;
  }
  // Verify CRC32 checksum of data
  if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), output,
                   ftr.uncompressed_size) != ftr.crc) {
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
  auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCI_DEC_CTX_FLAG_zstd);
  if (res != TEK_SC_ERRC_ok) {
    return res;
  }
  auto const content = input + sizeof(tscp_vsz_hdr);
  const int content_size =
      input_size - sizeof(tscp_vsz_hdr) - sizeof(tscp_vsz_ftr);
  // Verify VSZ footer
  tscp_vsz_ftr ftr;
  memcpy(&ftr, content + content_size, sizeof ftr);
  if ((ftr.magic[0] | (ftr.magic[1] << 8) | (ftr.magic[2] << 16)) !=
      TSCP_VSZ_FTR_MAGIC) {
    return TEK_SC_ERRC_magic_mismatch;
  }
  // Decompress the content
  if (ZSTD_decompressDCtx(ctx->zstd_ctx, output, ftr.uncompressed_size, content,
                          content_size) != ftr.uncompressed_size) {
    return TEK_SC_ERRC_zstd;
  }
  return TEK_SC_ERRC_ok;
}

//===-- Public functions --------------------------------------------------===//

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
  tsci_chunk_dec_ctx_free(ctx);
  free(ctx);
}

tek_sc_err tek_sc_sp_decode_chunk(tek_sc_sp_dec_ctx *ctx, void *enc_data,
                                  void *dec_data,
                                  const tek_sc_dm_chunk *chunk) {
  // Decrypt chunk
  auto res = tscp_chunk_dec_ctx_upd(ctx, TSCI_DEC_CTX_FLAG_aes);
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
    // "VZa" - VZ (ValveZip archive?)
    res = tscp_decomp_chunk_vz(ctx, enc_data, decrypted_size, dec_data);
  } else if (magic == TSCP_VSZ_HDR_MAGIC) {
    // "VSZa" - VSZ (Valve zStandard Zip archive?)
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
    auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCI_DEC_CTX_FLAG_lzma);
    if (res != TEK_SC_ERRC_ok) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
    }
    auto const content = pchunk->delta_chunk + sizeof(tsci_vzd_hdr);
    const int content_size =
        pchunk->delta_chunk_size - sizeof(tsci_vzd_hdr) - sizeof(tsci_vzd_ftr);
    tsci_vzd_ftr ftr;
    memcpy(&ftr, content + content_size, sizeof ftr);
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
    ctx->lzma_strm.avail_out = ftr.uncompressed_size;
    ctx->lzma_strm.total_out = 0;
    if (lzma_code(&ctx->lzma_strm, LZMA_RUN) != LZMA_OK) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_lzma);
    }
    // Verify CRC32 checksum of produced chunk
    if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), tgt_chunk,
                     ftr.uncompressed_size) != ftr.crc) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_crc_mismatch);
    }
    break;
  }
  case TEK_SC_DP_CHUNK_TYPE_vszd: {
    auto const res = tscp_chunk_dec_ctx_upd(ctx, TSCI_DEC_CTX_FLAG_zstd);
    if (res != TEK_SC_ERRC_ok) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, res);
    }
    auto const content = pchunk->delta_chunk + sizeof(tsci_vszd_hdr);
    const int content_size = pchunk->delta_chunk_size - sizeof(tsci_vszd_hdr) -
                             sizeof(tsci_vszd_ftr);
    tsci_vszd_ftr ftr;
    memcpy(&ftr, content + content_size, sizeof ftr);
    // Decompress the content
    if (ZSTD_decompress_usingDict(ctx->zstd_ctx, tgt_chunk,
                                  ftr.uncompressed_size, content, content_size,
                                  src_chunk, pchunk->source_chunk->size) !=
        ftr.uncompressed_size) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_zstd);
    }
    // Verify CRC32 checksum of produced chunk
    if (tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), tgt_chunk,
                     ftr.uncompressed_size) != ftr.crc) {
      return tsc_err_sub(TEK_SC_ERRC_sp_decode, TEK_SC_ERRC_crc_mismatch);
    }
  }
  } // switch (pchunk->type)
  return tsc_err_ok();
}
