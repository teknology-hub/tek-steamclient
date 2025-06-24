//===-- depot_patch.c - Steam depot patch API implementation --------------===//
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
/// Implementation of @ref tek_sc_dp_serialize, @ref tek_sc_dp_deserialize and
///    @ref tek_sc_dp_free.
///
/// The structure of serialized depot patch is as following:
///    tscp_sdp_hdr
///    tscp_sdp_chunk[num_chunks]
///    unsigned char delta_chunks[*the remainder of buffer*]
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/error.h"
#include "zlib_api.h"

#include <stdint.h>
#include <string.h>

//===-- Private types -----------------------------------------------------===//

/// Serialized patch header.
typedef struct tscp_sdp_hdr tscp_sdp_hdr;
/// @copydoc tscp_sdp_hdr
struct tscp_sdp_hdr {
  /// CRC32 checksum for the remainder of serialized data (excluding itself).
  uint32_t crc;
  /// Total number of chunk entries in the patch.
  int32_t num_chunks;
  /// ID of the manifest providing source chunks.
  uint64_t src_manifest_id;
  /// ID of the manifest providing target chunks.
  uint64_t tgt_manifest_id;
  /// Total size of delta chunks, in bytes.
  int64_t delta_size;
};

/// Serialized patch chunk entry.
typedef struct tscp_sdp_chunk tscp_sdp_chunk;
/// @copydoc tscp_sdp_chunk
struct tscp_sdp_chunk {
  /// Index of the chunk that the delta applies to, in the source manifest's
  ///    chunk array.
  int32_t src_index;
  /// Index of the chunk produced by patching, in the target manifest's chunk
  ///    array.
  int32_t tgt_index;
  /// Offset of the delta chunk data from the beginning of the delta chunk
  ///    buffer, in bytes.
  int32_t delta_chunk_offset;
  /// Size of the delta chunk, in bytes.
  int32_t delta_chunk_size;
  /// Type of the chunk.
  /// Holds a @ref tek_sc_dp_chunk_type value.
  int32_t type;
};

//===-- Private function --------------------------------------------------===//

/// Create a patch deserialization error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for specified patch deserialization error.
[[gnu::const]]
static inline tek_sc_err tscp_desdp_err(tek_sc_errc errc) {
  return tsc_err_sub(TEK_SC_ERRC_patch_deserialize, errc);
}

//===-- Public functions --------------------------------------------------===//

int tek_sc_dp_serialize(const tek_sc_depot_patch *patch, void *buf,
                        int buf_size) {
  // Compute required buffer size
  const int required_size = sizeof(tscp_sdp_hdr) +
                            sizeof(tscp_sdp_chunk) * patch->num_chunks +
                            patch->delta_size;
  if (!buf || buf_size < required_size) {
    return required_size;
  }
  // Write header
  tscp_sdp_hdr *const hdr = buf;
  *hdr = (tscp_sdp_hdr){.num_chunks = patch->num_chunks,
                        .src_manifest_id = patch->source_manifest->id,
                        .tgt_manifest_id = patch->target_manifest->id,
                        .delta_size = patch->delta_size};
  // Write chunks
  auto const delta_chunks = (const void *)(patch->chunks + patch->num_chunks);
  auto const sdp_chunks = (tscp_sdp_chunk *)(hdr + 1);
  for (int i = 0; i < patch->num_chunks; ++i) {
    auto const chunk = &patch->chunks[i];
    sdp_chunks[i] = (tscp_sdp_chunk){
        .src_index = chunk->source_chunk - patch->source_manifest->chunks,
        .tgt_index = chunk->target_chunk - patch->target_manifest->chunks,
        .delta_chunk_offset = chunk->delta_chunk - delta_chunks,
        .delta_chunk_size = chunk->delta_chunk_size,
        .type = chunk->type};
  }
  // Write delta chunks
  memcpy(sdp_chunks + patch->num_chunks, delta_chunks, patch->delta_size);
  // Compute CRC32
  hdr->crc = tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), buf + sizeof hdr->crc,
                          required_size - sizeof hdr->crc);
  return 0;
}

tek_sc_err tek_sc_dp_deserialize(const void *buf, int buf_size,
                                 const tek_sc_depot_manifest *source_manifest,
                                 const tek_sc_depot_manifest *target_manifest,
                                 tek_sc_depot_patch *patch) {
  if (buf_size < (int)sizeof(tscp_sdp_hdr)) {
    return tscp_desdp_err(TEK_SC_ERRC_invalid_data);
  }
  const tscp_sdp_hdr *const hdr = buf;
  // Verify CRC32
  if (hdr->crc != tsci_z_crc32(tsci_z_crc32(0, nullptr, 0),
                               buf + sizeof hdr->crc,
                               buf_size - sizeof hdr->crc)) {
    return tscp_desdp_err(TEK_SC_ERRC_crc_mismatch);
  }
  // Read header
  if (hdr->src_manifest_id != source_manifest->id ||
      hdr->tgt_manifest_id != target_manifest->id) {
    return tscp_desdp_err(TEK_SC_ERRC_patch_manifests_mismatch);
  }
  patch->source_manifest = source_manifest;
  patch->target_manifest = target_manifest;
  patch->num_chunks = hdr->num_chunks;
  patch->delta_size = hdr->delta_size;
  // Get SDP array pointers and verify input buffer size
  auto const sdp_chunks = (const tscp_sdp_chunk *)(hdr + 1);
  const void *const sdp_delta_chunks = sdp_chunks + hdr->num_chunks;
  if (buf_size < (sdp_delta_chunks + hdr->delta_size - buf)) {
    return tscp_desdp_err(TEK_SC_ERRC_invalid_data);
  }
  // Allocate the patch buffer
  patch->chunks = tsci_os_mem_alloc(sizeof *patch->chunks * hdr->num_chunks +
                                    hdr->delta_size);
  if (!patch->chunks) {
    return tsci_err_os(TEK_SC_ERRC_patch_deserialize, tsci_os_get_last_error());
  }
  void *const delta_chunks = patch->chunks + hdr->num_chunks;
  // Read chunks
  for (int i = 0; i < hdr->num_chunks; ++i) {
    auto const sdp_chunk = &sdp_chunks[i];
    patch->chunks[i] = (tek_sc_dp_chunk){
        .source_chunk = source_manifest->chunks + sdp_chunk->src_index,
        .target_chunk = target_manifest->chunks + sdp_chunk->tgt_index,
        .delta_chunk = delta_chunks + sdp_chunk->delta_chunk_offset,
        .delta_chunk_size = sdp_chunk->delta_chunk_size,
        .type = sdp_chunk->type};
  }
  // Read delta chunks
  memcpy(delta_chunks, sdp_delta_chunks, hdr->delta_size);
  return tsc_err_ok();
}

void tek_sc_dp_free(tek_sc_depot_patch *patch) {
  if (patch->chunks) {
    tsci_os_mem_free(patch->chunks, sizeof *patch->chunks * patch->num_chunks +
                                        patch->delta_size);
  }
  *patch = (tek_sc_depot_patch){};
}
