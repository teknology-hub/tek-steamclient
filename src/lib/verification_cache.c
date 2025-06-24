//===-- verification_cache.c - verification cache API implementation ------===//
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
/// Implementation of tek_sc_vc_* functions.
///
/// The structure of serialized verification cache is as following:
///    tscp_svc_hder
///    tscp_svc_file[num_files]
///    tscp_svc_dir[num_dirs]
///    tscp_svc_chunk[num_chunks] (at the end due to smaller alignment)
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/error.h"
#include "zlib_api.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

//===-- Private types -----------------------------------------------------===//

/// Serialized verification cache header.
typedef struct tscp_svc_hdr tscp_svc_hdr;
/// @copydoc tscp_svc_hdr
struct tscp_svc_hdr {
  /// CRC32 checksum for the remainder of serialized data (excluding itself).
  uint32_t crc;
  /// Must be set to zero to avoid producing inconsistent CRC on different
  ///    platforms.
  int32_t padding;
  /// ID of the manifest that the verification cache binds to.
  uint64_t manifest_id;
};

/// Serialized verification cache directory entry.
typedef struct tscp_svc_dir tscp_svc_dir;
/// @copydoc tscp_svc_dir
struct tscp_svc_dir {
  /// Number of files/subdirectories that haven't been verified yet, or `-1`
  ///    if the directory has already been fully verified.
  int32_t num_rem_children;
  /// Number of directory's verified files that are missing or have dirty
  ///    chunks.
  int32_t num_dirty_files;
  /// Number of verified subdirectories that are missing or have dirty child
  ///    entries. A value of `-1` indicates that the directory itself doesn't
  ///    exist in filesystem.
  int32_t num_dirty_subdirs;
};

/// Serialized verification cache file entry.
typedef struct tscp_svc_file tscp_svc_file;
/// @copydoc tscp_svc_file
struct tscp_svc_file {
  /// Number of chunks that haven't been verified yet, or `-1` if the file has
  ///    already been fully verified.
  int32_t num_rem_chunks;
  /// Number of file's verified chunks that are missing or have mismatching
  ///    data.
  uint32_t num_dirty_chunks : 30;
  /// Status of the file determined by verification.
  /// Holds a @ref tek_sc_vc_file_status value.
  uint32_t file_status : 2;
};

/// Serialized verification cache chunk entry.
enum tscp_svc_chunk : uint8_t {
  /// The chunk has not been verified yet.
  TSCP_SVC_CHUNK_pending,
  /// The chunk either isn't present in the file or SHA-1 hash of its data
  ///    doesn't match manifest chunk entry's `sha`.
  TSCP_SVC_CHUNK_mismatching,
  /// SHA-1 hash of chunk's data matches manifest chunk entry's `sha`.
  TSCP_SVC_CHUNK_matching
};
/// @copydoc tscp_svc_chunk
typedef enum tscp_svc_chunk tscp_svc_chunk;

//===-- Private function --------------------------------------------------===//

/// Create a verification cache deserialization error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for specified verification cache
///    deserialization error.
[[gnu::const]]
static inline tek_sc_err tscp_desvc_err(tek_sc_errc errc) {
  return tsc_err_sub(TEK_SC_ERRC_vc_deserialize, errc);
}

//===-- Public functions --------------------------------------------------===//

tek_sc_verification_cache
tek_sc_vc_create(const tek_sc_depot_manifest *manifest) {
  tek_sc_vc_dir *const dirs =
      calloc(1, sizeof(tek_sc_vc_dir) * manifest->num_dirs +
                    sizeof(tek_sc_vc_file) * manifest->num_files +
                    sizeof(tek_sc_vc_chunk) * manifest->num_chunks);
  auto const files = (tek_sc_vc_file *)(dirs + manifest->num_dirs);
  auto const chunks = (tek_sc_vc_chunk *)(files + manifest->num_files);
  for (int i = 0; i < manifest->num_dirs; ++i) {
    auto const dir = &manifest->dirs[i];
    auto const vc_dir = &dirs[i];
    vc_dir->num_rem_children = dir->num_files + dir->num_subdirs;
    atomic_init(&vc_dir->ref_count, vc_dir->num_rem_children);
    vc_dir->handle = TSCI_OS_INVALID_HANDLE;
  }
  atomic_init(&dirs[0].ref_count, -1);
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const vc_file = &files[i];
    vc_file->num_rem_chunks = manifest->files[i].num_chunks;
    vc_file->handle = TSCI_OS_INVALID_HANDLE;
  }
  return (tek_sc_verification_cache){
      .manifest = manifest, .chunks = chunks, .files = files, .dirs = dirs};
}

int tek_sc_vc_serialize(const tek_sc_verification_cache *vcache, void *buf,
                        int buf_size) {
  auto const man = vcache->manifest;
  // Compute required buffer size
  const int required_size = sizeof(tscp_svc_hdr) +
                            sizeof(tscp_svc_dir) * man->num_dirs +
                            sizeof(tscp_svc_file) * man->num_files +
                            sizeof(tscp_svc_chunk) * man->num_chunks;
  if (!buf || buf_size < required_size) {
    return required_size;
  }
  // Write header
  tscp_svc_hdr *const hdr = buf;
  *hdr = (tscp_svc_hdr){.manifest_id = man->id};
  // Write directories
  auto const svc_dirs = (tscp_svc_dir *)(hdr + 1);
  for (int i = 0; i < man->num_dirs; ++i) {
    auto const dir = &vcache->dirs[i];
    svc_dirs[i] = (tscp_svc_dir){.num_rem_children =
                                     dir->status == TEK_SC_JOB_ENTRY_STATUS_done
                                         ? -1
                                         : dir->num_rem_children,
                                 .num_dirty_files = dir->num_dirty_files,
                                 .num_dirty_subdirs = dir->num_dirty_subdirs};
  }
  // Write files
  auto const svc_files = (tscp_svc_file *)(svc_dirs + man->num_dirs);
  for (int i = 0; i < man->num_files; ++i) {
    auto const file = &vcache->files[i];
    svc_files[i] = (tscp_svc_file){
        .num_rem_chunks = file->status == TEK_SC_JOB_ENTRY_STATUS_done
                              ? -1
                              : file->num_rem_chunks,
        .num_dirty_chunks = file->num_dirty_chunks,
        .file_status = file->file_status};
  }
  // Write chunks
  auto const svc_chunks = (tscp_svc_chunk *)(svc_files + man->num_files);
  for (int i = 0; i < man->num_chunks; ++i) {
    auto const chunk = &vcache->chunks[i];
    svc_chunks[i] = chunk->status == TEK_SC_JOB_ENTRY_STATUS_done
                        ? (chunk->match ? TSCP_SVC_CHUNK_matching
                                        : TSCP_SVC_CHUNK_mismatching)
                        : TSCP_SVC_CHUNK_pending;
  }
  // Compute CRC32
  hdr->crc = tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), buf + sizeof hdr->crc,
                          required_size - sizeof hdr->crc);
  return 0;
}

tek_sc_err tek_sc_vc_deserialize(const void *buf, int buf_size,
                                 const tek_sc_depot_manifest *manifest,
                                 tek_sc_verification_cache *vcache) {
  if (buf_size < (int)sizeof(tscp_svc_hdr)) {
    return tscp_desvc_err(TEK_SC_ERRC_invalid_data);
  }
  const tscp_svc_hdr *const hdr = buf;
  // Verify CRC32
  if (hdr->crc != tsci_z_crc32(tsci_z_crc32(0, nullptr, 0),
                               buf + sizeof hdr->crc,
                               buf_size - sizeof hdr->crc)) {
    return tscp_desvc_err(TEK_SC_ERRC_crc_mismatch);
  }
  // Read header and get SVC array pointers
  if (hdr->manifest_id != manifest->id) {
    return tscp_desvc_err(TEK_SC_ERRC_vc_manifest_mismatch);
  }
  auto const svc_dirs = (const tscp_svc_dir *)(hdr + 1);
  auto const svc_files = (const tscp_svc_file *)(svc_dirs + manifest->num_dirs);
  auto const svc_chunks =
      (const tscp_svc_chunk *)(svc_files + manifest->num_files);
  // Verify input buffer size and allocate the vcache buffer
  if (buf_size < ((const void *)(svc_chunks + manifest->num_chunks) - buf)) {
    return tscp_desvc_err(TEK_SC_ERRC_invalid_data);
  }
  tek_sc_vc_dir *const dirs =
      malloc(sizeof *vcache->dirs * manifest->num_dirs +
             sizeof *vcache->files * manifest->num_files +
             sizeof *vcache->chunks * manifest->num_chunks);
  auto const files = (tek_sc_vc_file *)(dirs + manifest->num_dirs);
  auto const chunks = (tek_sc_vc_chunk *)(files + manifest->num_files);
  // Read directories
  for (int i = 0; i < manifest->num_dirs; ++i) {
    auto const svc_dir = &svc_dirs[i];
    dirs[i] = (tek_sc_vc_dir){
        .status = svc_dir->num_rem_children >= 0
                      ? TEK_SC_JOB_ENTRY_STATUS_pending
                      : TEK_SC_JOB_ENTRY_STATUS_done,
        .num_rem_children =
            svc_dir->num_rem_children >= 0 ? svc_dir->num_rem_children : 0,
        .num_dirty_files = svc_dir->num_dirty_files,
        .num_dirty_subdirs = svc_dir->num_dirty_subdirs,
        .ref_count =
            svc_dir->num_rem_children >= 0 ? svc_dir->num_rem_children : 0,
        .handle = TSCI_OS_INVALID_HANDLE};
  }
  atomic_init(&dirs[0].ref_count, -1);
  // Read files
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const svc_file = &svc_files[i];
    files[i] = (tek_sc_vc_file){.status = svc_file->num_rem_chunks >= 0
                                              ? TEK_SC_JOB_ENTRY_STATUS_pending
                                              : TEK_SC_JOB_ENTRY_STATUS_done,
                                .num_rem_chunks = svc_file->num_rem_chunks >= 0
                                                      ? svc_file->num_rem_chunks
                                                      : 0,
                                .num_dirty_chunks = svc_file->num_dirty_chunks,
                                .file_status = svc_file->file_status,
                                .handle = TSCI_OS_INVALID_HANDLE};
  }
  // Read chunks
  for (int i = 0; i < manifest->num_chunks; ++i) {
    auto const svc_chunk = svc_chunks[i];
    chunks[i] =
        (tek_sc_vc_chunk){.status = svc_chunk == TSCP_SVC_CHUNK_pending
                                        ? TEK_SC_JOB_ENTRY_STATUS_pending
                                        : TEK_SC_JOB_ENTRY_STATUS_done,
                          .match = svc_chunk == TSCP_SVC_CHUNK_matching};
  }
  *vcache = (tek_sc_verification_cache){
      .manifest = manifest, .chunks = chunks, .files = files, .dirs = dirs};
  return tsc_err_ok();
}

void tek_sc_vc_free(tek_sc_verification_cache *vcache) {
  free(vcache->dirs);
  *vcache = (tek_sc_verification_cache){};
}
