//===-- depot_manifest.c - Steam depot manifest API implementation --------===//
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
/// Implementation of @ref tek_sc_dm_serialize, @ref tek_sc_dm_deserialize and
///    @ref tek_sc_dm_free.
///
/// The structure of serialized depot manifest is as following:
///    tscp_sdm_hdr
///    tscp_sdm_chunk[num_chunks]
///    tscp_sdm_file[num_files]
///    tscp_sdm_dir[num_dirs]
///    char names[*the remainder of buffer*]
///
/// Names are stored in UTF-8 encoding regardless of OS and don't have any kind
///    of separation between each other, it's not needed when every entry stores
///    the length of its own name.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"
#include "zlib_api.h"

#include <stdint.h>
#include <string.h>

//===-- Private types -----------------------------------------------------===//

/// Serialized manifest header.
typedef struct tscp_sdm_hdr tscp_sdm_hdr;
/// @copydoc tscp_sdm_hdr
struct tscp_sdm_hdr {
  /// CRC32 checksum for the remainder of serialized data (excluding itself).
  uint32_t crc;
  /// Total number of chunk entries in the manifest.
  int32_t num_chunks;
  /// Total number of file entries in the manifest.
  int32_t num_files;
  /// Total number of directory entries in the manifest.
  int32_t num_dirs;
  /// ID of Steam item that the manifest belongs to.
  tek_sc_item_id item_id;
  /// ID of the manifest.
  uint64_t id;
  /// Total on-disk size of all files listed in the manifest, in bytes.
  int64_t data_size;
};

// Serialized manifest chunk entry.
typedef struct tscp_sdm_chunk tscp_sdm_chunk;
/// @copydoc tscp_sdm_chunk
struct tscp_sdm_chunk {
  /// SHA-1 hash of chunk data, part of its download URL in SteamPipe.
  unsigned char sha[20];
  /// Must be set to zero to avoid producing inconsistent CRC on different
  ///    platforms.
  uint32_t padding;
  /// Offset of chunk data from the beginning of containing file, in bytes.
  int64_t offset;
  /// Size of chunk data on disk, in bytes.
  int32_t size;
  /// Size of compressed chunk data on SteamPipe servers, in bytes.
  int32_t comp_size;
};

/// Serialized manifest file entry.
typedef struct tscp_sdm_file tscp_sdm_file;
/// @copydoc tscp_sdm_file
struct tscp_sdm_file {
  /// Length of UTF-8 encoded name of the file, in bytes.
  int32_t name_len;
  /// If @ref flags includes @ref TEK_SC_DM_FILE_FLAG_symlink, length of UTF-8
  ///    encoded path to the symbolic link target, in bytes, otherwise zero.
  int32_t target_path_len;
  /// Size of the file on disk, in bytes.
  int64_t size;
  /// Number of chunks assigned to the file.
  int32_t num_chunks;
  /// Flags describing file attributes and/or permissions.
  /// Holds a @ref tek_sc_dm_file_flag value.
  int32_t flags;
};

/// Serialized manifest directory entry.
typedef struct tscp_sdm_dir tscp_sdm_dir;
/// @copydoc tscp_sdm_dir
struct tscp_sdm_dir {
  /// Length of UTF-8 encoded name of the directory, in bytes.
  int32_t name_len;
  /// Number of files assigned to the directory.
  int32_t num_files;
  /// Number of assigned subdirectories.
  int32_t num_subdirs;
};

/// Pointer context shared across recursion levels of @ref tscp_dm_set_ptrs.
typedef struct tscp_sdm_ptr_ctx tscp_sdm_ptr_ctx;
/// @copydoc tscp_sdm_ptr_ctx
struct tscp_sdm_ptr_ctx {
  /// Pointer to the next available file entry in the manifest's buffer.
  const tek_sc_dm_file *_Nonnull next_file;
  /// Pointer to the next available directory entry in the manifest's buffer.
  const tek_sc_dm_dir *_Nonnull next_dir;
};

//===-- Private functions -------------------------------------------------===//

/// Create a manifest deserialization error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for specified manifest deserialization
///    error.
[[gnu::const]]
static inline tek_sc_err tscp_desdm_err(tek_sc_errc errc) {
  return tsc_err_sub(TEK_SC_ERRC_manifest_deserialize, errc);
}

/// Set correct entry pointers in specified directory by doing tree walking.
///
/// @param [in, out] ctx
///    Pointer to the pointer context to use.
/// @param [in, out] dir
///    Pointer to the manifest directory entry to process.
[[gnu::nonnull(1, 2), gnu::access(read_write, 1), gnu::access(read_write, 2)]]
static void tscp_dm_set_ptrs(tscp_sdm_ptr_ctx *_Nonnull ctx,
                             tek_sc_dm_dir *_Nonnull dir) {
  if (dir->num_files) {
    dir->files = ctx->next_file;
    ctx->next_file += dir->num_files;
    for (int i = 0; i < dir->num_files; ++i) {
      ((tek_sc_dm_file *)dir->files)[i].parent = dir;
    }
  } else {
    dir->files = nullptr;
  }
  if (dir->num_subdirs) {
    dir->subdirs = ctx->next_dir;
    ctx->next_dir += dir->num_subdirs;
    for (int i = 0; i < dir->num_subdirs; ++i) {
      auto const subdir = (tek_sc_dm_dir *)&dir->subdirs[i];
      subdir->parent = dir;
      tscp_dm_set_ptrs(ctx, subdir);
    }
  } else {
    dir->subdirs = nullptr;
  }
}

//===-- Public functions --------------------------------------------------===//

int tek_sc_dm_serialize(const tek_sc_depot_manifest *manifest, void *buf,
                        int buf_size) {
  // Compute required buffer size
  int required_size = sizeof(tscp_sdm_hdr) +
                      sizeof(tscp_sdm_chunk) * manifest->num_chunks +
                      sizeof(tscp_sdm_file) * manifest->num_files +
                      sizeof(tscp_sdm_dir) * manifest->num_dirs;
  char *cur_name = buf ? buf + required_size : nullptr;
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const file = &manifest->files[i];
    required_size += tsci_os_pstr_strlen(file->name);
    if (file->flags & TEK_SC_DM_FILE_FLAG_symlink) {
      required_size += tsci_os_pstr_strlen(file->target_path);
    }
  }
  for (int i = 1; i < manifest->num_dirs; ++i) {
    required_size += tsci_os_pstr_strlen(manifest->dirs[i].name);
  }
  if (!buf || buf_size < required_size) {
    return required_size;
  }
  // Write header
  tscp_sdm_hdr *const hdr = buf;
  *hdr = (tscp_sdm_hdr){.num_chunks = manifest->num_chunks,
                        .num_files = manifest->num_files,
                        .num_dirs = manifest->num_dirs,
                        .item_id = manifest->item_id,
                        .id = manifest->id,
                        .data_size = manifest->data_size};
  // Write chunks
  auto const sdm_chunks = (tscp_sdm_chunk *)(hdr + 1);
  for (int i = 0; i < manifest->num_chunks; ++i) {
    auto const chunk = &manifest->chunks[i];
    auto const sdm_chunk = &sdm_chunks[i];
    memcpy(sdm_chunk->sha, chunk->sha.bytes, sizeof chunk->sha.bytes);
    sdm_chunk->padding = 0;
    sdm_chunk->offset = chunk->offset;
    sdm_chunk->size = chunk->size;
    sdm_chunk->comp_size = chunk->comp_size;
  }
  // Write files
  auto const sdm_files = (tscp_sdm_file *)(sdm_chunks + manifest->num_chunks);
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const file = &manifest->files[i];
    const int name_len = tsci_os_pstr_to_str(file->name, cur_name);
    cur_name += name_len;
    const int target_path_len =
        (file->flags & TEK_SC_DM_FILE_FLAG_symlink)
            ? tsci_os_pstr_to_str(file->target_path, cur_name)
            : 0;
    cur_name += target_path_len;
    sdm_files[i] = (tscp_sdm_file){.name_len = name_len,
                                   .target_path_len = target_path_len,
                                   .size = file->size,
                                   .num_chunks = file->num_chunks,
                                   .flags = file->flags};
  }
  // Write directories
  auto const sdm_dirs = (tscp_sdm_dir *)(sdm_files + manifest->num_files);
  sdm_dirs[0] = (tscp_sdm_dir){.num_files = manifest->dirs[0].num_files,
                               .num_subdirs = manifest->dirs[0].num_subdirs};
  for (int i = 1; i < manifest->num_dirs; ++i) {
    auto const dir = &manifest->dirs[i];
    const int name_len = tsci_os_pstr_to_str(dir->name, cur_name);
    cur_name += name_len;
    sdm_dirs[i] = (tscp_sdm_dir){.name_len = name_len,
                                 .num_files = dir->num_files,
                                 .num_subdirs = dir->num_subdirs};
  }
  // Compute CRC32
  hdr->crc = tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), buf + sizeof hdr->crc,
                          required_size - sizeof hdr->crc);
  return 0;
}

tek_sc_err tek_sc_dm_deserialize(const void *buf, int buf_size,
                                 tek_sc_depot_manifest *manifest) {
  if (buf_size < (int)sizeof(tscp_sdm_hdr)) {
    return tscp_desdm_err(TEK_SC_ERRC_invalid_data);
  }
  const tscp_sdm_hdr *const hdr = buf;
  // Verify CRC32
  if (hdr->crc != tsci_z_crc32(tsci_z_crc32(0, nullptr, 0),
                               buf + sizeof hdr->crc,
                               buf_size - sizeof hdr->crc)) {
    return tscp_desdm_err(TEK_SC_ERRC_crc_mismatch);
  }
  // Read header
  manifest->num_chunks = hdr->num_chunks;
  manifest->num_files = hdr->num_files;
  manifest->num_dirs = hdr->num_dirs;
  manifest->item_id = hdr->item_id;
  manifest->id = hdr->id;
  manifest->data_size = hdr->data_size;
  // Get SDM entry array pointers and verify input buffer size
  auto const sdm_chunks = (const tscp_sdm_chunk *)(hdr + 1);
  auto const sdm_files =
      (const tscp_sdm_file *)(sdm_chunks + manifest->num_chunks);
  auto const sdm_dirs = (const tscp_sdm_dir *)(sdm_files + manifest->num_files);
  auto cur_sdm_name = (const char *)(sdm_dirs + manifest->num_dirs);
  if (buf_size < (cur_sdm_name - (const char *)buf)) {
    return tscp_desdm_err(TEK_SC_ERRC_invalid_data);
  }
  // Verify that all names are also in the input buffer
  int sdm_name_buf_len = 0;
  int num_symlinks = 0;
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const file = &sdm_files[i];
    sdm_name_buf_len += file->name_len;
    if (file->flags & TEK_SC_DM_FILE_FLAG_symlink) {
      sdm_name_buf_len += file->target_path_len;
      ++num_symlinks;
    }
  }
  for (int i = 0; i < manifest->num_dirs; ++i) {
    sdm_name_buf_len += sdm_dirs[i].name_len;
  }
  if (buf_size < (cur_sdm_name + sdm_name_buf_len - (const char *)buf)) {
    return tscp_desdm_err(TEK_SC_ERRC_invalid_data);
  }
  // Compute pathname buffer length
  const int name_buf_len = tsci_os_str_pstrlen(cur_sdm_name, sdm_name_buf_len) +
                           manifest->num_files + num_symlinks +
                           manifest->num_dirs - 1;
  // Allocate the manifest buffer and set array pointers
  manifest->buf_size = sizeof *manifest->chunks * manifest->num_chunks +
                       sizeof *manifest->files * manifest->num_files +
                       sizeof *manifest->dirs * manifest->num_dirs +
                       sizeof(tek_sc_os_char) * name_buf_len;
  manifest->chunks = tsci_os_mem_alloc(manifest->buf_size);
  if (!manifest->chunks) {
    return tsci_err_os(TEK_SC_ERRC_manifest_deserialize,
                       tsci_os_get_last_error());
  }
  manifest->files = (tek_sc_dm_file *)(manifest->chunks + manifest->num_chunks);
  manifest->dirs = (tek_sc_dm_dir *)(manifest->files + manifest->num_files);
  auto cur_name = (tek_sc_os_char *)(manifest->dirs + manifest->num_dirs);
  // Read chunks
  for (int i = 0; i < manifest->num_chunks; ++i) {
    auto const chunk = &manifest->chunks[i];
    auto const sdm_chunk = &sdm_chunks[i];
    memcpy(chunk->sha.bytes, sdm_chunk->sha, sizeof sdm_chunk->sha);
    chunk->offset = sdm_chunk->offset;
    chunk->size = sdm_chunk->size;
    chunk->comp_size = sdm_chunk->comp_size;
  }
  // Read files
  auto cur_chunk = manifest->chunks;
  for (int i = 0; i < manifest->num_files; ++i) {
    auto const file = &manifest->files[i];
    auto const sdm_file = &sdm_files[i];
    file->name = cur_name;
    cur_name += tsci_os_str_to_pstr(cur_sdm_name, sdm_file->name_len, cur_name);
    *cur_name++ = TEK_SC_OS_STR('\0');
    cur_sdm_name += sdm_file->name_len;
    if (sdm_file->flags & TEK_SC_DM_FILE_FLAG_symlink) {
      file->target_path = cur_name;
      cur_name += tsci_os_str_to_pstr(cur_sdm_name, sdm_file->target_path_len,
                                      cur_name);
      *cur_name++ = TEK_SC_OS_STR('\0');
      cur_sdm_name += sdm_file->target_path_len;
    } else {
      file->target_path = nullptr;
    }
    file->size = sdm_file->size;
    if (sdm_file->num_chunks) {
      file->chunks = cur_chunk;
      for (int i = 0; i < sdm_file->num_chunks; ++i) {
        cur_chunk++->parent = file;
      }
    } else {
      file->chunks = nullptr;
    }
    file->num_chunks = sdm_file->num_chunks;
    file->flags = sdm_file->flags;
  }
  // Read directories (except pointers)
  manifest->dirs[0] = (tek_sc_dm_dir){.num_files = sdm_dirs[0].num_files,
                                      .num_subdirs = sdm_dirs[0].num_subdirs};
  for (int i = 1; i < manifest->num_dirs; ++i) {
    auto const dir = &manifest->dirs[i];
    auto const sdm_dir = &sdm_dirs[i];
    dir->name = cur_name;
    cur_name += tsci_os_str_to_pstr(cur_sdm_name, sdm_dir->name_len, cur_name);
    *cur_name++ = TEK_SC_OS_STR('\0');
    cur_sdm_name += sdm_dir->name_len;
    dir->num_files = sdm_dir->num_files;
    dir->num_subdirs = sdm_dir->num_subdirs;
  }
  // Set entry pointers
  tscp_dm_set_ptrs(&(tscp_sdm_ptr_ctx){.next_file = manifest->files,
                                       .next_dir = &manifest->dirs[1]},
                   manifest->dirs);
  return tsc_err_ok();
}

void tek_sc_dm_free(tek_sc_depot_manifest *manifest) {
  if (manifest->chunks) {
    tsci_os_mem_free(manifest->chunks, manifest->buf_size);
  }
  *manifest = (tek_sc_depot_manifest){};
}
