//===-- depot_delta.c - depot delta API implementation --------------------===//
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
/// Implementation of @ref tek_sc_dd_compute_from_vc, @ref tek_sc_dd_serialize,
///    @ref tek_sc_dd_deserialize and @ref tek_sc_dd_free.
///
/// The structure of serialized depot delta is as following:
///    tscp_sdd_hdr
///    tscp_sdd_chunk[num_chunks]
///    tscp_sdd_transfer_op[num_transfer_ops]
///    tscp_sdd_file[num_files]
///    tscp_sdd_dirs[num_dirs]
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "common/error.h"
#include "os.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/error.h"
#include "zlib_api.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//===-- Private types -----------------------------------------------------===//

/// Write pass context shared across recursion levels of
///    @ref tscp_dd_write_missing_dir and @ref tscp_dd_write_dir.
typedef struct tscp_dd_write_ctx tscp_dd_write_ctx;
/// @copydoc tscp_dd_write_ctx
struct tscp_dd_write_ctx {
  /// Pointer to the next available chunk entry in the delta's buffer.
  tek_sc_dd_chunk *_Nonnull next_chunk;
  /// Pointer to the next available file entry in the delta's buffer.
  tek_sc_dd_file *_Nonnull next_file;
  /// Pointer to the next available directory entry in the delta's buffer.
  tek_sc_dd_dir *_Nonnull next_dir;
  /// Chunk buffer file offset to assign to the next chunk needing it.
  int64_t chunk_buf_off;
};

/// Serialized delta header.
typedef struct tscp_sdd_hdr tscp_sdd_hdr;
/// @copydoc tscp_sdd_hdr
struct tscp_sdd_hdr {
  /// CRC32 checksum for the remainder of serialized data (excluding itself).
  uint32_t crc;
  /// Value indicating whether the delta requires a depot patch.
  uint32_t patch_required;
  /// ID of the manifest describing source state, or `0` if delta was produced
  ///    by item verification.
  uint64_t src_manifest_id;
  /// ID of the manifest describing target state.
  uint64_t tgt_manifest_id;
  /// Total number of chunk entries in the delta.
  int32_t num_chunks;
  /// Total number of transfer operation entries in the delta.
  int32_t num_transfer_ops;
  /// Total number of file entries in the delta.
  int32_t num_files;
  /// Total number of directory entries in the delta.
  int32_t num_dirs;
  /// Current job stage that entries' statuses apply to.
  /// Holds a @ref tek_sc_dd_stage value.
  int32_t stage;
  // Total number of files and directories to be deleted.
  int32_t num_deletions;
  /// Total number of I/O operations required to perform all truncations and
  ///    transfer operations.
  int32_t num_io_ops;
  /// Size of the RAM buffer used when performing transfer operations, in bytes.
  int32_t transfer_buf_size;
  /// Total growth of existing files in size, in bytes.
  int64_t total_file_growth;
  /// Total download size / amount of data to be transferred over network, in
  ///    bytes.
  int64_t download_size;
};

/// Serialized delta chunk entry.
typedef struct tscp_sdd_chunk tscp_sdd_chunk;
/// @copydoc tscp_sdd_chunk
struct tscp_sdd_chunk {
  /// Index of the corresponding entry in the target manifest chunk array.
  int32_t index;
  /// Job status of the entry.
  /// Holds a @ref tek_sc_job_entry_status value.
  int32_t status;
  /// Offset of chunk data from the beginning of the chunk buffer file, in
  ///    bytes. Ignored if containing file has @ref TEK_SC_DD_FILE_FLAG_new
  ///    flag.
  int64_t chunk_buf_off;
};

/// Serialized delta transfer operation entry.
typedef struct tscp_sdd_transfer_op tscp_sdd_transfer_op;
/// @copydoc tscp_sdd_transfer_op
struct tscp_sdd_transfer_op {
  /// Job status of the entry.
  /// Holds a @ref tek_sc_job_entry_status value.
  int32_t status;
  /// Type of the operation.
  /// Holds a @ref tek_sc_dd_transfer_op_type value.
  int32_t type;
  /// Transfer operation data, depending on @ref type.
  union {
    /// Relocation descriptor, used when @ref type is
    ///    @ref TEK_SC_DD_TRANSFER_OP_TYPE_reloc.
    struct {
      /// File offset to copy the data bulk from, in bytes.
      int64_t src_off;
      /// File offset to copy the data bulk to, in bytes.
      int64_t tgt_off;
      /// Size of the data bulk, in bytes.
      int64_t size;
    } reloc;
    /// Patch chunk descriptor, used when @ref type is
    ///    @ref TEK_SC_DD_TRANSFER_OP_TYPE_patch.
    struct {
      /// Index of the entry in the patch chunk array.
      uint32_t index;
      /// Must be zeroed out to avoid producing inconsistent CRC on different
      ///    platforms.
      unsigned char padding[20];
    } pchunk;
  } data;
  // Offset of data from the beginning of the transfer buffer file, in bytes,
  ///    or `-1` if intermediate file buffering is not used.
  int64_t transfer_buf_off;
};

/// Serialized delta file entry.
typedef struct tscp_sdd_file tscp_sdd_file;
/// @copydoc tscp_sdd_file
struct tscp_sdd_file {
  /// Index of the corresponding entry in the manifest file array.
  int32_t index;
  /// Job status of the entry.
  /// Holds a @ref tek_sc_job_entry_status value.
  int32_t status;
  /// File operation flags.
  /// Holds a @ref tek_sc_dd_file_flag value.
  int32_t flags;
  /// Number of chunk entries assigned to the file.
  int32_t num_chunks;
  /// Number of transfer operation entries assigned to the file.
  int32_t num_transfer_ops;
};

/// Serialized delta directory entry.
typedef struct tscp_sdd_dir tscp_sdd_dir;
/// @copydoc tscp_sdd_dir
struct tscp_sdd_dir {
  /// Index of the corresponding entry in the manifest directory array.
  int32_t index;
  /// Job status of the entry.
  /// Holds a @ref tek_sc_job_entry_status value.
  int32_t status;
  /// Directory operation flags.
  /// Holds a @ref tek_sc_dd_dir_flag value.
  int32_t flags;
  /// Number of file entries assigned to the directory.
  int32_t num_files;
  /// Number of assigned subdirectory entries.
  int32_t num_subdirs;
};

/// Pointer context shared across recursion levels of @ref tscp_dd_set_ptrs.
typedef struct tscp_sdd_ptr_ctx tscp_sdd_ptr_ctx;
/// @copydoc tscp_sdd_ptr_ctx
struct tscp_sdd_ptr_ctx {
  /// Pointer to the next available file entry in the delta's buffer.
  tek_sc_dd_file *_Nonnull next_file;
  /// Pointer to the next available directory entry in the delta's buffer.
  tek_sc_dd_dir *_Nonnull next_dir;
};

//===-- Private functions -------------------------------------------------===//

/// Count the numbers of delta entries for specified missing directory.
///
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param [in, out] delta
///    Pointer to the delta object to compute numbers for.
[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_write, 2)]]
static void tscp_dd_count_missing_dir(const tek_sc_dm_dir *_Nonnull dir,
                                      tek_sc_depot_delta *_Nonnull delta) {
  delta->num_files += dir->num_files;
  delta->num_dirs += dir->num_subdirs;
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    delta->num_chunks += file->num_chunks;
    for (int j = 0; j < file->num_chunks; ++j) {
      delta->download_size += file->chunks[j].comp_size;
    }
  }
  for (int i = 0; i < dir->num_subdirs; ++i) {
    tscp_dd_count_missing_dir(&dir->subdirs[i], delta);
  }
}

/// Count the numbers of delta entries for specified directory.
///
/// @param [in] vcache
///    Pointer to the verification cache supplying information about mismatching
///    and missing data.
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param [in, out] delta
///    Pointer to the delta object to compute numbers for.
[[gnu::nonnull(1, 2, 3), gnu::access(read_only, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscp_dd_count_dir(const tek_sc_verification_cache *_Nonnull vcache,
                              const tek_sc_dm_dir *_Nonnull dir,
                              tek_sc_depot_delta *_Nonnull delta) {
  auto const man = vcache->manifest;
  auto const vc_dir = &vcache->dirs[dir - man->dirs];
  delta->num_files += vc_dir->num_dirty_files;
  delta->num_dirs += vc_dir->num_dirty_subdirs;
  // Iterate files
  auto const vc_files = &vcache->files[dir->files - man->files];
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    auto const vc_file = &vc_files[i];
    if (vc_file->file_status == TEK_SC_VC_FILE_STATUS_missing) {
      delta->num_chunks += file->num_chunks;
      for (int j = 0; j < file->num_chunks; ++j) {
        delta->download_size += file->chunks[j].comp_size;
      }
      continue;
    }
    if (vc_file->file_status == TEK_SC_VC_FILE_STATUS_truncate) {
      ++delta->num_io_ops;
    }
    delta->num_chunks += vc_file->num_dirty_chunks;
    // Iterate chunks
    auto const vc_chunks = &vcache->chunks[file->chunks - man->chunks];
    for (int j = 0; j < file->num_chunks; ++j) {
      if (!vc_chunks[j].match) {
        delta->download_size += file->chunks[j].comp_size;
      }
    }
  }
  // Iterate subdirectories
  auto const vc_subdirs = &vcache->dirs[dir->subdirs - man->dirs];
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    auto const vc_subdir = &vc_subdirs[i];
    if (vc_subdir->num_dirty_subdirs < 0) {
      tscp_dd_count_missing_dir(subdir, delta);
    } else if (vc_subdir->num_dirty_subdirs > 0 || vc_subdir->num_dirty_files) {
      tscp_dd_count_dir(vcache, subdir, delta);
    }
  }
}

/// Initialize delta file entry fields that do not depend on delta computation.
///
/// @param file
///    Pointer to the manifest file entry to bind to.
/// @param [out] dd_file
///    Pointer to the delta file entry to initialize.
[[gnu::nonnull(1, 2), gnu::access(none, 1), gnu::access(write_only, 2)]]
static inline void tscp_dd_init_file(const tek_sc_dm_file *_Nonnull file,
                                     tek_sc_dd_file *_Nonnull dd_file) {
  dd_file->file = file;
  dd_file->status = TEK_SC_JOB_ENTRY_STATUS_pending;
  dd_file->transfer_ops = nullptr;
  dd_file->num_transfer_ops = 0;
  dd_file->handle = TSCI_OS_INVALID_HANDLE;
}

/// Initialize delta directory entry fields that do not depend on delta
///    computation.
///
/// @param dir
///    Pointer to the manifest directory entry to bind to.
/// @param [out] dd_dir
///    Pointer to the delta directory entry to initialize.
[[gnu::nonnull(1, 2), gnu::access(none, 1), gnu::access(write_only, 2)]]
static inline void tscp_dd_init_dir(const tek_sc_dm_dir *_Nonnull dir,
                                    tek_sc_dd_dir *_Nonnull dd_dir) {
  dd_dir->dir = dir;
  dd_dir->status = TEK_SC_JOB_ENTRY_STATUS_pending;
  dd_dir->handle = TSCI_OS_INVALID_HANDLE;
  dd_dir->cache_handle = TSCI_OS_INVALID_HANDLE;
}

/// Write delta entries for specified missing directory.
///
/// @param [in, out] ctx
///    Pointer to the write pass context to use.
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param parent
///    Pointer to the parent directory entry.
/// @param [out] dd_dir
///    Pointer to the delta directory entry to write.
/// @return The children flags for the directory.
[[gnu::nonnull(1, 2, 3, 4), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(none, 3), gnu::access(read_write, 4)]]
static tek_sc_dd_dir_flag tscp_dd_write_missing_dir(
    tscp_dd_write_ctx *_Nonnull ctx, const tek_sc_dm_dir *_Nonnull dir,
    tek_sc_dd_dir *_Nonnull parent, tek_sc_dd_dir *_Nonnull dd_dir) {
  tscp_dd_init_dir(dir, dd_dir);
  dd_dir->parent = parent;
  dd_dir->flags = TEK_SC_DD_DIR_FLAG_new;
  if (dir->num_files) {
    dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dd_dir->files = ctx->next_file;
    ctx->next_file += dir->num_files;
  } else {
    dd_dir->files = nullptr;
  }
  if (dir->num_subdirs) {
    dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dd_dir->subdirs = ctx->next_dir;
    ctx->next_dir += dir->num_subdirs;
  } else {
    dd_dir->subdirs = nullptr;
  }
  dd_dir->num_files = dir->num_files;
  dd_dir->num_subdirs = dir->num_subdirs;
  // Iterate files
  for (int i = 0; i < dir->num_files; ++i) {
    auto const file = &dir->files[i];
    auto const dd_file = &dd_dir->files[i];
    tscp_dd_init_file(file, dd_file);
    dd_file->parent = dd_dir;
    dd_file->flags = TEK_SC_DD_FILE_FLAG_new;
    if (file->num_chunks) {
      dd_file->flags |= TEK_SC_DD_FILE_FLAG_download;
      dd_file->chunks = ctx->next_chunk;
      dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_download;
      ctx->next_chunk += file->num_chunks;
    } else {
      dd_file->chunks = nullptr;
    }
    dd_file->num_chunks = file->num_chunks;
    // Iterate chunks
    for (int j = 0; j < file->num_chunks; ++j) {
      dd_file->chunks[j] =
          (tek_sc_dd_chunk){.chunk = &file->chunks[j],
                            .parent = dd_file,
                            .status = TEK_SC_JOB_ENTRY_STATUS_pending,
                            .chunk_buf_offset = -1};
    }
  }
  // Iterate subdirectories
  for (int i = 0; i < dir->num_subdirs; ++i) {
    dd_dir->flags |= tscp_dd_write_missing_dir(ctx, &dir->subdirs[i], dd_dir,
                                               &dd_dir->subdirs[i]);
  }
  return (dd_dir->flags & TEK_SC_DD_DIR_FLAG_children_download) |
         TEK_SC_DD_DIR_FLAG_children_new;
}

// Write delta entries for specified directory.
///
/// @param [in, out] ctx
///    Pointer to the write pass context to use.
/// @param [in] vcache
///    Pointer to the verification cache supplying information about mismatching
///    and missing data.
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param parent
///    Pointer to the parent directory entry, or `nullptr` for root directory.
/// @param [out] dd_dir
///    Pointer to the delta directory entry to write.
[[gnu::nonnull(1, 2, 3, 5), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(read_only, 3), gnu::access(none, 4),
  gnu::access(read_write, 5)]]
static void tscp_dd_write_dir(tscp_dd_write_ctx *_Nonnull ctx,
                              const tek_sc_verification_cache *_Nonnull vcache,
                              const tek_sc_dm_dir *_Nonnull dir,
                              tek_sc_dd_dir *_Nullable parent,
                              tek_sc_dd_dir *_Nonnull dd_dir) {
  auto const man = vcache->manifest;
  auto const vc_dir = &vcache->dirs[dir - man->dirs];
  tscp_dd_init_dir(dir, dd_dir);
  dd_dir->parent = parent;
  dd_dir->flags = TEK_SC_DD_DIR_FLAG_none;
  dd_dir->files = vc_dir->num_dirty_files ? ctx->next_file : nullptr;
  if (vc_dir->num_dirty_subdirs) {
    dd_dir->subdirs = ctx->next_dir;
    ctx->next_dir += vc_dir->num_dirty_subdirs;
  } else {
    dd_dir->subdirs = nullptr;
  }
  dd_dir->num_files = vc_dir->num_dirty_files;
  dd_dir->num_subdirs = vc_dir->num_dirty_subdirs;
  // Iterate files
  auto const vc_files = &vcache->files[dir->files - man->files];
  for (int i = 0; i < dir->num_files; ++i) {
    auto const vc_file = &vc_files[i];
    auto const num_dirty_chunks = vc_file->num_dirty_chunks;
    if (vc_file->file_status == TEK_SC_VC_FILE_STATUS_regular &&
        !num_dirty_chunks) {
      continue;
    }
    auto const file = &dir->files[i];
    auto const dd_file = ctx->next_file++;
    tscp_dd_init_file(file, dd_file);
    dd_file->parent = dd_dir;
    if (vc_file->file_status == TEK_SC_VC_FILE_STATUS_missing) {
      // Missing file, just add all the chunks for download
      dd_file->flags = TEK_SC_DD_FILE_FLAG_new;
      dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_new;
      if (file->num_chunks) {
        dd_file->flags |= TEK_SC_DD_FILE_FLAG_download;
        dd_file->chunks = ctx->next_chunk;
        dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_download;
        ctx->next_chunk += file->num_chunks;
      } else {
        dd_file->chunks = nullptr;
      }
      // Iterate chunks
      for (int j = 0; j < file->num_chunks; ++j) {
        dd_file->chunks[j] =
            (tek_sc_dd_chunk){.chunk = &file->chunks[j],
                              .parent = dd_file,
                              .status = TEK_SC_JOB_ENTRY_STATUS_pending,
                              .chunk_buf_offset = -1};
      }
      dd_file->num_chunks = file->num_chunks;
      continue;
    }
    if (vc_file->file_status == TEK_SC_VC_FILE_STATUS_truncate &&
        (!file->num_chunks || num_dirty_chunks < file->num_chunks)) {
      // Set truncate flag only if the file isn't going to be fully redownloaded
      dd_file->flags = TEK_SC_DD_FILE_FLAG_truncate;
      dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_patch;
    } else {
      dd_file->flags = TEK_SC_DD_FILE_FLAG_none;
    }
    if (num_dirty_chunks) {
      dd_file->flags |= TEK_SC_DD_FILE_FLAG_download;
      dd_file->chunks = ctx->next_chunk;
      dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_download;
      if (num_dirty_chunks == file->num_chunks) {
        dd_file->flags |= TEK_SC_DD_FILE_FLAG_new;
        dd_dir->flags |= TEK_SC_DD_DIR_FLAG_children_new;
      }
    } else {
      dd_file->chunks = nullptr;
    }
    // Iterate chunks
    auto const vc_chunks = &vcache->chunks[file->chunks - man->chunks];
    for (int j = 0; j < file->num_chunks; ++j) {
      if (!vc_chunks[j].match) {
        auto const chunk = &file->chunks[j];
        *ctx->next_chunk++ =
            (tek_sc_dd_chunk){.chunk = chunk,
                              .parent = dd_file,
                              .status = TEK_SC_JOB_ENTRY_STATUS_pending,
                              .chunk_buf_offset = ctx->chunk_buf_off};
        ctx->chunk_buf_off += chunk->size;
      }
    }
    dd_file->num_chunks = num_dirty_chunks;
  } // for (files)
  // Iterate subdirectories
  auto const vc_subdirs = &vcache->dirs[dir->subdirs - man->dirs];
  auto dd_subdir = dd_dir->subdirs;
  for (int i = 0; i < dir->num_subdirs; ++i) {
    auto const subdir = &dir->subdirs[i];
    auto const vc_subdir = &vc_subdirs[i];
    if (vc_subdir->num_dirty_subdirs < 0) {
      dd_dir->flags |=
          tscp_dd_write_missing_dir(ctx, subdir, dd_dir, dd_subdir++);
    } else if (vc_subdir->num_dirty_subdirs > 0 || vc_subdir->num_dirty_files) {
      tscp_dd_write_dir(ctx, vcache, subdir, dd_dir, dd_subdir);
      // Apply only children flags
      dd_dir->flags |=
          dd_subdir->flags & (TEK_SC_DD_DIR_FLAG_children_new |
                              TEK_SC_DD_DIR_FLAG_children_download |
                              TEK_SC_DD_DIR_FLAG_children_patch);
      ++dd_subdir;
    }
  }
}

/// Create a delta deserialization error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for specified delta deserialization
/// error.
[[gnu::const]]
static inline tek_sc_err tscp_desdd_err(tek_sc_errc errc) {
  return tsc_err_sub(TEK_SC_ERRC_delta_deserialize, errc);
}

/// Set correct entry pointers in specified directory by doing tree walking.
///
/// @param [in, out] ctx
///    Pointer to the pointer context to use.
/// @param [in, out] dir
///    Pointer to the delta directory entry to process.
[[gnu::nonnull(1, 2), gnu::access(read_write, 1), gnu::access(read_write, 2)]]
static void tscp_dd_set_ptrs(tscp_sdd_ptr_ctx *_Nonnull ctx,
                             tek_sc_dd_dir *_Nonnull dir) {
  if (dir->num_files) {
    dir->files = ctx->next_file;
    ctx->next_file += dir->num_files;
    for (int i = 0; i < dir->num_files; ++i) {
      dir->files[i].parent = dir;
    }
  } else {
    dir->files = nullptr;
  }
  if (dir->num_subdirs) {
    dir->subdirs = ctx->next_dir;
    ctx->next_dir += dir->num_subdirs;
    for (int i = 0; i < dir->num_subdirs; ++i) {
      auto const subdir = &dir->subdirs[i];
      subdir->parent = dir;
      tscp_dd_set_ptrs(ctx, subdir);
    }
  } else {
    dir->subdirs = nullptr;
  }
}

//===-- Public functions --------------------------------------------------===//

tek_sc_depot_delta
tek_sc_dd_compute_from_vc(const tek_sc_verification_cache *vcache) {
  tek_sc_depot_delta res = {.target_manifest = vcache->manifest, .num_dirs = 1};
  // Run count pass
  tscp_dd_count_dir(vcache, vcache->manifest->dirs, &res);
  // Allocate the buffer and set array pointers
  res.chunks = tsci_os_mem_alloc(sizeof *res.chunks * res.num_chunks +
                                 sizeof *res.files * res.num_files +
                                 sizeof *res.dirs * res.num_dirs);
  if (!res.chunks) {
    abort();
  }
  res.files = (tek_sc_dd_file *)(res.chunks + res.num_chunks);
  res.dirs = (tek_sc_dd_dir *)(res.files + res.num_files);
  // Run write pass
  tscp_dd_write_dir(&(tscp_dd_write_ctx){.next_chunk = res.chunks,
                                         .next_file = res.files,
                                         .next_dir = res.dirs + 1},
                    vcache, vcache->manifest->dirs, nullptr, res.dirs);
  if (!res.num_chunks) {
    res.stage =
        res.num_io_ops ? TEK_SC_DD_STAGE_patching : TEK_SC_DD_STAGE_installing;
  }
  return res;
}

int tek_sc_dd_serialize(const tek_sc_depot_delta *delta, void *buf,
                        int buf_size) {
  // Compute required buffer size
  const int required_size =
      sizeof(tscp_sdd_hdr) + sizeof(tscp_sdd_chunk) * delta->num_chunks +
      sizeof(tscp_sdd_transfer_op) * delta->num_transfer_ops +
      sizeof(tscp_sdd_file) * delta->num_files +
      sizeof(tscp_sdd_dir) * delta->num_dirs;
  if (!buf || buf_size < required_size) {
    return required_size;
  }
  // Write header
  tscp_sdd_hdr *const hdr = buf;
  *hdr = (tscp_sdd_hdr){.patch_required = delta->patch ? 1 : 0,
                        .src_manifest_id = delta->source_manifest
                                               ? delta->source_manifest->id
                                               : 0,
                        .tgt_manifest_id = delta->target_manifest->id,
                        .num_chunks = delta->num_chunks,
                        .num_transfer_ops = delta->num_transfer_ops,
                        .num_files = delta->num_files,
                        .num_dirs = delta->num_dirs,
                        .stage = delta->stage,
                        .num_deletions = delta->num_deletions,
                        .num_io_ops = delta->num_io_ops,
                        .transfer_buf_size = delta->transfer_buf_size,
                        .total_file_growth = delta->total_file_growth,
                        .download_size = delta->download_size};
  // Write chunks
  auto const chunks_base = delta->target_manifest->chunks;
  auto const sdd_chunks = (tscp_sdd_chunk *)(hdr + 1);
  for (int i = 0; i < delta->num_chunks; ++i) {
    auto const chunk = &delta->chunks[i];
    sdd_chunks[i] =
        (tscp_sdd_chunk){.index = chunk->chunk - chunks_base,
                         .status = chunk->status == TEK_SC_JOB_ENTRY_STATUS_done
                                       ? TEK_SC_JOB_ENTRY_STATUS_done
                                       : TEK_SC_JOB_ENTRY_STATUS_pending,
                         .chunk_buf_off = chunk->chunk_buf_offset};
  }
  // Write transfer operations
  auto const pchunks_base = delta->patch ? delta->patch->chunks : nullptr;
  auto const sdd_transfer_ops =
      (tscp_sdd_transfer_op *)(sdd_chunks + delta->num_chunks);
  for (int i = 0; i < delta->num_transfer_ops; ++i) {
    auto const transfer_op = &delta->transfer_ops[i];
    auto const sdd_transfer_op = &sdd_transfer_ops[i];
    sdd_transfer_op->status = transfer_op->status;
    sdd_transfer_op->type = transfer_op->type;
    switch (transfer_op->type) {
    case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
      auto const reloc = &transfer_op->data.relocation;
      auto const sdd_reloc = &sdd_transfer_op->data.reloc;
      sdd_reloc->src_off = reloc->source_offset;
      sdd_reloc->tgt_off = reloc->target_offset;
      sdd_reloc->size = reloc->size;
      break;
    case TEK_SC_DD_TRANSFER_OP_TYPE_patch:
      auto const sdd_pchunk = &sdd_transfer_op->data.pchunk;
      sdd_pchunk->index = transfer_op->data.patch_chunk - pchunks_base;
      memset(sdd_pchunk->padding, 0, sizeof sdd_pchunk->padding);
    }
    sdd_transfer_op->transfer_buf_off = transfer_op->transfer_buf_offset;
  }
  // Write files
  auto const src_files_base =
      delta->source_manifest ? delta->source_manifest->files : nullptr;
  auto const tgt_files_base = delta->target_manifest->files;
  auto const sdd_files =
      (tscp_sdd_file *)(sdd_transfer_ops + delta->num_transfer_ops);
  for (int i = 0; i < delta->num_files; ++i) {
    auto const file = &delta->files[i];
    sdd_files[i] = (tscp_sdd_file){
        .index = file->file - ((file->flags & TEK_SC_DD_FILE_FLAG_delete)
                                   ? src_files_base
                                   : tgt_files_base),
        .status = delta->stage == TEK_SC_DD_STAGE_patching ? file->status
                  : file->status == TEK_SC_JOB_ENTRY_STATUS_done
                      ? TEK_SC_JOB_ENTRY_STATUS_done
                      : TEK_SC_JOB_ENTRY_STATUS_pending,
        .flags = file->flags,
        .num_chunks = file->num_chunks,
        .num_transfer_ops = file->num_transfer_ops};
  }
  // Write directories
  auto const src_dirs_base =
      delta->source_manifest ? delta->source_manifest->dirs : nullptr;
  auto const tgt_dirs_base = delta->target_manifest->dirs;
  auto const sdd_dirs = (tscp_sdd_dir *)(sdd_files + delta->num_files);
  for (int i = 0; i < delta->num_dirs; ++i) {
    auto const dir = &delta->dirs[i];
    sdd_dirs[i] = (tscp_sdd_dir){
        .index = dir->dir - ((dir->flags & TEK_SC_DD_DIR_FLAG_delete)
                                 ? src_dirs_base
                                 : tgt_dirs_base),
        .status = delta->stage == TEK_SC_DD_STAGE_deleting
                      ? dir->status
                      : (dir->status == TEK_SC_JOB_ENTRY_STATUS_done
                             ? TEK_SC_JOB_ENTRY_STATUS_done
                             : TEK_SC_JOB_ENTRY_STATUS_pending),
        .flags = dir->flags,
        .num_files = dir->num_files,
        .num_subdirs = dir->num_subdirs};
  }
  // Compute CRC32
  hdr->crc = tsci_z_crc32(tsci_z_crc32(0, nullptr, 0), buf + sizeof hdr->crc,
                          required_size - sizeof hdr->crc);
  return 0;
}

tek_sc_err tek_sc_dd_deserialize(const void *buf, int buf_size,
                                 const tek_sc_depot_manifest *source_manifest,
                                 const tek_sc_depot_manifest *target_manifest,
                                 const tek_sc_depot_patch *patch,
                                 tek_sc_depot_delta *delta) {
  if (buf_size < (int)sizeof(tscp_sdd_hdr)) {
    return tscp_desdd_err(TEK_SC_ERRC_invalid_data);
  }
  const tscp_sdd_hdr *const hdr = buf;
  // Verify CRC32
  if (hdr->crc != tsci_z_crc32(tsci_z_crc32(0, nullptr, 0),
                               buf + sizeof hdr->crc,
                               buf_size - sizeof hdr->crc)) {
    return tscp_desdd_err(TEK_SC_ERRC_crc_mismatch);
  }
  // Verify that correct manifests and patch are provided
  if (hdr->src_manifest_id) {
    if (!source_manifest || hdr->src_manifest_id != source_manifest->id) {
      return tscp_desdd_err(TEK_SC_ERRC_delta_manifests_mismatch);
    }
    delta->source_manifest = source_manifest;
  } else {
    delta->source_manifest = nullptr;
  }
  if (hdr->tgt_manifest_id != target_manifest->id) {
    return tscp_desdd_err(TEK_SC_ERRC_delta_manifests_mismatch);
  }
  delta->target_manifest = target_manifest;
  if (hdr->patch_required) {
    if (!patch || patch->source_manifest != source_manifest ||
        patch->target_manifest != target_manifest) {
      return tscp_desdd_err(TEK_SC_ERRC_delta_patch_mismatch);
    }
    delta->patch = patch;
  } else {
    delta->patch = nullptr;
  }
  // Read header
  delta->num_chunks = hdr->num_chunks;
  delta->num_transfer_ops = hdr->num_transfer_ops;
  delta->num_files = hdr->num_files;
  delta->num_dirs = hdr->num_dirs;
  delta->stage = hdr->stage;
  delta->num_deletions = hdr->num_deletions;
  delta->num_io_ops = hdr->num_io_ops;
  delta->transfer_buf_size = hdr->transfer_buf_size;
  delta->total_file_growth = hdr->total_file_growth;
  delta->download_size = hdr->download_size;
  // Get SDD array pointers and verify input buffer size
  auto const sdd_chunks = (const tscp_sdd_chunk *)(hdr + 1);
  auto const sdd_transfer_ops =
      (const tscp_sdd_transfer_op *)(sdd_chunks + hdr->num_chunks);
  auto const sdd_files =
      (const tscp_sdd_file *)(sdd_transfer_ops + hdr->num_transfer_ops);
  auto const sdd_dirs = (const tscp_sdd_dir *)(sdd_files + hdr->num_files);
  if (buf_size < ((const void *)(sdd_dirs + hdr->num_dirs) - buf)) {
    return tscp_desdd_err(TEK_SC_ERRC_invalid_data);
  }
  // Allocate the delta buffer and set array pointers
  delta->chunks =
      tsci_os_mem_alloc(sizeof *delta->chunks * hdr->num_chunks +
                        sizeof *delta->transfer_ops * hdr->num_transfer_ops +
                        sizeof *delta->files * hdr->num_files +
                        sizeof *delta->dirs * hdr->num_dirs);
  if (!delta->chunks) {
    return tsci_err_os(TEK_SC_ERRC_delta_deserialize, tsci_os_get_last_error());
  }
  delta->transfer_ops =
      (tek_sc_dd_transfer_op *)(delta->chunks + hdr->num_chunks);
  delta->files =
      (tek_sc_dd_file *)(delta->transfer_ops + delta->num_transfer_ops);
  delta->dirs = (tek_sc_dd_dir *)(delta->files + delta->num_files);
  // Read chunks
  auto const chunks_base = target_manifest->chunks;
  for (int i = 0; i < hdr->num_chunks; ++i) {
    auto const sdd_chunk = &sdd_chunks[i];
    delta->chunks[i] =
        (tek_sc_dd_chunk){.chunk = &chunks_base[sdd_chunk->index],
                          .status = sdd_chunk->status,
                          .chunk_buf_offset = sdd_chunk->chunk_buf_off};
  }
  // Read transfer operations
  auto const pchunks_base = hdr->patch_required ? patch->chunks : nullptr;
  for (int i = 0; i < hdr->num_transfer_ops; ++i) {
    auto const transfer_op = &delta->transfer_ops[i];
    auto const sdd_transfer_op = &sdd_transfer_ops[i];
    transfer_op->status = sdd_transfer_op->status;
    transfer_op->type = sdd_transfer_op->type;
    switch (transfer_op->type) {
    case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
      auto const reloc = &transfer_op->data.relocation;
      auto const sdd_reloc = &sdd_transfer_op->data.reloc;
      reloc->source_offset = sdd_reloc->src_off;
      reloc->target_offset = sdd_reloc->tgt_off;
      reloc->size = sdd_reloc->size;
      break;
    case TEK_SC_DD_TRANSFER_OP_TYPE_patch:
      transfer_op->data.patch_chunk =
          &pchunks_base[sdd_transfer_op->data.pchunk.index];
    }
    transfer_op->transfer_buf_offset = sdd_transfer_op->transfer_buf_off;
  }
  // Read files
  auto const src_files_base =
      hdr->src_manifest_id ? source_manifest->files : nullptr;
  auto const tgt_files_base = target_manifest->files;
  auto cur_chunk = delta->chunks;
  auto cur_transfer_op = delta->transfer_ops;
  for (int i = 0; i < hdr->num_files; ++i) {
    auto const file = &delta->files[i];
    auto const sdd_file = &sdd_files[i];
    file->file = &((sdd_file->flags & TEK_SC_DD_FILE_FLAG_delete)
                       ? src_files_base
                       : tgt_files_base)[sdd_file->index];
    file->status = sdd_file->status;
    file->flags = sdd_file->flags;
    if (sdd_file->num_chunks) {
      file->chunks = cur_chunk;
      for (int j = 0; j < sdd_file->num_chunks; ++j) {
        file->chunks[j].parent = file;
      }
      cur_chunk += sdd_file->num_chunks;
    } else {
      file->chunks = nullptr;
    }
    if (sdd_file->num_transfer_ops) {
      file->transfer_ops = cur_transfer_op;
      cur_transfer_op += sdd_file->num_transfer_ops;
    } else {
      file->transfer_ops = nullptr;
    }
    file->num_chunks = sdd_file->num_chunks;
    file->num_transfer_ops = sdd_file->num_transfer_ops;
    file->handle = TSCI_OS_INVALID_HANDLE;
  }
  // Read directories (except pointers)
  auto const src_dirs_base =
      hdr->src_manifest_id ? source_manifest->dirs : nullptr;
  auto const tgt_dirs_base = target_manifest->dirs;
  for (int i = 0; i < hdr->num_dirs; ++i) {
    auto const dir = &delta->dirs[i];
    auto const sdd_dir = &sdd_dirs[i];
    dir->dir = &((sdd_dir->flags & TEK_SC_DD_DIR_FLAG_delete)
                     ? src_dirs_base
                     : tgt_dirs_base)[sdd_dir->index];
    dir->status = sdd_dir->status;
    dir->flags = sdd_dir->flags;
    dir->num_files = sdd_dir->num_files;
    dir->num_subdirs = sdd_dir->num_subdirs;
    dir->handle = TSCI_OS_INVALID_HANDLE;
    dir->cache_handle = TSCI_OS_INVALID_HANDLE;
  }
  // Set entry pointers
  delta->dirs[0].parent = nullptr;
  tscp_dd_set_ptrs(&(tscp_sdd_ptr_ctx){.next_file = delta->files,
                                       .next_dir = delta->dirs + 1},
                   delta->dirs);
  return tsc_err_ok();
}

void tek_sc_dd_free(tek_sc_depot_delta *delta) {
  if (delta->chunks) {
    tsci_os_mem_free(delta->chunks,
                     sizeof *delta->chunks * delta->num_chunks +
                         sizeof *delta->transfer_ops * delta->num_transfer_ops +
                         sizeof *delta->files * delta->num_files +
                         sizeof *delta->dirs * delta->num_dirs);
  }
  *delta = (tek_sc_depot_delta){};
}

int64_t tek_sc_dd_estimate_disk_space(const tek_sc_depot_delta *delta) {
  int64_t size = 0;
  // Find the largest transfer buffer file size
  for (int i = 0; i < delta->num_files; ++i) {
    auto const file = &delta->files[i];
    int64_t transfer_buf_size = 0;
    for (int j = 0; j < file->num_transfer_ops; ++j) {
      auto const transfer_op = &file->transfer_ops[j];
      if (transfer_op->transfer_buf_offset >= 0) {
        switch (transfer_op->type) {
        case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
          transfer_buf_size += transfer_op->data.relocation.size;
          break;
        case TEK_SC_DD_TRANSFER_OP_TYPE_patch:
          auto const pchunk = transfer_op->data.patch_chunk;
          int size = pchunk->source_chunk->size;
          if (pchunk->target_chunk->size < size) {
            size = pchunk->target_chunk->size;
          }
          transfer_buf_size += size;
        }
      }
    }
    if (transfer_buf_size > size) {
      size = transfer_buf_size;
    }
  }
  // Add size of all chunks to be downloaded
  for (int i = 0; i < delta->num_chunks; ++i) {
    size += delta->chunks[i].chunk->size;
  }
  // Finish with pre-computed total file growth
  return size + delta->total_file_growth;
}
