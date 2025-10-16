//===-- content.h - Steam content structures interface --------------------===//
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
/// Declarations of various structures describing content of Steam application
///    depots and their updates, and the API to work with them.
///
/// SteamPipe content servers store data organized into depots, you can read
///    more about them
///    [here](https://partner.steamgames.com/doc/store/application/depots).
/// Depots host 3 known types of files:
///  Chunks - actual binary content of the application, no bigger than 1 MiB
///    each, although they are stored in an archive format (Zip, VZ or VSZ),
///    which may cause them to be slightly bigger if compression is ineffective
///    on them.
///    Application files are split into the chunks, which are identified by
///    SHA-1 hash of the data they contain, which allows them to be reused for
///    repetitive content and save both on server storage space and download
///    size, while also optimizing verification and updates.
///  Manifests - lists of all files and directories in a particular build of
///    the depot (manifest IDs can be considered depot versions in that sense)
///    and the chunks they contain. That information can be used to download the
///    content they list, verify the files, and two manifests for the same depot
///    can be compared to perform an update. TEK Steam Client however prefers to
///    use the term "item" rather than "depot" to also differentiate Steam
///    Workshop items, which are all stored in the same depot, but have
///    absolutely different data.
///  Patches - created between certain successive manifests, provide LZMA or
///    Zstandard delta data that can be applied to certain source manifest
///    chunks to convert them to target manifest chunks. This saves update
///    download size due to delta chunks being much smaller than produced target
///    chunks.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"
#include "error.h"
#include "os.h"

#include <stdatomic.h>
#include <stdint.h>

//===-- Common types ------------------------------------------------------===//

/// Status values for entries that are processed by an application manager job,
///    accounting for possible parallelism.
enum tek_sc_job_entry_status {
  /// The entry hasn't been reached by any job thread yet.
  TEK_SC_JOB_ENTRY_STATUS_pending,
  /// The entry is undergoing some initial setup (e.g. opening a file) during
  ///    which no other job threads should access it.
  TEK_SC_JOB_ENTRY_STATUS_setup,
  /// The entry is being processed by one or more job threads, depending on
  ///    entry type.
  TEK_SC_JOB_ENTRY_STATUS_active,
  /// The entry has been fully processed, including its children if any.
  TEK_SC_JOB_ENTRY_STATUS_done,
};
/// @copydoc tek_sc_job_entry_status
typedef enum tek_sc_job_entry_status tek_sc_job_entry_status;
/// Atomic variant of @ref tek_sc_job_entry_status.
typedef _Atomic(tek_sc_job_entry_status) tek_sc_job_entry_status_atomic;

/// SHA-1 hash representation that compilers can optimize with SSE instructions.
typedef union tek_sc_sha1_hash tek_sc_sha1_hash;
/// @copydoc tek_sc_sha1_hash
union tek_sc_sha1_hash {
  /// uint128 + uint32 representation, optimized for comparisons.
  __extension__ struct {
    __uint128_t low128;
    uint32_t high32;
  };
  /// 20 bytes representation, for string conversions.
  unsigned char bytes[20];
};

//===-- Depot manifest types ----------------------------------------------===//

/// Manifest file entry.
typedef struct tek_sc_dm_file tek_sc_dm_file;
/// Manifest directory entry.
typedef struct tek_sc_dm_dir tek_sc_dm_dir;

/// Manifest file chunk entry.
typedef struct tek_sc_dm_chunk tek_sc_dm_chunk;
/// @copydoc tek_sc_dm_chunk
struct tek_sc_dm_chunk {
  /// SHA-1 hash of chunk data, part of its download URL in SteamPipe.
  tek_sc_sha1_hash sha;
  /// Pointer to the parent file entry.
  const tek_sc_dm_file *_Nonnull parent;
  /// Offset of chunk data from the beginning of containing file, in bytes.
  int64_t offset;
  /// Size of chunk data on disk, in bytes.
  int size;
  /// Size of compressed chunk data on SteamPipe servers, in bytes.
  int comp_size;
};

/// Flags that may be applied to manifest files.
enum [[clang::flag_enum]] tek_sc_dm_file_flag {
  /// No flags.
  TEK_SC_DM_FILE_FLAG_none,
  /// Set read-only attribute (on Windows).
  TEK_SC_DM_FILE_FLAG_readonly = 1 << 0,
  /// Set hidden attribute (on Windows).
  TEK_SC_DM_FILE_FLAG_hidden = 1 << 1,
  /// Set execute permission (on Linux).
  TEK_SC_DM_FILE_FLAG_executable = 1 << 2,
  /// The file is a symbolic link.
  TEK_SC_DM_FILE_FLAG_symlink = 1 << 3
};
/// @copydoc tek_sc_dm_file_flag
typedef enum tek_sc_dm_file_flag tek_sc_dm_file_flag;

/// @copydoc tek_sc_dm_file
struct tek_sc_dm_file {
  /// Null-terminated name of the file.
  const tek_sc_os_char *_Nonnull name;
  /// Pointer to the parent directory entry.
  const tek_sc_dm_dir *_Nonnull parent;
  /// If @ref flags includes @ref TEK_SC_DM_FILE_FLAG_symlink, null-terminated
  ///    path to the symbolic link target.
  const tek_sc_os_char *_Nullable target_path;
  /// Size of the file on disk, in bytes.
  int64_t size;
  /// Pointer to the file's chunk entry array.
  const tek_sc_dm_chunk *_Nullable chunks;
  /// Number of chunks assigned to the file.
  int num_chunks;
  /// Flags describing file attributes and/or permissions.
  tek_sc_dm_file_flag flags;
};

/// @copydoc tek_sc_dm_directory
struct tek_sc_dm_dir {
  /// Null-terminated name of the directory, or `nullptr` for the root
  ///    directory.
  const tek_sc_os_char *_Nullable name;
  /// Pointer to the parent entry.
  const tek_sc_dm_dir *_Nullable parent;
  /// Pointer to the directory's file entry array.
  const tek_sc_dm_file *_Nullable files;
  /// Pointer to the directory's subdirectory entry array.
  const tek_sc_dm_dir *_Nullable subdirs;
  /// Number of files assigned to the directory.
  int num_files;
  /// Number of assigned subdirectories.
  int num_subdirs;
};

/// Steam depot manifest.
typedef struct tek_sc_depot_manifest tek_sc_depot_manifest;
/// @copydoc tek_sc_depot_manifest
struct tek_sc_depot_manifest {
  // ID of the Steam item that the manifest belongs to.
  tek_sc_item_id item_id;
  /// ID of the manifest.
  uint64_t id;
  /// Total on-disk size of all files listed in the manifest, in bytes.
  ///
  /// Used as progress total value for verification.
  int64_t data_size;
  /// Pointer to the manifest's chunk entry array.
  tek_sc_dm_chunk *_Nonnull chunks;
  /// Pointer to the manifest's file entry array.
  tek_sc_dm_file *_Nonnull files;
  /// Pointer to the manifest's directory entry array.
  ///
  /// The first element is the root of the tree with `name` set to `nullptr`.
  tek_sc_dm_dir *_Nonnull dirs;
  /// Total number of chunk entries in the manifest.
  int num_chunks;
  /// Total number of file entries in the manifest.
  int num_files;
  /// Total number of directory entries in the manifest.
  int num_dirs;
  /// Size of the buffer storing all entries, in bytes.
  int buf_size;
};

//===-- Depot patch types -------------------------------------------------===//

/// Patch chunk format types.
enum tek_sc_dp_chunk_type {
  /// VZd format, using LZMA compression algorithm.
  TEK_SC_DP_CHUNK_TYPE_vzd,
  /// VSZd format, using Zstd compression algorithm.
  TEK_SC_DP_CHUNK_TYPE_vszd
};
/// @copydoc tek_sc_dp_chunk_type
typedef enum tek_sc_dp_chunk_type tek_sc_dp_chunk_type;

/// Patch chunk entry.
///
/// Matches a delta chunk to the source manifest chunk it
///    applies to and the target manifest chunk it produces.
typedef struct tek_sc_dp_chunk tek_sc_dp_chunk;
/// @copydoc tek_sc_dp_chunk
struct tek_sc_dp_chunk {
  /// Pointer to the chunk that the delta applies to.
  const tek_sc_dm_chunk *_Nonnull source_chunk;
  /// Pointer to the chunk produced by patching.
  const tek_sc_dm_chunk *_Nonnull target_chunk;
  /// Pointer to the delta chunk.
  const void *_Nonnull delta_chunk;
  /// Size of the delta chunk, in bytes.
  int delta_chunk_size;
  /// Type of the chunk.
  tek_sc_dp_chunk_type type;
};

/// Steam depot patch.
typedef struct tek_sc_depot_patch tek_sc_depot_patch;
/// @copydoc tek_sc_depot_patch
struct tek_sc_depot_patch {
  /// Pointer to the manifest providing source chunks.
  const tek_sc_depot_manifest *_Nonnull source_manifest;
  /// Pointer to the manifest providing target chunks.
  const tek_sc_depot_manifest *_Nonnull target_manifest;
  /// Pointer to the patch chunk entry array.
  tek_sc_dp_chunk *_Nonnull chunks;
  /// Total number of chunk entries in the patch.
  int num_chunks;
  /// Total size of delta chunks, in bytes.
  int delta_size;
};

//===-- Verification cache types ------------------------------------------===//

/// Verification cache chunk entry.
typedef struct tek_sc_vc_chunk tek_sc_vc_chunk;
/// @copydoc tek_sc_vc_chunk
struct tek_sc_vc_chunk {
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  /// Value indicating whether SHA-1 hash of chunk's data matches manifest
  ///    chunk entry's `sha`.
  bool match;
};

/// Verification cache file status values.
enum tek_sc_vc_file_status {
  /// The file exists in filesystem and may have zero or more dirty chunks.
  TEK_SC_VC_FILE_STATUS_regular,
  /// The file doesn't exist in filesystem and all its chunks are to be
  ///    downloaded.
  TEK_SC_VC_FILE_STATUS_missing,
  /// The file exists in filesystem but its size is bigger than specified in
  ///    its manifest entry, so it is to be truncated, it may also have zero or
  ///    more dirty chunks.
  TEK_SC_VC_FILE_STATUS_truncate
};
/// @copydoc tek_sc_vc_file_status
typedef enum tek_sc_vc_file_status tek_sc_vc_file_status;

/// Verification cache file entry.
typedef struct tek_sc_vc_file tek_sc_vc_file;
/// @copydoc tek_sc_vc_file
struct tek_sc_vc_file {
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  union {
    /// Number of chunks that haven't been verified yet.
    int num_rem_chunks;
    /// Atomic access to @ref num_rem_chunks.
    atomic_int num_rem_chunks_a;
  };
  union {
    /// Number of file's verified chunks that are missing or have mismatching
    ///    data.
    int num_dirty_chunks;
    /// Atomic access to @ref num_dirty_chunks.
    atomic_int num_dirty_chunks_a;
  };
  /// Status of the file determined by verification.
  tek_sc_vc_file_status file_status;
  /// Handle for the opened local file.
  tek_sc_os_handle handle;
};

/// Verification cache directory entry.
typedef struct tek_sc_vc_dir tek_sc_vc_dir;
/// @copydoc tek_sc_vc_directory
struct tek_sc_vc_dir {
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  union {
    /// Number of files/subdirectories that haven't been verified yet.
    int num_rem_children;
    /// Atomic access to @ref num_rem_children.
    atomic_int num_rem_children_a;
  };
  union {
    /// Number of directory's verified files that are missing or have dirty
    ///    chunks.
    int num_dirty_files;
    /// Atomic access to @ref num_dirty_files.
    atomic_int num_dirty_files_a;
  };
  union {
    /// Number of verified subdirectories that are missing or have dirty child
    ///    entries. A value of `-1` indicates that the directory itself doesn't
    ///    exist in filesystem.
    int num_dirty_subdirs;
    /// Atomic access to @ref num_dirty_subdirs.
    atomic_int num_dirty_subdirs_a;
  };
  /// Number of remaining uses for @ref handle, which is closed when it reaches
  ///    zero.
  atomic_int ref_count;
  /// Handle for the opened local directory.
  tek_sc_os_handle handle;
};

/// Structure for tracking item verification progress and storing its results.
///
/// Verification cache entries map to manifest entries at the same array index.
typedef struct tek_sc_verification_cache tek_sc_verification_cache;
/// @copydoc tek_sc_verification_cache
struct tek_sc_verification_cache {
  /// Pointer to the manifest that the verification cache binds to.
  const tek_sc_depot_manifest *_Nonnull manifest;
  /// Pointer to the verificaiton cache's chunk entry array.
  tek_sc_vc_chunk *_Nonnull chunks;
  /// Pointer to the verificaiton cache's file entry array.
  tek_sc_vc_file *_Nonnull files;
  /// Pointer to the verificaiton cache's directory entry array.
  tek_sc_vc_dir *_Nonnull dirs;
};

//===-- Depot delta types -------------------------------------------------===//

/// Delta file entry.
typedef struct tek_sc_dd_file tek_sc_dd_file;
/// Delta directory entry.
typedef struct tek_sc_dd_dir tek_sc_dd_dir;

/// Delta chunk entry.
typedef struct tek_sc_dd_chunk tek_sc_dd_chunk;
/// @copydoc tek_sc_dd_chunk
struct tek_sc_dd_chunk {
  /// Pointer to the corresponding manifest chunk entry.
  const tek_sc_dm_chunk *_Nonnull chunk;
  /// Pointer to the parent file entry.
  tek_sc_dd_file *_Nonnull parent;
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  /// Offset of chunk data from the beginning of the chunk buffer file, in
  ///    bytes. Ignored if containing file has @ref TEK_SC_DD_FILE_FLAG_new
  ///    flag.
  int64_t chunk_buf_offset;

// Copy and move constructors and assignment operators for C++, due to an
//    atomic member implicitly deleting them
#ifdef __cplusplus

  constexpr tek_sc_dd_chunk(const tek_sc_dm_chunk *_Nonnull chunk,
                            tek_sc_dd_file &parent,
                            tek_sc_job_entry_status status,
                            int64_t chunk_buf_offset) noexcept
      : chunk(chunk), parent(&parent), status(status),
        chunk_buf_offset(chunk_buf_offset) {}
  constexpr tek_sc_dd_chunk(const tek_sc_dd_chunk &other) noexcept
      : chunk(other.chunk), parent(other.parent), status(other.status),
        chunk_buf_offset(other.chunk_buf_offset) {}
  constexpr tek_sc_dd_chunk(const tek_sc_dd_chunk &&other) noexcept
      : chunk(other.chunk), parent(other.parent), status(other.status),
        chunk_buf_offset(other.chunk_buf_offset) {}

  constexpr tek_sc_dd_chunk &operator=(const tek_sc_dd_chunk &other) noexcept {
    chunk = other.chunk;
    parent = other.parent;
    status = other.status;
    chunk_buf_offset = other.chunk_buf_offset;
    return *this;
  }
  constexpr tek_sc_dd_chunk &operator=(const tek_sc_dd_chunk &&other) noexcept {
    chunk = other.chunk;
    parent = other.parent;
    status = other.status;
    chunk_buf_offset = other.chunk_buf_offset;
    return *this;
  }

#endif // def __cplusplus
};

/// Delta transfer operation types.
enum tek_sc_dd_transfer_op_type {
  /// Move a batch of data from one location in the file to another.
  TEK_SC_DD_TRANSFER_OP_TYPE_reloc,
  /// Patch a chunk.
  TEK_SC_DD_TRANSFER_OP_TYPE_patch
};
/// @copydoc tek_sc_dd_transfer_op_type
typedef enum tek_sc_dd_transfer_op_type tek_sc_dd_transfer_op_type;

/// Delta transfer operation entry.
///
/// Transfer operations are operations that read a region of file as input
///    and write another region of the same file as output. Since these regions
///    can overlap each other and regions of consequent operations, some of
///    them are read into the transfer buffer file first, and then from there
///    written to their destination regions in the same order, delta
///    computation algorithm in turn ensures that there are as few such
///    overlaps as possible.
typedef struct tek_sc_dd_transfer_op tek_sc_dd_transfer_op;
/// @copydoc tek_sc_dd_transfer_op
struct tek_sc_dd_transfer_op {
  /// Job status of the entry.
  tek_sc_job_entry_status status;
  /// Type of the operation.
  tek_sc_dd_transfer_op_type type;
  /// Transfer operation data, depending on @ref type.
  union {
    /// Relocation descriptor, used when @ref type is
    ///    @ref TEK_SC_DD_TRANSFER_OP_TYPE_reloc.
    struct {
      /// File offset to copy the data bulk from, in bytes.
      int64_t source_offset;
      /// File offset to copy the data bulk to, in bytes.
      int64_t target_offset;
      /// Size of the data bulk, in bytes.
      int size;
    } relocation;
    /// Pointer to the patch chunk entry to apply, used when @ref type is
    ///    @ref TEK_SC_DD_TRANSFER_OP_TYPE_patch.
    ///
    /// When file buffering is used, data can be written to the transfer buffer
    ///    file either before or after patching, the decision is made based on
    ///    comparison of source and target chunk sizes, the smaller one of them
    ///    is written.
    const tek_sc_dp_chunk *_Nonnull patch_chunk;
  } data;
  /// Offset of data from the beginning of the transfer buffer file, in bytes,
  ///    or `-1` if intermediate file buffering is not used.
  int64_t transfer_buf_offset;
};

/// Flags describing types of operations to be performed for particular file.
enum [[clang::flag_enum]] tek_sc_dd_file_flag {
  /// No flags yet, only used during delta creation.
  TEK_SC_DD_FILE_FLAG_none,
  /// The file either doesn't exist in filesystem and must be created, or all
  ///    its chunks are dirty, so (unless it's empty) it can be downloaded and
  ///    installed as-is instead of utilizing chunk buffer file.
  TEK_SC_DD_FILE_FLAG_new = 1 << 0,
  /// The file has dirty or new chunks to download.
  TEK_SC_DD_FILE_FLAG_download = 1 << 1,
  /// The file has transfer operations to apply.
  TEK_SC_DD_FILE_FLAG_patch = 1 << 2,
  /// The file is to be truncated.
  TEK_SC_DD_FILE_FLAG_truncate = 1 << 3,
  /// The file has been delisted and is to be deleted.
  TEK_SC_DD_FILE_FLAG_delete = 1 << 4
};
/// @copydoc tek_sc_dd_file_flag
typedef enum tek_sc_dd_file_flag tek_sc_dd_file_flag;

/// @copydoc tek_sc_dd_file
struct tek_sc_dd_file {
  /// Pointer to the corresponding manifest file entry.
  const tek_sc_dm_file *_Nonnull file;
  /// Pointer to the parent directory entry.
  tek_sc_dd_dir *_Nonnull parent;
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  /// File operation flags.
  tek_sc_dd_file_flag flags;
  /// Pointer to the file's chunk entry array.
  tek_sc_dd_chunk *_Nullable chunks;
  /// Pointer to the file's transfer operation entry array.
  tek_sc_dd_transfer_op *_Nullable transfer_ops;
  /// Number of chunk entries assigned to the file.
  int num_chunks;
  /// Number of transfer operation entries assigned to the file.
  int num_transfer_ops;
  union {
    /// Number of chunks/transfer operations that haven't been processed yet at
    ///    current stage.
    int num_rem_children;
    /// Atomic access to @ref num_rem_children.
    atomic_int num_rem_children_a;
  };
  /// Handle for the opened file.
  tek_sc_os_handle handle;
};

/// Flags describing types of operations to be performed for particular
///    directory.
enum [[clang::flag_enum]] tek_sc_dd_dir_flag {
  /// No flags yet, only used during delta creation.
  TEK_SC_DD_DIR_FLAG_none,
  /// The directory doesn't exist in filesystem and must be created.
  TEK_SC_DD_DIR_FLAG_new = 1 << 0,
  /// The directory has been delisted and is to be deleted if there are no user
  ///    files in it.
  TEK_SC_DD_DIR_FLAG_delete = 1 << 1,
  /// The directory has child entries with a @ref TEK_SC_DD_FILE_FLAG_new,
  ///    @ref TEK_SC_DD_DIR_FLAG_new or @ref TEK_SC_DD_DIR_FLAG_children_new
  ///    flag.
  TEK_SC_DD_DIR_FLAG_children_new = 1 << 2,
  /// The directory has child entries with a @ref TEK_SC_DD_FILE_FLAG_download
  ///    or @ref TEK_SC_DD_DIR_FLAG_children_download flag.
  TEK_SC_DD_DIR_FLAG_children_download = 1 << 3,
  /// The directory has child entries with a @ref TEK_SC_DD_FILE_FLAG_patch,
  ///    @ref TEK_SC_DD_FILE_FLAG_truncate or
  ///    @ref TEK_SC_DD_DIR_FLAG_children_patch flag.
  TEK_SC_DD_DIR_FLAG_children_patch = 1 << 4,
  /// The directory has child entries with a @ref TEK_SC_DD_FILE_FLAG_delete,
  ///    @ref TEK_SC_DD_DIR_FLAG_delete or
  ///    @ref TEK_SC_DD_DIR_FLAG_children_delete flag.
  TEK_SC_DD_DIR_FLAG_children_delete = 1 << 5
};
/// @copydoc tek_sc_dd_dir_flag
typedef enum tek_sc_dd_dir_flag tek_sc_dd_dir_flag;

/// @copydoc tek_sc_dd_dir
struct tek_sc_dd_dir {
  /// Pointer to the corresponding manifest directory entry.
  const tek_sc_dm_dir *_Nonnull dir;
  /// Pointer to the parent entry.
  tek_sc_dd_dir *_Nullable parent;
  union {
    /// Job status of the entry.
    tek_sc_job_entry_status status;
    /// Atomic access to @ref status.
    tek_sc_job_entry_status_atomic status_a;
  };
  /// Directory operation flags.
  tek_sc_dd_dir_flag flags;
  /// Pointer to the directory's file entry array.
  tek_sc_dd_file *_Nullable files;
  /// Pointer to the directory's subdirectory entry array.
  tek_sc_dd_dir *_Nullable subdirs;
  /// Number of file entries assigned to the directory.
  int num_files;
  /// Number of assigned subdirectory entries.
  int num_subdirs;
  union {
    /// Number of files/subdirectories that haven't been processed yet at
    ///    current stage.
    int num_rem_children;
    /// Atomic access to @ref num_rem_children.
    atomic_int num_rem_children_a;
  };
  /// Number of remaining uses for @ref handle (and @ref cache_handle), which is
  ///    closed when it reaches zero.
  atomic_int ref_count;
  /// Handle for the opened directory.
  tek_sc_os_handle handle;
  /// Handle for the opened instance of the directory in the job cache. Used
  ///    only during installation stage.
  tek_sc_os_handle cache_handle;
};

/// Delta job stages.
enum tek_sc_dd_stage {
  /// Downloading chunks from SteamPipe.
  TEK_SC_DD_STAGE_downloading,
  /// Truncating files and performing transfer operations.
  TEK_SC_DD_STAGE_patching,
  /// Moving/copying downloaded data to the installation.
  TEK_SC_DD_STAGE_installing,
  /// Deleting delisted files and directories.
  TEK_SC_DD_STAGE_deleting
};
/// @copydoc tek_sc_dd_stage
typedef enum tek_sc_dd_stage tek_sc_dd_stage;

/// Structure describing all operations that need to be performed to update a
///    Steam item installation from one state to another, and storing the
///    progress of the update process.
///
/// Delta can be produced either by comparing two manifests (optionally
///    applying a patch), or by item verification, in which case it'll describe
///    the difference between the current state of the installation and the
///    manifest.
typedef struct tek_sc_depot_delta tek_sc_depot_delta;
/// @copydoc tek_sc_depot_delta
struct tek_sc_depot_delta {
  /// Pointer to the manifest describing source state, or `nullptr` if delta is
  ///    produced by item verification.
  const tek_sc_depot_manifest *_Nullable source_manifest;
  /// Pointer to the manifest describing target state.
  const tek_sc_depot_manifest *_Nonnull target_manifest;
  /// Pointer to the depot patch that the delta was computed with, or `nullptr`
  ///    if there was no patch available.
  const tek_sc_depot_patch *_Nullable patch;
  /// Pointer to the delta's chunk entry array.
  tek_sc_dd_chunk *_Nonnull chunks;
  /// Pointer to the delta's transfer operation entry array.
  tek_sc_dd_transfer_op *_Nonnull transfer_ops;
  /// Pointer to the delta's file entry array.
  tek_sc_dd_file *_Nonnull files;
  /// Pointer to the delta's directory entry array.
  ///
  /// The first element is the root of the tree.
  tek_sc_dd_dir *_Nonnull dirs;
  /// Total number of chunk entries in the delta.
  int num_chunks;
  /// Total number of transfer operation entries in the delta.
  int num_transfer_ops;
  /// Total number of file entries in the delta.
  int num_files;
  /// Total number of directory entries in the delta.
  int num_dirs;
  /// Current job stage that entries' statuses apply to.
  tek_sc_dd_stage stage;

  // Precomputed values:

  /// Total number of files and directories to be deleted.
  ///
  /// Equals to total number of file entries with
  ///    @ref TEK_SC_DD_FILE_FLAG_delete flag and directory entries with
  ///    @ref TEK_SC_DD_DIR_FLAG_delete flag. Used as progress total value for
  ///    deletion stage.
  int num_deletions;
  /// Size of the RAM buffer used when performing transfer operations, in bytes.
  ///
  /// Equals to the largest value among `relocation.size` values for transfer
  ///    operation entries with `type` set to
  ///    @ref TEK_SC_DD_TRANSFER_OP_TYPE_reloc and sums of
  ///    `patch_chunk->source_chunk->size` and
  ///    `patch_chunk->target_chunk->size` for transfer operation entries with
  ///    `type` set to @ref TEK_SC_DD_TRANSFER_OP_TYPE_patch. Used during
  ///    patching stage.
  int transfer_buf_size;
  /// Total download size / amount of data to be transferred over network, in
  ///    bytes.
  ///
  /// Equals to total `chunk->comp_size` of all chunk entries. Used as progress
  ///    total value for download stage.
  int64_t download_size;
  /// Total number of bytes to be read/written during patching stage.
  ///
  /// For each relocation, double its size (or quadruple its size if it's
  ///    intermediate file-buffered) is added. For each patch chunk, the sum of
  ///    its source and target chunk sizes is added (if it's intermediate
  ///    file-buffered, x2 of the smaller of these two is added too). Used as
  ///    progress total value for patching stage.
  int64_t patching_size;
  /// Total growth of existing files in size, in bytes.
  ///
  /// For every delta file that has neither @ref TEK_SC_DD_FILE_FLAG_new nor
  ///    @ref TEK_SC_DD_FILE_FLAG_delete, the difference between the target and
  ///    source file is taken. Where the target file is bigger, this difference
  ///    is added to the value. Used by @ref tek_sc_dd_estimate_disk_space.
  int64_t total_file_growth;
};

//===-- Functions ---------------------------------------------------------===//

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

//===--- Depot manifest functions -----------------------------------------===//

/// Decompress, decrypt and parse the manifest file downloaded from SteamPipe
///    to a @ref tek_sc_depot_manifest structure.
///
/// This function doesn't set the `item` field of @p manifest.
///
/// @param [in] data
///    Pointer to the buffer containing depot manifest file data from SteamPipe.
/// @param data_size
///    Number of bytes to read from @p data.
/// @param [in] depot_key
///    Pointer to the AES-256 depot decryption key.
/// @param [out] manifest
///    Address of variable that receives parsed manifest structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3, 4), gnu::access(read_only, 1, 2),
  gnu::access(read_only, 3), gnu::access(write_only, 4)]]
tek_sc_err tek_sc_dm_parse(const void *_Nonnull data, int data_size,
                           const tek_sc_aes256_key _Nonnull depot_key,
                           tek_sc_depot_manifest *_Nonnull manifest);

/// Serialize manifest data into persistent format that is safe to be written
///    to a file.
///
/// @param [in] manifest
///    Pointer to the manifest to serialize.
/// @param [out] buf
///    Pointer to the buffer that receives serialized manifest data. Pass
///    `nullptr` to get required buffer size.
/// @param buf_size
///    Size of the buffer pointed to by @p buf, in bytes.
/// @return `0` on success, otherwise the required buffer size to fit all
///    serialized data.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(write_only, 2, 3)]]
int tek_sc_dm_serialize(const tek_sc_depot_manifest *_Nonnull manifest,
                        void *_Nullable buf, int buf_size);

/// Deserialize manifest data from persistent format.
///
/// @param [in] buf
///    Pointer to the buffer containing serialized manifest data.
/// @param buf_size
///    Number of bytes to read from @p buf.
/// @param [out] manifest
///    Address of variable that receives deserialized manifest structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_only, 1, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tek_sc_dm_deserialize(const void *_Nonnull buf, int buf_size,
                                 tek_sc_depot_manifest *_Nonnull manifest);

/// Free all memory allocated for the manifest.
///
/// @param [in, out] manifest
///    Pointer to the manifest to free.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_dm_free(tek_sc_depot_manifest *_Nonnull manifest);

//===--- Depot patch functions --------------------------------------------===//

/// Decrypt and parse the patch file downloaded from SteamPipe to a
///    @ref tek_sc_depot_patch structure.
///
/// @param [in] data
///    Pointer to the buffer containing depot patch file data from SteamPipe.
/// @param data_size
///    Number of bytes to read from @p data.
/// @param [in] depot_key
///    Pointer to the AES-256 depot decryption key.
/// @param [in] source_manifest
///    Pointer to the manifest providing source chunks.
/// @param [in] target_manifest
///    Pointer to the manifest providing target chunks.
/// @param [out] patch
///    Address of variable that receives parsed patch structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3, 4, 5, 6), gnu::access(read_only, 1, 2),
  gnu::access(read_only, 3), gnu::access(read_only, 4),
  gnu::access(read_only, 5), gnu::access(write_only, 6)]]
tek_sc_err
tek_sc_dp_parse(const void *_Nonnull data, int data_size,
                const tek_sc_aes256_key _Nonnull depot_key,
                const tek_sc_depot_manifest *_Nonnull source_manifest,
                const tek_sc_depot_manifest *_Nonnull target_manifest,
                tek_sc_depot_patch *_Nonnull patch);

/// Serialize patch data into persistent format that is safe to be written to a
///    file.
///
/// @param [in] patch
///    Pointer to the patch to serialize.
/// @param [out] buf
///    Pointer to the buffer that receives serialized patch data. Pass
///    `nullptr` to get required buffer size.
/// @param buf_size
///    Size of the buffer pointed to by @p buf, in bytes.
/// @return `0` on success, otherwise the required buffer size to fit all
///    serialized data.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(write_only, 2, 3)]]
int tek_sc_dp_serialize(const tek_sc_depot_patch *_Nonnull patch,
                        void *_Nullable buf, int buf_size);

/// Deserialize patch data from persistent format.
///
/// @param [in] buf
///    Pointer to the buffer containing serialized patch data.
/// @param buf_size
///    Number of bytes to read from @p buf.
/// @param [in] source_manifest
///    Pointer to the manifest providing source chunks.
/// @param [in] target_manifest
///    Pointer to the manifest providing target chunks.
/// @param [out] patch
///    Address of variable that receives deserialized patch structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3, 4, 5), gnu::access(read_only, 1, 2),
  gnu::access(read_only, 3), gnu::access(read_only, 4),
  gnu::access(write_only, 5)]]
tek_sc_err
tek_sc_dp_deserialize(const void *_Nonnull buf, int buf_size,
                      const tek_sc_depot_manifest *_Nonnull source_manifest,
                      const tek_sc_depot_manifest *_Nonnull target_manifest,
                      tek_sc_depot_patch *_Nonnull patch);

/// Free all memory allocated for the patch.
///
/// @param [in, out] patch
///    Pointer to the patch to free.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_dp_free(tek_sc_depot_patch *_Nonnull patch);

//===--- Verification cache functions -------------------------------------===//

/// Create a verification cache for specified manifest.
///
/// @param [in] manifest
///    Pointer to the manifest to initialize verification cache for.
/// @return A verification cache structure initialized for @p manifest.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1)]]
tek_sc_verification_cache
tek_sc_vc_create(const tek_sc_depot_manifest *_Nonnull manifest);

/// Serialize verification cache data into persistent format that is safe to be
///    written to a file.
///
/// @param [in] vcache
///    Pointer to the verification cache to serialize.
/// @param [out] buf
///    Pointer to the buffer that receives serialized verification cache data.
///    Pass `nullptr` to get required buffer size.
/// @param buf_size
///    Size of the buffer pointed to by @p buf, in bytes.
/// @return `0` on success, otherwise the required buffer size to fit all
///    serialized data.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(write_only, 2, 3)]]
int tek_sc_vc_serialize(const tek_sc_verification_cache *_Nonnull vcache,
                        void *_Nullable buf, int buf_size);

/// Deserialize verification cache data from persistent format.
///
/// @param [in] buf
///    Pointer to the buffer containing serialized verification cache data.
/// @param buf_size
///    Number of bytes to read from @p buf.
/// @param [in] manifest
///    Pointer to the manifest that the verification cache was created for.
/// @param [out] vcache
///    Address of variable that receives deserialized verification cache
///    structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3, 4), gnu::access(read_only, 1, 2),
  gnu::access(read_only, 3), gnu::access(write_only, 4)]]
tek_sc_err tek_sc_vc_deserialize(const void *_Nonnull buf, int buf_size,
                                 const tek_sc_depot_manifest *_Nonnull manifest,
                                 tek_sc_verification_cache *_Nonnull vcache);

/// Free all memory allocated for the verification cache.
///
/// @param [in, out] vcache
///    Pointer to the verification cache to free.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_vc_free(tek_sc_verification_cache *_Nonnull vcache);

//===--- Depot delta functions --------------------------------------------===//

/// Compute delta between two manifests, including a patch if provided.
///
/// @param [in] source_manifest
///    Pointer to the manifest to compute changes from.
/// @param [in] target_manifest
///    Pointer to the manifest to compute changes to.
/// @param [in] patch
///    Pointer to the patch to use, if available.
/// @return An initialized depot delta structure.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(read_only, 2), gnu::access(read_only, 3)]]
tek_sc_depot_delta
tek_sc_dd_compute(const tek_sc_depot_manifest *_Nonnull source_manifest,
                  const tek_sc_depot_manifest *_Nonnull target_manifest,
                  const tek_sc_depot_patch *_Nullable patch);

/// Compute delta using data from a verification cache.
///
/// @param [in] vcache
///    Pointer to the verification cache to compute delta from.
/// @return An initialized depot delta structure.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1)]]
tek_sc_depot_delta
tek_sc_dd_compute_from_vc(const tek_sc_verification_cache *_Nonnull vcache);

/// Serialize delta data into persistent format that is safe to be written to a
///    file.
///
/// @param [in] delta
///    Pointer to the delta to serialize.
/// @param [out] buf
///    Pointer to the buffer that receives serialized delta data. Pass
///    `nullptr` to get required buffer size.
/// @param buf_size
///    Size of the buffer pointed to by @p buf, in bytes.
/// @return `0` on success, otherwise the required buffer size to fit all
///    serialized data.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(write_only, 2, 3)]]
int tek_sc_dd_serialize(const tek_sc_depot_delta *_Nonnull delta,
                        void *_Nullable buf, int buf_size);

/// Deserialize delta data from persistent format.
///
/// @param [in] buf
///    Pointer to the buffer containing serialized delta data.
/// @param buf_size
///    Number of bytes to read from @p buf.
/// @param [in] source_manifest
///    Pointer to the source manifest for delta, if delta was computed with it.
/// @param [in] target_manifest
///    Pointer to the source manifest for delta.
/// @param [in] patch
///    Pointer to the patch for delta, if delta was computed with it.
/// @param [out] delta
///    Address of variable that receives deserialized delta structure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 4, 6), gnu::access(read_only, 1, 2),
  gnu::access(read_only, 3), gnu::access(read_only, 4),
  gnu::access(read_only, 5), gnu::access(read_write, 6)]]
tek_sc_err
tek_sc_dd_deserialize(const void *_Nonnull buf, int buf_size,
                      const tek_sc_depot_manifest *_Nullable source_manifest,
                      const tek_sc_depot_manifest *_Nonnull target_manifest,
                      const tek_sc_depot_patch *_Nullable patch,
                      tek_sc_depot_delta *_Nonnull delta);

/// Free all memory allocated for the delta.
///
/// @param [in, out] delta
///    Pointer to the delta to free.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_dd_free(tek_sc_depot_delta *_Nonnull delta);

/// Estimate disk space required to fully process the delta
///
/// @param [in] delta
///    Pointer to the delta to estimate disk space for.
/// @return The estimated disk space requirement, in bytes.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1)]]
int64_t tek_sc_dd_estimate_disk_space(const tek_sc_depot_delta *_Nonnull delta);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
