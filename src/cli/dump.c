//===-- dump.c - content file dumping implementation ----------------------===//
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
/// Implementation of tek-steamclient content file dumping module.
///
//===----------------------------------------------------------------------===//
#include "dump.h"

#include "common.h"
#include "common/am.h" // IWYU pragma: keep
#include "common/error.h"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

/// Indentation layer string.
static const char tscl_dump_indent[] = "│ ";
/// Connection string.
static const char tscl_dump_conn_str[] = "├─";
/// Last connection string.
static const char tscl_dump_last_conn_str[] = "└─";

//===-- Private type ------------------------------------------------------===//

/// Dump context shared across recursion levels.
typedef struct tscl_dump_ctx tscl_dump_ctx;
/// @copydoc tscl_dump_ctx
struct tscl_dump_ctx {
  /// Pointer to the output file stream.
  FILE *file;
  /// Pointer to the indentation buffer.
  char *_Nonnull indent_buf;
  /// Unit string buffer.
  char unit_buf[32];
};

//===-- Private functions -------------------------------------------------===//

/// Convert a number of bytes to a corresponding unit string.
///
/// @param [out] ctx
///    Pointer to the dump context that will receive the unit string.
/// @param val
///    Number of bytes to convert.
[[gnu::nonnull(1), gnu::access(write_only, 1)]]
static inline void tscl_bytes_to_unit(tscl_dump_ctx *_Nonnull ctx,
                                      int64_t val) {
  if (val >= 0x40000000) { // 1 GiB
    snprintf(ctx->unit_buf, sizeof ctx->unit_buf, tsc_gettext(" (%.2f GiB)"),
             (double)val / 0x40000000);
  } else if (val >= 0x100000) { // 1 MiB
    snprintf(ctx->unit_buf, sizeof ctx->unit_buf, tsc_gettext(" (%.2f MiB)"),
             (double)val / 0x100000);
  } else if (val >= 0x400) { // 1 KiB
    snprintf(ctx->unit_buf, sizeof ctx->unit_buf, tsc_gettext(" (%.2f KiB)"),
             (double)val / 0x400);
  } else {
    ctx->unit_buf[0] = '\0';
  }
}

/// Convert a SHA-1 hash to a null-terminated string.
///
/// @param [in] hash
///    Pointer to the SHA-1 hash to convert.
/// @param [out] str
///    Pointer to the buffer that receives the resulting string.
[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(write_only, 2)]]
static void tscl_sha1_to_str(const unsigned char hash[20], char str[41]) {
  [[gnu::nonstring]] static const char hex_digits[16] = "0123456789ABCDEF";
  // Unrolled loop
  str[0] = hex_digits[hash[0] >> 4];
  str[1] = hex_digits[hash[0] & 0xF];
  str[2] = hex_digits[hash[1] >> 4];
  str[3] = hex_digits[hash[1] & 0xF];
  str[4] = hex_digits[hash[2] >> 4];
  str[5] = hex_digits[hash[2] & 0xF];
  str[6] = hex_digits[hash[3] >> 4];
  str[7] = hex_digits[hash[3] & 0xF];
  str[8] = hex_digits[hash[4] >> 4];
  str[9] = hex_digits[hash[4] & 0xF];
  str[10] = hex_digits[hash[5] >> 4];
  str[11] = hex_digits[hash[5] & 0xF];
  str[12] = hex_digits[hash[6] >> 4];
  str[13] = hex_digits[hash[6] & 0xF];
  str[14] = hex_digits[hash[7] >> 4];
  str[15] = hex_digits[hash[7] & 0xF];
  str[16] = hex_digits[hash[8] >> 4];
  str[17] = hex_digits[hash[8] & 0xF];
  str[18] = hex_digits[hash[9] >> 4];
  str[19] = hex_digits[hash[9] & 0xF];
  str[20] = hex_digits[hash[10] >> 4];
  str[21] = hex_digits[hash[10] & 0xF];
  str[22] = hex_digits[hash[11] >> 4];
  str[23] = hex_digits[hash[11] & 0xF];
  str[24] = hex_digits[hash[12] >> 4];
  str[25] = hex_digits[hash[12] & 0xF];
  str[26] = hex_digits[hash[13] >> 4];
  str[27] = hex_digits[hash[13] & 0xF];
  str[28] = hex_digits[hash[14] >> 4];
  str[29] = hex_digits[hash[14] & 0xF];
  str[30] = hex_digits[hash[15] >> 4];
  str[31] = hex_digits[hash[15] & 0xF];
  str[32] = hex_digits[hash[16] >> 4];
  str[33] = hex_digits[hash[16] & 0xF];
  str[34] = hex_digits[hash[17] >> 4];
  str[35] = hex_digits[hash[17] & 0xF];
  str[36] = hex_digits[hash[18] >> 4];
  str[37] = hex_digits[hash[18] & 0xF];
  str[38] = hex_digits[hash[19] >> 4];
  str[39] = hex_digits[hash[19] & 0xF];
  str[40] = '\0';
}

/// Get the depth of a depot manifest directory tree.
///
/// @param [in] dir
///    Pointer to the root of the manifest directory tree to process.
/// @return Depth of the directory tree.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int tscl_get_dm_dir_depth(const tek_sc_dm_dir *_Nonnull dir) {
  int depth = 0;
  for (int i = 0; i < dir->num_subdirs; ++i) {
    const int subdir_depth = tscl_get_dm_dir_depth(&dir->subdirs[i]);
    if (subdir_depth > depth) {
      depth = subdir_depth;
    }
  }
  return depth + 1;
}

/// Get the depth of a depot delta directory tree.
///
/// @param [in] dir
///    Pointer to the root of the delta directory tree to process.
/// @return Depth of the directory tree.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static int tscl_get_dd_dir_depth(const tek_sc_dd_dir *_Nonnull dir) {
  int depth = 0;
  for (int i = 0; i < dir->num_subdirs; ++i) {
    const int subdir_depth = tscl_get_dd_dir_depth(&dir->subdirs[i]);
    if (subdir_depth > depth) {
      depth = subdir_depth;
    }
  }
  return depth + 1;
}

/// Get string for a delta entry status.
///
/// @param status
///    Status value to get the string for.
/// @return Null-terminated UTF-8 string representing the status.
[[gnu::returns_nonnull]]
static const char *_Nonnull tscl_get_dd_status_str(
    tek_sc_job_entry_status status) {
  switch (status) {
  case TEK_SC_JOB_ENTRY_STATUS_pending:
    return tsc_gettext("Pending");
  case TEK_SC_JOB_ENTRY_STATUS_setup:
    return tsc_gettext("Setting up");
  case TEK_SC_JOB_ENTRY_STATUS_active:
    return tsc_gettext("Processing");
  case TEK_SC_JOB_ENTRY_STATUS_done:
    return tsc_gettext("Done");
  default:
    return tsc_gettext("Unknown status");
  }
}

/// Load a depot manifest from the file.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the manifest belongs to.
/// @param manifest_id
///    ID of the manifest to load.
/// @param [out] manifest
///    Address of variable that receives the manifest on success.
/// @return Value indicating whether the operation succeeded.
[[gnu::nonnull(1, 3), gnu::access(read_only, 1), gnu::access(read_write, 3)]]
static bool tscl_load_manifest(const tek_sc_item_id *_Nonnull item_id,
                               uint64_t manifest_id,
                               tek_sc_depot_manifest *_Nonnull manifest) {
  tek_sc_os_char file_path[66];
  if (item_id->ws_item_id) {
    TSCL_OS_SNPRINTF(
        file_path, sizeof file_path / sizeof *file_path,
        TEK_SC_OS_STR("manifests" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32
                      "-%" PRIx32 "-%" PRIx64 "_%" PRIx64 ".zst"),
        item_id->app_id, item_id->depot_id, item_id->ws_item_id, manifest_id);
  } else {
    TSCL_OS_SNPRINTF(file_path, sizeof file_path / sizeof *file_path,
                     TEK_SC_OS_STR("manifests" TSCL_OS_PATH_SEP_CHAR_STR
                                   "%" PRIx32 "-%" PRIx32 "_%" PRIx64 ".zst"),
                     item_id->app_id, item_id->depot_id, manifest_id);
  }
  auto const file_handle =
      tscl_os_file_open_at(tscl_g_ctx.am->data_dir_handle, file_path);
  if (file_handle == TSCL_OS_INVALID_HANDLE) {
    auto const err =
        tscl_os_io_err_at(tscl_g_ctx.am->data_dir_handle, file_path,
                          TEK_SC_ERRC_manifest_deserialize,
                          tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
    tscl_print_err(&err);
    return false;
  }
  auto const file_size = tscl_os_file_get_size(file_handle);
  if (file_size == SIZE_MAX) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_manifest_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  auto const file_buf = tscl_os_mem_alloc(file_size);
  if (!file_buf) {
    auto const err =
        tscl_err_os(TEK_SC_ERRC_mem_alloc, tscl_os_get_last_error());
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  if (!tscl_os_file_read(file_handle, file_buf, file_size)) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_manifest_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
    tscl_os_mem_free(file_buf, file_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  tscl_os_close_handle(file_handle);
  auto const uncomp_size = ZSTD_getFrameContentSize(file_buf, file_size);
  if (uncomp_size == ZSTD_CONTENTSIZE_UNKNOWN ||
      uncomp_size == ZSTD_CONTENTSIZE_ERROR) {
    tscl_os_mem_free(file_buf, file_size);
    auto const err =
        tsc_err_sub(TEK_SC_ERRC_manifest_deserialize, TEK_SC_ERRC_zstd);
    tscl_print_err(&err);
    return false;
  }
  auto const uncomp_buf = tscl_os_mem_alloc(uncomp_size);
  if (!uncomp_buf) {
    auto const err =
        tscl_err_os(TEK_SC_ERRC_mem_alloc, tscl_os_get_last_error());
    tscl_os_mem_free(file_buf, file_size);
    tscl_print_err(&err);
    return false;
  }
  auto const decomp_res =
      ZSTD_decompress(uncomp_buf, uncomp_size, file_buf, file_size);
  tscl_os_mem_free(file_buf, file_size);
  if (decomp_res != uncomp_size) {
    tscl_os_mem_free(uncomp_buf, uncomp_size);
    auto const err =
        tsc_err_sub(TEK_SC_ERRC_manifest_deserialize, TEK_SC_ERRC_zstd);
    tscl_print_err(&err);
    return false;
  }
  auto const res = tek_sc_dm_deserialize(uncomp_buf, uncomp_size, manifest);
  tscl_os_mem_free(uncomp_buf, uncomp_size);
  if (!tek_sc_err_success(&res)) {
    tscl_print_err(&res);
    return false;
  }
  return true;
}

/// Load a depot patch from the file.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the patch belongs to.
/// @param [in] src_man
///    Pointer to the source manifest.
/// @param [in] tgt_man
///    Pointer to the target manifest.
/// @param [out] patch
///    Address of variable that receives the patch on success.
/// @return Value indicating whether the operation succeeded.
[[gnu::nonnull(1, 2, 3, 4), gnu::access(read_only, 1),
  gnu::access(read_only, 2), gnu::access(read_only, 3),
  gnu::access(write_only, 4)]]
static bool tscl_load_patch(const tek_sc_item_id *_Nonnull item_id,
                            const tek_sc_depot_manifest *_Nonnull src_man,
                            const tek_sc_depot_manifest *_Nonnull tgt_man,
                            tek_sc_depot_patch *_Nonnull patch) {
  tek_sc_os_char file_path[46];
  if (item_id->ws_item_id) {
    TSCL_OS_SNPRINTF(
        file_path, sizeof file_path / sizeof *file_path,
        TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32 "-%" PRIx32
                      "-%" PRIx64 TSCL_OS_PATH_SEP_CHAR_STR "patch"),
        item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  } else {
    TSCL_OS_SNPRINTF(file_path, sizeof file_path / sizeof *file_path,
                     TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32
                                   "-%" PRIx32 TSCL_OS_PATH_SEP_CHAR_STR
                                   "patch"),
                     item_id->app_id, item_id->depot_id);
  }
  auto file_handle =
      tscl_os_file_open_at(tscl_g_ctx.am->data_dir_handle, file_path);
  if (file_handle == TSCL_OS_INVALID_HANDLE) {
    auto const err =
        tscl_os_io_err_at(tscl_g_ctx.am->data_dir_handle, file_path,
                          TEK_SC_ERRC_patch_deserialize,
                          tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
    tscl_print_err(&err);
    return false;
  }
  auto const file_size = tscl_os_file_get_size(file_handle);
  if (file_size == SIZE_MAX) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_patch_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  auto const file_buf = tscl_os_mem_alloc(file_size);
  if (!file_buf) {
    auto const err =
        tscl_err_os(TEK_SC_ERRC_mem_alloc, tscl_os_get_last_error());
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  if (!tscl_os_file_read(file_handle, file_buf, file_size)) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_patch_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
    tscl_os_mem_free(file_buf, file_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  tscl_os_close_handle(file_handle);
  auto const res =
      tek_sc_dp_deserialize(file_buf, file_size, src_man, tgt_man, patch);
  tscl_os_mem_free(file_buf, file_size);
  if (!tek_sc_err_success(&res)) {
    tscl_print_err(&res);
    return false;
  }
  return true;
}

/// Load a verification cache from the file.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the verification cache belongs to.
/// @param [in] manifest
///    Pointer to the manifest that the verification cache was created for.
/// @param [out] vcache
///    Address of variable that receives the verification cache on success.
/// @return Value indicating whether the operation succeeded.
[[gnu::nonnull(1, 2, 3), gnu::access(read_only, 1), gnu::access(read_only, 2),
  gnu::access(write_only, 3)]]
static bool tscl_load_vcache(const tek_sc_item_id *_Nonnull item_id,
                             const tek_sc_depot_manifest *_Nonnull manifest,
                             tek_sc_verification_cache *_Nonnull vcache) {
  tek_sc_os_char file_path[47];
  if (item_id->ws_item_id) {
    TSCL_OS_SNPRINTF(
        file_path, sizeof file_path / sizeof *file_path,
        TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32 "-%" PRIx32
                      "-%" PRIx64 TSCL_OS_PATH_SEP_CHAR_STR "vcache"),
        item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  } else {
    TSCL_OS_SNPRINTF(file_path, sizeof file_path / sizeof *file_path,
                     TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32
                                   "-%" PRIx32 TSCL_OS_PATH_SEP_CHAR_STR
                                   "vcache"),
                     item_id->app_id, item_id->depot_id);
  }
  auto file_handle =
      tscl_os_file_open_at(tscl_g_ctx.am->data_dir_handle, file_path);
  if (file_handle == TSCL_OS_INVALID_HANDLE) {
    auto const err = tscl_os_io_err_at(
        tscl_g_ctx.am->data_dir_handle, file_path, TEK_SC_ERRC_vc_deserialize,
        tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
    tscl_print_err(&err);
    return false;
  }
  auto const file_size = tscl_os_file_get_size(file_handle);
  if (file_size == SIZE_MAX) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_vc_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  auto const file_buf = tscl_os_mem_alloc(file_size);
  if (!file_buf) {
    auto const err =
        tscl_err_os(TEK_SC_ERRC_mem_alloc, tscl_os_get_last_error());
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  if (!tscl_os_file_read(file_handle, file_buf, file_size)) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_vc_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
    tscl_os_mem_free(file_buf, file_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  tscl_os_close_handle(file_handle);
  auto const res = tek_sc_vc_deserialize(file_buf, file_size, manifest, vcache);
  tscl_os_mem_free(file_buf, file_size);
  if (!tek_sc_err_success(&res)) {
    tscl_print_err(&res);
    return false;
  }
  return true;
}

/// Load a depot delta from the file.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the delta belongs to.
/// @param [in] src_man
///    Pointer to the source manifest.
/// @param [in] tgt_man
///    Pointer to the target manifest.
/// @param [in] patch
///    Pointer to the patch.
/// @param [out] delta
///    Address of variable that receives the patch on success.
/// @return Value indicating whether the operation succeeded.
[[gnu::nonnull(1, 3, 5), gnu::access(read_only, 1), gnu::access(read_only, 2),
  gnu::access(read_only, 3), gnu::access(read_only, 4),
  gnu::access(read_write, 5)]]
static bool tscl_load_delta(const tek_sc_item_id *_Nonnull item_id,
                            const tek_sc_depot_manifest *_Nullable src_man,
                            const tek_sc_depot_manifest *_Nonnull tgt_man,
                            const tek_sc_depot_patch *_Nullable patch,
                            tek_sc_depot_delta *_Nonnull delta) {
  tek_sc_os_char file_path[46];
  if (item_id->ws_item_id) {
    TSCL_OS_SNPRINTF(
        file_path, sizeof file_path / sizeof *file_path,
        TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32 "-%" PRIx32
                      "-%" PRIx64 TSCL_OS_PATH_SEP_CHAR_STR "delta"),
        item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  } else {
    TSCL_OS_SNPRINTF(file_path, sizeof file_path / sizeof *file_path,
                     TEK_SC_OS_STR("jobs" TSCL_OS_PATH_SEP_CHAR_STR "%" PRIx32
                                   "-%" PRIx32 TSCL_OS_PATH_SEP_CHAR_STR
                                   "delta"),
                     item_id->app_id, item_id->depot_id);
  }
  auto file_handle =
      tscl_os_file_open_at(tscl_g_ctx.am->data_dir_handle, file_path);
  if (file_handle == TSCL_OS_INVALID_HANDLE) {
    auto const err =
        tscl_os_io_err_at(tscl_g_ctx.am->data_dir_handle, file_path,
                          TEK_SC_ERRC_delta_deserialize,
                          tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_open);
    tscl_print_err(&err);
    return false;
  }
  auto const file_size = tscl_os_file_get_size(file_handle);
  if (file_size == SIZE_MAX) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_delta_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_get_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  auto const file_buf = tscl_os_mem_alloc(file_size);
  if (!file_buf) {
    auto const err =
        tscl_err_os(TEK_SC_ERRC_mem_alloc, tscl_os_get_last_error());
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  if (!tscl_os_file_read(file_handle, file_buf, file_size)) {
    auto const err =
        tscl_os_io_err(file_handle, TEK_SC_ERRC_delta_deserialize,
                       tscl_os_get_last_error(), TEK_SC_ERR_IO_TYPE_read);
    tscl_os_mem_free(file_buf, file_size);
    tscl_os_close_handle(file_handle);
    tscl_print_err(&err);
    return false;
  }
  tscl_os_close_handle(file_handle);
  auto const res = tek_sc_dd_deserialize(file_buf, file_size, src_man, tgt_man,
                                         patch, delta);
  tscl_os_mem_free(file_buf, file_size);
  if (!tek_sc_err_success(&res)) {
    tscl_print_err(&res);
    return false;
  }
  return true;
}

/// Recursively dump a manifest directory entry.
///
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param [in, out] ctx
///    Pointer to the dump context.
/// @param indent
///    Index of the end of parent's indentation string.
[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_write, 2)]]
static void tscl_dump_manifest_dir(const tek_sc_dm_dir *_Nonnull dir,
                                   tscl_dump_ctx *_Nonnull ctx, int indent) {
  fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("Directory"),
          dir->name ? dir->name : TEK_SC_OS_STR("[ROOT]"));
  fprintf(ctx->file, tsc_gettext("(%u files; %u subdirectories)\n"),
          dir->num_files, dir->num_subdirs);
  for (int i = 0; i < dir->num_files; ++i) {
    int file_indent;
    if ((i + 1) < dir->num_files || dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      file_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      file_indent = indent + 2;
    }
    auto const file = &dir->files[i];
    fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("File"),
            file->name);
    tscl_bytes_to_unit(ctx, file->size);
    fprintf(ctx->file, tsc_gettext("(Size: %llu B%s; %u chunks)\n"),
            (unsigned long long)file->size, ctx->unit_buf, file->num_chunks);
    for (int j = 0; j < file->num_chunks; ++j) {
      if ((j + 1) < file->num_chunks) {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_conn_str,
               sizeof tscl_dump_conn_str);
      } else {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_last_conn_str,
               sizeof tscl_dump_last_conn_str);
      }
      auto const chunk = &file->chunks[j];
      char sha[41];
      tscl_sha1_to_str(chunk->sha.bytes, sha);
      fprintf(
          ctx->file,
          tsc_gettext(
              "%sChunk %s (Offset: %llu; Size: %u B; Compressed size: %u B)\n"),
          ctx->indent_buf, sha, (unsigned long long)chunk->offset, chunk->size,
          chunk->comp_size);
    }
  } // for (int i = 0; i < dir->num_files; ++i)
  for (int i = 0; i < dir->num_subdirs; ++i) {
    int subdit_indent;
    if ((i + 1) < dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      subdit_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      subdit_indent = indent + 2;
    }
    tscl_dump_manifest_dir(&dir->subdirs[i], ctx, subdit_indent);
  }
  return;
}

/// Recursively dump a manifest/verification cache directory entry.
///
/// @param [in] vc
///    Pointer to the verification cache to dump.
/// @param [in] dir
///    Pointer to the manifest directory entry to process.
/// @param [in, out] ctx
///    Pointer to the dump context.
/// @param indent
///    Index of the end of parent's indentation string.
[[gnu::nonnull(1, 2, 3), gnu::access(read_only, 1), gnu::access(read_only, 2),
  gnu::access(read_write, 3)]]
static void tscl_dump_vcache_dir(const tek_sc_verification_cache *_Nonnull vc,
                                 const tek_sc_dm_dir *_Nonnull dir,
                                 tscl_dump_ctx *_Nonnull ctx, int indent) {
  fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("Directory"),
          dir->name ? dir->name : TEK_SC_OS_STR("[ROOT]"));
  auto const vc_dir = &vc->dirs[dir - vc->manifest->dirs];
  if (vc_dir->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
    fprintf(ctx->file,
            tsc_gettext("(Not verified yet; Dirty files: %u/%u; Dirty "
                        "subdirectories: %u/%u; Remaining children: %u)\n"),
            vc_dir->num_dirty_files, dir->num_files, vc_dir->num_dirty_subdirs,
            dir->num_subdirs, vc_dir->num_rem_children);
  } else if (vc_dir->num_dirty_subdirs < 0) {
    fprintf(ctx->file, tsc_gettext("(Missing; %u files; %u subdirectories)\n"),
            dir->num_files, dir->num_subdirs);
  } else {
    fprintf(
        ctx->file,
        tsc_gettext(
            "(Verified; Dirty files: %u/%u; Dirty subdirectories: %u/%u)\n"),
        vc_dir->num_dirty_files, dir->num_files, vc_dir->num_dirty_subdirs,
        dir->num_subdirs);
  }
  auto const vc_files = &vc->files[dir->files - vc->manifest->files];
  for (int i = 0; i < dir->num_files; ++i) {
    int file_indent;
    if ((i + 1) < dir->num_files || dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      file_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      file_indent = indent + 2;
    }
    auto const file = &dir->files[i];
    fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("File"),
            file->name);
    auto const vc_file = &vc_files[i];
    if (vc_file->status == TEK_SC_JOB_ENTRY_STATUS_pending) {
      fprintf(ctx->file,
              tsc_gettext("(Not verified yet; Dirty chunks: %u/%u; Remaining "
                          "chunks: %u)\n"),
              vc_file->num_dirty_chunks, file->num_chunks,
              vc_file->num_rem_chunks);
    } else {
      switch (vc_file->file_status) {
      case TEK_SC_VC_FILE_STATUS_regular:
        fprintf(ctx->file, tsc_gettext("(Verified; Dirty chunks: %u/%u)\n"),
                vc_file->num_dirty_chunks, file->num_chunks);
        break;
      case TEK_SC_VC_FILE_STATUS_missing:
        fprintf(ctx->file, tsc_gettext("(Missing; %u chunks)\n"),
                file->num_chunks);
        break;
      case TEK_SC_VC_FILE_STATUS_truncate:
        tscl_bytes_to_unit(ctx, file->size);
        fprintf(ctx->file,
                tsc_gettext("(Verified (truncation to %llu B%s required); "
                            "Dirty chunks: %u/%u)\n"),
                (unsigned long long)file->size, ctx->unit_buf,
                vc_file->num_dirty_chunks, file->num_chunks);
      }
    }
    auto const vc_chunks = &vc->chunks[file->chunks - vc->manifest->chunks];
    for (int j = 0; j < file->num_chunks; ++j) {
      if ((j + 1) < file->num_chunks) {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_conn_str,
               sizeof tscl_dump_conn_str);
      } else {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_last_conn_str,
               sizeof tscl_dump_last_conn_str);
      }
      auto const chunk = &file->chunks[j];
      char sha[41];
      tscl_sha1_to_str(chunk->sha.bytes, sha);
      auto const vc_chunk = &vc_chunks[j];
      fprintf(ctx->file,
              tsc_gettext("%sChunk %s (%s; Offset: %llu; Size: %u B; "
                          "Compressed size: %u B)\n"),
              ctx->indent_buf, sha,
              vc_chunk->status == TEK_SC_JOB_ENTRY_STATUS_pending
                  ? tsc_gettext("Not verified yet")
                  : (vc_chunk->match ? tsc_gettext("Match")
                                     : tsc_gettext("Mismatch")),
              (unsigned long long)chunk->offset, chunk->size, chunk->comp_size);
    }
  } // for (int i = 0; i < dir->num_files; ++i)
  for (int i = 0; i < dir->num_subdirs; ++i) {
    int subdit_indent;
    if ((i + 1) < dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      subdit_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      subdit_indent = indent + 2;
    }
    tscl_dump_vcache_dir(vc, &dir->subdirs[i], ctx, subdit_indent);
  }
  return;
}

/// Recursively dump a delta directory entry.
///
/// @param [in] dir
///    Pointer to the delta directory entry to process.
/// @param [in, out] ctx
///    Pointer to the dump context.
/// @param indent
///    Index of the end of parent's indentation string.
[[gnu::nonnull(1, 2), gnu::access(read_only, 1), gnu::access(read_write, 2)]]
static void tscl_dump_delta_dir(const tek_sc_dd_dir *_Nonnull dir,
                                tscl_dump_ctx *_Nonnull ctx, int indent) {
  fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("Directory"),
          dir->dir->name ? dir->dir->name : TEK_SC_OS_STR("[ROOT]"));
  char flags_str[256];
  flags_str[0] = '\0';
  bool first_flag = true;
  if (dir->flags & TEK_SC_DD_DIR_FLAG_new) {
    first_flag = false;
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("New"), sizeof flags_str);
  }
  if (dir->flags & TEK_SC_DD_DIR_FLAG_delete) {
    if (first_flag) {
      first_flag = false;
    } else {
      tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
    }
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("Delete"), sizeof flags_str);
  }
  if (dir->flags & TEK_SC_DD_DIR_FLAG_children_new) {
    if (first_flag) {
      first_flag = false;
    } else {
      tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
    }
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("Children new"),
                         sizeof flags_str);
  }
  if (dir->flags & TEK_SC_DD_DIR_FLAG_children_download) {
    if (first_flag) {
      first_flag = false;
    } else {
      tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
    }
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("Children download"),
                         sizeof flags_str);
  }
  if (dir->flags & TEK_SC_DD_DIR_FLAG_children_patch) {
    if (first_flag) {
      first_flag = false;
    } else {
      tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
    }
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("Children patch"),
                         sizeof flags_str);
  }
  if (dir->flags & TEK_SC_DD_DIR_FLAG_children_delete) {
    if (first_flag) {
      first_flag = false;
    } else {
      tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
    }
    tscl_os_strlcat_utf8(flags_str, tsc_gettext("Children delete"),
                         sizeof flags_str);
  }
  fprintf(ctx->file, tsc_gettext("(%s; [%s]; %u files; %u subdirectories)\n"),
          tscl_get_dd_status_str(dir->status), flags_str, dir->num_files,
          dir->num_subdirs);
  for (int i = 0; i < dir->num_files; ++i) {
    int file_indent;
    if ((i + 1) < dir->num_files || dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      file_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      file_indent = indent + 2;
    }
    auto const file = &dir->files[i];
    fprintf(ctx->file, "%s \"%" TSCL_OS_PRI_str "\" ", tsc_gettext("File"),
            file->file->name);
    flags_str[0] = '\0';
    first_flag = true;
    if (file->flags & TEK_SC_DD_FILE_FLAG_new) {
      first_flag = false;
      tscl_os_strlcat_utf8(flags_str, tsc_gettext("New"), sizeof flags_str);
    }
    if (file->flags & TEK_SC_DD_FILE_FLAG_download) {
      if (first_flag) {
        first_flag = false;
      } else {
        tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
      }
      tscl_os_strlcat_utf8(flags_str, tsc_gettext("Download"),
                           sizeof flags_str);
    }
    if (file->flags & TEK_SC_DD_FILE_FLAG_patch) {
      if (first_flag) {
        first_flag = false;
      } else {
        tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
      }
      tscl_os_strlcat_utf8(flags_str, tsc_gettext("Patch"), sizeof flags_str);
    }
    if (file->flags & TEK_SC_DD_FILE_FLAG_truncate) {
      if (first_flag) {
        first_flag = false;
      } else {
        tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
      }
      tscl_bytes_to_unit(ctx, file->file->size);
      char buf[64];
      snprintf(buf, sizeof buf, tsc_gettext("Truncate to %llu B%s"),
               (unsigned long long)file->file->size, ctx->unit_buf);
      tscl_os_strlcat_utf8(flags_str, buf, sizeof flags_str);
    }
    if (file->flags & TEK_SC_DD_FILE_FLAG_delete) {
      if (first_flag) {
        first_flag = false;
      } else {
        tscl_os_strlcat_utf8(flags_str, ", ", sizeof flags_str);
      }
      tscl_os_strlcat_utf8(flags_str, tsc_gettext("Delete"), sizeof flags_str);
    }
    fprintf(ctx->file,
            tsc_gettext("(%s; [%s]; %u chunks; %u transfer operations)\n"),
            tscl_get_dd_status_str(file->status), flags_str, file->num_chunks,
            file->num_transfer_ops);
    for (int j = 0; j < file->num_chunks; ++j) {
      if ((j + 1) < file->num_chunks || file->num_transfer_ops) {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_conn_str,
               sizeof tscl_dump_conn_str);
      } else {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_last_conn_str,
               sizeof tscl_dump_last_conn_str);
      }
      auto const chunk = &file->chunks[j];
      auto const dm_chunk = chunk->chunk;
      char sha[41];
      tscl_sha1_to_str(dm_chunk->sha.bytes, sha);
      char cb_str[128];
      if (file->flags & TEK_SC_DD_FILE_FLAG_new) {
        cb_str[0] = '\0';
      } else {
        snprintf(cb_str, sizeof cb_str,
                 tsc_gettext("; Chunk buffer file offset: %llu"),
                 (unsigned long long)chunk->chunk_buf_offset);
      }
      fprintf(ctx->file,
              tsc_gettext("%sChunk %s (%s; Offset: %llu; Size: %u B; "
                          "Compressed size: %u B%s)\n"),
              ctx->indent_buf, sha, tscl_get_dd_status_str(chunk->status),
              (unsigned long long)dm_chunk->offset, dm_chunk->size,
              dm_chunk->comp_size, cb_str);
    }
    for (int j = 0; j < file->num_transfer_ops; ++j) {
      if ((j + 1) < file->num_transfer_ops) {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_conn_str,
               sizeof tscl_dump_conn_str);
      } else {
        memcpy(&ctx->indent_buf[file_indent], tscl_dump_last_conn_str,
               sizeof tscl_dump_last_conn_str);
      }
      auto const transfer_op = &file->transfer_ops[j];
      char tb_str[128];
      if (transfer_op->transfer_buf_offset < 0) {
        tb_str[0] = '\0';
      } else {
        snprintf(tb_str, sizeof tb_str,
                 tsc_gettext("; Transfer buffer file offset: %llu"),
                 (unsigned long long)transfer_op->transfer_buf_offset);
      }
      switch (transfer_op->type) {
      case TEK_SC_DD_TRANSFER_OP_TYPE_reloc:
        tscl_bytes_to_unit(ctx, transfer_op->data.relocation.size);
        fprintf(ctx->file,
                tsc_gettext("%sRelocation (%s; Source offset: %llu; Target "
                            "offset: %llu; Size: %u B%s%s)\n"),
                ctx->indent_buf, tscl_get_dd_status_str(transfer_op->status),
                (unsigned long long)transfer_op->data.relocation.source_offset,
                (unsigned long long)transfer_op->data.relocation.target_offset,
                transfer_op->data.relocation.size, ctx->unit_buf, tb_str);
        break;
      case TEK_SC_DD_TRANSFER_OP_TYPE_patch: {
        char src_sha[41];
        tscl_sha1_to_str(transfer_op->data.patch_chunk->source_chunk->sha.bytes,
                         src_sha);
        char tgt_sha[41];
        tscl_sha1_to_str(transfer_op->data.patch_chunk->target_chunk->sha.bytes,
                         tgt_sha);
        const char *type;
        switch (transfer_op->data.patch_chunk->type) {
        case TEK_SC_DP_CHUNK_TYPE_vzd:
          type = "VZd";
          break;
        case TEK_SC_DP_CHUNK_TYPE_vszd:
          type = "VSZd";
          break;
        default:
          type = "Unknown";
        }
        fprintf(
            ctx->file,
            tsc_gettext(
                "%sPatch %s->%s (%s; Type: %s; Delta chunk size: %u B%s)\n"),
            ctx->indent_buf, src_sha, tgt_sha,
            tscl_get_dd_status_str(transfer_op->status), type,
            transfer_op->data.patch_chunk->delta_chunk_size, tb_str);
      }
      } // switch (transfer_op->type)
    } // for (int j = 0; j < file->num_transfer_ops; ++j)
  } // for (int i = 0; i < dir->num_files; ++i)
  for (int i = 0; i < dir->num_subdirs; ++i) {
    int subdit_indent;
    if ((i + 1) < dir->num_subdirs) {
      memcpy(&ctx->indent_buf[indent], tscl_dump_conn_str,
             sizeof tscl_dump_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], tscl_dump_indent,
             sizeof tscl_dump_indent - 1);
      subdit_indent = indent + sizeof tscl_dump_indent - 1;
    } else {
      memcpy(&ctx->indent_buf[indent], tscl_dump_last_conn_str,
             sizeof tscl_dump_last_conn_str);
      fputs(ctx->indent_buf, ctx->file);
      memcpy(&ctx->indent_buf[indent], "  ", 2);
      subdit_indent = indent + 2;
    }
    tscl_dump_delta_dir(&dir->subdirs[i], ctx, subdit_indent);
  }
  return;
}

//===-- Internal functions ------------------------------------------------===//

bool tscl_dump_manifest(const tek_sc_item_id *item_id, uint64_t manifest_id) {
  tek_sc_depot_manifest manifest = {};
  if (!tscl_load_manifest(item_id, manifest_id, &manifest)) {
    return false;
  }
  char item_id_str[43];
  snprintf(item_id_str, sizeof item_id_str,
           item_id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                               : "%" PRIu32 "-%" PRIu32,
           item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  char file_name[82];
  snprintf(file_name, sizeof file_name, "manifest_%s_%" PRIu64 ".dump.txt",
           item_id_str, manifest_id);
  auto const file = fopen(file_name, "w");
  if (!file) {
    fprintf(stderr, tsc_gettext("Error: failed to open/create file \"%s\"\n"),
            file_name);
    tek_sc_dm_free(&manifest);
    return false;
  }
  tscl_dump_ctx ctx = {
      .file = file,
      .indent_buf = malloc(6 * (tscl_get_dm_dir_depth(manifest.dirs) + 1) + 1)};
  if (!ctx.indent_buf) {
    fputs(tsc_gettext("Error: failed to allocate indentation buffer\n"),
          stderr);
    fclose(file);
    tek_sc_dm_free(&manifest);
    return false;
  }
  tscl_bytes_to_unit(&ctx, manifest.data_size);
  fprintf(file,
          tsc_gettext("Manifest %llu for %s\n"
                      "Total chunks: %u\n"
                      "Total files: %u\n"
                      "Total directories: %u\n"
                      "Total size of listed files: %llu B%s\n\n"
                      "Content tree:\n"),
          (unsigned long long)manifest.id, item_id_str, manifest.num_chunks,
          manifest.num_files, manifest.num_dirs,
          (unsigned long long)manifest.data_size, ctx.unit_buf);
  tscl_dump_manifest_dir(manifest.dirs, &ctx, 0);
  free(ctx.indent_buf);
  fclose(file);
  tek_sc_dm_free(&manifest);
  return true;
}

bool tscl_dump_patch(const tek_sc_item_id *item_id) {
  char item_id_str[43];
  snprintf(item_id_str, sizeof item_id_str,
           item_id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                               : "%" PRIu32 "-%" PRIu32,
           item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  auto const desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, item_id);
  if (!desc) {
    fprintf(stderr,
            tsc_gettext(
                "Error: Application manager doesn't have state for item %s\n"),
            item_id_str);
    return false;
  }
  if (!(desc->status & TEK_SC_AM_ITEM_STATUS_job)) {
    fprintf(stderr,
            tsc_gettext("Error: There is no unfinished job for item %s\n"),
            item_id_str);
    return false;
  }
  if (desc->job.patch_status != TEK_SC_AM_JOB_PATCH_STATUS_used) {
    fprintf(stderr,
            tsc_gettext("Error: There is no patch used for item %s's job\n"),
            item_id_str);
    return false;
  }
  tek_sc_depot_manifest source_manifest;
  if (!tscl_load_manifest(item_id, desc->job.source_manifest_id,
                          &source_manifest)) {
    return false;
  }
  tek_sc_depot_manifest target_manifest;
  if (!tscl_load_manifest(item_id, desc->job.target_manifest_id,
                          &target_manifest)) {
    goto cleanup_source_manifest;
  }
  tek_sc_depot_patch patch;
  if (!tscl_load_patch(item_id, &source_manifest, &target_manifest, &patch)) {
    goto cleanup_target_manifest;
  }
  char file_name[100];
  snprintf(file_name, sizeof file_name,
           "patch_%s_%" PRIu64 "_%" PRIu64 ".dump.txt", item_id_str,
           source_manifest.id, target_manifest.id);
  tscl_dump_ctx ctx;
  ctx.file = fopen(file_name, "w");
  if (!ctx.file) {
    fprintf(stderr, tsc_gettext("Error: failed to open/create file \"%s\"\n"),
            file_name);
    goto cleanup_patch;
  }
  tscl_bytes_to_unit(&ctx, patch.delta_size);
  fprintf(ctx.file,
          tsc_gettext("Patch from manifest %llu to manifest %llu for %s\n"
                      "Total chunks: %u\n"
                      "Total size of delta chunks: %llu B%s\n\n"
                      "Chunks:\n"),
          (unsigned long long)source_manifest.id,
          (unsigned long long)target_manifest.id, item_id_str, patch.num_chunks,
          (unsigned long long)patch.delta_size, ctx.unit_buf);
  for (int i = 0; i < patch.num_chunks; ++i) {
    auto const chunk = &patch.chunks[i];
    char src_sha[41];
    tscl_sha1_to_str(chunk->source_chunk->sha.bytes, src_sha);
    char tgt_sha[41];
    tscl_sha1_to_str(chunk->target_chunk->sha.bytes, tgt_sha);
    const char *type;
    switch (chunk->type) {
    case TEK_SC_DP_CHUNK_TYPE_vzd:
      type = "VZd";
      break;
    case TEK_SC_DP_CHUNK_TYPE_vszd:
      type = "VSZd";
      break;
    default:
      type = "Unknown";
    }
    fprintf(ctx.file,
            tsc_gettext("%s->%s (Type: %s; Delta chunk size: %u B)\n"), src_sha,
            tgt_sha, type, chunk->delta_chunk_size);
  }
  fclose(ctx.file);
  tek_sc_dp_free(&patch);
  tek_sc_dm_free(&target_manifest);
  tek_sc_dm_free(&source_manifest);
  return true;
cleanup_patch:
  tek_sc_dp_free(&patch);
cleanup_target_manifest:
  tek_sc_dm_free(&target_manifest);
cleanup_source_manifest:
  tek_sc_dm_free(&source_manifest);
  return false;
}

bool tscl_dump_vcache(const tek_sc_item_id *item_id) {
  char item_id_str[43];
  snprintf(item_id_str, sizeof item_id_str,
           item_id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                               : "%" PRIu32 "-%" PRIu32,
           item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  auto const desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, item_id);
  if (!desc) {
    fprintf(stderr,
            tsc_gettext(
                "Error: Application manager doesn't have state for item %s\n"),
            item_id_str);
    return false;
  }
  if (!(desc->status & TEK_SC_AM_ITEM_STATUS_job)) {
    fprintf(stderr,
            tsc_gettext("Error: There is no unfinished job for item %s\n"),
            item_id_str);
    return false;
  }
  tek_sc_depot_manifest manifest;
  if (!tscl_load_manifest(item_id, desc->job.target_manifest_id, &manifest)) {
    return false;
  }
  tek_sc_verification_cache vcache;
  if (!tscl_load_vcache(item_id, &manifest, &vcache)) {
    tek_sc_dm_free(&manifest);
    return false;
  }
  char file_name[80];
  snprintf(file_name, sizeof file_name, "vcache_%s_%" PRIu64 ".dump.txt",
           item_id_str, manifest.id);
  auto const file = fopen(file_name, "w");
  if (!file) {
    fprintf(stderr, tsc_gettext("Error: failed to open/create file \"%s\"\n"),
            file_name);
    tek_sc_vc_free(&vcache);
    tek_sc_dm_free(&manifest);
    return false;
  }
  tscl_dump_ctx ctx = {
      .file = file,
      .indent_buf = malloc(6 * (tscl_get_dm_dir_depth(manifest.dirs) + 1) + 1)};
  if (!ctx.indent_buf) {
    fputs(tsc_gettext("Error: failed to allocate indentation buffer\n"),
          stderr);
    fclose(file);
    tek_sc_vc_free(&vcache);
    tek_sc_dm_free(&manifest);
    return false;
  }
  fprintf(file,
          tsc_gettext("Verification cache for manifest %llu for %s\n"
                      "Total chunks in manifest: %u\n"
                      "Total files in manifest: %u\n"
                      "Total directories in manifest: %u\n\n"
                      "Content tree:\n"),
          (unsigned long long)manifest.id, item_id_str, manifest.num_chunks,
          manifest.num_files, manifest.num_dirs);
  tscl_dump_vcache_dir(&vcache, manifest.dirs, &ctx, 0);
  free(ctx.indent_buf);
  fclose(file);
  tek_sc_vc_free(&vcache);
  tek_sc_dm_free(&manifest);
  return false;
}

bool tscl_dump_delta(const tek_sc_item_id *item_id) {
  char item_id_str[43];
  snprintf(item_id_str, sizeof item_id_str,
           item_id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                               : "%" PRIu32 "-%" PRIu32,
           item_id->app_id, item_id->depot_id, item_id->ws_item_id);
  auto const desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, item_id);
  if (!desc) {
    fprintf(stderr,
            tsc_gettext(
                "Error: Application manager doesn't have state for item %s\n"),
            item_id_str);
    return false;
  }
  if (!(desc->status & TEK_SC_AM_ITEM_STATUS_job)) {
    fprintf(stderr,
            tsc_gettext("Error: There is no unfinished job for item %s\n"),
            item_id_str);
    return false;
  }
  tek_sc_depot_manifest source_manifest;
  tek_sc_depot_manifest *src_man_ptr;
  if (desc->job.source_manifest_id) {
    if (!tscl_load_manifest(item_id, desc->job.source_manifest_id,
                            &source_manifest)) {
      return false;
    }
    src_man_ptr = &source_manifest;
  } else {
    src_man_ptr = nullptr;
  }
  tek_sc_depot_manifest target_manifest;
  if (!tscl_load_manifest(item_id, desc->job.target_manifest_id,
                          &target_manifest)) {
    goto cleanup_source_manifest;
  }
  tek_sc_depot_patch patch;
  tek_sc_depot_patch *patch_ptr;
  if (desc->job.patch_status == TEK_SC_AM_JOB_PATCH_STATUS_used) {
    if (!tscl_load_patch(item_id, &source_manifest, &target_manifest, &patch)) {
      goto cleanup_target_manifest;
    }
    patch_ptr = &patch;
  } else {
    patch_ptr = nullptr;
  }
  tek_sc_depot_delta delta;
  if (!tscl_load_delta(item_id, src_man_ptr, &target_manifest, patch_ptr,
                       &delta)) {
    goto cleanup_patch;
  }
  char file_name[100];
  if (src_man_ptr) {
    snprintf(file_name, sizeof file_name,
             "delta_%s_%" PRIu64 "_%" PRIu64 ".dump.txt", item_id_str,
             source_manifest.id, target_manifest.id);
  } else {
    snprintf(file_name, sizeof file_name, "delta_%s_%" PRIu64 ".dump.txt",
             item_id_str, target_manifest.id);
  }
  auto const file = fopen(file_name, "w");
  if (!file) {
    fprintf(stderr, tsc_gettext("Error: failed to open/create file \"%s\"\n"),
            file_name);
    goto cleanup_delta;
  }
  tscl_dump_ctx ctx = {
      .file = file,
      .indent_buf = malloc(6 * (tscl_get_dd_dir_depth(delta.dirs) + 1) + 1)};
  if (!ctx.indent_buf) {
    fputs(tsc_gettext("Error: failed to allocate indentation buffer\n"),
          stderr);
    goto cleanup_file;
  }
  if (src_man_ptr) {
    fprintf(file,
            tsc_gettext("Delta from manifest %llu to manifest %llu for %s\n"
                        "Depot patch used: %s\n"),
            (unsigned long long)source_manifest.id,
            (unsigned long long)target_manifest.id, item_id_str,
            patch_ptr ? tsc_gettext("Yes") : tsc_gettext("No"));
  } else {
    fprintf(file, tsc_gettext("Verification delta for manifest %llu for %s\n"),
            (unsigned long long)target_manifest.id, item_id_str);
  }
  const char *stage_str;
  switch (delta.stage) {
  case TEK_SC_DD_STAGE_downloading:
    stage_str = tsc_gettext("Downloading");
    break;
  case TEK_SC_DD_STAGE_patching:
    stage_str = tsc_gettext("Patching");
    break;
  case TEK_SC_DD_STAGE_installing:
    stage_str = tsc_gettext("Installing");
    break;
  case TEK_SC_DD_STAGE_deleting:
    stage_str = tsc_gettext("Deleting");
    break;
  default:
    stage_str = tsc_gettext("Unknown stage");
  }
  fprintf(file,
          tsc_gettext("Total chunks: %u\n"
                      "Total transfer operations: %u\n"
                      "Total files: %u\n"
                      "Total directories: %u\n"
                      "Current stage: %s\n"
                      "Total deletions: %u\n"),
          delta.num_chunks, delta.num_transfer_ops, delta.num_files,
          delta.num_dirs, stage_str, delta.num_deletions);
  tscl_bytes_to_unit(&ctx, delta.transfer_buf_size);
  fprintf(file, tsc_gettext("RAM transfer buffer size: %u B%s\n"),
          delta.transfer_buf_size, ctx.unit_buf);
  tscl_bytes_to_unit(&ctx, delta.download_size);
  fprintf(file, tsc_gettext("Total download size: %llu B%s\n"),
          (unsigned long long)delta.download_size, ctx.unit_buf);
  tscl_bytes_to_unit(&ctx, delta.patching_size);
  fprintf(file, tsc_gettext("Total patching read/write size: %llu B%s\n"),
          (unsigned long long)delta.patching_size, ctx.unit_buf);
  tscl_bytes_to_unit(&ctx, delta.total_file_growth);
  fprintf(file, tsc_gettext("Total file growth: %llu B%s\n"),
          (unsigned long long)delta.total_file_growth, ctx.unit_buf);
  tscl_dump_delta_dir(delta.dirs, &ctx, 0);
  fclose(ctx.file);
  tek_sc_dp_free(&patch);
  tek_sc_dm_free(&target_manifest);
  tek_sc_dm_free(&source_manifest);
  return true;
cleanup_file:
  fclose(file);
cleanup_delta:
  tek_sc_dd_free(&delta);
cleanup_patch:
  if (patch_ptr) {
    tek_sc_dp_free(&patch);
  }
cleanup_target_manifest:
  tek_sc_dm_free(&target_manifest);
cleanup_source_manifest:
  if (src_man_ptr) {
    tek_sc_dm_free(&source_manifest);
  }
  return false;
}
