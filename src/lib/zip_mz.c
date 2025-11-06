//===-- zip_mz.c - minizip-based zip extraction API implementation --------===//
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
/// Implementation of zip extraction API based on minizip library.
///
//===----------------------------------------------------------------------===//
#include "zip_api.h"

#include <minizip/ioapi.h>
#include <minizip/unzip.h>
#include <stdlib.h>
#include <string.h>
#include <zconf.h>

//===-- Private type ------------------------------------------------------===//

/// Zip archive context.
typedef struct tscp_mz_ctx tscp_mz_ctx;
/// @copydoc tscp_mz_ctx
struct tscp_mz_ctx {
  /// minizip file handle.
  unzFile file;
  /// Size of the archive, in bytes.
  ZPOS64_T size;
  /// Current position within the archive.
  ZPOS64_T position;
};

//===-- I/O callbacks for minizip -----------------------------------------===//

[[gnu::returns_nonnull, gnu::nonnull(2)]]
static voidpf ZCALLBACK tscp_mz_open64(voidpf, const void *_Nonnull filename,
                                       int) {
  return (voidpf)filename;
}

[[gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(write_only, 3, 4)]]
static uLong ZCALLBACK tscp_mz_read(voidpf opaque, voidpf stream, void *buf,
                                    uLong size) {
  tscp_mz_ctx *const ctx = opaque;
  uLong n = ctx->size - ctx->position;
  if (size < n) {
    n = size;
  }
  memcpy(buf, stream + ctx->position, n);
  ctx->position += n;
  return n;
}

[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static ZPOS64_T ZCALLBACK tscp_mz_tell64(voidpf opaque, voidpf) {
  return ((const tscp_mz_ctx *)opaque)->position;
}

[[gnu::nonnull(1), gnu::access(read_write, 1)]]
static long ZCALLBACK tscp_mz_seek64(voidpf opaque, voidpf, ZPOS64_T offset,
                                     int origin) {
  tscp_mz_ctx *const ctx = opaque;
  switch (origin) {
  case ZLIB_FILEFUNC_SEEK_SET:
    ctx->position = offset;
    return 0;
  case ZLIB_FILEFUNC_SEEK_CUR:
    ctx->position += offset;
    return 0;
  case ZLIB_FILEFUNC_SEEK_END:
    ctx->position = ctx->size + offset;
    return 0;
  default:
    return -1;
  }
}

static int ZCALLBACK tscp_mz_close(voidpf, voidpf) { return 0; }

static int ZCALLBACK tscp_mz_error(voidpf, voidpf) { return 0; }

//===-- Internal functions ------------------------------------------------===//

void *tsci_zip_open_get_size(const void *data, int size,
                             int *uncompressed_size) {
  tscp_mz_ctx *const ctx = malloc(sizeof *ctx);
  if (!ctx) {
    return nullptr;
  }
  ctx->size = size;
  ctx->position = 0;
  ctx->file =
      unzOpen2_64(data, &(zlib_filefunc64_def){.zopen64_file = tscp_mz_open64,
                                               .zread_file = tscp_mz_read,
                                               .ztell64_file = tscp_mz_tell64,
                                               .zseek64_file = tscp_mz_seek64,
                                               .zclose_file = tscp_mz_close,
                                               .zerror_file = tscp_mz_error,
                                               .opaque = ctx});
  if (!ctx->file) {
    goto free_ctx;
  }
  if (unzGoToFirstFile(ctx->file) != UNZ_OK) {
    goto close_file;
  }
  if (unzOpenCurrentFile(ctx->file) != UNZ_OK) {
    goto close_file;
  }
  unz_file_info64 info;
  if (unzGetCurrentFileInfo64(ctx->file, &info, nullptr, 0, nullptr, 0, nullptr,
                              0) != UNZ_OK) {
    goto close_file;
  }
  *uncompressed_size = info.uncompressed_size;
  return ctx;
close_file:
  unzClose(ctx->file);
free_ctx:
  free(ctx);
  return nullptr;
}

bool tsci_zip_read_close(void *handle, void *buf, int size) {
  tscp_mz_ctx *const ctx = handle;
  const bool res = unzReadCurrentFile(ctx->file, buf, size) == size;
  unzCloseCurrentFile(ctx->file);
  unzClose(ctx->file);
  free(ctx);
  return res;
}
