//===-- zip_mzng.c - minizip-ng-based zip extraction API implementation ---===//
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
/// Implementation of zip extraction API based on minizip-ng library.
///
//===----------------------------------------------------------------------===//
#include "zip_api.h"

#include <minizip-ng/mz.h>
#include <minizip-ng/mz_strm_mem.h>
#include <minizip-ng/mz_zip.h>

void *tsci_zip_open_get_size(const void *data, int size,
                             int *uncompressed_size) {
  auto strm = mz_stream_mem_create();
  if (!strm) {
    return nullptr;
  }
  mz_stream_mem_set_buffer(strm, (void *)data, size);
  auto zip = mz_zip_create();
  if (!zip) {
    goto delete_strm;
  }
  if (mz_zip_open(zip, strm, MZ_OPEN_MODE_READ) != MZ_OK) {
    goto delete_zip;
  }
  if (mz_zip_goto_first_entry(zip) != MZ_OK) {
    goto delete_zip;
  }
  if (mz_zip_entry_read_open(zip, 0, nullptr) != MZ_OK) {
    goto delete_zip;
  }
  mz_zip_file *info;
  if (mz_zip_entry_get_info(zip, &info) != MZ_OK) {
    goto delete_zip;
  }
  *uncompressed_size = info->uncompressed_size;
  return zip;
delete_zip:
  mz_zip_delete(&zip);
delete_strm:
  mz_stream_mem_delete(&strm);
  return nullptr;
}

bool tsci_zip_read_close(void *handle, void *buf, int size) {
  const bool res = mz_zip_entry_read(handle, buf, size) == size;
  mz_zip_entry_close(handle);
  mz_zip_close(handle);
  return res;
}
