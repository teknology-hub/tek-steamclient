//===-- zip_api.h - zip extraction API ------------------------------------===//
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
/// Generic API for extracting zip archives, implemented via minizip or
///    minizip-ng based on the build option.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h" // IWYU pragma: keep

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Open a zip archive at specified memory buffer and get uncompressed size of
///    the file stored inside.
///
/// @param [in] data
///    Pointer to the buffer containing zip archive data.
/// @param size
///    Size of the buffer pointed to by @p data, in bytes.
/// @param [out] uncompressed_size
///    Address of variable that on success receives uncompressed size of the
///    file stored in the archive.
/// @return Handle for the archive that should be passed to
///    @ref tsci_zip_read_close, or `nullptr` on failure.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_only, 1, 2),
  gnu::access(write_only, 3)]]
void *_Nullable tsci_zip_open_get_size(const void *_Nonnull data, int size,
                                       int *_Nonnull uncompressed_size);

/// Extract file data from the zip archive and close it.
///
/// @param [in, out] handle
///    Zip archive handle returned by @ref tsci_zip_open_get_size.
/// @param [out] buf
///    Pointer to the buffer that receives the read data.
/// @param size
///    Size of the buffer pointed to by @p data, in bytes.
/// @return Value indicating whether the operation succeeded.
[[gnu::visibility("internal"), gnu::nonnull(1, 2),
  gnu::access(write_only, 2, 3)]]
bool tsci_zip_read_close(void *_Nonnull handle, void *_Nonnull buf, int size);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
