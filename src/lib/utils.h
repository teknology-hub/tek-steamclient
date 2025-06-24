//===-- utils.h - utility function declarations ---------------------------===//
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
/// Declarations of small utility functions that may be used anywhere in the
///    project.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h" // IWYU pragma: keep

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Decode a Base64 string.
///
/// @param [in] input
///    Pointer to the Base64 string to decode.
/// @param input_len
///    Length of @p input string.
/// @param [out] output
///    Pointer to the buffer that receives decoded data. Caller must ensure that
///    it is large enough, that is its size is at least 3/4 of (@p input_size -
///    number of non-base64 characters).
/// @return The number of bytes written to @p output.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_only, 1, 2),
  gnu::access(write_only, 3)]]
int tsci_u_base64_decode(const char *_Nonnull input, int input_len,
                         unsigned char *_Nonnull output);

/// Encode data into a Base64 string.
///
/// @param [in] input
///    Pointer to the data to encode.
/// @param input_size
///    Number of bytes to read from @p input.
/// @param [out] output
///    Pointer to the buffer that receives the encoded string. Caller must
///    ensure that it is large enough, that is its size is at least (4/3 of
///    @p input_size) rounded to the next multiple of 4.
/// @return The number of characters written to @p output.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_only, 1, 2),
  gnu::access(write_only, 3)]]
int tsci_u_base64_encode(const unsigned char *_Nonnull input, int input_size,
                         char *_Nonnull output);

/// Convert a SHA-1 hash to a string.
///
/// @param [in] hash
///    Pointer to the SHA-1 hash to convert.
/// @param [out] str
///    Pointer to the buffer that receives the resulting string (without
///    terminating null character).
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(write_only, 2)]]
void tsci_u_sha1_to_str(const unsigned char hash[_Nonnull 20],
                        char str[_Nonnull 40]);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
