//===-- s3c.h - tek-s3 client interface -----------------------------------===//
//
// Copyright (c) 2025-2026 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Declarations of functions for interacting with tek-s3 servers.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"
#include "cm.h"
#include "error.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Download/update tek-s3 server manifest. This will save to library's cache
///    depot decryption keys provided by the server and the information on
///    which apps/depots it can provide manifest request codes for.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context that receives the manifest data.
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
tek_sc_err tek_sc_s3c_sync_manifest(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                    const char *_Nonnull url, long timeout_ms);

/// Remove specified tek-s3 server from library context's cache.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to remove server from.
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
void tek_sc_s3c_remove_server(tek_sc_lib_ctx *_Nonnull lib_ctx,
                              const char *_Nonnull url);

/// Get URL of a tek-s3 server that can provide manifest request codes for
///    specified app/depot.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to search in.
/// @param app_id
///    ID of the application that the depot belongs to.
/// @param depot_id
///    ID of the depot to search a server for.
/// @return URL of a tek-s3 server, as a null-terminated UTF-8 string, if found
///    in library context's cache, otherwise `nullptr`. The pointer stays valid
///    until @p lib_ctx is destroyed, and should not be freed.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1)]]
const char *_Nullable tek_sc_s3c_get_srv_for_mrc(
    tek_sc_lib_ctx *_Nonnull lib_ctx, uint32_t app_id, uint32_t depot_id);

/// Get manifest request code from a tek-s3 server.
///
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param [in, out] data
///    Pointer to the request/response data.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_only, 1),
  gnu::access(read_write, 3), gnu::null_terminated_string_arg(1)]]
void tek_sc_s3c_get_mrc(const char *_Nonnull url, long timeout_ms,
                        tek_sc_cm_data_mrc *_Nonnull data);

/// Get depot decryption key from a tek-s3 server.
///
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param depot_id
///    ID of the depot to get decryption key for.
/// @param [out] key
///    Address of variable that receives decryption key on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 4), gnu::access(read_only, 1),
  gnu::access(write_only, 4), gnu::null_terminated_string_arg(1)]]
tek_sc_err tek_sc_s3c_get_depot_key(const char *_Nonnull url, long timeout_ms,
                                    uint32_t depot_id,
                                    tek_sc_aes256_key _Nonnull key);

/// Get PICS access token from a tek-s3 server.
///
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param app_id
///    ID of the application to get PICS access token for.
/// @param [out] token
///    Address of variable that receives access token on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 4), gnu::access(read_only, 1),
  gnu::access(write_only, 4), gnu::null_terminated_string_arg(1)]]
tek_sc_err tek_sc_s3c_get_pics_at(const char *_Nonnull url, long timeout_ms,
                                  uint32_t app_id, uint64_t *_Nonnull token);

/// Get manifest request code from tek-s3 servers known by speicifed library
///    context. This function may try every available tek-s3 server until it
///    succeeds.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to use tek-s3 server cache from.
/// @param timeout_ms
///    Timeout for requests, in milliseconds. It applies to each tek-s3 server
///    independently.
/// @param [in, out] data
///    Pointer to the request/response data.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 3)]]
void tek_sc_s3c_ctx_get_mrc(tek_sc_lib_ctx *_Nonnull lib_ctx, long timeout_ms,
                            tek_sc_cm_data_mrc *_Nonnull data);

/// Get depot decryption key from tek-s3u servers known by speicifed library
///    context. This function may try every available tek-s3u server until it
///    succeeds.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to use tek-s3u server cache from.
/// @param timeout_ms
///    Timeout for requests, in milliseconds. It applies to each tek-s3u server
///    independently.
/// @param depot_id
///    ID of the depot to get decryption key for.
/// @param [out] key
///    Address of variable that receives decryption key on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 4), gnu::access(read_write, 1),
  gnu::access(read_write, 4)]]
tek_sc_err tek_sc_s3c_ctx_get_depot_key(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                        long timeout_ms, uint32_t depot_id,
                                        tek_sc_aes256_key _Nonnull key);

/// Get PICS access token from tek-s3u servers known by speicifed library
///    context. This function may try every available tek-s3u server until it
///    succeeds.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to use tek-s3u server cache from.
/// @param timeout_ms
///    Timeout for requests, in milliseconds. It applies to each tek-s3u server
///    independently.
/// @param app_id
///    ID of the application to get PICS access token for.
/// @param [out] token
///    Address of variable that receives access token on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 4), gnu::access(read_write, 1),
  gnu::access(read_write, 4)]]
tek_sc_err tek_sc_s3c_ctx_get_pics_at(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                      long timeout_ms, uint32_t app_id,
                                      uint64_t *_Nonnull token);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
