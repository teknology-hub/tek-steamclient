//===-- s3c.h - tek-s3 client interface -----------------------------------===//
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

/// Start credentials-based authentication session to submit a Steam account to
///    a tek-s3 server. The credentials are sent to the server as plain text, so
///    it's highly recommended to avoid using this authentication method with
///    insecure (non-https) servers.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context that will host the WebSocket connection.
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param [in] account_name
///    Steam account name (login), as a null-terminated UTF-8 string.
/// @param [in] password
///    Steam account password, as a null-terminated UTF-8 string.
/// @param cb
///    Pointer to the function that will be called when authentication session
///    ends or changes its status. `client` will be `nullptr`, `data` will
///    point to a @ref tek_sc_cm_data_auth_polling, and `user_data` will be
///    @p user_data.
/// @param user_data
///    Pointer that will be passed to @p cb.
/// @param timeout_ms
///    The maximum amount of time the session is allowed to take, in
///    milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3, 4, 5), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(read_only, 3),
  gnu::access(read_only, 4), gnu::null_terminated_string_arg(2),
  gnu::null_terminated_string_arg(3), gnu::null_terminated_string_arg(4),
  clang::callback(cb, __, __, __)]]
void tek_sc_s3c_auth_credentials(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                 const char *_Nonnull url,
                                 const char *_Nonnull account_name,
                                 const char *_Nonnull password,
                                 tek_sc_cm_callback_func *_Nonnull cb,
                                 void *_Nullable user_data, long timeout_ms);

/// Start QR code-based authentication session to submit a Steam account to a
///    tek-s3 server.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context that will host the WebSocket connection.
/// @param [in] url
///    tek-s3 server URL, e.g. "https://api.teknology-hub.com/s3", as a
///    null-terminated UTF-8 string.
/// @param cb
///    Pointer to the function that will be called when authentication session
///    ends or changes its status. `client` will be `nullptr`, `data` will
///    point to a @ref tek_sc_cm_data_auth_polling, and `user_data` will be
///    @p user_data.
/// @param user_data
///    Pointer that will be passed to @p cb.
/// @param timeout_ms
///    The maximum amount of time the session is allowed to take, in
///    milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(none, 4),
  gnu::null_terminated_string_arg(2), clang::callback(cb, __, __, __)]]
void tek_sc_s3c_auth_qr(tek_sc_lib_ctx *_Nonnull lib_ctx,
                        const char *_Nonnull url,
                        tek_sc_cm_callback_func *_Nonnull cb,
                        void *_Nullable user_data, long timeout_ms);

/// Submit Steam Guard code for current authentication session.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context running the authentication session.
/// @param code_type
///    Steam Guard confirmation type that the code belongs to.
/// @param [in] code
///    Steam Guard code to submit, as a null-terminated UTF-8 string.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 3), gnu::null_terminated_string_arg(3)]]
void tek_sc_s3c_auth_submit_code(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                 tek_sc_cm_auth_confirmation_type code_type,
                                 const char *_Nonnull code);

/// Terminate current authentication session.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context running the authentication session.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_s3c_auth_cancel(tek_sc_lib_ctx *_Nonnull lib_ctx);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
