//===-- error.h - TEK Steam Client error type and function declarations ---===//
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
/// Declarations of error-related types and functions used in TEK Steam Client.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"

//===-- Types -------------------------------------------------------------===//

/// TEK Steam Client error type values.
/// This type identifies the error domain and which fields in
///    @ref tek_sc_err are set, as well as their types. `primary` is set for all
///    error types.
enum tek_sc_err_type {
  /// Library internal error, only `primary` code is set.
  ///    @ref TEK_SC_ERRC_cm_connect also sets `uri` to the URL of the CM
  ///    server. @ref TEK_SC_ERRC_cm_disconnect also sets `extra` to WebSocket
  ///    close code and `uri` to the URL of the CM server.
  TEK_SC_ERR_TYPE_basic,
  /// Compound library internal error with a sub-operation defined by
  ///    `auxiliary` code, which has type @ref tek_sc_errc.
  ///    @ref TEK_SC_ERRC_cm_connect also sets `uri` to the URL of the CM
  ///    server. @ref TEK_SC_ERRC_cm_disconnect also sets `extra` to WebSocket
  ///    close code and `uri` to the URL of the CM server.
  TEK_SC_ERR_TYPE_sub,
  /// Error contained in a Steam CM server response, `auxiliary` code is a
  ///    @ref tek_sc_cm_eresult.
  TEK_SC_ERR_TYPE_steam_cm,
  /// System call error, `auxiliary` code is a @ref tek_sc_os_errc. I/O errors
  ///    also set `extra` to a non-zero @ref tek_sc_err_io_type and `uri` to
  ///    path to the affected file.
  TEK_SC_ERR_TYPE_os,
  /// libcurl-easy interface error, `auxiliary` code is a `CURLcode`. If
  ///    `auxiliary` is `CURLE_HTTP_RETURNED_ERROR`, `extra` is set to the HTTP
  ///    response status code. `uri` may be set to the URL of the failed
  ///    download.
  TEK_SC_ERR_TYPE_curle,
  /// libcurl-multi interface error, `auxiliary` code is a `CURLMcode`.
  TEK_SC_ERR_TYPE_curlm,
  /// SQLite error, `auxiliary` code is an `int` with a `SQLITE_*` value.
  ///    Connection open errors may also set `uri` to the path to the database
  ///    file.
  TEK_SC_ERR_TYPE_sqlite
};
/// @copydoc tek_sc_error_type
typedef enum tek_sc_err_type tek_sc_err_type;

/// TEK Steam Client error codes.
enum tek_sc_errc {
  /// (0) Operation completed successfully.
  TEK_SC_ERRC_ok,
  /// (1) AES decryption error.
  TEK_SC_ERRC_aes_decryption,
  /// (2) Failed to initialize asynchronous I/O context.
  TEK_SC_ERRC_aio_init,
  /// (3) Failed to create an application manager instance.
  TEK_SC_ERRC_am_create,
  /// (4) Failed to insert a database row.
  TEK_SC_ERRC_am_db_insert,
  /// (5) Failed to update a database row.
  TEK_SC_ERRC_am_db_update,
  /// (6) Application manager job I/O error.
  TEK_SC_ERRC_am_io,
  /// (7) The job is already running.
  TEK_SC_ERRC_am_job_alr_running,
  /// (8) Steam didn't provide any manifest ID for this item.
  TEK_SC_ERRC_am_no_man_id,
  /// (9) There is no job for this item.
  TEK_SC_ERRC_am_no_job,
  /// (10) Attempting to start a job for a Steam Workshop item, but no directory
  ///    for such items was provided.
  TEK_SC_ERRC_am_no_ws_dir,
  /// (11) There is already an unifnished job for this item.
  TEK_SC_ERRC_am_unfin_job,
  /// (12) Attempting to uninstall an item with unknown current manifest ID.
  TEK_SC_ERRC_am_uninst_unknown,
  /// (13) Failed to set Steam Workshop item directory.
  TEK_SC_ERRC_am_ws_dir,
  /// (14) Worker thread error.
  TEK_SC_ERRC_am_wt,
  /// (15) Failed to get PICS access token.
  TEK_SC_ERRC_cm_access_token,
  /// (16) PICS access token request has been denied.
  TEK_SC_ERRC_cm_access_token_denied,
  /// (17) There is another incomplete Steam CM authentication session on the
  ///    client.
  TEK_SC_ERRC_cm_another_auth,
  /// (18) Steam CM authentication session failed.
  TEK_SC_ERRC_cm_auth,
  /// (19) Failed to get PICS changes.
  TEK_SC_ERRC_cm_changes,
  /// (20) Failed to establish connection to a Steam CM server.
  TEK_SC_ERRC_cm_connect,
  /// (21) Failed to create a CM client instance.
  TEK_SC_ERRC_cm_create,
  /// (22) Failed to get depot decryption key.
  TEK_SC_ERRC_cm_depot_key,
  /// (23) Failed to get depot patch information.
  TEK_SC_ERRC_cm_depot_patch_info,
  /// (24) Abnormal disconnection from a Steam CM server.
  TEK_SC_ERRC_cm_disconnect,
  /// (25) Failed to get encrypted app ticket.
  TEK_SC_ERRC_cm_enc_app_ticket,
  /// (26) Failed to get account license list.
  TEK_SC_ERRC_cm_licenses,
  /// (27) Missing PICS access token for the app/package.
  TEK_SC_ERRC_cm_missing_token,
  /// (28) Failed to get manifest request code.
  TEK_SC_ERRC_cm_mrc,
  /// (29) CM client is not connected to a server.
  TEK_SC_ERRC_cm_not_connected,
  /// (30) CM client is not signed into an account.
  TEK_SC_ERRC_cm_not_signed_in,
  /// (31) Failed to encrypt account password with the RSA public key.
  TEK_SC_ERRC_cm_pass_encryption,
  /// (32) Failed to get PICS product info.
  TEK_SC_ERRC_cm_product_info,
  /// (33) Failed to get Steam CM server list from the Steam Web API.
  TEK_SC_ERRC_cm_server_list,
  /// (34) Steam Web API returned empty CM server list.
  TEK_SC_ERRC_cm_server_list_empty,
  /// (35) Steam CM server reported itself as unavailable.
  TEK_SC_ERRC_cm_server_unavailable,
  /// (36) Failed to sign into a Steam account.
  TEK_SC_ERRC_cm_sign_in,
  /// (37) Failed to get SteamPipe server list.
  TEK_SC_ERRC_cm_sp_servers,
  /// (38) Got empty SteamPipe server list.
  TEK_SC_ERRC_cm_sp_servers_empty,
  /// (39) Failed to submit Steam Guard code.
  TEK_SC_ERRC_cm_submit_code,
  /// (40) Timed out waiting for response to a message.
  TEK_SC_ERRC_cm_timeout,
  /// (41) Expired Steam authentication token.
  TEK_SC_ERRC_cm_token_expired,
  /// (42) Invalid Steam authentication token.
  TEK_SC_ERRC_cm_token_invalid,
  /// (43) The token is not renewable.
  TEK_SC_ERRC_cm_token_not_renewable,
  /// (44) Failed to renew Steam authentication token.
  TEK_SC_ERRC_cm_token_renew,
  /// (45) Unknown app/package ID.
  TEK_SC_ERRC_cm_unknown_product,
  /// (46) Failed to get Steam Workshop item details.
  TEK_SC_ERRC_cm_ws_details,
  /// (47) Failed to query Steam Workshop items.
  TEK_SC_ERRC_cm_ws_query,
  /// (48) CRC32 checksum mismatch.
  TEK_SC_ERRC_crc_mismatch,
  /// (49) curl_easy_init() returned nullptr.
  TEK_SC_ERRC_curle_init,
  /// (50) curl_multi_init() returned nullptr.
  TEK_SC_ERRC_curlm_init,
  /// (51) curl_url() returned nullptr.
  TEK_SC_ERRC_curl_url,
  /// (52) Failed to deserialize depot delta.
  TEK_SC_ERRC_delta_deserialize,
  /// (53) Provided manifests do not match the ones expected by the delta.
  TEK_SC_ERRC_delta_manifests_mismatch,
  /// (54) Provided patch does not match the one expected by the delta.
  TEK_SC_ERRC_delta_patch_mismatch,
  /// (55) Depot decryption key not found in the cache.
  TEK_SC_ERRC_depot_key_not_found,
  /// (56) GZip decompression error.
  TEK_SC_ERRC_gzip,
  /// (57) Encountered invalid data.
  TEK_SC_ERRC_invalid_data,
  /// (58) Invalid URL was specified.
  TEK_SC_ERRC_invalid_url,
  /// (59) JSON parsing error.
  TEK_SC_ERRC_json_parse,
  /// (60) LZMA decompression error.
  TEK_SC_ERRC_lzma,
  /// (61) Magic number mismatch (data corruption).
  TEK_SC_ERRC_magic_mismatch,
  /// (62) Failed to deserialize depot manifest.
  TEK_SC_ERRC_manifest_deserialize,
  /// (63) Failed to parse depot manifest.
  TEK_SC_ERRC_manifest_parse,
  /// (64) Memory allocation error.
  TEK_SC_ERRC_mem_alloc,
  /// (65) Failed to deserialize depot patch.
  TEK_SC_ERRC_patch_deserialize,
  /// (66) Provided manifests do not match the ones expected by the patch.
  TEK_SC_ERRC_patch_manifests_mismatch,
  /// (67) Failed to parse depot patch.
  TEK_SC_ERRC_patch_parse,
  /// (68) The job has been paused.
  TEK_SC_ERRC_paused,
  /// (69) Failed to deserialize a Protobuf message.
  TEK_SC_ERRC_protobuf_deserialize,
  /// (70) Failed to serialize a Protobuf message.
  TEK_SC_ERRC_protobuf_serialize,
  /// (71) Failed to fetch a tek-s3 server manifest.
  TEK_SC_ERRC_s3c_manifest,
  /// (72) Failed to get manifest request code from a tek-s3 server.
  TEK_SC_ERRC_s3c_mrc,
  /// (73) Failed to establish WebSocket connection to a tek-s3 server.
  TEK_SC_ERRC_s3c_ws_connect,
  /// (74) Abnormal disconnection from a tek-s3 server.
  TEK_SC_ERRC_s3c_ws_disconnect,
  /// (75) Timed out waiting for server response.
  TEK_SC_ERRC_s3c_ws_timeout,
  /// (76) SHA-1 hashing error.
  TEK_SC_ERRC_sha,
  /// (77) Failed to download a chunk from SteamPipe.
  TEK_SC_ERRC_sp_chunk,
  /// (78) Failed to decode a chunk.
  TEK_SC_ERRC_sp_decode,
  /// (79) Failed to create a chunk decoding context.
  TEK_SC_ERRC_sp_dec_ctx,
  /// (80) Failed to download a depot manifest from SteamPipe.
  TEK_SC_ERRC_sp_dm,
  /// (81) Failed to download a depot patch from SteamPipe.
  TEK_SC_ERRC_sp_dp,
  /// (82) There is already a maximum number of active requests on the thread.
  TEK_SC_ERRC_sp_max_reqs,
  /// (83) Failed to create multi downloader.
  TEK_SC_ERRC_sp_multi_dlr,
  /// (84) Unknown chunk compression method.
  TEK_SC_ERRC_sp_unknown_comp,
  /// (85) Item installation is already up to date.
  TEK_SC_ERRC_up_to_date,
  /// (86) Failed to deserialize verification cache.
  TEK_SC_ERRC_vc_deserialize,
  /// (87) Verification cache does not bind to the provided manifest.
  TEK_SC_ERRC_vc_manifest_mismatch,
  /// (88) VDF parsing error.
  TEK_SC_ERRC_vdf_parse,
  /// (89) Failed to start a worker thread.
  TEK_SC_ERRC_wt_start,
  /// (90) Zip extraction error.
  TEK_SC_ERRC_zip,
  /// (91) Zstandard decompression error.
  TEK_SC_ERRC_zstd,
  /// (92) There are no available tek-s3 servers.
  TEK_SC_ERRC_s3c_no_srv,
  /// (93) Failed to get depot decryption key from a tek-s3 server.
  TEK_SC_ERRC_s3c_depot_key,
  /// (94) Failed to get PICS access token from a tek-s3 server.
  TEK_SC_ERRC_s3c_pics_at,
  /// (95) Failed to get CDN auth token.
  TEK_SC_ERRC_cm_cdn_auth_token,
  /// (96) Loaded libcurl version does not support WSS protocol.
  TEK_SC_ERRC_cm_wss_unsupp
};
/// @copydoc tek_sc_errc
typedef enum tek_sc_errc tek_sc_errc;

/// Types of I/O operations that may fail.
enum tek_sc_err_io_type {
  /// Not an I/O operation.
  TEK_SC_ERR_IO_TYPE_none,
  /// Checking for existence of a pathname.
  TEK_SC_ERR_IO_TYPE_check_existence,
  /// Creating or opening a file or directory.
  TEK_SC_ERR_IO_TYPE_open,
  /// Getting type of filesystem entry to determine whether it's file or
  ///    directory.
  TEK_SC_ERR_IO_TYPE_get_type,
  /// Getting file size.
  TEK_SC_ERR_IO_TYPE_get_size,
  /// Truncating a file.
  TEK_SC_ERR_IO_TYPE_truncate,
  /// Reading data from a file.
  TEK_SC_ERR_IO_TYPE_read,
  /// Writing data to a file.
  TEK_SC_ERR_IO_TYPE_write,
  /// Applying flags to a file.
  TEK_SC_ERR_IO_TYPE_apply_flags,
  /// Copying data from a file.
  TEK_SC_ERR_IO_TYPE_copy,
  /// Moving a file or directory.
  TEK_SC_ERR_IO_TYPE_move,
  /// Deleting a file or directory.
  TEK_SC_ERR_IO_TYPE_delete,
  /// Creating a symbolic link.
  TEK_SC_ERR_IO_TYPE_symlink,
  /// Registering a file for asynchronous I/O.
  TEK_SC_ERR_IO_TYPE_aio_reg,
  /// Submitting an asynchronous I/O request.
  TEK_SC_ERR_IO_TYPE_aio_submit,
  /// Waiting for asynchronous I/O completions.
  TEK_SC_ERR_IO_TYPE_aio_wait
};
/// @copydoc tek_sc_err_io_type
typedef enum tek_sc_err_io_type tek_sc_err_io_type;

/// TEK Steam Client error description structure.
typedef struct tek_sc_err tek_sc_err;
/// @copydoc tek_sc_err
struct tek_sc_err {
  // Type of the error. Defines which fields are set.
  tek_sc_err_type type;
  /// Primary error code. Defines the outermost operation that has failed.
  tek_sc_errc primary;
  /// Auxiliary error code, the value and type depend on @ref type.
  int auxiliary;
  /// Extra information value, the value and type depend on @ref type.
  int extra;
  /// May be set by certain errors to provide a file path or a URL, as a
  ///    null-terminated UTF-8 string.
  /// If set, must be freed with `free` after use.
  const char *_Nullable uri;
};

/// Human-readable messages for @ref tek_sc_err fields.
typedef struct tek_sc_err_msgs tek_sc_err_msgs;
/// @copydoc tek_sc_err_msgs
struct tek_sc_err_msgs {
  // Type of the error that the messages were produced for.
  tek_sc_err_type type;
  /// String representation of @ref type.
  const char *_Nonnull type_str;
  /// Message for the primary error code.
  const char *_Nonnull primary;
  /// Message for the auxiliary error code, if the error has one.
  const char *_Nullable auxiliary;
  /// Message for the extra error code, if the error has one.
  const char *_Nullable extra;
  /// Message identifying type of string that `uri` refers to.
  const char *_Nullable uri_type;
};

//===-- Functions ---------------------------------------------------------===//

/// Check whether specified error structure indicates success.
///
/// @param [in] err
///    Pointer to the error structure to examine.
/// @return Value indicating whether @p err indicates success.
[[gnu::nothrow, gnu::nonnull(1), gnu::access(read_only, 1)]]
static inline bool tek_sc_err_success(const tek_sc_err *_Nonnull err) {
  return err->primary == TEK_SC_ERRC_ok;
}

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Get human-readable messages for specified error structure.
///
/// @param [in] err
///    Pointer to the error structure to get messages for.
/// @return A structure containing messages for the error structure fields. It
///    must be released with @ref tek_sc_err_release_msgs after use.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1)]]
tek_sc_err_msgs tek_sc_err_get_msgs(const tek_sc_err *_Nonnull err);

/// Release error messages.
///
/// @param [in, out] err_msgs
///    Pointer to the error messages structure to release.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_err_release_msgs(tek_sc_err_msgs *_Nonnull err_msgs);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
