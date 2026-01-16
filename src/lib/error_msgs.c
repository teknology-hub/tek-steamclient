//===-- error_msgs.c - error message getters implementation ---------------===//
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
/// Implementation of @ref tek_sc_err_get_msgs and @ref tek_sc_err_release_msgs.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/error.h"

#include "config.h" // IWYU pragma: keep
#include "os.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/cm.h"
#include "ws_close_code.h"

#include <curl/curl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef TEK_SCB_GETTEXT
#include <libintl.h>

[[gnu::returns_nonnull, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]] static inline const char
    *_Nonnull tsc_gettext(const char *_Nonnull msg) {
  return dgettext("tek-steamclient", msg);
}

#else // def TEK_SCB_GETTEXT

#define tsc_gettext(msg) msg

#endif // def TEK_SCB_GETTEXT else

//===-- Private functions -------------------------------------------------===//

/// Get the message for specified @ref tek_sc_errc value.
///
/// @param errc
///    Error code to get the message for.
/// @return Human-readable message for @p errc, as a statically allocated
///    null-terminated UTF-8 string.
[[gnu::returns_nonnull]]
static inline const char *tscp_msg_errc(tek_sc_errc errc) {
  switch (errc) {
  case TEK_SC_ERRC_ok:
    return tsc_gettext("Operation completed successfully");
  case TEK_SC_ERRC_aes_decryption:
    return tsc_gettext("AES decryption error");
  case TEK_SC_ERRC_aio_init:
    return tsc_gettext("Failed to initialize asynchronous I/O context");
  case TEK_SC_ERRC_am_create:
    return tsc_gettext("Failed to create an application manager instance");
  case TEK_SC_ERRC_am_db_insert:
    return tsc_gettext("Failed to insert a database row");
  case TEK_SC_ERRC_am_db_update:
    return tsc_gettext("Failed to update a database row");
  case TEK_SC_ERRC_am_io:
    return tsc_gettext("Application manager job I/O error");
  case TEK_SC_ERRC_am_job_alr_running:
    return tsc_gettext("The job is already running");
  case TEK_SC_ERRC_am_no_man_id:
    return tsc_gettext("Steam didn't provide any manifest ID for this item");
  case TEK_SC_ERRC_am_no_job:
    return tsc_gettext("There is no job for this item");
  case TEK_SC_ERRC_am_no_ws_dir:
    return tsc_gettext(
        "Attempting to start a job for a Steam Workshop item, but no "
        "directory for such items was provided");
  case TEK_SC_ERRC_am_unfin_job:
    return tsc_gettext("There is already an unifnished job for this item");
  case TEK_SC_ERRC_am_uninst_unknown:
    return tsc_gettext(
        "Attempting to uninstall an item with unknown current manifest ID");
  case TEK_SC_ERRC_am_ws_dir:
    return tsc_gettext("Failed to set Steam Workshop item directory");
  case TEK_SC_ERRC_am_wt:
    return tsc_gettext("Worker thread error");
  case TEK_SC_ERRC_cm_access_token:
    return tsc_gettext("Failed to get PICS access token");
  case TEK_SC_ERRC_cm_access_token_denied:
    return tsc_gettext("PICS access token request has been denied");
  case TEK_SC_ERRC_cm_another_auth:
    return tsc_gettext(
        "There is another incomplete authentication session on the client");
  case TEK_SC_ERRC_cm_auth:
    return tsc_gettext("Steam CM authenticaiton session failed");
  case TEK_SC_ERRC_cm_changes:
    // L18N: PICS is an acronym that should not be translated
    return tsc_gettext("Failed to get PICS changes");
  case TEK_SC_ERRC_cm_connect:
    return tsc_gettext("Failed to connect to a Steam CM server");
  case TEK_SC_ERRC_cm_create:
    return tsc_gettext("Failed to create a CM client instance");
  case TEK_SC_ERRC_cm_depot_key:
    return tsc_gettext("Failed to get depot decryption key");
  case TEK_SC_ERRC_cm_depot_patch_info:
    return tsc_gettext("Failed to get depot patch information");
  case TEK_SC_ERRC_cm_disconnect:
    return tsc_gettext("Abnormal disconnection from a Steam CM server");
  case TEK_SC_ERRC_cm_enc_app_ticket:
    return tsc_gettext("Failed to get encrypted app ticket");
  case TEK_SC_ERRC_cm_licenses:
    return tsc_gettext("Failed to get account license list");
  case TEK_SC_ERRC_cm_missing_token:
    return tsc_gettext("Missing PICS access token");
  case TEK_SC_ERRC_cm_mrc:
    return tsc_gettext("Failed to get manifest request code");
  case TEK_SC_ERRC_cm_not_connected:
    return tsc_gettext("Not connected to a server");
  case TEK_SC_ERRC_cm_not_signed_in:
    return tsc_gettext("Not signed into an account");
  case TEK_SC_ERRC_cm_pass_encryption:
    return tsc_gettext("Failed to encrypt account password");
  case TEK_SC_ERRC_cm_product_info:
    return tsc_gettext("Failed to get PICS product information");
  case TEK_SC_ERRC_cm_server_list:
    return tsc_gettext("Failed to fetch Steam CM server list");
  case TEK_SC_ERRC_cm_server_list_empty:
    return tsc_gettext("Got empty server list");
  case TEK_SC_ERRC_cm_server_unavailable:
    return tsc_gettext("Server unavailable");
  case TEK_SC_ERRC_cm_sign_in:
    return tsc_gettext("Failed to sign into a Steam account");
  case TEK_SC_ERRC_cm_sp_servers:
    // L18N: "SteamPipe" should not be translated
    return tsc_gettext("Failed to get SteamPipe server list");
  case TEK_SC_ERRC_cm_sp_servers_empty:
    return tsc_gettext("Got empty SteamPipe server list");
  case TEK_SC_ERRC_cm_submit_code:
    return tsc_gettext("Failed to submit Steam Guard code");
  case TEK_SC_ERRC_cm_timeout:
    return tsc_gettext("Timed out waiting for server response");
  case TEK_SC_ERRC_cm_token_expired:
    return tsc_gettext("The authentication token has expired");
  case TEK_SC_ERRC_cm_token_invalid:
    return tsc_gettext("Invalid authentication token");
  case TEK_SC_ERRC_cm_token_not_renewable:
    return tsc_gettext("The token is not renewable");
  case TEK_SC_ERRC_cm_token_renew:
    return tsc_gettext("Failed to renew Steam authentication token");
  case TEK_SC_ERRC_cm_unknown_product:
    return tsc_gettext("Unknown app/package ID");
  case TEK_SC_ERRC_cm_ws_details:
    return tsc_gettext("Failed to get Steam Workshop item details");
  case TEK_SC_ERRC_cm_ws_query:
    return tsc_gettext("Failed to query Steam Workshop items");
  case TEK_SC_ERRC_crc_mismatch:
    return tsc_gettext("CRC32 checksum mismatch");
  case TEK_SC_ERRC_curle_init:
    // L18N: "curl easy/multi/URL" are API names that should not be translated
    return tsc_gettext("Failed to initialize curl easy handle");
  case TEK_SC_ERRC_curlm_init:
    return tsc_gettext("Failed to initialize curl multi handle");
  case TEK_SC_ERRC_curl_url:
    return tsc_gettext("Failed to initialize curl URL handle");
  case TEK_SC_ERRC_delta_deserialize:
    return tsc_gettext("Depot delta deserialization error");
  case TEK_SC_ERRC_delta_manifests_mismatch:
    return tsc_gettext(
        "Provided manifests do not match the ones expected by the delta");
  case TEK_SC_ERRC_delta_patch_mismatch:
    return tsc_gettext(
        "Provided patch does not match the one expected by the delta");
  case TEK_SC_ERRC_depot_key_not_found:
    return tsc_gettext("Depot decryption key not found in the cache");
  case TEK_SC_ERRC_gzip:
    return tsc_gettext("GZip decompression failure");
  case TEK_SC_ERRC_invalid_data:
    return tsc_gettext("Encountered invalid data");
  case TEK_SC_ERRC_invalid_url:
    return tsc_gettext("Invalid URL was specified");
  case TEK_SC_ERRC_json_parse:
    return tsc_gettext("JSON parsing error");
  case TEK_SC_ERRC_lzma:
    return tsc_gettext("LZMA decompression failure");
  case TEK_SC_ERRC_magic_mismatch:
    return tsc_gettext("Magic number mismatch");
  case TEK_SC_ERRC_manifest_deserialize:
    return tsc_gettext("Depot manifest deserialization error");
  case TEK_SC_ERRC_manifest_parse:
    return tsc_gettext("Depot manifest parsing error");
  case TEK_SC_ERRC_mem_alloc:
    return tsc_gettext("Memory allocation error");
  case TEK_SC_ERRC_patch_deserialize:
    return tsc_gettext("Depot patch deserialization error");
  case TEK_SC_ERRC_protobuf_deserialize:
    return tsc_gettext("Protobuf deserialization failure");
  case TEK_SC_ERRC_protobuf_serialize:
    return tsc_gettext("Protobuf serialization failure");
  case TEK_SC_ERRC_patch_manifests_mismatch:
    return tsc_gettext(
        "Provided manifests do not match the ones expected by the patch");
  case TEK_SC_ERRC_patch_parse:
    return tsc_gettext("Depot patch parsing error");
  case TEK_SC_ERRC_paused:
    return tsc_gettext("The job has been paused");
  case TEK_SC_ERRC_s3c_manifest:
    return tsc_gettext("Failed to fetch tek-s3 server manifest");
  case TEK_SC_ERRC_s3c_mrc:
    return tsc_gettext(
        "Failed to get manifest request code from tek-s3 server");
  case TEK_SC_ERRC_s3c_ws_connect:
    return tsc_gettext(
        "Failed to establish WebSocket connection to the tek-s3 server");
  case TEK_SC_ERRC_s3c_ws_disconnect:
    return tsc_gettext("Abnormal disconnection from the tek-s3 server");
  case TEK_SC_ERRC_s3c_ws_timeout:
    return tsc_gettext("Timed out waiting for server response");
  case TEK_SC_ERRC_sha:
    return tsc_gettext("SHA-1 hashing error");
  case TEK_SC_ERRC_sp_chunk:
    return tsc_gettext("Failed to download chunk from SteamPipe");
  case TEK_SC_ERRC_sp_decode:
    return tsc_gettext("Failed to decode chunk");
  case TEK_SC_ERRC_sp_dec_ctx:
    return tsc_gettext("Failed to create a chunk decoding context");
  case TEK_SC_ERRC_sp_dm:
    return tsc_gettext("Failed to download depot manifest from SteamPipe");
  case TEK_SC_ERRC_sp_dp:
    return tsc_gettext("Failed to download depot patch from SteamPipe");
  case TEK_SC_ERRC_sp_max_reqs:
    return tsc_gettext(
        "There is already a maximum number of active requests on the thread");
  case TEK_SC_ERRC_sp_multi_dlr:
    return tsc_gettext("Failed to create SteamPipe multi downloader");
  case TEK_SC_ERRC_sp_unknown_comp:
    return tsc_gettext("Unknown chunk compression method");
  case TEK_SC_ERRC_up_to_date:
    return tsc_gettext("Item installation is already up to date");
  case TEK_SC_ERRC_vc_deserialize:
    return tsc_gettext("Verification cache deserialization error");
  case TEK_SC_ERRC_vc_manifest_mismatch:
    return tsc_gettext(
        "Verification cache does not bind to the provided manifest");
  case TEK_SC_ERRC_vdf_parse:
    return tsc_gettext("VDF parsing error");
  case TEK_SC_ERRC_wt_start:
    return tsc_gettext("Failed to start a worker thread");
  case TEK_SC_ERRC_zip:
    return tsc_gettext("Zip extraction failure");
  case TEK_SC_ERRC_zstd:
    return tsc_gettext("Zstandard decompression failure");
  case TEK_SC_ERRC_s3c_no_srv:
    return tsc_gettext("There are no available tek-s3 servers");
  case TEK_SC_ERRC_s3c_depot_key:
    return tsc_gettext("Failed to get depot decryption key from tek-s3 server");
  case TEK_SC_ERRC_s3c_pics_at:
    return tsc_gettext("Failed to get PICS access token from tek-s3 server");
  default:
    return tsc_gettext("Unknown");
  } // switch (errc)
}

/// Get the message for specified @ref tek_sc_cm_eresult value.
///
/// @param eresult
///    EResult code to get the message for.
/// @return Hhuman-readable message for @p eresult, as a statically allocated
///    null-terminated UTF-8 string.
[[gnu::returns_nonnull]]
static inline const char *tscp_msg_eresult(tek_sc_cm_eresult eresult) {
  switch (eresult) {
  case TEK_SC_CM_ERESULT_invalid:
    return tsc_gettext("Invalid EResult value");
  case TEK_SC_CM_ERESULT_ok:
    return tsc_gettext("OK");
  case TEK_SC_CM_ERESULT_fail:
    return tsc_gettext("Failure");
  case TEK_SC_CM_ERESULT_no_connection:
    return tsc_gettext("No connection");
  case TEK_SC_CM_ERESULT_invalid_password:
    return tsc_gettext("Invalid password");
  case TEK_SC_CM_ERESULT_logged_in_elsewhere:
    return tsc_gettext("Already logged in elsewhere");
  case TEK_SC_CM_ERESULT_invalid_protocol_ver:
    return tsc_gettext("Invalid protocol version");
  case TEK_SC_CM_ERESULT_invalid_param:
    return tsc_gettext("Invalid parameter");
  case TEK_SC_CM_ERESULT_file_not_found:
    return tsc_gettext("File not found");
  case TEK_SC_CM_ERESULT_busy:
    return tsc_gettext("Busy");
  case TEK_SC_CM_ERESULT_invalid_state:
    return tsc_gettext("Invalid state");
  case TEK_SC_CM_ERESULT_invalid_name:
    return tsc_gettext("Invalid name");
  case TEK_SC_CM_ERESULT_invalid_email:
    return tsc_gettext("Invalid email address");
  case TEK_SC_CM_ERESULT_duplicate_name:
    return tsc_gettext("Duplicate name");
  case TEK_SC_CM_ERESULT_access_denied:
    return tsc_gettext("Access denied");
  case TEK_SC_CM_ERESULT_timeout:
    return tsc_gettext("Timeout");
  case TEK_SC_CM_ERESULT_banned:
    return tsc_gettext("Banned");
  case TEK_SC_CM_ERESULT_account_not_found:
    return tsc_gettext("Account not found");
  case TEK_SC_CM_ERESULT_invalid_steam_id:
    return tsc_gettext("Invalid Steam ID");
  case TEK_SC_CM_ERESULT_service_unavailable:
    return tsc_gettext("Service unavailable");
  case TEK_SC_CM_ERESULT_not_logged_on:
    return tsc_gettext("Not logged on");
  case TEK_SC_CM_ERESULT_pending:
    return tsc_gettext("Pending");
  case TEK_SC_CM_ERESULT_encryption_failure:
    return tsc_gettext("Encryption failure");
  case TEK_SC_CM_ERESULT_insufficient_privilege:
    return tsc_gettext("Insufficient privilege");
  case TEK_SC_CM_ERESULT_limit_exceeded:
    return tsc_gettext("Limit exceeded");
  case TEK_SC_CM_ERESULT_revoked:
    return tsc_gettext("Revoked");
  case TEK_SC_CM_ERESULT_expired:
    return tsc_gettext("Expired");
  case TEK_SC_CM_ERESULT_already_redeemed:
    return tsc_gettext("Already redeemed");
  case TEK_SC_CM_ERESULT_duplicate_request:
    return tsc_gettext("Duplicate request");
  case TEK_SC_CM_ERESULT_already_owned:
    return tsc_gettext("Already owned");
  case TEK_SC_CM_ERESULT_ip_not_found:
    return tsc_gettext("IP not found");
  case TEK_SC_CM_ERESULT_persist_failed:
    return tsc_gettext("Persist failed");
  case TEK_SC_CM_ERESULT_locking_failed:
    return tsc_gettext("Locking failed");
  case TEK_SC_CM_ERESULT_logon_session_replaced:
    return tsc_gettext("Logon session replaced");
  case TEK_SC_CM_ERESULT_connect_failed:
    return tsc_gettext("Connect failed");
  case TEK_SC_CM_ERESULT_handshake_failed:
    return tsc_gettext("Handshake failed");
  case TEK_SC_CM_ERESULT_io_failure:
    return tsc_gettext("I/O failure");
  case TEK_SC_CM_ERESULT_remote_disconnect:
    return tsc_gettext("Remote disconnect");
  case TEK_SC_CM_ERESULT_shopping_cart_not_found:
    return tsc_gettext("Shopping cart not found");
  case TEK_SC_CM_ERESULT_blocked:
    return tsc_gettext("Blocked");
  case TEK_SC_CM_ERESULT_ignored:
    return tsc_gettext("Ignored");
  case TEK_SC_CM_ERESULT_no_match:
    return tsc_gettext("No match");
  case TEK_SC_CM_ERESULT_account_disabled:
    return tsc_gettext("Account disabled");
  case TEK_SC_CM_ERESULT_service_read_only:
    return tsc_gettext("Service read-only");
  case TEK_SC_CM_ERESULT_account_not_featured:
    return tsc_gettext("Account not featured");
  case TEK_SC_CM_ERESULT_administrator_ok:
    return tsc_gettext("Administrator OK");
  case TEK_SC_CM_ERESULT_content_version:
    return tsc_gettext("Content version");
  case TEK_SC_CM_ERESULT_try_another_cm:
    return tsc_gettext("Try another Steam CM server");
  case TEK_SC_CM_ERESULT_password_required_to_kick_session:
    return tsc_gettext("Password required to kick session");
  case TEK_SC_CM_ERESULT_already_logged_in_elsewhere:
    return tsc_gettext("Already logged in elsewhere");
  case TEK_SC_CM_ERESULT_suspended:
    return tsc_gettext("Suspended");
  case TEK_SC_CM_ERESULT_cancelled:
    return tsc_gettext("Cancelled");
  case TEK_SC_CM_ERESULT_data_corruption:
    return tsc_gettext("Data corruption");
  case TEK_SC_CM_ERESULT_disk_full:
    return tsc_gettext("Disk full");
  case TEK_SC_CM_ERESULT_remote_call_failed:
    return tsc_gettext("Remote call failed");
  case TEK_SC_CM_ERESULT_password_unset:
    return tsc_gettext("Password unset");
  case TEK_SC_CM_ERESULT_external_account_unlinked:
    return tsc_gettext("External account unlinked");
  case TEK_SC_CM_ERESULT_psn_ticket_invalid:
    return tsc_gettext("PSN ticket invalid");
  case TEK_SC_CM_ERESULT_external_account_already_linked:
    return tsc_gettext("External account already linked");
  case TEK_SC_CM_ERESULT_remote_file_conflict:
    return tsc_gettext("Remote file conflict");
  case TEK_SC_CM_ERESULT_illegal_password:
    return tsc_gettext("Illegal password");
  case TEK_SC_CM_ERESULT_same_as_previous_value:
    return tsc_gettext("Same as previous value");
  case TEK_SC_CM_ERESULT_account_logon_denied:
    return tsc_gettext("Account logon denied");
  case TEK_SC_CM_ERESULT_cannot_use_old_password:
    return tsc_gettext("Cannot use old password");
  case TEK_SC_CM_ERESULT_invalid_login_auth_code:
    return tsc_gettext("Invalid login auth code");
  case TEK_SC_CM_ERESULT_account_logon_denied_no_mail:
    return tsc_gettext("Account logon denied, no mail");
  case TEK_SC_CM_ERESULT_hardware_not_capable_of_ipt:
    return tsc_gettext("Hardware not capable of IPT");
  case TEK_SC_CM_ERESULT_ipt_init_error:
    return tsc_gettext("IPT initialization error");
  case TEK_SC_CM_ERESULT_parental_control_restricted:
    return tsc_gettext("Parental control restricted");
  case TEK_SC_CM_ERESULT_facebook_query_error:
    return tsc_gettext("Facebook query error");
  case TEK_SC_CM_ERESULT_expired_login_auth_code:
    return tsc_gettext("Expired login auth code");
  case TEK_SC_CM_ERESULT_ip_login_restriction_failed:
    return tsc_gettext("IP login restriction failed");
  case TEK_SC_CM_ERESULT_account_locked_down:
    return tsc_gettext("Account locked down");
  case TEK_SC_CM_ERESULT_account_logon_denied_verified_email_required:
    return tsc_gettext("Account logon denied, verified email required");
  case TEK_SC_CM_ERESULT_no_matching_url:
    return tsc_gettext("No matching URL");
  case TEK_SC_CM_ERESULT_bad_response:
    return tsc_gettext("Bad response");
  case TEK_SC_CM_ERESULT_require_password_reentry:
    return tsc_gettext("Require password reentry");
  case TEK_SC_CM_ERESULT_value_out_of_range:
    return tsc_gettext("Value out of range");
  case TEK_SC_CM_ERESULT_unexpected_error:
    return tsc_gettext("Unexpected error");
  case TEK_SC_CM_ERESULT_disabled:
    return tsc_gettext("Disabled");
  case TEK_SC_CM_ERESULT_invalid_ceg_submission:
    return tsc_gettext("Invalid CEG submission");
  case TEK_SC_CM_ERESULT_restricted_device:
    return tsc_gettext("Restricted device");
  case TEK_SC_CM_ERESULT_region_locked:
    return tsc_gettext("Region locked");
  case TEK_SC_CM_ERESULT_rate_limit_exceeded:
    return tsc_gettext("Rate limit exceeded");
  case TEK_SC_CM_ERESULT_account_login_denied_need_two_factor:
    return tsc_gettext("Account login denied, need two-factor authentication");
  case TEK_SC_CM_ERESULT_item_deleted:
    return tsc_gettext("Item deleted");
  case TEK_SC_CM_ERESULT_account_login_denied_throttle:
    return tsc_gettext("Account login denied, throttle");
  case TEK_SC_CM_ERESULT_two_factor_code_mismatch:
    return tsc_gettext("Two-factor code mismatch");
  case TEK_SC_CM_ERESULT_two_factor_activation_code_mismatch:
    return tsc_gettext("Two-factor activation code mismatch");
  case TEK_SC_CM_ERESULT_account_associated_to_multiple_partners:
    return tsc_gettext("Account associated to multiple partners");
  case TEK_SC_CM_ERESULT_not_modified:
    return tsc_gettext("Not modified");
  case TEK_SC_CM_ERESULT_no_mobile_device:
    return tsc_gettext("No mobile device");
  case TEK_SC_CM_ERESULT_time_not_synced:
    return tsc_gettext("Time not synced");
  case TEK_SC_CM_ERESULT_sms_code_failed:
    return tsc_gettext("SMS code failed");
  case TEK_SC_CM_ERESULT_account_limit_exceeded:
    return tsc_gettext("Account limit exceeded");
  case TEK_SC_CM_ERESULT_account_activity_limit_exceeded:
    return tsc_gettext("Account activity limit exceeded");
  case TEK_SC_CM_ERESULT_phone_activity_limit_exceeded:
    return tsc_gettext("Phone activity limit exceeded");
  case TEK_SC_CM_ERESULT_refund_to_wallet:
    return tsc_gettext("Refund to wallet");
  case TEK_SC_CM_ERESULT_email_send_failure:
    return tsc_gettext("Email send failure");
  case TEK_SC_CM_ERESULT_not_settled:
    return tsc_gettext("Not settled");
  case TEK_SC_CM_ERESULT_need_captcha:
    return tsc_gettext("Need CAPTCHA");
  case TEK_SC_CM_ERESULT_gslt_denied:
    return tsc_gettext("GSLT denied");
  case TEK_SC_CM_ERESULT_gs_owner_denied:
    return tsc_gettext("GS owner denied");
  case TEK_SC_CM_ERESULT_invalid_item_type:
    return tsc_gettext("Invalid item type");
  case TEK_SC_CM_ERESULT_ip_banned:
    return tsc_gettext("IP banned");
  case TEK_SC_CM_ERESULT_gslt_expired:
    return tsc_gettext("GSLT expired");
  case TEK_SC_CM_ERESULT_insufficient_funds:
    return tsc_gettext("Insufficient funds");
  case TEK_SC_CM_ERESULT_too_many_pending:
    return tsc_gettext("Too many pending");
  case TEK_SC_CM_ERESULT_no_site_licenses_found:
    return tsc_gettext("No site licenses found");
  case TEK_SC_CM_ERESULT_wg_network_send_exceeded:
    return tsc_gettext("WG network send exceeded");
  case TEK_SC_CM_ERESULT_account_not_friends:
    return tsc_gettext("Account not friends");
  case TEK_SC_CM_ERESULT_limited_user_account:
    return tsc_gettext("Limited user account");
  case TEK_SC_CM_ERESULT_cant_remove_item:
    return tsc_gettext("Can't remove item");
  case TEK_SC_CM_ERESULT_account_deleted:
    return tsc_gettext("Account deleted");
  case TEK_SC_CM_ERESULT_existing_user_cancelled_license:
    return tsc_gettext("Existing user cancelled license");
  case TEK_SC_CM_ERESULT_community_cooldown:
    return tsc_gettext("Community cooldown");
  case TEK_SC_CM_ERESULT_no_launcher_specified:
    return tsc_gettext("No launcher specified");
  case TEK_SC_CM_ERESULT_must_agree_to_ssa:
    return tsc_gettext("Must agree to Steam Subscriber Agreement");
  case TEK_SC_CM_ERESULT_launcher_migrated:
    return tsc_gettext("Launcher migrated");
  case TEK_SC_CM_ERESULT_steam_realm_mismatch:
    return tsc_gettext("Steam realm mismatch");
  case TEK_SC_CM_ERESULT_invalid_signature:
    return tsc_gettext("Invalid signature");
  case TEK_SC_CM_ERESULT_parse_failure:
    return tsc_gettext("Parse failure");
  case TEK_SC_CM_ERESULT_no_verified_phone:
    return tsc_gettext("No verified phone");
  case TEK_SC_CM_ERESULT_insufficient_battery:
    return tsc_gettext("Insufficient battery");
  case TEK_SC_CM_ERESULT_charger_required:
    return tsc_gettext("Charger required");
  case TEK_SC_CM_ERESULT_cached_credential_invalid:
    return tsc_gettext("Cached credential invalid");
  case TEK_SC_CM_ERESULT_phone_number_is_voip:
    return tsc_gettext("Phone number is VoIP");
  case TEK_SC_CM_ERESULT_not_supported:
    return tsc_gettext("Not supported");
  case TEK_SC_CM_ERESULT_family_size_limit_exceeded:
    return tsc_gettext("Family size limit exceeded");
  default:
    return tsc_gettext("Unknown");
  } // switch (eresult)
}

/// Get the message for specified @ref tek_sc_err_io_type value.
///
/// @param type
///    I/O operation type to get the message for.
/// @return Human-readable message for @p type, as a statically allocated
///    null-terminated UTF-8 string.
[[gnu::returns_nonnull]]
static inline const char *tscp_msg_io_type(tek_sc_err_io_type type) {
  switch (type) {
  case TEK_SC_ERR_IO_TYPE_check_existence:
    return tsc_gettext("Checking for existence");
  case TEK_SC_ERR_IO_TYPE_open:
    return tsc_gettext("Creating or opening");
  case TEK_SC_ERR_IO_TYPE_get_type:
    return tsc_gettext("Getting type of filesystem entry");
  case TEK_SC_ERR_IO_TYPE_get_size:
    return tsc_gettext("Getting file size");
  case TEK_SC_ERR_IO_TYPE_truncate:
    return tsc_gettext("Truncating");
  case TEK_SC_ERR_IO_TYPE_read:
    return tsc_gettext("Reading data");
  case TEK_SC_ERR_IO_TYPE_write:
    return tsc_gettext("Writing data");
  case TEK_SC_ERR_IO_TYPE_apply_flags:
    return tsc_gettext("Setting attributes or permissions");
  case TEK_SC_ERR_IO_TYPE_copy:
    return tsc_gettext("Copying data");
  case TEK_SC_ERR_IO_TYPE_move:
    return tsc_gettext("Moving");
  case TEK_SC_ERR_IO_TYPE_delete:
    return tsc_gettext("Deleting");
  case TEK_SC_ERR_IO_TYPE_symlink:
    return tsc_gettext("Creating symbolic link");
  case TEK_SC_ERR_IO_TYPE_aio_reg:
    return tsc_gettext("Registering for asynchronous I/O");
  case TEK_SC_ERR_IO_TYPE_aio_submit:
    return tsc_gettext("Submitting an asynchronous I/O request");
  case TEK_SC_ERR_IO_TYPE_aio_wait:
    return tsc_gettext("Waiting for asynchronous I/O completions");
  default:
    return tsc_gettext("Unknown");
  } // switch (type)
}

/// Get the message for specified @ref tsci_ws_close_code value.
///
/// @param code
///    WebSocket close code to get the message for.
/// @return Human-readable message for @p code, as a statically allocated
///    null-terminated UTF-8 string.
[[gnu::returns_nonnull]]
static inline const char *tscp_msg_ws_cc(tsci_ws_close_code code) {
  switch (code) {
  case TSCI_WS_CLOSE_CODE_NORMAL:
    return tsc_gettext("Normal closure");
  case TSCI_WS_CLOSE_CODE_GOING_AWAY:
    return tsc_gettext("Going away");
  case TSCI_WS_CLOSE_CODE_PROTO_ERR:
    return tsc_gettext("Protocol error");
  case TSCI_WS_CLOSE_CODE_UNSUPP_DATA:
    return tsc_gettext("Unsupported data");
  case TSCI_WS_CLOSE_CODE_NO_STATUS:
    return tsc_gettext("No status code received");
  case TSCI_WS_CLOSE_CODE_ABNORMAL:
    return tsc_gettext("Abnormal closure");
  case TSCI_WS_CLOSE_CODE_INVALID_PAYLOAD:
    return tsc_gettext("Invalid payload");
  case TSCI_WS_CLOSE_CODE_POLICY_VIOLATION:
    return tsc_gettext("Policy violation");
  case TSCI_WS_CLOSE_CODE_MSG_TOO_BIG:
    return tsc_gettext("Message too big");
  case TSCI_WS_CLOSE_CODE_MANDATORY_EXT:
    return tsc_gettext("Mandatory extension not supported");
  case TSCI_WS_CLOSE_CODE_INTERNAL_ERR:
    return tsc_gettext("Internal server error");
  case TSCI_WS_CLOSE_CODE_SVC_RESTART:
    return tsc_gettext("Service restart");
  case TSCI_WS_CLOSE_CODE_TRY_AGAIN:
    return tsc_gettext("Try again later");
  case TSCI_WS_CLOSE_CODE_BAD_GATEWAY:
    return tsc_gettext("Bad gateway");
  case TSCI_WS_CLOSE_CODE_TLS_HANDSHAKE:
    return tsc_gettext("TLS handshake failure");
  default:
    return tsc_gettext("Unknown");
  } // switch (code)
}

//===-- Public functions --------------------------------------------------===//

tek_sc_err_msgs tek_sc_err_get_msgs(const tek_sc_err *err) {
  const char *type;
  const char *aux = nullptr;
  const char *extra = nullptr;
  const char *uri_type = nullptr;
  switch (err->type) {
  case TEK_SC_ERR_TYPE_basic:
    // L18N: An error type
    type = tsc_gettext("Basic");
    if (err->extra) {
      auto const msg = tscp_msg_ws_cc(err->extra);
      // L18N: %u is the WebSocket close code number, %s is its string
      //    representation
      auto const fmt = tsc_gettext("WebSocket close code: (%u) %s");
      const int size = snprintf(nullptr, 0, fmt, err->extra, msg) + 1;
      char *const buf = malloc(size);
      if (buf) {
        snprintf(buf, size, fmt, err->extra, msg);
        extra = buf;
      }
    }
    if (err->uri) {
      // L18N: An error URI kind
      uri_type = tsc_gettext("URL");
    }
    break;
  case TEK_SC_ERR_TYPE_sub:
    // L18N: An error type
    type = tsc_gettext("Compound");
    aux = tscp_msg_errc(err->auxiliary);
    if (err->uri) {
      // L18N: An error URI kind
      uri_type = tsc_gettext("URL");
    }
    break;
  case TEK_SC_ERR_TYPE_steam_cm:
    // L18N: An error type
    type = tsc_gettext("Steam CM response");
    aux = tscp_msg_eresult(err->auxiliary);
    break;
  case TEK_SC_ERR_TYPE_os:
    // L18N: An error type
    type = tsc_gettext("OS");
    aux = tsci_os_get_err_msg((tek_sc_os_errc)err->auxiliary);
    if (err->extra != TEK_SC_ERR_IO_TYPE_none) {
      auto const msg = tscp_msg_io_type(err->extra);
      // L18N: %u is the I/O operation type code, %s is its string
      //    representation
      auto const fmt = tsc_gettext("I/O operation type: (%u) %s");
      const int size = snprintf(nullptr, 0, fmt, err->extra, msg) + 1;
      char *const buf = malloc(size);
      if (buf) {
        snprintf(buf, size, fmt, err->extra, msg);
        extra = buf;
      }
    } // if (err->extra != TEK_SC_ERR_IO_TYPE_none)
    if (err->uri) {
      // L18N: An error URI kind
      uri_type = tsc_gettext("Path");
    }
    break;
  case TEK_SC_ERR_TYPE_curle:
    // L18N: An error type
    type = tsc_gettext("libcurl-easy");
    aux = curl_easy_strerror(err->auxiliary);
    if (err->auxiliary == CURLE_HTTP_RETURNED_ERROR) {
      // L18N: %u is the status code number
      auto const fmt = tsc_gettext("HTTP status code: %u");
      const int size = snprintf(nullptr, 0, fmt, err->extra) + 1;
      char *const buf = malloc(size);
      if (buf) {
        snprintf(buf, size, fmt, err->extra);
        extra = buf;
      }
    }
    if (err->uri) {
      // L18N: An error URI kind
      uri_type = tsc_gettext("URL");
    }
    break;
  case TEK_SC_ERR_TYPE_curlm:
    // L18N: An error type
    type = tsc_gettext("libcurl-multi");
    aux = curl_multi_strerror(err->auxiliary);
    break;
  case TEK_SC_ERR_TYPE_sqlite:
    // L18N: An error type
    type = tsc_gettext("SQLite");
    aux = sqlite3_errstr(err->auxiliary);
    if (err->uri) {
      // L18N: An error URI kind
      uri_type = tsc_gettext("Path");
    }
    break;
  default:
    // L18N: An error type
    type = tsc_gettext("Unknown");
  } // switch (err->type)
  return (tek_sc_err_msgs){.type = err->type,
                           .type_str = type,
                           .primary = tscp_msg_errc(err->primary),
                           .auxiliary = aux,
                           .extra = extra,
                           .uri_type = uri_type};
}

void tek_sc_err_release_msgs(tek_sc_err_msgs *err_msgs) {
  if (err_msgs->type == TEK_SC_ERR_TYPE_os) {
    free((void *)err_msgs->auxiliary);
  }
  if (err_msgs->extra) {
    free((void *)err_msgs->extra);
  }
  *err_msgs = (tek_sc_err_msgs){};
}
