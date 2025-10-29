//===-- cm.h - Steam CM client interface ----------------------------------===//
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
/// Declarations for the interface for Steam CM (Connection Manager) servers.
/// CM handles account authentication and all account-related functions.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"
#include "error.h"

#include <stdint.h>
#include <time.h>

//===-- Types -------------------------------------------------------------===//

/// Opaque CM client instance type.
/// This instance holds WebSocket connection to a CM server and keeps track of
///    outgoing and incoming messages.
typedef struct tek_sc_cm_client tek_sc_cm_client;

/// Steam's EResult enumeration returned by some CM functions.
enum tek_sc_cm_eresult {
  TEK_SC_CM_ERESULT_invalid,
  TEK_SC_CM_ERESULT_ok,
  TEK_SC_CM_ERESULT_fail,
  TEK_SC_CM_ERESULT_no_connection,
  TEK_SC_CM_ERESULT_invalid_password = 5,
  TEK_SC_CM_ERESULT_logged_in_elsewhere,
  TEK_SC_CM_ERESULT_invalid_protocol_ver,
  TEK_SC_CM_ERESULT_invalid_param,
  TEK_SC_CM_ERESULT_file_not_found,
  TEK_SC_CM_ERESULT_busy,
  TEK_SC_CM_ERESULT_invalid_state,
  TEK_SC_CM_ERESULT_invalid_name,
  TEK_SC_CM_ERESULT_invalid_email,
  TEK_SC_CM_ERESULT_duplicate_name,
  TEK_SC_CM_ERESULT_access_denied,
  TEK_SC_CM_ERESULT_timeout,
  TEK_SC_CM_ERESULT_banned,
  TEK_SC_CM_ERESULT_account_not_found,
  TEK_SC_CM_ERESULT_invalid_steam_id,
  TEK_SC_CM_ERESULT_service_unavailable,
  TEK_SC_CM_ERESULT_not_logged_on,
  TEK_SC_CM_ERESULT_pending,
  TEK_SC_CM_ERESULT_encryption_failure,
  TEK_SC_CM_ERESULT_insufficient_privilege,
  TEK_SC_CM_ERESULT_limit_exceeded,
  TEK_SC_CM_ERESULT_revoked,
  TEK_SC_CM_ERESULT_expired,
  TEK_SC_CM_ERESULT_already_redeemed,
  TEK_SC_CM_ERESULT_duplicate_request,
  TEK_SC_CM_ERESULT_already_owned,
  TEK_SC_CM_ERESULT_ip_not_found,
  TEK_SC_CM_ERESULT_persist_failed,
  TEK_SC_CM_ERESULT_locking_failed,
  TEK_SC_CM_ERESULT_logon_session_replaced,
  TEK_SC_CM_ERESULT_connect_failed,
  TEK_SC_CM_ERESULT_handshake_failed,
  TEK_SC_CM_ERESULT_io_failure,
  TEK_SC_CM_ERESULT_remote_disconnect,
  TEK_SC_CM_ERESULT_shopping_cart_not_found,
  TEK_SC_CM_ERESULT_blocked,
  TEK_SC_CM_ERESULT_ignored,
  TEK_SC_CM_ERESULT_no_match,
  TEK_SC_CM_ERESULT_account_disabled,
  TEK_SC_CM_ERESULT_service_read_only,
  TEK_SC_CM_ERESULT_account_not_featured,
  TEK_SC_CM_ERESULT_administrator_ok,
  TEK_SC_CM_ERESULT_content_version,
  TEK_SC_CM_ERESULT_try_another_cm,
  TEK_SC_CM_ERESULT_password_required_to_kick_session,
  TEK_SC_CM_ERESULT_already_logged_in_elsewhere,
  TEK_SC_CM_ERESULT_suspended,
  TEK_SC_CM_ERESULT_cancelled,
  TEK_SC_CM_ERESULT_data_corruption,
  TEK_SC_CM_ERESULT_disk_full,
  TEK_SC_CM_ERESULT_remote_call_failed,
  TEK_SC_CM_ERESULT_password_unset,
  TEK_SC_CM_ERESULT_external_account_unlinked,
  TEK_SC_CM_ERESULT_psn_ticket_invalid,
  TEK_SC_CM_ERESULT_external_account_already_linked,
  TEK_SC_CM_ERESULT_remote_file_conflict,
  TEK_SC_CM_ERESULT_illegal_password,
  TEK_SC_CM_ERESULT_same_as_previous_value,
  TEK_SC_CM_ERESULT_account_logon_denied,
  TEK_SC_CM_ERESULT_cannot_use_old_password,
  TEK_SC_CM_ERESULT_invalid_login_auth_code,
  TEK_SC_CM_ERESULT_account_logon_denied_no_mail,
  TEK_SC_CM_ERESULT_hardware_not_capable_of_ipt,
  TEK_SC_CM_ERESULT_ipt_init_error,
  TEK_SC_CM_ERESULT_parental_control_restricted,
  TEK_SC_CM_ERESULT_facebook_query_error,
  TEK_SC_CM_ERESULT_expired_login_auth_code,
  TEK_SC_CM_ERESULT_ip_login_restriction_failed,
  TEK_SC_CM_ERESULT_account_locked_down,
  TEK_SC_CM_ERESULT_account_logon_denied_verified_email_required,
  TEK_SC_CM_ERESULT_no_matching_url,
  TEK_SC_CM_ERESULT_bad_response,
  TEK_SC_CM_ERESULT_require_password_reentry,
  TEK_SC_CM_ERESULT_value_out_of_range,
  TEK_SC_CM_ERESULT_unexpected_error,
  TEK_SC_CM_ERESULT_disabled,
  TEK_SC_CM_ERESULT_invalid_ceg_submission,
  TEK_SC_CM_ERESULT_restricted_device,
  TEK_SC_CM_ERESULT_region_locked,
  TEK_SC_CM_ERESULT_rate_limit_exceeded,
  TEK_SC_CM_ERESULT_account_login_denied_need_two_factor,
  TEK_SC_CM_ERESULT_item_deleted,
  TEK_SC_CM_ERESULT_account_login_denied_throttle,
  TEK_SC_CM_ERESULT_two_factor_code_mismatch,
  TEK_SC_CM_ERESULT_two_factor_activation_code_mismatch,
  TEK_SC_CM_ERESULT_account_associated_to_multiple_partners,
  TEK_SC_CM_ERESULT_not_modified,
  TEK_SC_CM_ERESULT_no_mobile_device,
  TEK_SC_CM_ERESULT_time_not_synced,
  TEK_SC_CM_ERESULT_sms_code_failed,
  TEK_SC_CM_ERESULT_account_limit_exceeded,
  TEK_SC_CM_ERESULT_account_activity_limit_exceeded,
  TEK_SC_CM_ERESULT_phone_activity_limit_exceeded,
  TEK_SC_CM_ERESULT_refund_to_wallet,
  TEK_SC_CM_ERESULT_email_send_failure,
  TEK_SC_CM_ERESULT_not_settled,
  TEK_SC_CM_ERESULT_need_captcha,
  TEK_SC_CM_ERESULT_gslt_denied,
  TEK_SC_CM_ERESULT_gs_owner_denied,
  TEK_SC_CM_ERESULT_invalid_item_type,
  TEK_SC_CM_ERESULT_ip_banned,
  TEK_SC_CM_ERESULT_gslt_expired,
  TEK_SC_CM_ERESULT_insufficient_funds,
  TEK_SC_CM_ERESULT_too_many_pending,
  TEK_SC_CM_ERESULT_no_site_licenses_found,
  TEK_SC_CM_ERESULT_wg_network_send_exceeded,
  TEK_SC_CM_ERESULT_account_not_friends,
  TEK_SC_CM_ERESULT_limited_user_account,
  TEK_SC_CM_ERESULT_cant_remove_item,
  TEK_SC_CM_ERESULT_account_deleted,
  TEK_SC_CM_ERESULT_existing_user_cancelled_license,
  TEK_SC_CM_ERESULT_community_cooldown,
  TEK_SC_CM_ERESULT_no_launcher_specified,
  TEK_SC_CM_ERESULT_must_agree_to_ssa,
  TEK_SC_CM_ERESULT_launcher_migrated,
  TEK_SC_CM_ERESULT_steam_realm_mismatch,
  TEK_SC_CM_ERESULT_invalid_signature,
  TEK_SC_CM_ERESULT_parse_failure,
  TEK_SC_CM_ERESULT_no_verified_phone,
  TEK_SC_CM_ERESULT_insufficient_battery,
  TEK_SC_CM_ERESULT_charger_required,
  TEK_SC_CM_ERESULT_cached_credential_invalid,
  TEK_SC_CM_ERESULT_phone_number_is_voip,
  TEK_SC_CM_ERESULT_not_supported,
  TEK_SC_CM_ERESULT_family_size_limit_exceeded
};
/// @copydoc tek_sc_cm_eresult
typedef enum tek_sc_cm_eresult tek_sc_cm_eresult;

/// CM authentication session status values.
enum tek_sc_cm_auth_status {
  /// Authentication session has been completed, `err` and `token` can be
  ///    inspected for result.
  TEK_SC_CM_AUTH_STATUS_completed,
  /// New URL for QR code has been generated, speicifed in `url`.
  TEK_SC_CM_AUTH_STATUS_new_url,
  /// A confirmation specified by `confirmation_types` is required for
  ///    authentication to proceed.
  TEK_SC_CM_AUTH_STATUS_awaiting_confirmation
};
/// @copydoc tek_sc_cm_auth_status
typedef enum tek_sc_cm_auth_status tek_sc_cm_auth_status;

/// Types of CM authentication confirmations.
enum [[clang::flag_enum]] tek_sc_cm_auth_confirmation_type {
  /// No confirmation required.
  TEK_SC_CM_AUTH_CONFIRMATION_TYPE_none,
  /// Pressing confirmation button in the mobile app.
  TEK_SC_CM_AUTH_CONFIRMATION_TYPE_device = 1 << 0,
  /// Entering TOTP Steam Guard code from the mobile app.
  TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code = 1 << 1,
  /// Entering confirmation code sent via email.
  TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email = 1 << 2
};
/// @copydoc tek_sc_cm_auth_confirmation_type
typedef enum tek_sc_cm_auth_confirmation_type tek_sc_cm_auth_confirmation_type;

/// Prototype of CM client callback function.
///
/// @param [in, out] client
///    Pointer to the CM client instance that emitted the callback.
/// @param data
///    Data associated with the callback. The type of data depends on the
///    function that registered the callback.
/// @param user_data
///    User data pointer previously passed to @ref tek_sc_cm_client_create or
///    @ref tek_sc_cm_set_user_data for @p client.
typedef void tek_sc_cm_callback_func(tek_sc_cm_client *_Nullable client,
                                     void *_Nonnull data,
                                     void *_Nullable user_data);

/// Data parsed from a Steam authentication token.
typedef struct tek_sc_cm_auth_token_info tek_sc_cm_auth_token_info;
/// @copydoc tek_sc_cm_auth_token_info
struct tek_sc_cm_auth_token_info {
  // Steam ID of the account that the token authenticates.
  uint64_t steam_id;
  // Token expiration timestamp.
  time_t expires;
  // Value indicating whether the token is eligible for renewal.
  bool renewable;
};

/// Steam account license entry.
typedef struct tek_sc_cm_lic_entry tek_sc_cm_lic_entry;
/// @copydoc tek_sc_cm_lic_entry
struct tek_sc_cm_lic_entry {
  /// ID of the package granted by the license.
  uint32_t package_id;
  /// PICS access token for the package.
  uint64_t access_token;
};

/// PICS request/response entry. Exact usage depends on kind of request.
typedef struct tek_sc_cm_pics_entry tek_sc_cm_pics_entry;
/// @copydoc tek_sc_cm_pics_entry
struct tek_sc_cm_pics_entry {
  /// PICS access token for the app/package.
  uint64_t access_token;
  /// ID of the app/package to get info or access token for.
  uint32_t id;
  /// Size of the buffer pointed to by @ref data, in bytes.
  int data_size;
  /// On product info request's success, pointer to the buffer containing the
  ///    product info in VDF or Binary VDF format. Must be freed with `free`
  ///    after use.
  void *_Nullable data;
  /// Result codes for the product.
  tek_sc_err result;
};

/// PICS application info change entry.
typedef struct tek_sc_cm_pics_change_entry tek_sc_cm_pics_change_entry;
/// @copydoc tek_sc_cm_pics_change_entry
struct tek_sc_cm_pics_change_entry {
  /// ID of the application that changed.
  uint32_t id;
  /// Value indicating whether requesting application info requires a token.
  bool needs_token;
};

/// SteamPipe server entry.
typedef struct tek_sc_cm_sp_srv_entry tek_sc_cm_sp_srv_entry;
/// @copydoc tek_sc_cm_sp_srv_entry
struct tek_sc_cm_sp_srv_entry {
  /// Hostname of the server, as a null-terminated UTF-8 string.
  /// Located in the same buffer as the entry, should not be freed on its own.
  const char *_Nonnull host;
  /// Value indicating whether the server supports HTTPS.
  bool supports_https;
};

/// Steam Workshop item details.
///
/// Pointers stay valid during the callback and should not be freed.
typedef struct tek_sc_cm_ws_item_details tek_sc_cm_ws_item_details;
/// @copydoc tek_sc_cm_ws_item_details
struct tek_sc_cm_ws_item_details {
  /// ID of the item.
  uint64_t id;
  /// ID of the item's latest manifest.
  uint64_t manifest_id;
  /// Last item update timestamp.
  time_t last_updated;
  /// Name of the item, as a null-terminated UTF-8 string.
  const char *_Nullable name;
  /// URL of the item's preview image, as a null-terminated UTF-8 string.
  const char *_Nullable preview_url;
  /// If the item is a collection, pointer to the array of IDs of items that
  ///    compose it.
  const uint64_t *_Nullable children;
  /// Number of IDs pointed to by @ref children.
  int num_children;
  /// ID of the application that the item belongs to.
  uint32_t app_id;
  /// Result codes for the item.
  tek_sc_err result;
};

/// Data for authentication session callbacks.
///
/// Pointers stay valid during the callback and should not be freed.
typedef struct tek_sc_cm_data_auth_polling tek_sc_cm_data_auth_polling;
/// @copydoc tek_sc_cm_auth_polling_data
struct tek_sc_cm_data_auth_polling {
  /// Status of the authentication session.
  tek_sc_cm_auth_status status;
  /// Supported confirmation types, if @ref status is
  ///    @ref TEK_SC_CM_AUTH_STATUS_awaiting_confirmation.
  tek_sc_cm_auth_confirmation_type confirmation_types;
  /// Authentication URL, as a null-terminated UTF-8 string, to be displayed as
  ///    a QR code, if @ref status is @ref TEK_SC_CM_AUTH_STATUS_new_url.
  const char *_Nullable url;
  /// Authentication token, as a null-terminated UTF-8 string, if @ref status is
  ///    @ref TEK_SC_CM_AUTH_STATUS_completed and @ref result indicates success.
  /// Not returned for tek-s3 client responses, the token stays on the server.
  const char *_Nullable token;
  /// Result codes for the session, if @ref status is
  ///    @ref TEK_SC_CM_AUTH_STATUS_completed.
  /// For tek-s3 client responses, if it indicates success and the token is
  ///    non-renewable, `auxiliary` encodes the lower half and `extra` encodes
  ///    the higher half of the expiration time (`time_t`).
  tek_sc_err result;
};

/// Data for depot decryption key requests and callbacks.
typedef struct tek_sc_cm_data_depot_key tek_sc_cm_data_depot_key;
/// @copydoc tek_sc_cm_data_depot_key
struct tek_sc_cm_data_depot_key {
  /// ID of the application that the depot belongs to.
  uint32_t app_id;
  /// ID of the depot to get decryption key for.
  uint32_t depot_id;
  /// On success, decryption key for the depot.
  tek_sc_aes256_key key;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for depot patch info callbacks.
typedef struct tek_sc_cm_data_dp_info tek_sc_cm_data_dp_info;
/// @copydoc tek_sc_cm_data_dp_info
struct tek_sc_cm_data_dp_info {
  /// On success, value indicating whether a patch is available for specified
  ///    manifests.
  bool available;
  /// If @ref available is set, size of the patch file, in bytes.
  int64_t size;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for encrypted app ticket requests and callbacks.
typedef struct tek_sc_cm_data_enc_app_ticket tek_sc_cm_data_enc_app_ticket;
/// @copydoc tek_sc_cm_data_enc_app_ticket
struct tek_sc_cm_data_enc_app_ticket {
  /// ID of the application to request ticket for.
  uint32_t app_id;
  /// Size of the buffer pointed to by @ref data, in bytes.
  int data_size;
  /// On request, optional pointer to data to include into the ticket. On
  ///    successful response, pointer to the buffer containing the encrypted
  ///    ticket, which stays valid during the callback and should not be freed.
  const void *_Nullable data;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for license list callbacks.
typedef struct tek_sc_cm_data_lics tek_sc_cm_data_lics;
/// @copydoc tek_sc_cm_data_lics
struct tek_sc_cm_data_lics {
  /// On success, pointer to the array of license entries sorted by package ID
  ///    in ascending order. The pointer stays valid until the CM client
  ///    instance is disconnected, and should not be freed.
  const tek_sc_cm_lic_entry *_Nullable entries;
  /// Number of entries pointed to by @ref entries.
  int num_entries;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for manifest request code requests and callbacks.
typedef struct tek_sc_cm_data_mrc tek_sc_cm_data_mrc;
/// @copydoc tek_sc_cm_data_mrc
struct tek_sc_cm_data_mrc {
  /// ID of the application that the depot belongs to.
  uint32_t app_id;
  /// ID of the depot that the manifest belongs to.
  uint32_t depot_id;
  /// ID of the manifest to get request code for.
  uint64_t manifest_id;
  /// On success, manifest request code value.
  uint64_t request_code;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for PICS access token and product info requests and callbacks.
typedef struct tek_sc_cm_data_pics tek_sc_cm_data_pics;
/// @copydoc tek_sc_cm_data_pics
struct tek_sc_cm_data_pics {
  /// Pointer to the array of app entries.
  tek_sc_cm_pics_entry *_Nullable app_entries;
  /// Pointer to the array of package entries.
  tek_sc_cm_pics_entry *_Nullable package_entries;
  /// Number of entries pointed to by @ref app_entries.
  int num_app_entries;
  /// Number of entries pointed to by @ref package_entries.
  int num_package_entries;
  /// Timeout for HTTP info buffer downloads, in milliseconds. The download is
  ///    performed in the connection processing thread, which means that no
  ///    other CM messages will be processed until it finishes.
  long timeout_ms;
  /// General result codes for the response. Even on success, `result` fields of
  ///    individual entries may still indicate an error due to them being
  ///    processed separately.
  tek_sc_err result;
};

/// Data for PICS changes callbacks.
typedef struct tek_sc_cm_data_pics_changes tek_sc_cm_data_pics_changes;
/// @copydoc tek_sc_cm_data_pics_changes
struct tek_sc_cm_data_pics_changes {
  /// On success, pointer to the array of change entries. It stays valid during
  ///    the callback and should not be freed.
  const tek_sc_cm_pics_change_entry *_Nullable entries;
  /// Number of entries pointed to by @ref entries. A special value of `-1`
  ///    indicates that there are too many changes and the client should
  ///    instead request info for all its apps.
  int num_entries;
  /// On success, current changenumber in PICS.
  uint32_t changenumber;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for SteamPipe server list callbacks.
typedef struct tek_sc_cm_data_sp_servers tek_sc_cm_data_sp_servers;
/// @copydoc tek_sc_cm_data_sp_servers
struct tek_sc_cm_data_sp_servers {
  /// On success, pointer to the array of server entries. Must be freed with
  ///    `free` after use.
  tek_sc_cm_sp_srv_entry *_Nullable entries;
  /// Number of entries pointed to by @ref entries.
  int num_entries;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for token renewal callbacks.
typedef struct tek_sc_cm_data_renew_token tek_sc_cm_data_renew_token;
/// @copydoc tek_sc_cm_data_renew_token
struct tek_sc_cm_data_renew_token {
  /// New authentication token, as a null-terminated UTF-8 string, if Steam
  ///    accepted the renewal. The pointer stays valid during the callback and
  ///    should not be freed.
  const char *_Nullable new_token;
  /// Result codes for the response.
  tek_sc_err result;
};

/// Data for Steam Workshop requests and callbacks.
typedef struct tek_sc_cm_data_ws tek_sc_cm_data_ws;
/// @copydoc tek_sc_cm_data_ws
struct tek_sc_cm_data_ws {
  /// Pointer to the array of item details entries.
  tek_sc_cm_ws_item_details *_Nullable details;
  /// Number of details entries pointed to by @ref details.
  int num_details;
  /// For query responses, the number of entries in @ref details that have been
  ///    written.
  int num_returned_details;
  /// For query responses, the total number of items matching the query.
  int total_items;
  /// General result codes for the response. Even on success, `result` fields of
  ///    individual entries may still indicate an error due to them being
  ///    processed separately.
  tek_sc_err result;
};

//===-- Functions ---------------------------------------------------------===//

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

//===--- Create/destroy ---------------------------------------------------===//

/// Create a Steam CM client instance.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context hosting connection processing thread and
///    providing and storing cache data.
/// @param user_data
///    A pointer that will be passed to all callbacks associated with this
///    client instance.
/// @return Pointer to created CM client instance that can be passed to other
///    functions. It must be destroyed with @ref tek_sc_cm_client_destroy after
///    use. `nullptr` may be returned on failure.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1),
  gnu::access(none, 2)]] tek_sc_cm_client
    *_Nullable tek_sc_cm_client_create(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                       void *_Nullable user_data);

/// Request CM client instance to disconnect and free its memory afterwards.
///
/// @param [in, out] client
///    Pointer to the CM client instance to destroy.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_cm_client_destroy(tek_sc_cm_client *_Nonnull client);

/// Set new user data pointer for specified CM client instance.
///
/// @param [in, out] client
///    Pointer to the CM client instance to set user data for.
/// @param user_data
///    New user data pointer.
[[gnu::TEK_SC_API, gnu::notrow, gnu::nonnull(1), gnu::access(read_write, 1),
  gnu::access(none, 2)]]
void tek_sc_cm_set_user_data(tek_sc_cm_client *_Nonnull client,
                             void *_Nullable user_data);

//===--- Connect/disconnect -----------------------------------------------===//

/// Initiate WebSocket connection of CM client instance to a server.
/// If CM server list is not present in the cache, this function will also
///    fetch it from Steam Web API. Fetching is a blocking operation, but you
///    may specify its timeout via @p fetch_timeout_ms.
///
/// @param [in, out] client
///    Pointer to the CM client instance to connect.
/// @param connection_cb
///    Pointer to the function that will be called when connection attempt
///    succeeds or errors. `data` will point to a @ref tek_sc_err indicating
///    the result.
/// @param fetch_timeout_ms
///    Timeout for fetching the server list, in milliseconds.
/// @param disconnection_cb
///    Pointer to the function that will be called after disconnection from the
///    server. `data` will point to a @ref tek_sc_err indicating the
///    disconnection reason.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 4), gnu::access(read_write, 1),
  clang::callback(connection_cb, __, __, __)]]
void tek_sc_cm_connect(tek_sc_cm_client *_Nonnull client,
                       tek_sc_cm_callback_func *_Nonnull connection_cb,
                       long fetch_timeout_ms,
                       tek_sc_cm_callback_func *_Nonnull disconnection_cb);

/// Initiate disconnection of CM client instance from the server.
///
/// @param [in, out] client
///    Pointer to the CM client instance to disconnect.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_cm_disconnect(tek_sc_cm_client *_Nonnull client);

//===--- Authentication ---------------------------------------------------===//

/// Parse Steam authentication token.
///
/// @param [in] token
///    Steam authentication token, as a null-terminated UTF-8 string.
/// @return A @ref tek_sc_cm_auth_token_info containing parsed token
///    information. If parsing fails due to invalid data in @p token, all its
///    fileds will be zeroed.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
tek_sc_cm_auth_token_info
tek_sc_cm_parse_auth_token(const char *_Nonnull token);

/// Start credentials-based Steam authentication session.
///
/// @param [in, out] client
///    Pointer to the CM client instance to authenticate with.
/// @param [in] device_name
///    User-friendly device name to send to Steam, as a null-terminated UTF-8
///    string. This name will be displayed in the list of authorized devices in
///    the Steam mobile app.
/// @param [in] account_name
///    Steam account name (login), as a null-terminated UTF-8 string.
/// @param [in] password
///    Steam account password, as a null-terminated UTF-8 string. It will be
///    encrypted with an RSA public key before being sent to the server over WSS
///    connection, which is also encrypted via TLS.
/// @param cb
///    Pointer to the function that will be called when authentication session
///    ends or changes its status. `data` will point to a
///    @ref tek_sc_cm_data_auth_polling.
/// @param timeout_ms
///    Timeout for the initial message response, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3, 4, 5), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(read_only, 3),
  gnu::access(read_only, 4), gnu::null_terminated_string_arg(2),
  gnu::null_terminated_string_arg(3), gnu::null_terminated_string_arg(4),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_auth_credentials(tek_sc_cm_client *_Nonnull client,
                                const char *_Nonnull device_name,
                                const char *_Nonnull account_name,
                                const char *_Nonnull password,
                                tek_sc_cm_callback_func *_Nonnull cb,
                                long timeout_ms);

/// Start QR code-based Steam authentication session.
///
/// @param [in, out] client
///    Pointer to the CM client instance to authenticate with.
/// @param [in] device_name
///    User-friendly device name to send to Steam, as a null-terminated UTF-8
///    string. This name will be displayed in the list of authorized devices in
///    the Steam mobile app.
/// @param cb
///    Pointer to the function that will be called when authentication session
///    ends or changes its status. `data` will point to a
///    @ref tek_sc_cm_data_auth_polling.
/// @param timeout_ms
///    Timeout for the initial message response, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_auth_qr(tek_sc_cm_client *_Nonnull client,
                       const char *_Nonnull device_name,
                       tek_sc_cm_callback_func *_Nonnull cb, long timeout_ms);

/// Submit Steam Guard code for current authentication session.
///
/// @param [in, out] client
///    Pointer to the CM client instance running authentication session.
/// @param code_type
///    Steam Guard confirmation type that the code belongs to.
/// @param [in] code
///    Steam Guard code to submit, as a null-terminated UTF-8 string.
/// @return A @ref tek_sc_err indicating the result of message send operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 3), gnu::null_terminated_string_arg(3)]]
tek_sc_err
tek_sc_cm_auth_submit_code(tek_sc_cm_client *_Nonnull client,
                           tek_sc_cm_auth_confirmation_type code_type,
                           const char *_Nonnull code);

/// Attempt to renew Steam authentication token. If the token is renewed, new
///    one is returned, and @p token is invalidated. Steam may choose not to
///    renew the token, in that case it will not return a new token, and the old
///    one will stay valid.
///
/// @param [in, out] client
///    Pointer to the CM client instance to send request from.
/// @param [in] token
///    Steam authentication token to renew, as a null-terminated UTF-8 string.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will point to a
///    @ref tek_sc_cm_data_renew_roken.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_auth_renew_token(tek_sc_cm_client *_Nonnull client,
                                const char *_Nonnull token,
                                tek_sc_cm_callback_func *_Nonnull cb,
                                long timeout_ms);

/// Get encrypted ticket for an application.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_enc_app_ticket(tek_sc_cm_client *_Nonnull client,
                                  tek_sc_cm_data_enc_app_ticket *_Nonnull data,
                                  tek_sc_cm_callback_func *_Nonnull cb,
                                  long timeout_ms);

//===--- Sign-in ----------------------------------------------------------===//

/// Sign into a Steam account.
///
/// @param [in, out] client
///    Pointer to the CM client instance to sign in
/// @param [in] token
///    Steam authentication token, as a null-terminated UTF-8 string.
/// @param cb
///    Pointer to the function that will be called when sign-in succeeds or
///    times out. `data` will point to a @ref tek_sc_err indicating the result
///    of the sign-in attempt.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_sign_in(tek_sc_cm_client *_Nonnull client,
                       const char *_Nonnull token,
                       tek_sc_cm_callback_func *_Nonnull cb, long timeout_ms);

/// Sign into anonymous Steam account.
///
/// @param [in, out] client
///    Pointer to the CM client instance to sign in.
/// @param cb
///    Pointer to the function that will be called when sign-in succeeds or
///    times out. `data` will point to a @ref tek_sc_err indicating the result
///    of the sign-in attempt.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_sign_in_anon(tek_sc_cm_client *_Nonnull client,
                            tek_sc_cm_callback_func *_Nonnull cb,
                            long timeout_ms);

//===--- PICS -------------------------------------------------------------===//

/// Get licenses for current Steam account.
///
/// @param [in, out] client
///    Pointer to the CM client instance to get licenses for.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will point to a @ref tek_sc_cm_data_lics.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_licenses(tek_sc_cm_client *_Nonnull client,
                            tek_sc_cm_callback_func *_Nonnull cb,
                            long timeout_ms);

/// Request PICS access tokens for specified products.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data. On request, `id` field of the
///    entries will be used, on successful response the `result` and
///    `access_token` fields will be set.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_access_token(tek_sc_cm_client *_Nonnull client,
                                tek_sc_cm_data_pics *_Nonnull data,
                                tek_sc_cm_callback_func *_Nonnull cb,
                                long timeout_ms);

/// Request information for specified products via PICS.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data. On request, `id` and `access_token`
///    fields of the entries will be used, on successful response the remaining
///    fields will be set.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message(s), in milliseconds. For response info
///    buffers that have to be downloaded over HTTP, the `timeout_ms` specified
///    in @p data applies on top of this one.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_product_info(tek_sc_cm_client *_Nonnull client,
                                tek_sc_cm_data_pics *_Nonnull data,
                                tek_sc_cm_callback_func *_Nonnull cb,
                                long timeout_ms);

/// Request the list of applications that have had changes since specified
///    changenumber via PICS.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param changenumber
///    Current changenumber to get changes since.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will point to a
///    @ref tek_sc_cm_data_pics_changes.
/// @param timeout_ms
///    Timeout for the response message(s), in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_changes(tek_sc_cm_client *_Nonnull client,
                           uint32_t changenumber,
                           tek_sc_cm_callback_func *_Nonnull cb,
                           long timeout_ms);

//===--- SteamPipe --------------------------------------------------------===//

/// Get AES-256 decryption key for specified depot.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_depot_key(tek_sc_cm_client *_Nonnull client,
                             tek_sc_cm_data_depot_key *_Nonnull data,
                             tek_sc_cm_callback_func *_Nonnull cb,
                             long timeout_ms);

/// Get patch information for specified manifests.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in] item_id
///    Pointer to the ID of the item that the manifests belong to.
/// @param source_manifest_id
///    ID of the source manifest for patching.
/// @param target_manifest_id
///    ID of the target manifest for patching.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will point to a
///    @ref tek_sc_cm_data_dp_info.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 5), gnu::access(read_write, 1),
  gnu::access(read_only, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_dp_info(tek_sc_cm_client *_Nonnull client,
                           const tek_sc_item_id *_Nonnull item_id,
                           uint64_t source_manifest_id,
                           uint64_t target_manifest_id,
                           tek_sc_cm_callback_func *_Nonnull cb,
                           long timeout_ms);

/// Get request code for specified manifest.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_mrc(tek_sc_cm_client *_Nonnull client,
                       tek_sc_cm_data_mrc *_Nonnull data,
                       tek_sc_cm_callback_func *_Nonnull cb, long timeout_ms);

/// Get SteamPipe server list.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will point to a
///    @ref tek_sc_cm_data_sp_servers.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  clang::callback(cb, __, __, __)]]
void tek_sc_cm_get_sp_servers(tek_sc_cm_client *_Nonnull client,
                              tek_sc_cm_callback_func *_Nonnull cb,
                              long timeout_ms);

//===--- Steam Workshop ---------------------------------------------------===//

/// Request details for specified Steam Workshop items.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the request.
/// @param [in, out] data
///    Pointer to the request/response data. On request, `id` field of the
///    details entries will be used, on successful response the remaining fields
///    will be set.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_write, 2), clang::callback(cb, __, __, __)]]
void tek_sc_cm_ws_get_details(tek_sc_cm_client *_Nonnull client,
                              tek_sc_cm_data_ws *_Nonnull data,
                              tek_sc_cm_callback_func *_Nonnull cb,
                              long timeout_ms);

/// Query Steam Workshop items.
///
/// @param [in, out] client
///    Pointer to the CM client instance that will perform the query.
/// @param [in, out] data
///    Pointer to the request/response data. `details` must be a valid pointer
///    to an array of at least `num_details` entries. On success, up to
///    `num_details` entries in `details` will be written, the actual number of
///    written entries will be stored in `num_returned_details`, and
///    `total_items` will be set.
/// @param app_id
///    ID of the appplication to query items for.
/// @param page
///    Current page number to query, assuming pages contain `data->num_details`
///    items each.
/// @param [in] search_query
///    If specified, a null-terminated UTF-8 search query text.
/// @param cb
///    Pointer to the function that will be called when the response is
///    received or timed out. `data` will be @p data.
/// @param timeout_ms
///    Timeout for the response message, in milliseconds.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 6), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_only, 5),
  gnu::null_terminated_string_arg(5), clang::callback(cb, __, __, __)]]
void tek_sc_cm_ws_query_items(tek_sc_cm_client *_Nonnull client,
                              tek_sc_cm_data_ws *_Nonnull data, uint32_t app_id,
                              int page, const char *_Nullable search_query,
                              tek_sc_cm_callback_func *_Nonnull cb,
                              long timeout_ms);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
