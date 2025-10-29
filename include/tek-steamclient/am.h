//===-- am.h - Steam application manager interface ------------------------===//
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
/// Declarations for the app manager interface, that manages state of Steam
///    applications, their DLC, and Steam Workshop items, in specified directory
///    and provides options for downloading, updating and verifying them.
/// Application manager uses (and creates if it doesn't exist) a directory
///    named `tek-sc-data` in the application directory, where it stores its
///    data, which includes:
///    - State database in the `state.sqlite3` file
///    - Zstandard-compressed depot manifest (`<item_id>_<manifest_id_hex>.zst`)
///        files in the `manifests` subdirectory.
///    - Temporary job files in `jobs/<item_id>` subdirectories:
///        - Depot patch (`patch`), verification cache (`vcache`), delta
///            (`delta`), chunk (`chunk_buf`) and transfer (`transfer_buf`)
///            buffer files.
///        - Download cache for whole files in the `img` subdirectory
///    Where `<item_id>` is `<app_id_hex>-<depot_id_hex>` for regular depots or
///    `<app_id_hex>-<depot_id_hex>-<workshop_item_id_hex>` for Steam Workshop
///    items.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"
#include "content.h"
#include "error.h"
#include "os.h"

#include <stdatomic.h>
#include <stdint.h>

//===-- Types -------------------------------------------------------------===//

/// Opaque application manager instance type.
typedef struct tek_sc_am tek_sc_am;

/// Application manager item status flags.
enum [[clang::flag_enum]] tek_sc_am_item_status {
  /// There is an unfinished job for the item.
  TEK_SC_AM_ITEM_STATUS_job = 1 << 0,
  /// There is an update available for the item.
  TEK_SC_AM_ITEM_STATUS_upd_available = 1 << 1
};
/// @copydoc tek_sc_am_item_status
typedef enum tek_sc_am_item_status tek_sc_am_item_status;

/// Application manager job stages.
enum tek_sc_am_job_stage {
  /// Fetching required data from Steam CM/tek-s3 (depot decryption key, patch
  ///    availability, latest manifest IDs if necessary, SteamPipe server list,
  ///    etc).
  ///
  /// No progress is provided.
  TEK_SC_AM_JOB_STAGE_fetching_data,
  /// Downloading a depot manifest.
  ///
  /// Current progress: Amount of downloaded manifest data, in bytes.
  /// Total progress: Total size of the manifest data, in bytes (becomes
  ///    available after HTTP headers are received).
  TEK_SC_AM_JOB_STAGE_dw_manifest,
  /// Downloading a depot patch.
  ///
  /// Current progress: Amount of downloaded patch data, in bytes.
  /// Total progress: Total size of the patch data, in bytes (becomes available
  ///    after HTTP headers are received).
  TEK_SC_AM_JOB_STAGE_dw_patch,
  /// Verifying item files.
  ///
  /// Current progress: Amount of verified/skipped data, in bytes.
  /// Total progress: Total size of all files listed in the manifest, in bytes.
  TEK_SC_AM_JOB_STAGE_verifying,
  /// Downloading new chunks from SteamPipe.
  ///
  /// Current progress: Amount of downloaded data, in bytes.
  /// Total progress: Total compressed size of all chunks in the delta, in
  ///    bytes.
  TEK_SC_AM_JOB_STAGE_downloading,
  /// Performing transfer operations and truncating files as needed.
  ///
  /// Current progress: Number of bytes read from/written to disk.
  /// Total progress: Total number of bytes to be read/written.
  TEK_SC_AM_JOB_STAGE_patching,
  /// Installing chunks/files downloaded from SteamPipe and creating new files
  ///    and directories as needed.
  ///
  /// Current progress: Number of installed chunks.
  /// Total progress: Total number of chunks in the delta.
  TEK_SC_AM_JOB_STAGE_installing,
  /// Deleting delisted files and directories.
  ///
  /// Current progress: Number of deleted files/directories.
  /// Total progress: Total number of delisted files/directories.
  TEK_SC_AM_JOB_STAGE_deleting,
  /// Deleting remaining job cache files.
  ///
  /// No progress is provided.
  TEK_SC_AM_JOB_STAGE_finalizing
};
/// @copydoc tek_sc_am_job_stage
typedef enum tek_sc_am_job_stage tek_sc_am_job_stage;

/// Application manager job execution state values.
enum tek_sc_am_job_state {
  /// The job is stopped.
  TEK_SC_AM_JOB_STATE_stopped,
  /// The job is running.
  TEK_SC_AM_JOB_STATE_running,
  /// The job has been requested to pause.
  TEK_SC_AM_JOB_STATE_pause_pending
};
/// @copydoc tek_sc_am_job_state
typedef enum tek_sc_am_job_state tek_sc_am_job_state;

/// Application manager patch usage status values.
enum tek_sc_am_job_patch_status {
  /// It hasn't been determined yet if the job needs a patch or not.
  TEK_SC_AM_JOB_PATCH_STATUS_unknown,
  /// There is no patch available for the job.
  TEK_SC_AM_JOB_PATCH_STATUS_unused,
  /// There is a patch available for the job.
  TEK_SC_AM_JOB_PATCH_STATUS_used
};
/// @copydoc tek_sc_am_job_patch_status
typedef enum tek_sc_am_job_patch_status tek_sc_am_job_patch_status;

/// Types of application manager job state updates.
enum [[clang::flag_enum]] tek_sc_am_upd_type {
  /// `state` field value has been changed.
  TEK_SC_AM_UPD_TYPE_state = 1 << 0,
  /// `stage` field value has been changed.
  TEK_SC_AM_UPD_TYPE_stage = 1 << 1,
  /// `progress_current` and/or `progress_total` field values have been changed.
  TEK_SC_AM_UPD_TYPE_progress = 1 << 2,
  /// Fired once right after computing the delta, allowing to inspect `delta`
  ///    field before proceeding.
  TEK_SC_AM_UPD_TYPE_delta_created = 1 << 3
};
/// @copydoc tek_sc_am_upd_type
typedef enum tek_sc_am_upd_type tek_sc_am_upd_type;

/// Application manager job state descriptor.
typedef struct tek_sc_am_job_desc tek_sc_am_job_desc;
/// @copydoc tek_sc_am_job_desc
struct tek_sc_am_job_desc {
  /// Execution state of the job.
  _Atomic(tek_sc_am_job_state) state;
  /// Current job stage
  tek_sc_am_job_stage stage;
  /// Current stage progress value.
  int64_t progress_current;
  /// Total stage progress value.
  int64_t progress_total;
  /// For update jobs, ID of the source manifest, `0` otherwise.
  uint64_t source_manifest_id;
  /// ID of target manifest that the job is updating to or verifying against.
  uint64_t target_manifest_id;
  /// Patch usage status of the job.
  tek_sc_am_job_patch_status patch_status;
  /// Pointer to currently used depot delta object, when available.
  const tek_sc_depot_delta *_Nullable delta;
};

/// Application manager item state descriptor.
typedef struct tek_sc_am_item_desc tek_sc_am_item_desc;
/// @copydoc tek_sc_am_item_desc
struct tek_sc_am_item_desc {
  /// Pointer to the next item descriptor in the list.
  tek_sc_am_item_desc *_Nullable next;
  /// ID of the Steam item described by this structure.
  tek_sc_item_id id;
  /// Current status of the item.
  tek_sc_am_item_status status;
  /// ID of the manifest describing current item installation, `0` if unknown.
  uint64_t current_manifest_id;
  /// ID of the latest manifest available for the item at the moment of last
  ///    update check, `0` if unknown.
  uint64_t latest_manifest_id;
  /// Descriptor for the running job if `status` has
  ///    @ref TEK_SC_AM_ITEM_STATUS_job_running
  tek_sc_am_job_desc job;
};

/// Prototype of application manager job update handler function.
///
/// @param [in] desc
///    Pointer to the item state descriptor whose job has been updated.
/// @param upd_mask
///    Bitmask describing which fields have been changed.
typedef void tek_sc_am_job_upd_func(tek_sc_am_item_desc *_Nonnull desc,
                                    tek_sc_am_upd_type upd_mask);

//===-- Functions ---------------------------------------------------------===//

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Create an application manager instance for specified directory.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to use.
/// @param [in] dir
///    Path to the application installation directory, as a null-terminated
///    string. The parent of this directory must exist.
/// @param [out] err
///    Address of variable that receives the error on failure.
/// @return Pointer to created application manager instance that can be passed
///    to other functions. It must be destroyed with @ref tek_sc_am_destroy
///    after use. `nullptr` may be returned on failure, check @p err for
///    details.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(write_only, 3),
  gnu::null_terminated_string_arg(2)]] tek_sc_am
    *_Nullable tek_sc_am_create(tek_sc_lib_ctx *_Nonnull lib_ctx,
                                const tek_sc_os_char *_Nonnull dir,
                                tek_sc_err *_Nonnull err);

/// Stop all running jobs for an application manager and free its resources.
///
/// @param [in, out] am
///    Pointer to the application manager instance to destroy.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_am_destroy(tek_sc_am *_Nonnull am);

/// Set the base directory for Steam Workshop items.
///
/// @param [in, out] am
///    Pointer to the application manager instance to set the directory for.
/// @param [in] ws_dir
///    Path to the base directory for Steam Workshop items (i.e installation
///    path for these items is assumed to be `<ws_dir>/<ws_item_id>`), as a
///    null-terminated string. The parent of this directory must exist.
///    `nullptr` can be specified to unset the directory and close current one.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
tek_sc_err tek_sc_am_set_ws_dir(tek_sc_am *_Nonnull am,
                                const tek_sc_os_char *_Nullable ws_dir);

/// Get pointer to the state descriptor of specified item.
///
/// @param [in, out] am
///    Pointer to the application manager instance to get state descriptor from.
/// @param [in] item_id
///    Pointer to the ID of the item to get state descriptor for. Pass
///    `nullptr` to get pointer to the first state descriptor in application
///    manager's linked list.
/// @return If @p item_id is `nullptr`, pointer to the first item state
///    descriptor in application manager's linked list if there is any,
///    otherwise pointer to the state descriptor of specified item, or
///    `nullptr` if @p am doesn't have it.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1),
  gnu::access(read_only, 2)]] tek_sc_am_item_desc
    *_Nullable tek_sc_am_get_item_desc(tek_sc_am *_Nonnull am,
                                       const tek_sc_item_id *_Nullable item_id);

/// Lock application manager's internal mutex to prevent it from adding entries
///    to/removing entries from its item state descriptor linked list until
///    @ref tek_sc_am_item_descs_unlock is called.
///
/// @param [in, out] am
///    Pointer to the application manager instance to lock.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_am_item_descs_lock(tek_sc_am *_Nonnull am);

/// Unock application manager's internal mutex previously locked by
///    @ref tek_sc_am_item_descs_lock.
///
/// @param [in, out] am
///    Pointer to the application manager instance to unlock.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_am_item_descs_unlock(tek_sc_am *_Nonnull am);

/// Check for item updates on specified application manager instance.
/// On success, this will update `latest_manifest_id` field on all item
///    descriptors in the manager's linked list.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will run the check.
/// @param timeout_ms
///    Timeout for response messages, in milliseconds. Applies to each CM
///    request individually, not to the whole operation. The function may send
///    up to 5 CM requests, so in worst case it may be assumed to take
///    `timeout_ms * 5` ms to run.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
tek_sc_err tek_sc_am_check_for_upds(tek_sc_am *_Nonnull am, long timeout_ms);

/// Create an application manager job for specified item.
///
/// If current manifest ID for the item is unknown (item's
///    @ref tek_sc_am_item_desc is not present or has `current_manifest_id` set
///    to `0`) or `force_verify` is `true`, the job will perform a verification,
///    that is comparing all local files of the item and their data against
///    manifest entries to determine mismatching and missing ones, and produce a
///    delta from it. If delta is empty (all entries match),
///    @ref tek_sc_am_run_job will return @ref tek_sc_err with `primary` set to
///    @ref TEK_SC_ERRC_up_to_date.
/// If current manifest ID is `manifest_id`, @ref tek_sc_am_run_job will return
///    a @ref tek_sc_err with `primary` set to @ref TEK_SC_ERRC_up_to_date
///    immediately.
/// Otherwise, the job will compute a delta between current manifest and
///    @p manifest_id.
///
/// @param [in, out] am
///    Pointer to the application manager instance that the job will belong to.
/// @param [in] item_id
///    Pointer to the ID of the item to run the job for.
/// @param manifest_id
///    ID of the manifest to update to/verify against. Can be set to `0` to use
///    `latest_manifest_id` from the item's @ref tek_sc_am_item_desc if
///    available, or fetch latest from Steam CM if not. Can be set to
///    `UINT64_MAX` to uninstall the item.
/// @param force_verify
///    Value indicating whether to perform verification even if it can be
///    avoided (e.g no update is required or current manifest ID is known before
///    update).
/// @param [out] item_desc
///    Optional address of variable that on success receives pointer to the
///    @ref tek_sc_am_item_desc for the item.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(write_only, 5)]]
tek_sc_err
tek_sc_am_create_job(tek_sc_am *_Nonnull am,
                     const tek_sc_item_id *_Nonnull item_id,
                     uint64_t manifest_id, bool force_verify,
                     tek_sc_am_item_desc *_Nullable *_Nullable item_desc);

/// Run/resume an application manager job.
///
/// The job may be running for a long time, so in GUI applications it's
///    recommended to call this function in its own thread.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will run the job.
/// @param [in, out] item_desc
///    Pointer to the item state descriptor whose job is to be run.
/// @param upd_handler
///    Optional pointer to the job update handler function to use.
/// @return A @ref tek_sc_err indicating the result of the job. There are
///    `primary` values with special meaning: @ref TEK_SC_ERRC_up_to_date
///    indicates that there is no update available, or verification found no
///    mismatches; @ref TEK_SC_ERRC_paused indicates that the job has been
///    paused.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2), clang::callback(upd_handler, __, __)]]
tek_sc_err tek_sc_am_run_job(tek_sc_am *_Nonnull am,
                             tek_sc_am_item_desc *_Nonnull item_desc,
                             tek_sc_am_job_upd_func *_Nullable upd_handler);

/// Request specified job to pause.
///
/// @param [in, out] item_desc
///    Pointer to the item state descriptor whose job is to be paused.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_am_pause_job(tek_sc_am_item_desc *_Nonnull item_desc);

/// Cancel specified job, that is clean its cache directory and reset the state.
///    If the job is running, the function will request it to pause and wait for
///    it to stop first.
///
/// @param [in, out] am
///    Pointer to the application manager instance to cancel the job for.
/// @param [in, out] item_desc
///    Pointer to the item state descriptor whose job is to be cancelled.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_write, 2)]]
tek_sc_err tek_sc_am_cancel_job(tek_sc_am *_Nonnull am,
                                tek_sc_am_item_desc *_Nonnull item_desc);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
