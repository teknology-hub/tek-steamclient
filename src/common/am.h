//===-- am.h - Steam application manager internal interface ---------------===//
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
/// Declarations of common types and functions to be used by application manager
///    implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/cm.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"
#include "tek-steamclient/sp.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

//===-- Types -------------------------------------------------------------===//

/// Types of requests to send after CM client has established connection and
///    signed in.
enum tsci_am_pending_cm_req {
  /// Request PICS changes.
  TSCI_AM_PENDING_CM_REQ_changes,
  /// Request app's latest manifest IDs.
  TSCI_AM_PENDING_CM_REQ_app_man_ids,
  /// Request Steam Workshop item's latest manifest ID.
  TSCI_AM_PENDING_CM_REQ_ws_man_id,
  /// Request SteamPipe server list.
  TSCI_AM_PENDING_CM_REQ_sp_servers,
  /// Request depot decryption key.
  TSCI_AM_PENDING_CM_REQ_depot_key,
  /// Request manifest request code.
  TSCI_AM_PENDING_CM_REQ_mrc,
  /// Request patch availability information.
  TSCI_AM_PENDING_CM_REQ_patch_info
};
/// @copydoc tek_sc_am_pending_cm_req
typedef enum tsci_am_pending_cm_req tsci_am_pending_cm_req;

/// Application manager item state descriptor extended with internal fields.
typedef struct tsci_am_item_desc tsci_am_item_desc;
/// @copydoc tek_sc_am_item_desc
struct tsci_am_item_desc {
  /// Public part of the descriptor.
  tek_sc_am_item_desc desc;
  /// Pointer to current job state update handler function.
  tek_sc_am_job_upd_func *_Nullable job_upd_handler;
  /// Pointer to the SteamPipe multi downloader instance currently used by the
  ///    job. If not `nullptr`, used by @ref tek_sc_am_pause_job to cancel the
  ///    downloads.
  tek_sc_sp_multi_dlr *_Nullable dlr;
  /// Flag for cancelling SteamPipe manifest and patch downloads.
  atomic_bool sp_cancel_flag;
};

/// Application manager running job context.
typedef struct tsci_am_job_ctx tsci_am_job_ctx;

/// Application manager's CM client context.
typedef struct tsci_am_cm_ctx tsci_am_cm_ctx;
/// @copydoc tsci_am_cm_ctx
struct tsci_am_cm_ctx {
  /// Mutex locking concurrent CM requests.
  pthread_mutex_t mtx;
  /// Type of request to send after CM client has established connection and
  ///    signed in.
  tsci_am_pending_cm_req pending_req;
  /// The number of remaining CM response messages to receive before the
  ///    request can be marked as completed.
  int num_rem_reqs;
  /// Timeout for CM requests, in milliseconds.
  long timeout;
  /// Changenumber received from CM that is awaiting other responses before
  ///    being applied.
  uint32_t pending_changenum;
  /// Value set to `1` when CM request is completed.
  _Atomic(uint32_t) completed;
  /// Pointer to the ID of the item to perform request for.
  const tek_sc_item_id *_Nullable item_id;
  union {
    /// Pointer to the job context that receives SteamPipe server list.
    tsci_am_job_ctx *_Nonnull job_ctx;
    /// ID of the manifest to perform request for.
    uint64_t manifest_id;
    /// ID of the source manifest for patching.
    uint64_t source_manifest_id;
    /// Returned manifest request code.
    uint64_t mrc;
    /// Value indicating whether a patch is available for specified manifests.
    bool patch_available;
  };
  /// ID of the target manifest for patching.
  uint64_t target_manifest_id;
  /// Result of the last CM request.
  tek_sc_err result;
};

/// @copydoc tek_sc_am_job_ctx
struct tsci_am_job_ctx {
  /// Pointer to the array of SteamPipe server entries.
  tek_sc_cm_sp_srv_entry *_Nullable sp_srvs;
  /// Number of entries pointed to by @ref sp_srvs.
  int num_sp_srvs;
  /// Number of logical processors in the system, and hence the number of
  ///    threads created on paralleled job stages.
  int nproc;
  /// Handle for the job directory.
  tek_sc_os_handle dir_handle;
  /// Handle for the download cache image directory.
  tek_sc_os_handle img_dir_handle;
  /// Source depot manifest instance.
  tek_sc_depot_manifest source_manifest;
  /// Target depot manifest instance.
  tek_sc_depot_manifest target_manifest;
  /// Depot patch instance.
  tek_sc_depot_patch patch;
  /// Depot delta instance.
  tek_sc_depot_delta delta;
};

/// @copydoc tek_sc_am
struct tek_sc_am {
  /// Pointer to the library context to use.
  tek_sc_lib_ctx *_Nonnull lib_ctx;
  /// Head of the linked list of item state descriptors.
  tsci_am_item_desc *_Nullable item_descs;
  /// Mutex locking concurrent modification access (adding/removing entries) to
  ///    @ref item_descs.
  pthread_mutex_t item_descs_mtx;
  /// Handle for the root installation directory.
  tek_sc_os_handle inst_dir_handle;
  /// Handle for the `tek-sc-data` subdirectory.
  tek_sc_os_handle data_dir_handle;
  /// Handle for the base directory for Steam Workshop items.
  tek_sc_os_handle ws_dir_handle;
  /// Last recorded Steam changenumber. Used for update checks.
  uint32_t changenum;
  /// Pointer to the Steam CM client instance for fetching data.
  tek_sc_cm_client *_Nonnull cm_client;
  /// State database connection handle.
  sqlite3 *_Nonnull db;
  /// CM client state.
  tsci_am_cm_ctx cm_ctx;
};

//===-- Functions ---------------------------------------------------------===//

/// Three-way compare two @ref tek_sc_item_id values.
///
/// @param [in] left
///    Pointer to the first item identifier to compare.
/// @param [in] right
///    Pointer to the second item identifier to compare.
/// @return `0` if the item identifiers are equal, a negative value if @p left
///    is less than @p right, or a positive value if @p left is greater than
///    @p right.
[[gnu::nothrow, gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(read_only, 2)]]
static inline int tsci_am_cmp_item_id(const tek_sc_item_id *_Nonnull left,
                                      const tek_sc_item_id *_Nonnull right) {
  if (left->app_id != right->app_id) {
    return left->app_id < right->app_id ? -1 : 1;
  }
  if (left->depot_id != right->depot_id) {
    return left->depot_id < right->depot_id ? -1 : 1;
  }
  if (left->ws_item_id != right->ws_item_id) {
    return left->ws_item_id < right->ws_item_id ? -1 : 1;
  }
  return 0;
}

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

//===-- General functions -------------------------------------------------===//

/// Propagate directory job stage completion to its ancestors.
///
/// @param [in, out] dir
///    Pointer to the delta directory entry being finished.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_write, 1)]]
void tsci_am_job_finish_dir(tek_sc_dd_dir *_Nonnull dir);

/// Cleanup and delete a job cache directory.
///
/// @param data_dir_handle
///    Handle for the `tek-sc-data` directory.
/// @param [in] item_id
///    Pointer to the ID of the item to delete job directory for.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::nonnull(2), gnu::access(read_only, 2)]]
tek_sc_err tsci_am_clean_job_dir(tek_sc_os_handle data_dir_handle,
                                 const tek_sc_item_id *_Nonnull item_id);

/// Parse a Steam application's info VDF and extract latest manifest IDs from
///    it.
///
/// @param [in, out] am
///    Pointer to the application manager instance whose items will receive new
///    latest manifest IDs.
/// @param [in] buf
///    Pointer to the buffer containing application info in VDF format to parse.
/// @param len
///    Number of bytes to read from @p buf.
/// @return Value indicating whether parsing succeeded or an error has occurred.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2, 3)]]
bool tsci_am_parse_app_info(tek_sc_am *_Nonnull am, const char *_Nonnull buf,
                            size_t len);

//===-- CM request functions ----------------------------------------------===//

/// Get latest manifest ID for specified item from Steam CM.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will perform the
///    request.
/// @param [in] item_id
///    Pointer to the ID of the item to get latest manifest ID for.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2)]]
tek_sc_err tsci_am_get_latest_man_id(tek_sc_am *_Nonnull am,
                                     const tek_sc_item_id *_Nonnull item_id);

/// Get SteamPipe server list from Steam CM.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will perform the
///    request.
/// @param [out] ctx
///    Pointer to the job context that receives the server list on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(write_only, 2)]]
tek_sc_err tsci_am_get_sp_servers(tek_sc_am *_Nonnull am,
                                  tsci_am_job_ctx *_Nonnull ctx);

/// Get decryption key for specified depot from Steam CM.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will perform the
///    request.
/// @param [in] item_id
///    Pointer to the ID of the item to get depot decryption key for.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2)]]
tek_sc_err tsci_am_get_depot_key(tek_sc_am *_Nonnull am,
                                 const tek_sc_item_id *_Nonnull item_id);

/// Get a manifest request code from Steam CM.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will perform the
///    request.
/// @param [in] item_id
///    Pointer to the ID of the item that the manifest belongs to.
/// @param manifest_id
///    ID of the manifest to get request code for.
/// @param [out] mrc
///    Address of variable that receives the manifest request code on success.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 4),
  gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(write_only, 4)]]
tek_sc_err tsci_am_get_mrc(tek_sc_am *_Nonnull am,
                           const tek_sc_item_id *_Nonnull item_id,
                           uint64_t manifest_id, uint64_t *_Nonnull mrc);

/// Get patch availability information from Steam CM.
///
/// @param [in, out] am
///    Pointer to the application manager instance that will perform the
///    request.
/// @param [in] item_id
///    Pointer to the ID of the item that the manifests belong to.
/// @param source_manifest_id
///    ID of the source manifest for patching.
/// @param target_manifest_id
///    ID of the target manifest for patching.
/// @param [out] available
///    Address of variable that receives the value indicating if the patch is
///    available for specified manifests.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 5),
  gnu::access(read_write, 1), gnu::access(read_only, 2),
  gnu::access(write_only, 5)]]
tek_sc_err tsci_am_get_patch_info(tek_sc_am *_Nonnull am,
                                  const tek_sc_item_id *_Nonnull item_id,
                                  uint64_t source_manifest_id,
                                  uint64_t target_manifest_id,
                                  bool *_Nonnull available);

//===-- Job stage runners -------------------------------------------------===//

/// Verify item installation and determine if it's up to date, compute a delta
///    if it's not.
///
/// @param [in, out] am
///    Pointer to the application manager instance running the job.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tsci_am_job_verify(tek_sc_am *_Nonnull am,
                              tsci_am_item_desc *_Nonnull desc,
                              tsci_am_job_ctx *_Nonnull ctx);

/// Download new chunks from SteamPipe.
///
/// @param [in, out] am
///    Pointer to the application manager instance running the job.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tsci_am_job_download(tek_sc_am *_Nonnull am,
                                tsci_am_item_desc *_Nonnull desc,
                                tsci_am_job_ctx *_Nonnull ctx);

/// Move/copy downloaded data to the installation and create new files and
///    directories if needed.
///
/// @param [in, out] am
///    Pointer to the application manager instance running the job.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tsci_am_job_install(tek_sc_am *_Nonnull am,
                               tsci_am_item_desc *_Nonnull desc,
                               tsci_am_job_ctx *_Nonnull ctx);

/// Perform transfer operations and file truncations.
///
/// @param [in, out] am
///    Pointer to the application manager instance running the job.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tsci_am_job_patch(tek_sc_am *_Nonnull am,
                             tsci_am_item_desc *_Nonnull desc,
                             tsci_am_job_ctx *_Nonnull ctx);

/// Delete delisted files and directories.
///
/// @param [in, out] am
///    Pointer to the application manager instance running the job.
/// @param [in, out] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param [in, out] ctx
///    Pointer to the job context.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_write, 3)]]
tek_sc_err tsci_am_job_delete(tek_sc_am *_Nonnull am,
                              tsci_am_item_desc *_Nonnull desc,
                              tsci_am_job_ctx *_Nonnull ctx);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
