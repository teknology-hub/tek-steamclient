//===-- common.h - common tek-sc-cli declarations -------------------------===//
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
/// Declarations of types, global variables and functions used across multiple
///    modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "config.h"
#ifdef TEK_SCB_AM
#include "tek-steamclient/am.h"
#endif // def TEK_SCB_AM
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <stdatomic.h>
#include <stdint.h>
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

/// Global tek-sc-cli context.
typedef struct tscl_ctx tscl_ctx;
/// @copydoc tscl_ctx
struct tscl_ctx {
  /// Pointer to the tek-steamclient library context.
  tek_sc_lib_ctx *_Nonnull lib_ctx;
#ifdef TEK_SCB_AM
  /// Pointer to the application manager instance.
  tek_sc_am *_Nonnull am;
  /// Path to the current application manager directory, as a heap-allocated
  ///    null-terminated string.
  tek_sc_os_char *_Nullable am_path;
#endif // def TEK_SCB_AM
  /// Value indicating whether the program is terminating.
  _Atomic(uint32_t) terminating;
  /// Value indicating whether the program is running in interactive mode.
  bool interactive;
};

#ifdef TEK_SCB_CLI_DUMP
/// tek-steamclient content file types for dumping.
enum tscl_dump_type {
  /// Depot manifest.
  TSCL_DUMP_TYPE_manifest,
  /// Depot patch.
  TSCL_DUMP_TYPE_patch,
  /// Verification cache.
  TSCL_DUMP_TYPE_vcache,
  /// Depot delta.
  TSCL_DUMP_TYPE_delta
};
/// @copydoc tscl_dump_type
typedef enum tscl_dump_type tscl_dump_type;
#endif // def TEK_SCB_CLI_DUMP

#ifdef TEK_SCB_S3C
/// tek-s3 authentication types.
enum tscl_s3_auth_type {
  /// Credentials-based authentication.
  TSCL_S3_AUTH_TYPE_credentials,
  /// QR code-based authentication.
  TSCL_S3_AUTH_TYPE_qr
};
/// @copydoc tscl_s3_auth_type
typedef enum tscl_s3_auth_type tscl_s3_auth_type;
#endif // def TEK_SCB_S3C

/// Command types.
enum tscl_cmd_type {
  /// Display help message.
  TSCL_CMD_TYPE_help,
  /// Exit the program.
  TSCL_CMD_TYPE_exit,
#ifdef TEK_SCB_AM
  /// Initialize application manager at specified directory.
  TSCL_CMD_TYPE_am_init,
  /// Destroy current application manager instance.
  TSCL_CMD_TYPE_am_close,
  /// Set Steam Workshop directory path for current application manager
  ///    instance.
  TSCL_CMD_TYPE_am_set_workshop_dir,
  /// Get current status of all items managed by current application manager
  ///    instance.
  TSCL_CMD_TYPE_am_status,
  /// Check for item updates.
  TSCL_CMD_TYPE_am_check_for_updates,
  /// Create an application manager job.
  TSCL_CMD_TYPE_am_create_job,
  /// Run/resume an application manager job.
  TSCL_CMD_TYPE_am_run_job,
  /// Cancel an application manager job.
  TSCL_CMD_TYPE_am_cancel_job,
#ifdef TEK_SCB_CLI_DUMP
  /// Dump specified tek-steamclient content file into a human-readable text
  ///    file at current working directory.
  TSCL_CMD_TYPE_am_dump,
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
  /// Synchronize manifest of tek-s3 server at specified URL.
  TSCL_CMD_TYPE_s3c_sync_manifest,
  /// Submit a Steam account to a tek-s3 server at specified URL.
  TSCL_CMD_TYPE_s3c_signin
#endif // def TEK_SCB_S3C
};
/// @copydoc tscl_cmd_type
typedef enum tscl_cmd_type tscl_cmd_type;

/// Command descriptor.
typedef struct tscl_command tscl_command;
/// @copydoc tscl_command
struct tscl_command {
  /// Type of the command.
  tscl_cmd_type type;
  union {
    /// So the union is not empty if none of build options are set.
    int unused;
#ifdef TEK_SCB_AM
    /// "am init" command arguments.
    struct {
      /// Path to the directory to initialize application manager at, as a
      ///    null-terminated string. Empty string implies current working
      ///    directory.
      const tek_sc_os_char *_Nullable path;
    } am_init;
    /// "am set-workshop-dir" command arguments.
    struct {
      /// Path to the directory to use for Steam Workshop items, as a
      ///    null-terminated string.
      const tek_sc_os_char *_Nonnull path;
    } am_set_workshop_dir;
    /// "am create-job" command arguments.
    struct {
      /// ID of the item to create a job for.
      tek_sc_item_id item_id;
      /// ID of the manifest to update to/verify against.
      uint64_t manifest_id;
      /// Value indicating whether file verification will still be performed
      ///    even if it's otherwise not necessary.
      bool force_verify;
    } am_create_job;
    /// "am run-job" command arguments.
    struct {
      /// ID of the item to run/resume job for.
      tek_sc_item_id item_id;
    } am_run_job;
    /// "am cancel-job" command arguments.
    struct {
      /// ID of the item to cancel job for.
      tek_sc_item_id item_id;
    } am_cancel_job;
#ifdef TEK_SCB_CLI_DUMP
    /// "am dump" command arguments.
    struct {
      /// Type of the file to dump.
      tscl_dump_type type;
      /// ID of the item to dump the file for.
      tek_sc_item_id item_id;
      /// If @ref type is @ref TSCL_DUMP_TYPE_manifest, ID of the manifest to
      ///    dump.
      uint64_t manifest_id;
    } am_dump;
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
    /// "s3c sync-manifest" command arguments.
    struct {
      /// URL of the tek-s3 server to synchronize manifest for. Must be freed
      ///    with `free` after use.
      const char *_Nonnull url;
    } s3c_sync_manifest;
    /// "s3c signin" command arguments.
    struct {
      /// Chosen authentication type.
      tscl_s3_auth_type type;
      /// URL of the tek-s3 server to submit Steam account to. Must be freed
      ///    with `free` after use.
      const char *_Nonnull url;
    } s3c_signin;
#endif // def TEK_SCB_S3C
  }; // union
};

/// Global instance of @ref tscl_ctx.
extern tscl_ctx tscl_g_ctx;

/// Display an error message for specified tek-steamclient error.
///
/// @param [in] err
///    Pointer to the tek-steamclient error object to display message for.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1)]]
void tscl_print_err(const tek_sc_err *_Nonnull err);

/// Process command-line arguments.
///
/// @param argc
///    Number of arguments passed to the program. Assumed to be >= 2.
/// @param [in] argv
///    Pointer to the array of arguments passed to the program.
/// @param [out] cmds
///    If return value is non-zero, pointer to heap-allocated array of
///    descriptors for parsed commands. The returned pointer must be freed with
///    `free` after use.
/// @return Number of parsed commands in @p cmds, if any. `-1` is returned if a
///    command parsing error occurs.
[[gnu::visibility("internal"), gnu::nonnull(2, 3), gnu::access(read_only, 2, 1),
  gnu::access(write_only, 3)]]
int tscl_process_args(int argc, tek_sc_os_char *_Nonnull *_Nonnull argv,
                      tscl_command *_Nullable *_Nonnull cmds);

/// Parse a command.
///
/// @param argc
///    Number of elements in @p argv.
/// @param [in] argv
///    Pointer to the array of strings that make up the command.
/// @param ind
///    Index of the first element of @p argv to parse.
/// @param [out] cmd
///    Address of variable that receives the parsed command descriptor on
///    success.
/// @return On success, index of the next element of @p argv after the last
///    element that is part of parsed command, otherwise `0`.
[[gnu::visibility("internal"), gnu::nonnull(2, 4), gnu::access(read_only, 2, 1),
  gnu::access(write_only, 4)]]
int tscl_parse_cmd(int argc, tek_sc_os_char *_Nonnull *_Nonnull argv, int ind,
                   tscl_command *_Nonnull cmd);

/// Run a command.
///
/// @param [in] cmd
///    Pointer to the descriptor of the command to run.
/// @return Value indicating whether execution succeeded.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1)]]
bool tscl_run_cmd(const tscl_command *_Nonnull cmd);
