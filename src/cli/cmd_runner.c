//===-- cmd_runner.c - command runner -------------------------------------===//
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
/// Implementation of tek-sc-cli command runner.
///
//===----------------------------------------------------------------------===//
#include "common.h"

#include "config.h"
#include "os.h"
#include "tek-steamclient/base.h"
#ifdef TEK_SCB_AM
#include "tek-steamclient/am.h"
#ifdef TEK_SCB_CLI_DUMP
#include "dump.h"
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#include "tek-steamclient/error.h"
#ifdef TEK_SCB_S3C
#include "tek-steamclient/s3c.h"
#endif // def TEK_SCB_S3C

#include <ctype.h>
#include <inttypes.h>
#ifdef TEK_SCB_QR
#include <qrencode.h>
#endif // def TEK_SCB_QR
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEK_SCB_AM
/// Pointer to the state descriptor of the item that current job is operating
/// on.
static tek_sc_am_item_desc *_Nullable tscl_job_desc;
#endif // def TEK_SCB_AM

//===-- Private functions -------------------------------------------------===//

#ifdef TEK_SCB_AM
/// Job state update handler.
///
/// @param [in] desc
///    Pointer to the state descriptor of the item that the job is operating on.
/// @param types
///    Bitmask of job state update types.
[[gnu::nonnull(1), gnu::access(read_only, 1)]]
static void tscl_upd_handler(tek_sc_am_item_desc *_Nonnull desc,
                             tek_sc_am_upd_type types) {
  if (types & TEK_SC_AM_UPD_TYPE_delta_created) {
    auto const disk_space = tscl_os_get_disk_free_space(tscl_g_ctx.am_path);
    if (disk_space < 0) {
      return;
    }
    auto const req_space = tek_sc_dd_estimate_disk_space(desc->job.delta);
    if (disk_space >= req_space) {
      return;
    }
    if (tscl_g_ctx.interactive) {
      // L18N: Message displayed when not enough disk space is available, in
      //    interactive mode. First %.2f is the amount of required disk space,
      //    second %.2f is the number of available disk space, both in gibibytes
      printf(tsc_gettext("The job is estimated to require %.2f GiB of disk "
                         "space, but only %.2f GiB is available on the "
                         "disk.\nDo you want to proceed anyway? [Y/N]: "),
             (double)req_space / 0x40000000, (double)disk_space / 0x40000000);
      fflush(stdout);
      char buf[16];
      while (fgets(buf, sizeof buf, stdin)) {
        const int ans = tolower(buf[0]);
        if (ans == 'y' || ans == 'n') {
          if (ans == 'n') {
            tek_sc_am_pause_job(desc);
          }
          break;
        }
        puts(tsc_gettext("Unrecognized input. Please answer Y or N."));
      }
    } else {
      fprintf(stderr,
              // L18N: Message displayed when not enough disk space is
              //    available, in non-interactive mode. First %.2f is the amount
              //    of required disk space, second %.2f is the number of
              //    available disk space, both in gibibytes
              tsc_gettext(
                  "Warning: The job is estimated to require %.2f GiB of disk "
                  "space, but only %.2f GiB is available on the disk.\n"),
              (double)req_space / 0x40000000, (double)disk_space / 0x40000000);
    }
    return;
  }
  if (types & TEK_SC_AM_UPD_TYPE_state) {
    switch (desc->job.state) {
    case TEK_SC_AM_JOB_STATE_running: {
      char item_id[43];
      snprintf(item_id, sizeof item_id,
               desc->id.ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                                   : "%" PRIu32 "-%" PRIu32,
               desc->id.app_id, desc->id.depot_id, desc->id.ws_item_id);
      // L18N: Job state notification. %s is the item ID
      printf(tsc_gettext("Starting the job for %s\n"), item_id);
      break;
    }
    case TEK_SC_AM_JOB_STATE_pause_pending:
      puts(tsc_gettext("\nA pause has been requested for the job"));
      break;
    default:
    }
  }
  if (!tscl_g_ctx.interactive) {
    return;
  }
  static int64_t start_progress;
  static uint64_t start_ticks;
  static int64_t previous;
  static int num_width;
  const bool stage_upd = types & TEK_SC_AM_UPD_TYPE_stage;
  if (stage_upd) {
    const char *stage_str;
    switch (desc->job.stage) {
    case TEK_SC_AM_JOB_STAGE_fetching_data:
      // L18N: Job stage name
      stage_str = tsc_gettext("Fetching data");
      break;
    case TEK_SC_AM_JOB_STAGE_dw_manifest:
      // L18N: Job stage name
      stage_str = tsc_gettext("Downloading manifest");
      break;
    case TEK_SC_AM_JOB_STAGE_dw_patch:
      // L18N: Job stage name
      stage_str = tsc_gettext("Downloading patch");
      break;
    case TEK_SC_AM_JOB_STAGE_verifying:
      // L18N: Job stage name
      stage_str = tsc_gettext("Verifying installed files");
      break;
    case TEK_SC_AM_JOB_STAGE_downloading:
      // L18N: Job stage name
      stage_str = tsc_gettext("Downloading new data");
      break;
    case TEK_SC_AM_JOB_STAGE_patching:
      // L18N: Job stage name
      stage_str = tsc_gettext("Patching");
      break;
    case TEK_SC_AM_JOB_STAGE_installing:
      // L18N: Job stage name
      stage_str = tsc_gettext("Installing new data");
      break;
    case TEK_SC_AM_JOB_STAGE_deleting:
      // L18N: Job stage name
      stage_str = tsc_gettext("Deleting delisted content");
      break;
    case TEK_SC_AM_JOB_STAGE_finalizing:
      // L18N: Job stage name
      stage_str = tsc_gettext("Finalizing");
      break;
    default:
      // L18N: Job stage name
      stage_str = tsc_gettext("Unknown stage");
    }
    fputs("\033[2K\r", stdout);
    // L18N: Job stage notification. %s is a job stage name from above
    printf(tsc_gettext("Job stage updated: %s\n"), stage_str);
    start_progress =
        (types & TEK_SC_AM_UPD_TYPE_progress) ? desc->job.progress_current : 0;
    start_ticks = tscl_os_get_ticks();
    previous = 0;
    num_width = 0;
  }
  if (types & TEK_SC_AM_UPD_TYPE_progress) {
    auto const total = desc->job.progress_total;
    static uint64_t prev_ticks;
    auto const cur_ticks = stage_upd ? start_ticks + 1 : tscl_os_get_ticks();
    auto const prev_ticks_val = prev_ticks;
    auto const current = desc->job.progress_current;
    if (current && current < total && (cur_ticks - prev_ticks_val) < 1000) {
      return;
    }
    prev_ticks = cur_ticks;
    auto const previous_val = previous;
    previous = current;
    // Build progress bar
    const int tenths = (double)(current * 10) / (double)total;
    char bar[11];
    for (int i = 0; i < 10; ++i) {
      if (i < tenths) {
        bar[i] = '=';
      } else if (i == tenths) {
        bar[i] = '>';
      } else {
        bar[i] = ' ';
      }
    }
    bar[10] = '\0';
    char eta_buf[64];
    eta_buf[0] = '\0';
    if (!stage_upd) {
      // Compute ETA (in seconds)
      // L18N: Appended to the progress message when ETA is available
      tscl_os_strlcat_utf8(eta_buf, tsc_gettext(", ETA: "), sizeof eta_buf);
      const int64_t eta = (double)(total - current) /
                          ((double)(current - start_progress) /
                           ((double)(cur_ticks - start_ticks) / 1000.0));
      char unit_buf[16];
      bool first_unit = true;
      if (eta > 3600) {
        // L18N: Appended to the ETA message above. %u is the number of hours
        snprintf(unit_buf, sizeof unit_buf, tsc_gettext("%uh"),
                 (unsigned)(eta / 3600));
        tscl_os_strlcat_utf8(eta_buf, unit_buf, sizeof eta_buf);
        first_unit = false;
      }
      const unsigned mins = (eta % 3600) / 60;
      if (mins) {
        if (!first_unit) {
          tscl_os_strlcat_utf8(eta_buf, " ", sizeof eta_buf);
        }
        // L18N: Appended to the ETA message above. %u is the number of minutes
        snprintf(unit_buf, sizeof unit_buf, tsc_gettext("%umin"), mins);
        tscl_os_strlcat_utf8(eta_buf, unit_buf, sizeof eta_buf);
        first_unit = false;
      }
      const unsigned secs = eta % 60;
      if (eta < 600 && secs) {
        if (!first_unit) {
          tscl_os_strlcat_utf8(eta_buf, " ", sizeof eta_buf);
        }
        // L18N: Appended to the ETA message above. %u is the number of seconds
        snprintf(unit_buf, sizeof unit_buf, tsc_gettext("%usec"), secs);
        tscl_os_strlcat_utf8(eta_buf, unit_buf, sizeof eta_buf);
      }
    }
    fputs("\033[2K\r", stdout);
    switch (desc->job.stage) {
    case TEK_SC_AM_JOB_STAGE_verifying:
    case TEK_SC_AM_JOB_STAGE_patching:
      // L18N: Progress message for stages that display percentage only. First
      //    %s is improvised progress bar, %6.2f is the percentage number,
      //    second %s is the ETA message if available
      printf(tsc_gettext("[%s] %6.2f%%%s"), bar,
             (double)(current * 100) / (double)total, eta_buf);
      break;
    case TEK_SC_AM_JOB_STAGE_dw_manifest:
    case TEK_SC_AM_JOB_STAGE_dw_patch:
    case TEK_SC_AM_JOB_STAGE_downloading: {
      // Bytes display with speed
      char cur_buf[32];
      cur_buf[0] = '\0';
      if (current >= 0x40000000) { // 1 GiB
        // L18N: %.2f is the number of gibibytes for progress display
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%.2f GiB"),
                 (double)current / 0x40000000);
      } else if (current >= 0x100000) { // 1 MiB
        // L18N: %.1f is the number of mebibytes for progress display
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%.1f MiB"),
                 (double)current / 0x100000);
      } else {
        // L18N: %u is the number of kibibytes for progress display
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%u KiB"),
                 (unsigned)current / 0x400);
      }
      char total_buf[32];
      total_buf[0] = '\0';
      if (total >= 0x40000000) { // 1 GiB
        // L18N: %.2f is the number of gibibytes for progress display
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%.2f GiB"),
                 (double)total / 0x40000000);
      } else if (total >= 0x100000) { // 1 MiB
        // L18N: %.1f is the number of mebibytes for progress display
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%.1f MiB"),
                 (double)total / 0x100000);
      } else {
        // L18N: %u is the number of kibibytes for progress display
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%u KiB"),
                 (unsigned)total / 0x400);
      }
      const double speed = (double)((current - previous_val) * 8000) /
                           (double)(cur_ticks - prev_ticks_val);
      char speed_buf[32];
      speed_buf[0] = '\0';
      if (speed >= 1000000000) { // 1 Gbit/s
        // L18N: %.2f is the number of gigabits/second for download speed
        //    display
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%.2f Gbit/s"),
                 speed / 1000000000);
      } else if (speed >= 1000000) { // 1 Mbit/s
        // L18N: %.1f is the number of megabits/second for download speed
        //    display
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%.1f Mbit/s"),
                 speed / 1000000);
      } else {
        // L18N: %u is the number of kilobits/second for download speed
        //    display
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%u kbit/s"),
                 (unsigned)speed / 1000);
      }
      // L18N: Progress message for download stages. First %s is improvised
      //    progress bar, %12s is the current progress, first %-12s is the total
      //    progress, second %-12f is the speed, second %s is the ETA message if
      //    available. Both progress and speed strings are created via one of
      //    the format strings above
      printf(tsc_gettext("[%s] %12s/%-12s (%-12s)%s"), bar, cur_buf, total_buf,
             speed_buf, eta_buf);
      break;
    }
    case TEK_SC_AM_JOB_STAGE_installing:
    case TEK_SC_AM_JOB_STAGE_deleting: {
      // Plain numbers display
      if (!num_width) {
        num_width = snprintf(nullptr, 0, "%llu", (unsigned long long)total);
      }
      // L18N: Progress message for stages that use plain numbers. First %s is
      //    improvised progress bar, %*llu is the current progress number, %llu
      //    is the total progress number, second %s is the ETA message if
      //    available
      printf(tsc_gettext("[%s] %*llu/%llu%s"), bar, num_width,
             (unsigned long long)current, (unsigned long long)total, eta_buf);
      break;
    }
    default:
      return;
    } // switch (desc->job.stage)
    fflush(stdout);
  } // if (types & TEK_SC_AM_UPD_TYPE_progress)
  return;
}

/// Signal handler for application manager job.
static void tscl_job_sig_handler() { tek_sc_am_pause_job(tscl_job_desc); }
#endif // def TEK_SCB_AM

//===-- Internal function -------------------------------------------------===//

bool tscl_run_cmd(const tscl_command *cmd) {
  switch (cmd->type) {
  case TSCL_CMD_TYPE_help:
    // L18N: output of tek-sc-cli's "help" command (main part)
    // Here and further, command names cannot be translated; you may however
    //    translate stuff in <angled brackets>, but make sure to use the same
    //    translations in other messages that reference them, e.g. error ones
    puts(tsc_gettext("General commands:\n"
                     "  help - Display this message\n"
                     "  exit - Exit the program\n"
                     "  quit - Synonym for \"exit\""));
#ifdef TEK_SCB_AM
    // L18N: output of tek-sc-cli's "help" command (application manager module).
    puts(tsc_gettext(
        "Application manager commands:\n"
        "  am init <path> - Initialize application manager at specified "
        "directory, allowing the following commands to be used. Specifying "
        "<path> as empty string (\"\") implies using current working "
        "directory\n"
        "  am close - Close current application manager instance, allowing it "
        "to be initialized in another directory later\n"
        "  am set-workshop-dir <path> - Set Steam Workshop directory path for "
        "current application manager instance. You cannot run jobs for Steam "
        "Workshop items before executing this command\n"
        "  am status - Get current status of all items managed by current "
        "application manager instance\n"
        "  am check-for-updates - Check for all item updates. The results can "
        "be viewed via \"am status\" command\n"
        "For the commands below, <item_id> is either <app_id>-<depot_id> or "
        "<app_id>-<depot_id>-<workshop_item_id>\n"
        "  am create-job <item_id> <manifest_id> <force_verify> - Create a job "
        "for specified item. This command won't run the created job "
        "automatically, for that use \"run-job\" command. Only one job can "
        "exist for an item at a time; if you want to create another job, the "
        "previous one must be successfully finished or cancelled first. "
        "<manifest_id> can be ID of the manifest to update to or verify "
        "against, or 0 to use ID of the latest available manifest, or -1 to "
        "uninstall the item. <force_verify> must be either \"true\" or "
        "\"false\"; if \"true\", file verification will still be performed "
        "even if it's otherwise not necessary\n"
        "  am run-job <item_id> - Run/resume a job for specified item. It can "
        "be paused by sending a SIGINT signal (Ctrl+C) or terminating the "
        "program\n"
        "  am cancel-job <item_id> - Cancel a job for specified item, cleaning "
        "up its cache directory and resetting its state"));
#ifdef TEK_SCB_CLI_DUMP
    // L18N: output of tek-sc-cli's "help" command ("am dump" command)
    puts(tsc_gettext(
        "  am dump <type> <item_id> <manifest_id> - Dump specified "
        "tek-steamclient content file into a human-readable text file at "
        "current working directory. The file must be present in current "
        "application manager's directories, i.e. for manifests they must've "
        "been downloaded before, for other types there must be a job paused "
        "after creating that file. <type> must be one of: \"manifest\", "
        "\"patch\", \"vcache\", \"delta\". <manifest_id> is only used when "
        "<type> is \"manifest\" and can be set to 0 otherwise"));
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
    // L18N: output of tek-sc-cli's "help" command ("s3c sync-manifest" command)
    puts(tsc_gettext(
        "tek-s3 client commands:\n"
        "  s3c sync-manifest <url> - Synchronize manifest of tek-s3 server at "
        "specified URL, i.e. fetch its depot decryption keys and update list "
        "of apps/depots that it can provide manifest request codes for"));
#endif // def TEK_SCB_S3C
    return true;
#ifdef TEK_SCB_AM
  case TSCL_CMD_TYPE_am_init:
    if (tscl_g_ctx.am) {
      fputs(tsc_gettext("Error: There is already an initialized application "
                        "manager instance\n"),
            stderr);
      return false;
    } else {
      auto path = cmd->am_init.path;
      const bool use_cwd = !path[0];
      if (use_cwd) {
        path = tscl_os_get_cwd();
        if (!path) {
          auto const errc = tscl_os_get_last_error();
          auto const msg = tscl_os_get_err_msg(errc);
          fprintf(
              stderr,
              // L18N: %u is the OS error code number, %s is the OS error
              //    message
              tsc_gettext("Failed to get current working directory: (%u) %s\n"),
              (unsigned)errc, msg);
          free(msg);
          return false;
        }
      }
      auto const path_size = sizeof *path * (tscl_os_strlen(path) + 1);
      tscl_g_ctx.am_path = malloc(path_size);
      if (tscl_g_ctx.am_path) {
        memcpy(tscl_g_ctx.am_path, path, path_size);
      }
      tek_sc_err res;
      tscl_g_ctx.am = tek_sc_am_create(tscl_g_ctx.lib_ctx, path, &res);
      if (use_cwd) {
        free((void *)path);
      }
      if (!tscl_g_ctx.am) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        // L18N: This message is followed by path to the application manager
        //    directory
        printf("%s \"%" TSCL_OS_PRI_str "\"\n",
               tsc_gettext("Initialized application manager instance at"),
               tscl_g_ctx.am_path);
      }
      return true;
    }
    return false;
  case TSCL_CMD_TYPE_am_close:
    if (tscl_g_ctx.am) {
      tek_sc_am_destroy(tscl_g_ctx.am);
      tscl_g_ctx.am = nullptr;
      free(tscl_g_ctx.am_path);
      tscl_g_ctx.am_path = nullptr;
      if (tscl_g_ctx.interactive) {
        puts(tsc_gettext("Application manager instance has been closed"));
      }
      return true;
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to close\n"),
            stderr);
      return false;
    }
  case TSCL_CMD_TYPE_am_set_workshop_dir:
    if (tscl_g_ctx.am) {
      auto const res =
          tek_sc_am_set_ws_dir(tscl_g_ctx.am, cmd->am_set_workshop_dir.path);
      if (!tek_sc_err_success(&res)) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        // L18N: This message is followed by path to the workshop directory
        printf("%s \"%" TSCL_OS_PRI_str "\"\n",
               tsc_gettext("Workshop directory has been set to"),
               cmd->am_set_workshop_dir.path);
      }
      return true;
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to set workshop directory for\n"),
            stderr);
      return false;
    }
  case TSCL_CMD_TYPE_am_status:
    if (tscl_g_ctx.am) {
      tek_sc_am_item_descs_lock(tscl_g_ctx.am);
      auto desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, nullptr);
      if (!desc) {
        puts(tsc_gettext("No items are currently managed"));
      }
      for (; desc; desc = desc->next) {
        char item_id[43];
        snprintf(item_id, sizeof item_id,
                 desc->id.ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                                     : "%" PRIu32 "-%" PRIu32,
                 desc->id.app_id, desc->id.depot_id, desc->id.ws_item_id);
        if (desc->status & TEK_SC_AM_ITEM_STATUS_job) {
          // L18N: Item status string. %s is the item ID, first %llu is the
          //    source manifest ID for the job, seconds %llu is the target
          //    manifest ID for the job
          printf(tsc_gettext("%s: job %llu->%llu\n"), item_id,
                 (unsigned long long)desc->job.source_manifest_id,
                 (unsigned long long)desc->job.target_manifest_id);
        } else {
          // L18N: Item status string. First %s is the item ID, %llu is current
          //    manifest ID, second %s may be "update available" string from
          //    below if applicable
          printf(tsc_gettext("%s: manifest ID %llu%s\n"), item_id,
                 (unsigned long long)desc->current_manifest_id,
                 (desc->status & TEK_SC_AM_ITEM_STATUS_upd_available)
                     // L18N: Appended to the status string if item update is
                     //    available
                     ? tsc_gettext(", update available")
                     : "");
        }
      }
      tek_sc_am_item_descs_unlock(tscl_g_ctx.am);
      return true;
    } else { // if (tscl_g_ctx.am)
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to get status of\n"),
            stderr);
      return false;
    } // if (tscl_g_ctx.am) else
  case TSCL_CMD_TYPE_am_check_for_updates:
    if (tscl_g_ctx.am) {
      auto const res = tek_sc_am_check_for_upds(tscl_g_ctx.am, 20000);
      if (!tek_sc_err_success(&res)) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        puts(tsc_gettext("Check for updates succeeded"));
      }
      return true;
    } else { // if (tscl_g_ctx.am)
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to check for updates for\n"),
            stderr);
      return false;
    } // if (tscl_g_ctx.am) else
  case TSCL_CMD_TYPE_am_create_job:
    if (tscl_g_ctx.am) {
      auto const res =
          tek_sc_am_create_job(tscl_g_ctx.am, &cmd->am_create_job.item_id,
                               cmd->am_create_job.manifest_id,
                               cmd->am_create_job.force_verify, nullptr);
      if (!tek_sc_err_success(&res)) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        puts(tsc_gettext("The job has been created successfully"));
      }
      return true;
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to create job for\n"),
            stderr);
      return false;
    }
  case TSCL_CMD_TYPE_am_run_job:
    if (tscl_g_ctx.am) {
      auto const id = &cmd->am_run_job.item_id;
      auto const desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, id);
      if (!desc) {
        char item_id[43];
        snprintf(item_id, sizeof item_id,
                 id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                                : "%" PRIu32 "-%" PRIu32,
                 id->app_id, id->depot_id, id->ws_item_id);
        fprintf(
            stderr,
            // L18N: %s is the item ID
            tsc_gettext(
                "Error: Application manager doesn't have state for item %s\n"),
            item_id);
        return false;
      }
      tscl_job_desc = desc;
      const bool verification = !desc->job.source_manifest_id;
      tscl_os_reg_sig_handler(tscl_job_sig_handler);
      auto const res = tek_sc_am_run_job(tscl_g_ctx.am, desc, tscl_upd_handler);
      tscl_os_unreg_sig_handler();
      switch (res.primary) {
      case TEK_SC_ERRC_ok:
        puts(tsc_gettext("The job has finished successfully"));
        return true;
      case TEK_SC_ERRC_paused:
        puts(tsc_gettext("The job has been paused successfully"));
        return true;
      case TEK_SC_ERRC_up_to_date:
        puts(verification ? tsc_gettext("No mismatches have been found")
                          : tsc_gettext("The item is already up to date"));
        return true;
      default:
        puts("");
        tscl_print_err(&res);
        return false;
      }
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to run job for\n"),
            stderr);
      return false;
    }
  case TSCL_CMD_TYPE_am_cancel_job:
    if (tscl_g_ctx.am) {
      auto const id = &cmd->am_cancel_job.item_id;
      auto const desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, id);
      if (!desc) {
        char item_id[43];
        snprintf(item_id, sizeof item_id,
                 id->ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                                : "%" PRIu32 "-%" PRIu32,
                 id->app_id, id->depot_id, id->ws_item_id);
        fprintf(
            stderr,
            // L18N: %s is the item ID
            tsc_gettext(
                "Error: Application manager doesn't have state for item %s\n"),
            item_id);
        return false;
      }
      auto const res = tek_sc_am_cancel_job(tscl_g_ctx.am, desc);
      if (!tek_sc_err_success(&res)) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        puts(tsc_gettext("The job has been cancelled successfully"));
      }
      return true;
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to cancel job for\n"),
            stderr);
      return false;
    }
#ifdef TEK_SCB_CLI_DUMP
  case TSCL_CMD_TYPE_am_dump:
    if (tscl_g_ctx.am) {
      switch (cmd->am_dump.type) {
      case TSCL_DUMP_TYPE_manifest:
        return tscl_dump_manifest(&cmd->am_dump.item_id,
                                  cmd->am_dump.manifest_id);
      case TSCL_DUMP_TYPE_patch:
        return tscl_dump_patch(&cmd->am_dump.item_id);
      case TSCL_DUMP_TYPE_vcache:
        return tscl_dump_vcache(&cmd->am_dump.item_id);
      case TSCL_DUMP_TYPE_delta:
        return tscl_dump_delta(&cmd->am_dump.item_id);
      default:
        return false;
      }
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to dump for\n"),
            stderr);
      return false;
    }
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
  case TSCL_CMD_TYPE_s3c_sync_manifest: {
    auto const res = tek_sc_s3c_sync_manifest(
        tscl_g_ctx.lib_ctx, cmd->s3c_sync_manifest.url, 30000);
    if (!tek_sc_err_success(&res)) {
      tscl_print_err(&res);
      return false;
    }
    if (tscl_g_ctx.interactive) {
      // L18N: %s is the server URL entered by the user
      printf(
          tsc_gettext("Successfully synchronized tek-s3 manifest for \"%s\"\n"),
          cmd->s3c_sync_manifest.url);
    }
    return true;
  }
#endif // def TEK_SCB_S3C
  default:
    return false;
  } // switch (cmd->type)
}
