//===-- cmd_runner.c - command runner -------------------------------------===//
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
#include <time.h>

#ifdef TEK_SCB_AM
/// Pointer to the state descriptor of the item that current job is operating
/// on.
static tek_sc_am_item_desc *_Nullable tscl_job_desc;
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
/// tek-s3 authentication session result.
static tek_sc_err tscl_s3c_res;
#endif // def TEK_SCB_S3C

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
      printf(tsc_gettext("Starting the job for %s\n"), item_id);
      break;
    }
    case TEK_SC_AM_JOB_STATE_pause_pending:
      puts(tsc_gettext("A pause has been requested for the job"));
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
      stage_str = tsc_gettext("Fetching data");
      break;
    case TEK_SC_AM_JOB_STAGE_dw_manifest:
      stage_str = tsc_gettext("Downloading manifest");
      break;
    case TEK_SC_AM_JOB_STAGE_dw_patch:
      stage_str = tsc_gettext("Downloading patch");
      break;
    case TEK_SC_AM_JOB_STAGE_verifying:
      stage_str = tsc_gettext("Verifying installed files");
      break;
    case TEK_SC_AM_JOB_STAGE_downloading:
      stage_str = tsc_gettext("Downloading new data");
      break;
    case TEK_SC_AM_JOB_STAGE_patching:
      stage_str = tsc_gettext("Patching");
      break;
    case TEK_SC_AM_JOB_STAGE_installing:
      stage_str = tsc_gettext("Installing new data");
      break;
    case TEK_SC_AM_JOB_STAGE_deleting:
      stage_str = tsc_gettext("Deleting delisted content");
      break;
    case TEK_SC_AM_JOB_STAGE_finalizing:
      stage_str = tsc_gettext("Finalizing");
      break;
    default:
      stage_str = tsc_gettext("Unknown stage");
    }
    printf(tsc_gettext("\033[2K\rJob stage updated: %s\n"), stage_str);
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
      tscl_os_strlcat_utf8(eta_buf, tsc_gettext(", ETA: "), sizeof eta_buf);
      const int64_t eta = (double)(total - current) /
                          ((double)(current - start_progress) /
                           ((double)(cur_ticks - start_ticks) / 1000.0));
      char unit_buf[16];
      bool first_unit = true;
      if (eta > 3600) {
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
        snprintf(unit_buf, sizeof unit_buf, tsc_gettext("%umin"), mins);
        tscl_os_strlcat_utf8(eta_buf, unit_buf, sizeof eta_buf);
        first_unit = false;
      }
      const unsigned secs = eta % 60;
      if (eta < 600 && secs) {
        if (!first_unit) {
          tscl_os_strlcat_utf8(eta_buf, " ", sizeof eta_buf);
        }
        snprintf(unit_buf, sizeof unit_buf, tsc_gettext("%usec"), secs);
        tscl_os_strlcat_utf8(eta_buf, unit_buf, sizeof eta_buf);
      }
    }
    switch (desc->job.stage) {
    case TEK_SC_AM_JOB_STAGE_verifying:
    case TEK_SC_AM_JOB_STAGE_patching:
      // Percentage display
      printf(tsc_gettext("\033[2K\r[%s] %6.2f%%%s\r"), bar,
             (double)(current * 100) / (double)total, eta_buf);
      break;
    case TEK_SC_AM_JOB_STAGE_dw_manifest:
    case TEK_SC_AM_JOB_STAGE_dw_patch:
    case TEK_SC_AM_JOB_STAGE_downloading: {
      // Bytes display with speed
      char cur_buf[32];
      cur_buf[0] = '\0';
      if (current >= 0x40000000) { // 1 GiB
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%.2f GiB"),
                 (double)current / 0x40000000);
      } else if (current >= 0x100000) { // 1 MiB
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%.1f MiB"),
                 (double)current / 0x100000);
      } else {
        snprintf(cur_buf, sizeof cur_buf, tsc_gettext("%u KiB"),
                 (unsigned)current / 0x400);
      }
      char total_buf[32];
      total_buf[0] = '\0';
      if (total >= 0x40000000) { // 1 GiB
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%.2f GiB"),
                 (double)total / 0x40000000);
      } else if (total >= 0x100000) { // 1 MiB
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%.1f MiB"),
                 (double)total / 0x100000);
      } else {
        snprintf(total_buf, sizeof total_buf, tsc_gettext("%u KiB"),
                 (unsigned)total / 0x400);
      }
      const double speed = (double)((current - previous_val) * 8000) /
                           (double)(cur_ticks - prev_ticks_val);
      char speed_buf[32];
      speed_buf[0] = '\0';
      if (speed >= 1000000000) { // 1 Gbit/s
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%.2f Gbit/s"),
                 speed / 1000000000);
      } else if (speed >= 1000000) { // 1 Mbit/s
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%.1f Mbit/s"),
                 speed / 1000000);
      } else {
        snprintf(speed_buf, sizeof speed_buf, tsc_gettext("%u kbit/s"),
                 (unsigned)speed / 1000);
      }
      printf(tsc_gettext("\033[2K\r[%s] %12s/%-12s (%-12s)%s\r"), bar, cur_buf,
             total_buf, speed_buf, eta_buf);
      break;
    }
    case TEK_SC_AM_JOB_STAGE_installing:
    case TEK_SC_AM_JOB_STAGE_deleting: {
      // Plain numbers display
      if (!num_width) {
        num_width = snprintf(nullptr, 0, "%llu", (unsigned long long)total);
      }
      printf(tsc_gettext("\033[2K\r[%s] %*llu/%llu%s\r"), bar, num_width,
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

#ifdef TEK_SCB_S3C
/// tek-s3 sign-in callback.
///
/// @param [in] data
///    Pointer to the @ref tek_sc_cm_data_auth_polling.
static void tscl_signin_cb(tek_sc_cm_client *, void *_Nonnull data,
                           void *_Nonnull user_data) {
  const tek_sc_cm_data_auth_polling *const data_ap = data;
  _Atomic(uint32_t) *const ftx = user_data;
  switch (data_ap->status) {
  case TEK_SC_CM_AUTH_STATUS_completed:
    tscl_s3c_res = data_ap->result;
    atomic_store_explicit(ftx, 1, memory_order_release);
    tscl_os_futex_wake(ftx);
    break;
  case TEK_SC_CM_AUTH_STATUS_new_url: {
#ifdef TEK_SCB_QR
    auto const qr =
        QRcode_encodeString(data_ap->url, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qr) {
      fputs(tsc_gettext("Failed to generate QR code\n"), stderr);
      break;
    }
    const int line_len = qr->width + 2;
    char *const line_buf = malloc(7 * (line_len + 1));
    if (!line_buf) {
      QRcode_free(qr);
      fputs(tsc_gettext("Failed to allocate memory for printing the QR code\n"),
            stderr);
      break;
    }
    puts(tsc_gettext("Scan this QR code in Steam mobile app:"));
    memcpy(line_buf, "\033[47m", 5);
    // Print top border
    memset(&line_buf[5], ' ', line_len * 2);
    memcpy(&line_buf[5 + line_len * 2], "\033[0m", 5);
    puts(line_buf);
    // Print rows
    for (int i = 0; i < qr->width; ++i) {
      auto cur = &line_buf[7];
      bool is_black = false;
      for (int j = 0; j < qr->width; ++j) {
        if ((qr->data[i * qr->width + j] & 1) ^ is_black) {
          // Flip backgound color
          is_black = !is_black;
          memcpy(cur, is_black ? "\033[40m" : "\033[47m", 5);
          cur += 5;
        }
        memcpy(cur, "  ", 2);
        cur += 2;
      }
      if (is_black) {
        memcpy(cur, "\033[47m", 5);
        cur += 5;
      }
      memcpy(cur, "  \033[0m", 7);
      puts(line_buf);
    }
    // Print bottom border
    memset(&line_buf[5], ' ', line_len * 2);
    memcpy(&line_buf[5 + line_len * 2], "\033[0m", 5);
    puts(line_buf);
    free(line_buf);
    QRcode_free(qr);
#endif
    break;
  } // case TEK_SC_CM_AUTH_STATUS_new_url
  case TEK_SC_CM_AUTH_STATUS_awaiting_confirmation: {
    if (data_ap->confirmation_types & TEK_SC_CM_AUTH_CONFIRMATION_TYPE_device) {
      puts(tsc_gettext("Awaiting confirmation from Steam mobile app..."));
    } else if (data_ap->confirmation_types &
               TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code) {
      fputs(tsc_gettext("Enter Steam Guard code from your mobile device: "),
            stdout);
      char buf[24];
      if (fgets(buf, sizeof buf, stdin)) {
        auto const lf = strrchr(buf, '\n');
        if (lf) {
          *lf = '\0';
#ifdef _WIN32
          if (lf > buf && lf[-1] == '\r') {
            lf[-1] = '\0';
          }
#endif // def _WIN32
        }
        tek_sc_s3c_auth_submit_code(tscl_g_ctx.lib_ctx,
                                    TEK_SC_CM_AUTH_CONFIRMATION_TYPE_guard_code,
                                    buf);
      }
    } else if (data_ap->confirmation_types &
               TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email) {
      fputs(tsc_gettext("Enter confirmation code sent to your email: "),
            stdout);
      char buf[24];
      if (fgets(buf, sizeof buf, stdin)) {
        auto const lf = strrchr(buf, '\n');
        if (lf) {
          *lf = '\0';
#ifdef _WIN32
          if (lf > buf && lf[-1] == '\r') {
            lf[-1] = '\0';
          }
#endif // def _WIN32
        }
        tek_sc_s3c_auth_submit_code(
            tscl_g_ctx.lib_ctx, TEK_SC_CM_AUTH_CONFIRMATION_TYPE_email, buf);
      }
    }
  } // case TEK_SC_CM_AUTH_STATUS_awaiting_confirmation
  } // switch (data_ap->status)
}

/// Signal handler for tek-s3 sign-in session.
static void tscl_signin_sig_handler() {
  tek_sc_s3c_auth_cancel(tscl_g_ctx.lib_ctx);
}
#endif // def TEK_SCB_S3C

//===-- Internal function -------------------------------------------------===//

bool tscl_run_cmd(const tscl_command *cmd) {
  switch (cmd->type) {
  case TSCL_CMD_TYPE_help:
    puts(tsc_gettext("General commands:\n"
                     "  help - Display this message\n"
                     "  exit - Exit the program\n"
                     "  quit - Synonym for \"exit\""));
#ifdef TEK_SCB_AM
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
        "  am status - Get status of all items managed by current application "
        "manager instance, and check for their updates\n"
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
    puts(tsc_gettext(
        "tek-s3 client commands:\n"
        "  s3c sync-manifest <url> - Synchronize manifest of tek-s3 server at "
        "specified URL, i.e. fetch its depot decryption keys and update list "
        "of apps/depots that it can provide manifest request codes for"));
    puts(
#ifdef TEK_SCB_QR
        tsc_gettext("  s3c signin <type> <url> - Submit a Steam account to a "
                    "tek-s3 server at specified URL. <type> must be either "
                    "\"credentials\" or \"qr\"")
#else  // def TEK_SCB_QR
        tsc_gettext("  s3c signin <url> - Submit a Steam account to a tek-s3 "
                    "server at specified URL")
#endif // def TEK_SCB_QR else
    );
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
      return true;
    }
    return false;
  case TSCL_CMD_TYPE_am_close:
    if (tscl_g_ctx.am) {
      tek_sc_am_destroy(tscl_g_ctx.am);
      tscl_g_ctx.am = nullptr;
      free(tscl_g_ctx.am_path);
      tscl_g_ctx.am_path = nullptr;
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
      return true;
    } else {
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to set workshop directory for\n"),
            stderr);
      return false;
    }
  case TSCL_CMD_TYPE_am_status:
    if (tscl_g_ctx.am) {
      auto const res = tek_sc_am_check_for_upds(tscl_g_ctx.am, 10000);
      if (!tek_sc_err_success(&res)) {
        tscl_print_err(&res);
        return false;
      }
      if (tscl_g_ctx.interactive) {
        tek_sc_am_item_descs_lock(tscl_g_ctx.am);
        for (auto desc = tek_sc_am_get_item_desc(tscl_g_ctx.am, nullptr); desc;
             desc = desc->next) {
          char item_id[43];
          snprintf(item_id, sizeof item_id,
                   desc->id.ws_item_id ? "%" PRIu32 "-%" PRIu32 "-%" PRIu64
                                       : "%" PRIu32 "-%" PRIu32,
                   desc->id.app_id, desc->id.depot_id, desc->id.ws_item_id);
          char status[256];
          status[0] = '\0';
          if (desc->current_manifest_id) {
            tscl_os_strlcat_utf8(status, tsc_gettext("installed"),
                                 sizeof status);
          }
          if (desc->status & TEK_SC_AM_ITEM_STATUS_job) {
            if (status[0]) {
              tscl_os_strlcat_utf8(status, ", ", sizeof status);
            }
            tscl_os_strlcat_utf8(status, tsc_gettext("job paused"),
                                 sizeof status);
          } else if (desc->current_manifest_id &&
                     (desc->status & TEK_SC_AM_ITEM_STATUS_upd_available)) {
            tscl_os_strlcat_utf8(status, ", ", sizeof status);
            tscl_os_strlcat_utf8(status, tsc_gettext("update available"),
                                 sizeof status);
          }
          printf(tsc_gettext("%s: [%s]\n"), item_id, status);
        }
        tek_sc_am_item_descs_unlock(tscl_g_ctx.am);
      } // if (tscl_g_ctx.interactive)
      return true;
    } else { // if (tscl_g_ctx.am)
      fputs(tsc_gettext("Error: There is no initialized application manager "
                        "instance to get status of\n"),
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
    auto const res = tek_sc_s3c_fetch_manifest(
        tscl_g_ctx.lib_ctx, cmd->s3c_sync_manifest.url, 10000);
    if (!tek_sc_err_success(&res)) {
      tscl_print_err(&res);
      return false;
    }
    return true;
  }
  case TSCL_CMD_TYPE_s3c_signin:
    printf(tsc_gettext(
               "IMPORTANT NOTES\n"
               "You are about to sign tek-s3 server at %s into your Steam "
               "account.\n"
               "What it WILL do:\n"
               "- Get decryption keys (that are not present in the server's "
               "cache yet) for all Steam depots that your account has access "
               "to. This is a one-time operation\n"
               "- Get manifest request codes for Steam depots that your "
               "account has access to, on demand\n"
               "That is, it will essentially allow all tek-steamclient users "
               "to download and update apps owned on your account, without "
               "exposing any account information to them\n"
               "What it CAN do (but WON'T unless the server is maliciously "
               "modified):\n"
               "- Access most of your account information\n"
               "- Do most of the stuff that is not protected by Steam Guard\n"
               "What it CANNOT do under any circumstances (as long as you have "
               "Steam Guard enabled):\n"
               "- Change your email, password, make purchases\n"
               "- Gain any further access to your account after the token "
               "expires or you revoke it\n"),
           cmd->s3c_signin.url);
    if (cmd->s3c_signin.type == TSCL_S3_AUTH_TYPE_qr) {
      puts(tsc_gettext("Since you're using QR code-based authentication, the "
                       "server will never know your password"));
    }
    puts(
        tsc_gettext("If you use Steam mobile app for sign-in confirmation and "
                    "tick \"Remember my password on this device\", the server "
                    "will be able to renew access to your account indefinitely "
                    "until you revoke it, otherwise it'll gain access only for "
                    "a limited amount of time (usually around a month)\n"
                    "You can revoke server's access to your account anytime "
                    "you want via Steam mobile app: on Steam Guard tab tap on "
                    "the gear > Authorized Devices, the server will be listed "
                    "there as a device with name starting with \"tek-s3\"\n\n"
                    "Press Enter to proceed"));
    getchar();
    _Atomic(uint32_t) ftx = 0;
    switch (cmd->s3c_signin.type) {
    case TSCL_S3_AUTH_TYPE_credentials:
      if (strstr(cmd->s3c_signin.url, "https://") != cmd->s3c_signin.url) {
        puts(tsc_gettext(
            "WARNING: Connection to specified server is not encrypted, "
            "credentials sent to it are vulnerable to eavesdropping!"));
      }
      fputs(tsc_gettext("Enter your account name: "), stdout);
      char account_name[128];
      if (!fgets(account_name, sizeof account_name, stdin)) {
        fputs(tsc_gettext("Failed to read input string\n"), stderr);
        return false;
      }
      auto lf = strrchr(account_name, '\n');
      if (lf) {
        *lf = '\0';
#ifdef _WIN32
        if (lf > account_name && lf[-1] == '\r') {
          lf[-1] = '\0';
        }
#endif // def _WIN32
      }
      fputs(tsc_gettext("Enter your account password: "), stdout);
      char password[128];
      if (!fgets(password, sizeof password, stdin)) {
        fputs(tsc_gettext("Failed to read input string\n"), stderr);
        return false;
      }
      lf = strrchr(password, '\n');
      if (lf) {
        *lf = '\0';
#ifdef _WIN32
        if (lf > password && lf[-1] == '\r') {
          lf[-1] = '\0';
        }
#endif // def _WIN32
      }
      tek_sc_s3c_auth_credentials(tscl_g_ctx.lib_ctx, cmd->s3c_signin.url,
                                  account_name, password, tscl_signin_cb, &ftx,
                                  60000);
      break;
    case TSCL_S3_AUTH_TYPE_qr:
      tek_sc_s3c_auth_qr(tscl_g_ctx.lib_ctx, cmd->s3c_signin.url,
                         tscl_signin_cb, &ftx, 60000);
    }
    tscl_os_reg_sig_handler(tscl_signin_sig_handler);
    while (!atomic_load_explicit(&ftx, memory_order_acquire)) {
      tscl_os_futex_wait(&ftx, 0, 65000);
    }
    tscl_os_unreg_sig_handler();
    if (tek_sc_err_success(&tscl_s3c_res)) {
      const time_t exp_time = ((uint64_t)tscl_s3c_res.auxiliary |
                               ((uint64_t)tscl_s3c_res.extra << 32));
      if (exp_time) {
        struct tm tm;
#ifdef _WIN32
        gmtime_s(&tm, &exp_time);
#else
        gmtime_r(&exp_time, &tm);
#endif
        char buf[256];
        strftime(buf, sizeof buf, "%x %X", &tm);
        printf(tsc_gettext("Authentication succeeded, server got non-renewable "
                           "token that will expire at %s\n"),
               buf);
      } else {
        puts(tsc_gettext("Authentication succeeded, server got persistent "
                         "token that will be renewed automatically"));
      }
    } else if (tscl_s3c_res.primary == TEK_SC_ERRC_paused) {
      puts(tsc_gettext("The authentication session has been interrupted"));
    } else {
      tscl_print_err(&tscl_s3c_res);
    }
    return true;
#endif // def TEK_SCB_S3C
  default:
    return false;
  } // switch (cmd->type)
}
