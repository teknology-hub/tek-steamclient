//===-- cmd_parser.c - command parser -------------------------------------===//
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
/// Implementation of tek-sc-cli command parser.
///
//===----------------------------------------------------------------------===//
#include "common.h"

#include "config.h"
#include "os.h"
#include "tek-steamclient/os.h"

#include <stdio.h>
#include <stdlib.h>

int tscl_parse_cmd(int argc, tek_sc_os_char **argv, int ind,
                   tscl_command *cmd) {
  if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("help"))) {
    cmd->type = TSCL_CMD_TYPE_help;
    return ind + 1;
  } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("exit")) ||
             !tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("quit"))) {
    cmd->type = TSCL_CMD_TYPE_exit;
    return ind + 1;
  }
#ifdef TEK_SCB_AM
  else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("am"))) {
    if (++ind == argc) {
      fputs(tsc_gettext("Error: no command provided for module \"am\"\n"),
            stderr);
      return 0;
    }
    if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("init"))) {
      cmd->type = TSCL_CMD_TYPE_am_init;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <path> not provided for \"init\"\n"), stderr);
        return 0;
      }
      cmd->am_init.path = argv[ind];
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("close"))) {
      cmd->type = TSCL_CMD_TYPE_am_close;
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("set-workshop-dir"))) {
      cmd->type = TSCL_CMD_TYPE_am_set_workshop_dir;
      if (++ind == argc) {
        fputs(tsc_gettext(
                  "Error: <path> not provided for \"set-workshop-dir\"\n"),
              stderr);
        return 0;
      }
      cmd->am_set_workshop_dir.path = argv[ind];
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("status"))) {
      cmd->type = TSCL_CMD_TYPE_am_status;
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("check-for-updates"))) {
      cmd->type = TSCL_CMD_TYPE_am_check_for_updates;
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("create-job"))) {
      cmd->type = TSCL_CMD_TYPE_am_create_job;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <item_id> not provided for \"create-job\"\n"),
              stderr);
        return 0;
      }
      const tek_sc_os_char *cur = argv[ind];
      const tek_sc_os_char *endptr;
      auto val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: app ID part of <item_id> for \"create-job\" "
                          "is not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_create_job.item_id.app_id = val;
      if (*endptr != '-') {
        fputs(tsc_gettext("Error: <item_id> for \"create-job\" doesn't contain "
                          "a depot ID\n"),
              stderr);
        return 0;
      }
      cur = endptr + 1;
      val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: depot ID part of <item_id> for "
                          "\"create-job\" is not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_create_job.item_id.depot_id = val;
      if (*endptr == '-') {
        cur = endptr + 1;
        val = tscl_os_strtoull(cur, &endptr);
        if (endptr == cur) {
          fputs(tsc_gettext("Error: Steam Workshop item ID part of <item_id> "
                            "for \"create-job\" is not a number\n"),
                stderr);
          return 0;
        }
        cmd->am_create_job.item_id.ws_item_id = val;
      } else {
        cmd->am_create_job.item_id.ws_item_id = 0;
      }
      if (++ind == argc) {
        fputs(tsc_gettext(
                  "Error: <manifest_id> not provided for \"create-job\"\n"),
              stderr);
        return 0;
      }
      cur = argv[ind];
      cmd->am_create_job.manifest_id = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext(
                  "Error: <manifest_id> for \"create-job\" is not a number\n"),
              stderr);
        return 0;
      }
      if (++ind == argc) {
        fputs(tsc_gettext(
                  "Error: <force_verify> not provided for \"create-job\"\n"),
              stderr);
        return 0;
      }
      if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("true"))) {
        cmd->am_create_job.force_verify = true;
      } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("false"))) {
        cmd->am_create_job.force_verify = false;
      } else {
        fputs(tsc_gettext("Error: <force_verify> for \"create-job\" must be "
                          "\"true\" or \"false\"\n"),
              stderr);
        return 0;
      }
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("run-job"))) {
      cmd->type = TSCL_CMD_TYPE_am_run_job;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <item_id> not provided for \"run-job\"\n"),
              stderr);
        return 0;
      }
      const tek_sc_os_char *cur = argv[ind];
      const tek_sc_os_char *endptr;
      auto val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: app ID part of <item_id> for \"run-job\" is "
                          "not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_run_job.item_id.app_id = val;
      if (*endptr != '-') {
        fputs(tsc_gettext("Error: <item_id> for \"run-job\" doesn't contain a "
                          "depot ID\n"),
              stderr);
        return 0;
      }
      cur = endptr + 1;
      val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: depot ID part of <item_id> for \"run-job\" "
                          "is not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_run_job.item_id.depot_id = val;
      if (*endptr == '-') {
        cur = endptr + 1;
        val = tscl_os_strtoull(cur, &endptr);
        if (endptr == cur) {
          fputs(tsc_gettext("Error: Steam Workshop item ID part of <item_id> "
                            "for \"run-job\" is not a number\n"),
                stderr);
          return 0;
        }
        cmd->am_run_job.item_id.ws_item_id = val;
      } else {
        cmd->am_run_job.item_id.ws_item_id = 0;
      }
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("cancel-job"))) {
      cmd->type = TSCL_CMD_TYPE_am_cancel_job;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <item_id> not provided for \"cancel-job\"\n"),
              stderr);
        return 0;
      }
      const tek_sc_os_char *cur = argv[ind];
      const tek_sc_os_char *endptr;
      auto val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: app ID part of <item_id> for \"cancel-job\" "
                          "is not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_cancel_job.item_id.app_id = val;
      if (*endptr != '-') {
        fputs(tsc_gettext("Error: <item_id> for \"cancel-job\" doesn't contain "
                          "a depot ID\n"),
              stderr);
        return 0;
      }
      cur = endptr + 1;
      val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: depot ID part of <item_id> for "
                          "\"cancel-job\" is not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_cancel_job.item_id.depot_id = val;
      if (*endptr == '-') {
        cur = endptr + 1;
        val = tscl_os_strtoull(cur, &endptr);
        if (endptr == cur) {
          fputs(tsc_gettext("Error: Steam Workshop item ID part of <item_id> "
                            "for \"cancel-job\" is not a number\n"),
                stderr);
          return 0;
        }
        cmd->am_cancel_job.item_id.ws_item_id = val;
      } else {
        cmd->am_cancel_job.item_id.ws_item_id = 0;
      }
      return ind + 1;
    }
#ifdef TEK_SCB_CLI_DUMP
    else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("dump"))) {
      cmd->type = TSCL_CMD_TYPE_am_dump;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <type> not provided for \"dump\"\n"), stderr);
        return 0;
      }
      if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("manifest"))) {
        cmd->am_dump.type = TSCL_DUMP_TYPE_manifest;
      } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("patch"))) {
        cmd->am_dump.type = TSCL_DUMP_TYPE_patch;
      } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("vcache"))) {
        cmd->am_dump.type = TSCL_DUMP_TYPE_vcache;
      } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("delta"))) {
        cmd->am_dump.type = TSCL_DUMP_TYPE_delta;
      } else {
        auto const str = tscl_os_str_to_utf8(argv[ind]);
        fprintf(stderr,
                // L18N: %s is the value of <type> entered by the user
                tsc_gettext("Error: unknown <type> \"%s\" for \"dump\"\n"),
                str);
        free(str);
        return 0;
      }
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <item_id> not provided for \"dump\"\n"),
              stderr);
        return 0;
      }
      const tek_sc_os_char *cur = argv[ind];
      const tek_sc_os_char *endptr;
      auto val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: app ID part of <item_id> for \"dump\" is not "
                          "a number\n"),
              stderr);
        return 0;
      }
      cmd->am_dump.item_id.app_id = val;
      if (*endptr != '-') {
        fputs(tsc_gettext(
                  "Error: <item_id> for \"dump\" doesn't contain a depot ID\n"),
              stderr);
        return 0;
      }
      cur = endptr + 1;
      val = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(tsc_gettext("Error: depot ID part of <item_id> for \"dump\" is "
                          "not a number\n"),
              stderr);
        return 0;
      }
      cmd->am_dump.item_id.depot_id = val;
      if (*endptr == '-') {
        cur = endptr + 1;
        val = tscl_os_strtoull(cur, &endptr);
        if (endptr == cur) {
          fputs(tsc_gettext("Error: Steam Workshop item ID part of <item_id> "
                            "for \"dump\" is not a number\n"),
                stderr);
          return 0;
        }
        cmd->am_dump.item_id.ws_item_id = val;
      } else {
        cmd->am_dump.item_id.ws_item_id = 0;
      }
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <manifest_id> not provided for \"dump\"\n"),
              stderr);
        return 0;
      }
      cur = argv[ind];
      cmd->am_dump.manifest_id = tscl_os_strtoull(cur, &endptr);
      if (endptr == cur) {
        fputs(
            tsc_gettext("Error: <manifest_id> for \"dump\" is not a number\n"),
            stderr);
        return 0;
      }
      return ind + 1;
    } else {
      auto const str = tscl_os_str_to_utf8(argv[ind]);
      fprintf(stderr,
              // L18N: %s is the command name entered by the user
              tsc_gettext("Error: unknown command \"%s\" for module \"am\"\n"),
              str);
      free(str);
      return 0;
    }
#endif // def TEK_SCB_CLI_DUMP
  } // else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("am")))
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
  else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("s3c"))) {
    if (++ind == argc) {
      fputs(tsc_gettext("Error: no command provided for module \"s3c\"\n"),
            stderr);
      return 0;
    }
    if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("sync-manifest"))) {
      cmd->type = TSCL_CMD_TYPE_s3c_sync_manifest;
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <url> not provided for \"sync-manifest\"\n"),
              stderr);
        return 0;
      }
      cmd->s3c_sync_manifest.url = tscl_os_str_to_utf8(argv[ind]);
      return ind + 1;
    } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("signin"))) {
      cmd->type = TSCL_CMD_TYPE_s3c_signin;
#ifdef TEK_SCB_QR
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <type> not provided for \"signin\"\n"),
              stderr);
        return 0;
      }
      if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("credentials"))) {
        cmd->s3c_signin.type = TSCL_S3_AUTH_TYPE_credentials;
      } else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("qr"))) {
        cmd->s3c_signin.type = TSCL_S3_AUTH_TYPE_qr;
      } else {
        auto const str = tscl_os_str_to_utf8(argv[ind]);
        fprintf(stderr,
                // L18N: %s is the value of <type> provied by the user
                tsc_gettext("Error: unknown <type> \"%s\" for \"signin\"\n"),
                str);
        free(str);
        return 0;
      }
#else  // def TEK_SCB_QR
      cmd->s3c_signin.type = TSCL_S3_AUTH_TYPE_credentials;
#endif // def TEK_SCB_QR else
      if (++ind == argc) {
        fputs(tsc_gettext("Error: <url> not provided for \"signin\"\n"),
              stderr);
        return 0;
      }
      cmd->s3c_signin.url = tscl_os_str_to_utf8(argv[ind]);
      return ind + 1;
    } else {
      auto const str = tscl_os_str_to_utf8(argv[ind]);
      fprintf(stderr,
              // L18N: %s is the command name entered by the user
              tsc_gettext("Error: unknown command \"%s\" for module \"s3c\"\n"),
              str);
      free(str);
      return 0;
    }
  } // else if (!tscl_os_strcmp(argv[ind], TEK_SC_OS_STR("s3c")))
#endif // def TEK_SCB_S3C
  auto const str = tscl_os_str_to_utf8(argv[ind]);
  // L18N: %s is the command entered by the user
  fprintf(stderr, tsc_gettext("Error: unknown command \"%s\"\n"), str);
  free(str);
  return 0;
}
