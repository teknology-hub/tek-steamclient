//===-- main.c - command-line argument parser -----------------------------===//
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
/// Command-line argument parser that handles basic options and builds command
///    queue.
///
//===----------------------------------------------------------------------===//
#include "common.h"

#include "config.h"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/os.h"

#include <stdio.h>
#include <stdlib.h>

int tscl_process_args(int argc, tek_sc_os_char **argv, tscl_command **cmds) {
  if (!tscl_os_strcmp(argv[1], TEK_SC_OS_STR("--version"))) {
    printf("tek-steamclient %s\n", tek_sc_version());
    *cmds = nullptr;
    return 0;
  }
  if (!tscl_os_strcmp(argv[1], TEK_SC_OS_STR("--help"))) {
    puts(tsc_gettext("Usage: tek-sc-cli - run interactively, allowing you to "
                     "enter commands one at a time\n"
                     "    OR tek-sc-cli <option> - see options below\n"
                     "    OR tek-sc-cli <commands...> - execute commands with "
                     "their arguments in order they appear in the command "
                     "line, then exit. See commands below\n\n"
                     "Options:\n"
                     "  --version  Display tek-steamclient version and exit\n"
                     "  --help     Display this message and exit\n"
                     "Commands:\n"
                     "  help  (interactive mode only) List available commands\n"
                     "  exit  (interactive mode only) Exit the program\n"
                     "  quit  (interactive mode only) Synonym for \"exit\""));
#ifdef TEK_SCB_AM
    puts(tsc_gettext(
        " Application manager:\n"
        "  am init <path>                                        Initialize "
        "application manager at specified directory, allowing the following "
        "commands to be used. <path> may be specified as empty string (\"\") "
        "to use current working directory\n"
        "  am close                                              Close current "
        "application manager instance, allowing it to be initialized in "
        "another directory later\n"
        "  am set-workshop-dir <path>                            Set Steam "
        "Workshop directory path for current application manager instance. You "
        "cannot run jobs for Steam Workshop items before executing this "
        "command\n"
        "  am status                                             (interactive "
        "mode only) Get current status of all items managed by current "
        "application manager instance\n"
        "  am check-for-updates                                  Check for all "
        "item updates. The results can be viewed via \"am status\" command\n"
        " For the commands below, <item_id> is either <app_id>-<depot_id> or "
        "<app_id>-<depot_id>-<workshop_item_id>\n"
        "  am create-job <item_id> <manifest_id> <force_verify>  Create a job "
        "for specified item. This command won't run the created job "
        "automatically, for that use \"run-job\" command. Only one job can "
        "exist for an item at a time; if you want to create another job, the "
        "previous one must be successfully finished or cancelled first. "
        "<manifest_id> can be ID of the manifest to update to or verify "
        "against, or 0 to use ID of the latest available manifest, or -1 to "
        "uninstall the item. <force_verify> must be either \"true\" or "
        "\"false\"; if \"true\", file verification will still be performed "
        "even if it's otherwise not necessary\n"
        "  am run-job <item_id>                                  Run/resume a "
        "job for specified item. It can be paused by sending a SIGINT signal "
        "(Ctrl+C) or terminating the program\n"
        "  am cancel-job <item_id>                               Cancel a job "
        "for specified item, cleaning up its cache directory and resetting its "
        "state"));
#ifdef TEK_SCB_CLI_DUMP
    puts(tsc_gettext(
        "  am dump <type> <item_id> <manifest_id>                Dump "
        "specified tek-steamclient content file into a human-readable text "
        "file at current working directory. The file must be present in "
        "current application manager's directories, i.e. for manifests they "
        "must've been downloaded before, for other types there must be a job "
        "paused after creating that file. <type> must be one of: \"manifest\", "
        "\"patch\", \"vcache\", \"delta\". <manifest_id> is only used when "
        "<type> is \"manifest\" and can be set to 0 otherwise"));
#endif // def TEK_SCB_CLI_DUMP
#endif // def TEK_SCB_AM
#ifdef TEK_SCB_S3C
    puts(tsc_gettext(
        " tek-s3 client:\n"
        "  s3c sync-manifest <url>  Synchronize manifest of tek-s3 server at "
        "specified URL, i.e. fetch its depot decryption keys and update list "
        "of apps/depots that it can provide manifest request codes for"));
    puts(
#ifdef TEK_SCB_QR
        tsc_gettext("  s3c signin <type> <url>  (interactive mode only) Submit "
                    "a Steam account to a tek-s3 server at specified URL. "
                    "<type> must be either \"credentials\" or \"qr\"")
#else  // def TEK_SCB_QR
        tsc_gettext("  s3c signin <url>         (interactive mode only) Submit "
                    "a Steam account to a tek-s3 server at specified URL")
#endif // def TEK_SCB_QR else
    );
#endif // def TEK_SCB_S3C
    *cmds = nullptr;
    return 0;
  }
  int num_cmds = 0;
  tscl_command *const cmd_buf = malloc(sizeof *cmd_buf * (argc - 1));
  for (int i = 1; i < argc;) {
    auto const cmd = &cmd_buf[num_cmds++];
    const int new_i = tscl_parse_cmd(argc, argv, i, cmd);
    if (!new_i) {
      free(cmd_buf);
      *cmds = nullptr;
      return -1;
    }
    switch (cmd->type) {
    case TSCL_CMD_TYPE_help:
    case TSCL_CMD_TYPE_exit:
    case TSCL_CMD_TYPE_s3c_signin: {
      const char *name;
      switch (cmd->type) {
      case TSCL_CMD_TYPE_help:
        name = "help";
        break;
      case TSCL_CMD_TYPE_exit:
        name = "exit/quit";
        break;
      case TSCL_CMD_TYPE_am_status:
        name = "am status";
        break;
      case TSCL_CMD_TYPE_s3c_signin:
        name = "s3c signin";
        break;
      default:
        name = nullptr;
        break;
      }
      fprintf(
          stderr,
          tsc_gettext("Error: \"%s\" can only be used in interactive mode\n"),
          name);
      free(cmd_buf);
      *cmds = nullptr;
      return -1;
    }
    default:
    }
    i = new_i;
  }
  *cmds = cmd_buf;
  return num_cmds;
}
