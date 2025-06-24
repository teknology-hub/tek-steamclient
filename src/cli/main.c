//===-- main.c - tek-sc-cli entry point -----------------------------------===//
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
/// Entry point and initial setup code for tek-sc-cli.
///
//===----------------------------------------------------------------------===//
#include "common.h"

#include "config.h"
#include "os.h"
#include "tek-steamclient/am.h"
#include "tek-steamclient/base.h"

#include <locale.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

tscl_ctx tscl_g_ctx;

#ifdef _WIN32
int wmain(int argc, wchar_t *argv[]) {
  setlocale(LC_ALL, ".UTF-8");
  tscl_os_win_setup();
#else  // def _WIN32
int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
#endif // def _WIN32 else
  tscl_command *cmds = nullptr;
  int num_cmds;
  if (argc > 1) {
    num_cmds = tscl_process_args(argc, argv, &cmds);
    if (num_cmds <= 0) {
      return num_cmds == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
  }
  tscl_g_ctx.lib_ctx = tek_sc_lib_init(true, true);
  if (!tscl_g_ctx.lib_ctx) {
    fputs(tsc_gettext("Failed to initialize tek-steamclient library context\n"),
          stderr);
    return EXIT_FAILURE;
  }
  int res;
  if (argc > 1) {
    for (int i = 0; i < num_cmds; i++) {
      if (!tscl_run_cmd(&cmds[i])) {
        res = EXIT_FAILURE;
        goto cleanup;
      }
      if (atomic_load_explicit(&tscl_g_ctx.terminating, memory_order_relaxed)) {
        break;
      }
    }
  } else { // if (argc > 1)
    tscl_g_ctx.interactive = true;
    printf(
        tsc_gettext(
            "tek-steamclient %s\nEnter \"help\" to list available commands\n"),
        tek_sc_version());
    for (tek_sc_os_char buf[256];;) {
      fputs("> ", stdout);
      if (!tscl_os_fgets(buf, sizeof buf / sizeof *buf)) {
        fputs(tsc_gettext("Failed to read input string\n"), stderr);
        res = EXIT_FAILURE;
        goto cleanup;
      }
      // Remove (CR)LF from the string
      auto const lf = tscl_os_strrchr(buf, TEK_SC_OS_STR('\n'));
      if (lf) {
        *lf = TEK_SC_OS_STR('\0');
#ifdef _WIN32
        if (lf > buf && lf[-1] == L'\r') {
          lf[-1] = L'\0';
        }
#endif // def _WIN32
      }
      if (!buf[0]) {
        continue;
      }
      // Tokenize the string
      int argc = 1;
      tek_sc_os_char *argv[6];
      argv[0] = buf;
      for (tek_sc_os_char *const buf_end = buf + tscl_os_strlen(buf),
                                 *cur = buf;
           cur < buf_end;) {
        switch (*cur) {
        case TEK_SC_OS_STR(' '):
          // Turn the space into terminating null for current token, and check
          // the
          //    next character
          *cur = TEK_SC_OS_STR('\0');
          if (++cur >= buf_end) {
            break;
          }
          bool fallthrough = false;
          switch (*cur) {
          case TEK_SC_OS_STR(' '):
            // Proceed to the next iteration, which will hit the outer case
            // again
            break;
          case TEK_SC_OS_STR('"'):
          case TEK_SC_OS_STR('\''):
            // Fallthrough to same cases in outer switch
            fallthrough = true;
            break;
          default:
            // This is the beginning of the next token
            argv[argc++] = cur;
            if (argc == sizeof argv / sizeof *argv) {
              cur = buf_end;
            }
          } // switch (*cur)
          if (!fallthrough) {
            break;
          }
          [[fallthrough]];
        case TEK_SC_OS_STR('"'):
        case TEK_SC_OS_STR('\''):
          auto const c = *cur;
          // Turn the opening quote into terminating null for current token
          *cur++ = TEK_SC_OS_STR('\0');
          // Find the closing quote
          auto const closing = tscl_os_strchr(cur, c);
          if (!closing) {
            fprintf(stderr,
                    tsc_gettext(
                        "Error: The command is missing closing %c character\n"),
                    (char)c);
            argc = -1;
            break;
          }
          // The next character after opening quote is the beginning of next
          // token
          argv[argc++] = cur;
          // Null-terminate the token
          *closing = TEK_SC_OS_STR('\0');
          cur = closing + 1;
          if (argc == sizeof argv / sizeof *argv) {
            cur = buf_end;
          }
          break;
        default:
          ++cur;
        } // switch (*cur)
      } // for (*cur in buf)
      if (argc < 0) {
        continue;
      }
      // Parse and run the command
      tscl_command cmd;
      if (!tscl_parse_cmd(argc, argv, 0, &cmd)) {
        continue;
      }
      if (cmd.type == TSCL_CMD_TYPE_exit) {
        break;
      }
      tscl_run_cmd(&cmd);
#ifdef TEK_SCB_S3C
      switch (cmd.type) {
      case TSCL_CMD_TYPE_s3c_sync_manifest:
        free((void *)cmd.s3c_sync_manifest.url);
        break;
      case TSCL_CMD_TYPE_s3c_signin:
        free((void *)cmd.s3c_signin.url);
        break;
      default:
      }
      if (atomic_load_explicit(&tscl_g_ctx.terminating, memory_order_relaxed)) {
        break;
      }
#endif // def TEK_SCB_S3C
    } // for (tek_sc_os_char buf[256];;)
  } // if (argc > 1) else
  res = EXIT_SUCCESS;
cleanup:
  if (cmds) {
#ifdef TEK_SCB_S3C
    for (int i = 0; i < num_cmds; i++) {
      auto const cmd = &cmds[i];
      switch (cmd->type) {
      case TSCL_CMD_TYPE_s3c_sync_manifest:
        free((void *)cmd->s3c_sync_manifest.url);
        break;
      case TSCL_CMD_TYPE_s3c_signin:
        free((void *)cmd->s3c_signin.url);
        break;
      default:
      }
    }
#endif // def TEK_SCB_S3C
    free(cmds);
  }
#ifdef TEK_SCB_AM
  if (tscl_g_ctx.am) {
    tek_sc_am_destroy(tscl_g_ctx.am);
  }
  free(tscl_g_ctx.am_path);
#endif // def TEK_SCB_AM
  tek_sc_lib_cleanup(tscl_g_ctx.lib_ctx);
#ifdef _WIN32
  atomic_store_explicit(&tscl_g_ctx.terminating, 0, memory_order_relaxed);
  tscl_os_futex_wake(&tscl_g_ctx.terminating);
#endif // def _WIN32
  return res;
}
