//===-- print_err.c - tek-steamclient error printing ----------------------===//
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
/// Implementation @ref tscl_print_err.
///
//===----------------------------------------------------------------------===//
#include "common.h"

#include "tek-steamclient/error.h"

#include <stdio.h>
#include <stdlib.h>

void tscl_print_err(const tek_sc_err *err) {
  auto msgs = tek_sc_err_get_msgs(err);
  fprintf(stderr,
          tsc_gettext("An error has occurred\n  Error type: (%u) %s\n  Primary "
                      "message: (%u) %s\n"),
          err->type, msgs.type_str, err->primary, msgs.primary);
  if (err->type != TEK_SC_ERR_TYPE_basic) {
    fprintf(stderr, tsc_gettext("  Auxiliary message: (%u) %s\n"),
            err->auxiliary, msgs.auxiliary);
    if (msgs.extra) {
      fprintf(stderr, "  %s\n", msgs.extra);
    }
  }
  if (err->uri) {
    fprintf(stderr, "  %s: %s\n", msgs.uri_type, err->uri);
    free((void *)err->uri);
  }
  tek_sc_err_release_msgs(&msgs);
}
