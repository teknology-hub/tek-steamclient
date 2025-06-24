//===-- error.h - error creation helpers ----------------------------------===//
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
/// Helper functions for creating @ref tek_sc_err objects.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/error.h"

/// Create a basic @ref tek_sc_err for specified error code.
///
/// @param errc
///    Error code to create error object for.
/// @return A @ref tek_sc_err for specified error code.
[[gnu::nothrow, gnu::const]]
static inline tek_sc_err tsc_err_basic(tek_sc_errc errc) {
  return
#ifdef __cplusplus
      {.type = TEK_SC_ERR_TYPE_basic,
       .primary = errc,
       .auxiliary = 0,
       .extra = 0,
       .uri = nullptr};
#else  // def __cplusplus
      (tek_sc_err){.type = TEK_SC_ERR_TYPE_basic, .primary = errc};
#endif // def __cplusplus else
}

/// Create a @ref tek_sc_err object indicating success.
/// @return A @ref tek_sc_err indicating success.
[[gnu::nothrow, gnu::const]]
static inline tek_sc_err tsc_err_ok(void) {
  return tsc_err_basic(TEK_SC_ERRC_ok);
}

/// Create a compound @ref tek_sc_err.
///
/// @param prim
///    Primary error code.
/// @param aux
///    Auxiliary error code.
/// @return A @ref tek_sc_err for specified error codes.
[[gnu::nothrow, gnu::const]]
static inline tek_sc_err tsc_err_sub(tek_sc_errc prim, tek_sc_errc aux) {
  return
#ifdef __cplusplus
      {.type = TEK_SC_ERR_TYPE_sub,
       .primary = prim,
       .auxiliary = aux,
       .extra = 0,
       .uri = nullptr};
#else  // def __cplusplus
      (tek_sc_err){
          .type = TEK_SC_ERR_TYPE_sub, .primary = prim, .auxiliary = aux};
#endif // def __cplusplus else
}
