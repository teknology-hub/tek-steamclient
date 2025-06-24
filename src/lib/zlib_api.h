//===-- zlib_api.h - zlib adapter API -------------------------------------===//
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
/// Type definitions and macros that are resolved to zlib or zlib-ng based on
///    the build option.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "config.h" // IWYU pragma: keep

#include <stdint.h>

#ifdef TEK_SCB_ZNG
#include <zlib-ng.h>

typedef zng_stream tsci_z_stream;
#define tsci_z_crc32 zng_crc32
#define tsci_z_inflate zng_inflate
#define tsci_z_inflateEnd zng_inflateEnd
#define tsci_z_inflateInit2 zng_inflateInit2
#define tsci_z_inflateReset2 zng_inflateReset2

#else // def TEK_SCB_ZNG
#include <zlib.h>

typedef z_stream tsci_z_stream;
#define tsci_z_crc32 crc32
#define tsci_z_inflate inflate
#define tsci_z_inflateEnd inflateEnd
#define tsci_z_inflateInit2 inflateInit2
#define tsci_z_inflateReset2 inflateReset2

#endif // def TEK_SCB_ZNG else
