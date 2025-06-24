//===-- dump.h - content file dumping interface ---------------------------===//
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
/// Declaration of tek-steamclient content file dumping API to be used by
///    `am dump` command.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h"

#include <stdint.h>

/// Dump a depot manifest.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the manifest belongs to.
/// @param manifest_id
///    ID of the manifest to dump.
/// @return Value indicating whether the operation succeeded.
[[gnu::visibility("internal")]]
bool tscl_dump_manifest(const tek_sc_item_id *_Nonnull item_id,
                        uint64_t manifest_id);

/// Dump a depot patch.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the patch belongs to.
/// @return Value indicating whether the operation succeeded.
[[gnu::visibility("internal")]]
bool tscl_dump_patch(const tek_sc_item_id *_Nonnull item_id);

/// Dump a verification cache.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the verification cache belongs to.
/// @return Value indicating whether the operation succeeded.
[[gnu::visibility("internal")]]
bool tscl_dump_vcache(const tek_sc_item_id *_Nonnull item_id);

/// Dump a depot delta.
///
/// @param [in] item_id
///    Pointer to the ID of the item that the delta belongs to.
/// @return Value indicating whether the operation succeeded.
[[gnu::visibility("internal")]]
bool tscl_dump_delta(const tek_sc_item_id *_Nonnull item_id);
