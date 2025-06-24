//===-- content_ops.hpp - operators for content types ---------------------===//
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
/// Implementation of common operators for content types to be used by content
///    API implementation modules.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/content.h"

#include <compare>
#include <tuple>

namespace tek::steamclient::content {

constexpr bool operator==(const tek_sc_sha1_hash &left,
                          const tek_sc_sha1_hash &right) noexcept {
  return std::tie(left.high32, left.low128) ==
         std::tie(right.high32, right.low128);
}

constexpr bool operator!=(const tek_sc_sha1_hash &left,
                          const tek_sc_sha1_hash &right) noexcept {
  return std::tie(left.high32, left.low128) !=
         std::tie(right.high32, right.low128);
}

constexpr std::strong_ordering
operator<=>(const tek_sc_dm_chunk &left,
            const tek_sc_dm_chunk &right) noexcept {
  return std::tie(left.sha.high32, left.sha.low128) <=>
         std::tie(right.sha.high32, right.sha.low128);
}

/// Compare two depot manifest chunk entry pointers by `sha`, and by `offset`
///    for equal `sha` values of entries they point at.
///
/// @param [in] left
///    The first chunk entry pointer to compare.
/// @param [in] right
///    The second chunk entry pointer to compare.
/// @return Value indicating whether the entry pointed to by @p left has
///    smaller `sha` value than the entry pointed to by @p right, or it has the
///    same `sha` value but smaller `offset` value.
constexpr bool
cmp_dm_chunk_sha_and_off(const tek_sc_dm_chunk *const _Nonnull left,
                         const tek_sc_dm_chunk *const _Nonnull right) noexcept {
  return std::tie(left->sha.high32, left->sha.low128, left->offset) <
         std::tie(right->sha.high32, right->sha.low128, right->offset);
}

/// Get a pointer to a manifest chunk entry.
///
/// @param [in] chunk
///    Manifest chunk entry to get pointer to.
/// @return Pointer to @p chunk.
[[gnu::returns_nonnull]]
constexpr const tek_sc_dm_chunk *_Nonnull dm_chunk_to_ptr(
    const tek_sc_dm_chunk &chunk) noexcept {
  return &chunk;
}

} // namespace tek::steamclient::content
