//===-- s3c.hpp - tek-s3 client WebSocket protocol declaration ------------===//
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
/// Declaration of tek-s3 WebSocket protocol object.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <libwebsockets.h>

namespace tek::steamclient::s3c {

/// libwebsockets protocol for tek-s3.
[[gnu::visibility("internal")]]
extern const lws_protocols protocol;

} // namespace tek::steamclient::s3c
