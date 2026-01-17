//===-- ws_close_code.h - WebSocket close code enum definition ------------===//
//
// Copyright (c) 2026 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Definition of @ref tsci_ws_close_code.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <stdint.h>

/// WebSocket close codes.
enum tsci_ws_close_code : uint16_t {
  /// Normal closure.
  TSCI_WS_CLOSE_CODE_NORMAL = 1000,
  /// Going away (server is shutting down).
  TSCI_WS_CLOSE_CODE_GOING_AWAY = 1001,
  /// Protocol error.
  TSCI_WS_CLOSE_CODE_PROTO_ERR = 1002,
  /// Unsupported data.
  TSCI_WS_CLOSE_CODE_UNSUPP_DATA = 1003,
  /// No status code received.
  TSCI_WS_CLOSE_CODE_NO_STATUS = 1005,
  /// Abnormal closure.
  TSCI_WS_CLOSE_CODE_ABNORMAL = 1006,
  /// Invalid payload data.
  TSCI_WS_CLOSE_CODE_INVALID_PAYLOAD = 1007,
  /// Policy violation.
  TSCI_WS_CLOSE_CODE_POLICY_VIOLATION = 1008,
  /// Message too big.
  TSCI_WS_CLOSE_CODE_MSG_TOO_BIG = 1009,
  /// Mandatory extension not supported.
  TSCI_WS_CLOSE_CODE_MANDATORY_EXT = 1010,
  /// Internal server error.
  TSCI_WS_CLOSE_CODE_INTERNAL_ERR = 1011,
  /// Service restart.
  TSCI_WS_CLOSE_CODE_SVC_RESTART = 1012,
  /// Try again later.
  TSCI_WS_CLOSE_CODE_TRY_AGAIN = 1013,
  /// Bad gateway.
  TSCI_WS_CLOSE_CODE_BAD_GATEWAY = 1014,
  /// TLS handshake failure.
  TSCI_WS_CLOSE_CODE_TLS_HANDSHAKE = 1015,
  /// Steam CM servers return this code for normal closure.
  TSCI_WS_CLOSE_CODE_STEAM_NORMAL = 59395
};
/// @copydoc tsci_ws_close_code
typedef enum tsci_ws_close_code tsci_ws_close_code;
