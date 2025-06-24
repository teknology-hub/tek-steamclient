//===-- delta_chunks.h - VZd and VSZd header and footer definitions -------===//
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
/// Definitions of VZd and VSZd format header and footer structures used by
///    depot patch parsing and processing functions.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <stdint.h>

/// @def TSCI_VZD_HDR_MAGIC
/// Expected magic value for VZd header.
#define TSCI_VZD_HDR_MAGIC 0x645A56 // "VZd"
/// @def TSCI_VZD_FTR_MAGIC
/// Expected magic value for VZd footer.
#define TSCI_VZD_FTR_MAGIC 0x767A // "zv"

/// VZd header.
typedef struct tsci_vzd_hdr tsci_vzd_hdr;
/// @copydoc tsci_vzd_hdr
struct [[gnu::packed]] tsci_vzd_hdr {
  /// VZd header magic value, the integer representation must be
  ///    @ref TSCI_VZD_HDR_MAGIC.
  unsigned char magic[3];
  /// CRC32 checksum of uncompressed chunk data.
  uint32_t crc;
};

/// VZd footer.
typedef struct tsci_vzd_ftr tsci_vzd_ftr;
/// @copydoc tsci_vzd_ftr
struct [[gnu::packed]] tsci_vzd_ftr {
  /// CRC32 checksum of uncompressed chunk data.
  uint32_t crc;
  /// Size of uncompressed data, in bytes.
  uint32_t uncompressed_size;
  /// VZd footer magic value, must be @ref TSCI_VZD_FTR_MAGIC.
  uint16_t magic;
};

/// @def TSCI_VSZD_HDR_MAGIC
/// Expected magic value for VSZd header.
#define TSCI_VSZD_HDR_MAGIC 0x645A5356 // "VSZd"
/// @def TSCI_VSZD_FTR_MAGIC
/// Expected magic value for VSZd footer.
#define TSCI_VSZD_FTR_MAGIC 0x76737A // "zsv"

/// VSZd header.
typedef struct tsci_vszd_hdr tsci_vszd_hdr;
/// @copydoc tsci_vzd_hdr
struct [[gnu::packed]] tsci_vszd_hdr {
  /// VSZd header magic value, must be @ref TSCP_VSZD_HDR_MAGIC.
  uint32_t magic;
  /// CRC32 checksum of uncompressed chunk data.
  uint32_t crc;
};

/// VSZd footer.
typedef struct tsci_vszd_ftr tsci_vszd_ftr;
/// @copydoc tsci_vszd_ftr
struct [[gnu::packed]] tsci_vszd_ftr {
  /// CRC32 checksum of uncompressed chunk data.
  uint32_t crc;
  /// Size of uncompressed data, in bytes.
  uint32_t uncompressed_size;
  /// Reserved?
  uint32_t unknown;
  /// VSZd footer magic value, the integer representation must be
  ///    @ref TSCP_VSZD_FTR_MAGIC.
  unsigned char magic[3];
};
