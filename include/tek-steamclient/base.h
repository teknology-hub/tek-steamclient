//===-- base.h - basic TEK Steam Client declarations ----------------------===//
//
// Copyright (c) 2025-2026 Nuclearist <nuclearist@teknology-hub.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// Declarations of TEK Steam Client's basic macros, types and functions.
///
//===----------------------------------------------------------------------===//
#pragma once

#include <stdint.h>

//===-- Compiler macros ---------------------------------------------------===//

#ifndef __clang__
// Clang nullability attributes are replaced with mock macros for other
//    compilers.

#ifndef _Nullable
#define _Nullable
#endif // ndef _Nullable
#ifndef _Nonnull
#define _Nonnull
#endif // ndef _Nonnull
#ifndef _Null_unspecified
#define _Null_unspecified
#endif // ndef _Null_unspecified

#endif // ndef __clang__

// Public API attribute.
#if defined(_WIN32) && !defined(TEK_SC_STATIC)

// Use DLL exports/imports.
#ifdef TEK_SC_EXPORT
#define TEK_SC_API dllexport
#else // def TEK_SC_EXPORT
#define TEK_SC_API dllimport
#endif // def TEK_SC_EXPORT else

#else // defined(_WIN32) && !defined(TEK_SC_STATIC)
#define TEK_SC_API visibility("default")
#endif // defined(_WIN32) && !defined(TEK_SC_STATIC) else

//===-- Common types ------------------------------------------------------===//

/// AES-256 key type.
typedef unsigned char tek_sc_aes256_key[32];

/// Steam content item identifier.
typedef struct tek_sc_item_id tek_sc_item_id;
/// @copydoc tek_sc_item_id
struct tek_sc_item_id {
  /// ID of a Steam application.
  uint32_t app_id;
  /// ID of a content depot.
  uint32_t depot_id;
  /// ID of a Steam Workshop item, must be `0` unless the depot is a Workshop
  /// depot.
  uint64_t ws_item_id;
};

//===-- Library context ---------------------------------------------------===//

/// Opaque TEK Steam Client library context.
/// This context holds caches for various data and WebSocket connection
///    processing event loop.
typedef struct tek_sc_lib_ctx tek_sc_lib_ctx;

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

/// Initialize TEK Steam Client library context.
///
/// @remark
/// This function creates a single thread that processes WebSocket connections
///    for all CM client instances associated with the context.
/// This function also creates/opens an sqlite3 database for cache purposes at
///    `$XDG_CACHE_HOME/tek-steamclient/cache.sqlite3`
///    (`/var/cache/tek-steamclient/cache.sqlite3` for root user if
///    `$XDG_CACHE_HOME` is not set) on Unix-like systems, and
///    `%appdata%\tek-steamclient\cache.sqlite3` on Windows systems.
/// Not safe to call inside `DllMain`.
///
/// @param reserved1
///    This parameter was used in earlier versions of tek-steamclient. It
///    remains for API compatibility and will be removed or changed in the next
///    major release.
/// @param reserved2
///    This parameter was used in earlier versions of tek-steamclient. It
///    remains for API compatibility and will be removed or changed in the next
///    major release.
/// @return Pointer to the created library context that can be passed to other
///    functions. It must be cleaned up with @ref tek_sc_lib_cleanup after use.
///    `nullptr` may be returned on failure, which may be caused by the
///    libraries that tek-steamclient depends on failing to initialize.
[[gnu::TEK_SC_API]]
tek_sc_lib_ctx *_Nullable tek_sc_lib_init(bool reserved1, bool reserved2);

/// Cleanup TEK Steam Client library context.
///
/// @param [in, out] ctx
///    Pointer to the library context to clean up.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_lib_cleanup(tek_sc_lib_ctx *_Nonnull ctx);

/// Get the version of TEK Steam Client library.
///
/// @return Pointer to the statically allocated null-terminated version string.
[[gnu::TEK_SC_API,
  gnu::returns_nonnull]] const char *_Nonnull tek_sc_version(void);

/// Add decryption key for specified depot to library context's cache.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to add the key to.
/// @param depot_id
///    ID of the depot to add decryption key for.
/// @param [in] key
///    Pointer to the decryption key to add.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(read_only, 3)]]
void tek_sc_lib_add_depot_key(tek_sc_lib_ctx *_Nonnull lib_ctx,
                              uint32_t depot_id,
                              const tek_sc_aes256_key _Nonnull key);

/// Get decryption key for specified depot from library context's cache.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to get the key from.
/// @param depot_id
///    ID of the depot to get decryption key for.
/// @param [out] key
///    Address of variable that receives decryption key for the depot on
///    success.
/// @return Value indicating whether the key was found in the cache.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(write_only, 3)]]
bool tek_sc_lib_get_depot_key(tek_sc_lib_ctx *_Nonnull lib_ctx,
                              uint32_t depot_id,
                              tek_sc_aes256_key _Nonnull key);

/// Add PICS access token for specified app to library context's cache.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to add the access token to.
/// @param app_id
///    ID of the Steam application to add PICS access token for.
/// @param token
///    Access token value.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_lib_add_pics_at(tek_sc_lib_ctx *_Nonnull lib_ctx, uint32_t app_id,
                            uint64_t token);

/// Get PICS access token for specified app from library context's cache.
///
/// @param [in, out] lib_ctx
///    Pointer to the library context to get the access token from.
/// @param app_id
///    ID of the Steam application to get access token for.
/// @param [out] token
///    Address of variable that receives access token for the app on success.
/// @return Value indicating whether the access token was found in the cache.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
bool tek_sc_lib_get_pics_at(tek_sc_lib_ctx *_Nonnull lib_ctx, uint32_t app_id,
                            uint64_t *_Nonnull token);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
