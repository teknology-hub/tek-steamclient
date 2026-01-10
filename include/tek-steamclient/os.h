//===-- os.h - OS-specific types ------------------------------------------===//
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
/// Declarations of types that vary across different operating systems.
///
//===----------------------------------------------------------------------===//
#pragma once

#ifdef _WIN32
// Windows-specific declarations

#include "base.h" // IWYU pragma: keep

#ifdef TEK_SC_IMPL
// Include windows.h with API set reduced as much as possible
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0xA000
#include <sdkddkver.h>
#define WIN32_LEAN_AND_MEAN
#define NOGDICAPMASKS
#define NOVIRTUALKEYCODES
#define NOWINSTYLES
#define NOSYSMETRICS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define NOSYSCOMMANDS
#define NORASTEROPS
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NODRAWTEXT
#define NOGDI
#define NOKERNEL
#define NOMEMMGR
#define NOMETAFILE
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOTEXTMETRIC
#define NOWH
#define NOWINOFFSETS
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX
#endif // def TEK_SC_IMPL
#include <windows.h>

/// OS type for pathname characters.
typedef WCHAR tek_sc_os_char;
/// OS error code type.
typedef DWORD tek_sc_os_errc;
/// OS type for handles for files or other system resources.
typedef _Null_unspecified HANDLE tek_sc_os_handle;
/// @def TEK_SC_OS_STR
/// Make a string literal for @ref tek_sc_os_char string.
#define TEK_SC_OS_STR(str) L##str

#ifndef TEK_SC_STATIC

/// If library was built with localization support, extract localization files
///    to specified directory and use them.
///
/// This will also call `setlocale` to use OS current locale.
///
/// @param [in] path
///    Path to the directory where a directory structure similar to Unix'
///    `/usr/locale` will be created at, as a null-terminated string.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
void tek_sc_load_locale(const tek_sc_os_char *_Nonnull path);

#endif // ndef TEK_SC_STATIC

#elifdef __linux__ // def _WIN32
// Linux-specific declarations

/// OS type for pathname characters.
typedef char tek_sc_os_char;
/// OS error code type.
typedef int tek_sc_os_errc;
/// OS type for handles for files or other system resources.
typedef int tek_sc_os_handle;
/// @def TEK_SC_OS_STR
/// Make a string literal for @ref tek_sc_os_char string.
#define TEK_SC_OS_STR(str) str

#elifdef __APPLE__ // def _WIN32 elifdef __linux__

/// OS type for pathname characters.
typedef char tek_sc_os_char;
/// OS error code type.
typedef int tek_sc_os_errc;
/// OS type for handles for files or other system resources.
typedef int tek_sc_os_handle;
/// @def TEK_SC_OS_STR
/// Make a string literal for @ref tek_sc_os_char string.
#define TEK_SC_OS_STR(str) str

#else

#error Unsupported target OS. Only Windows (_WIN32), Linux (__linux__) and MacOS (__APPLE__) are supported.

#endif // def _WIN32 elifdef __linux__ else
