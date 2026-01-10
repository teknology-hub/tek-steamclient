//===-- os.h - OS-specific code -------------------------------------------===//
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
/// Declarations of functions that are implemented differently on different
///    operating systems. Implementations are provided by corresponding os_*.c.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h> // IWYU pragma: keep

//===-- OS-specific declarations ------------------------------------------===//

#ifdef _WIN32

/// @def TSCL_OS_PRI_str
/// Format specifier for printing @ref tek_sc_os_char strings via printf family
///     of functions.
#define TSCL_OS_PRI_str "S"
/// @def TSCL_OS_INVALID_HANDLE
/// Invalid value for @ref tek_sc_os_handle.
#define TSCL_OS_INVALID_HANDLE INVALID_HANDLE_VALUE
/// @def TSCL_OS_PATH_SEP_CHAR_STR
/// Path separator character for current operating system as a string literal.
#define TSCL_OS_PATH_SEP_CHAR_STR "\\"
/// @def TSCL_OS_SNPRINTF
/// snprintf-like function for @ref tek_sc_os_char string.
#define TSCL_OS_SNPRINTF snwprintf

#elifdef __linux__ // def _WIN32

/// @def TSCL_OS_PRI_str
/// Format specifier for printing @ref tek_sc_os_char strings via printf family
///     of functions.
#define TSCL_OS_PRI_str "s"
/// @def TSCL_OS_INVALID_HANDLE
/// Invalid value for @ref tek_sc_os_handle.
#define TSCL_OS_INVALID_HANDLE -1
/// @def TSCL_OS_PATH_SEP_CHAR_STR
/// Path separator character for current operating system as a string literal.
#define TSCL_OS_PATH_SEP_CHAR_STR "/"
/// @def TSCL_OS_SNPRINTF
/// snprintf-like function for @ref tek_sc_os_char string.
#define TSCL_OS_SNPRINTF snprintf

#elifdef __APPLE__

/// @def TSCL_OS_PRI_str
/// Format specifier for printing @ref tek_sc_os_char strings via printf family
///     of functions.
#define TSCL_OS_PRI_str "s"
/// @def TSCL_OS_INVALID_HANDLE
/// Invalid value for @ref tek_sc_os_handle.
#define TSCL_OS_INVALID_HANDLE -1
/// @def TSCL_OS_PATH_SEP_CHAR_STR
/// Path separator character for current operating system as a string literal.
#define TSCL_OS_PATH_SEP_CHAR_STR "/"
/// @def TSCL_OS_SNPRINTF
/// snprintf-like function for @ref tek_sc_os_char string.
#define TSCL_OS_SNPRINTF snprintf

#endif // def _WIN32 elifdef __linux__ elifdef __APPLE__

//===-- Functions ---------------------------------------------------------===//

/// Create a @ref tek_sc_err out of a @ref tek_sc_errc and a
///    @ref tek_sc_os_errc.
///
/// @param prim
///    Primary error code.
/// @param errc
///    OS error code.
/// @return A @ref tek_sc_err for specified error codes.
[[gnu::nothrow, gnu::const]]
static inline tek_sc_err tscl_err_os(tek_sc_errc prim, tek_sc_os_errc errc) {
  return
#ifdef __cplusplus
      {.type = TEK_SC_ERR_TYPE_os,
       .primary = prim,
       .auxiliary = static_cast<int>(errc),
       .extra = 0,
       .uri = nullptr};
#else  // def __cplusplus
      (tek_sc_err){
          .type = TEK_SC_ERR_TYPE_os, .primary = prim, .auxiliary = (int)errc};
#endif // def __cplusplus else
}

//===-- General functions -------------------------------------------------===//

#ifdef _WIN32
/// Perform Windows-specific program setup.
[[gnu::visibility("internal")]]
void tscl_os_win_setup(void);
#endif // def _WIN32

/// Close operating system resource handle.
///
/// @param handle
///    OS handle to close.
[[gnu::visibility("internal"), gnu::fd_arg(1)]]
void tscl_os_close_handle(
    [[clang::release_handle("os")]] tek_sc_os_handle handle);

/// Get current working directory.
///
/// @return Absolute path to the process current working directory, as a
///    heap-allocated null-terminated string, or `nullptr` on failure. Use
///    @ref tscl_os_get_last_error to get the error code. The returned pointer
///    must be freed with `free` after use.
[[gnu::visibility("internal")]] tek_sc_os_char *_Nullable tscl_os_get_cwd(void);

/// Get the amount of free space on a disk containing specified pathname.
///
/// @param [in] path
///    Path to a file or directory on the target disk, as a null-terminated
///    string.
/// @return The amount of free space on the disk, in bytes, or `-1` on failure.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
int64_t tscl_os_get_disk_free_space(const tek_sc_os_char *_Nonnull path);

/// Get the message for specified error code.
///
/// @param errc
///    OS error code to get the message for.
/// @return Human-readable message for @p errc, as a heap-allocated
///    null-terminated UTF-8 string. It must be freed with `free` after use.
[[gnu::visibility("internal"), gnu::returns_nonnull]]
char *_Nonnull tscl_os_get_err_msg(tek_sc_os_errc errc);

/// Get the last error code set by a system call.
///
/// @return OS-specific error code.
[[gnu::visibility("internal")]]
tek_sc_os_errc tscl_os_get_last_error(void);

/// Get the number of milliseconds passed since some point in the past, where
///    the point is guaranteed to be consistent during program runtime.
///
/// @return Number of milliseconds passed since some point in the past.
[[gnu::visibility("internal")]]
uint64_t tscl_os_get_ticks(void);

/// Register a handler for SIGINT and SIGTERM signals.
///
/// @param handler
///    Signal handler function to register.
[[gnu::visibility("internal"), gnu::nonnull(1)]]
void tscl_os_reg_sig_handler(void (*_Nonnull handler)(void));

/// Unregister current handler for SIGINT and SIGTERM signals.
[[gnu::visibility("internal")]]
void tscl_os_unreg_sig_handler(void);

//===-- I/O functions -----------------------------------------------------===//

/// Create an I/O error object for specified file/directory handle and OS error
///    code.
///
/// @param handle
///    Handle for the file/directory.
/// @param prim
///    Primary error code.
/// @param errc
///    OS error code.
/// @param io_type
///    Type of the I/O operation that failed.
/// @return A @ref tek_sc_err describing the I/O error.
[[gnu::visibility("internal"), gnu::fd_arg(1)]]
tek_sc_err tscl_os_io_err([[clang::use_handle("os")]] tek_sc_os_handle handle,
                          tek_sc_errc prim, tek_sc_os_errc errc,
                          tek_sc_err_io_type io_type);

/// Create an I/O error object for specified parent directory handle,
///     file/directory name, and OS error code.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Name of the file/directory that was subject to failed I/O operation, as a
///    null-terminated string.
/// @param prim
///    Primary error code.
/// @param errc
///    OS error code.
/// @param io_type
///    Type of the I/O operation that failed.
/// @return A @ref tek_sc_err describing the I/O error.
[[gnu::visibility("internal"), gnu::nonnull(2), gnu::fd_arg(1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
tek_sc_err tscl_os_io_err_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tek_sc_errc prim, tek_sc_os_errc errc,
    tek_sc_err_io_type io_type);

/// Open a file at specified directory for reading.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to open, as a null-terminated string.
/// @return Handle for the opened file, or @ref TSCL_OS_INVALID_HANDLE if the
///    function fails. Use @ref tscl_os_get_last_error to get the error code.
///    The returned handle must be closed with @ref tscl_os_close_handle after
///    use.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::acquire_handle("os")]]
tek_sc_os_handle tscl_os_file_open_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

/// Read data from file. Exactly @p n bytes will be read.
///
/// @param handle
///    OS handle for the file.
/// @param [out] buf
///    Pointer to the buffer that receives the read data.
/// @param n
///    Number of bytes to read.
/// @return Value indicating whether the function succeeded. Use
///    @ref tscl_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_read(1), gnu::nonnull(2),
  gnu::access(write_only, 2, 3)]]
bool tscl_os_file_read([[clang::use_handle("os")]] tek_sc_os_handle handle,
                       void *_Nonnull buf, size_t n);

/// Get the size of file.
///
/// @param handle
///    OS handle for the file.
/// @return Size of the file in bytes, or `SIZE_MAX` if the function fails. Use
///    @ref tscl_os_get_last_error to get the error code.
[[gnu::visibility("internal"), gnu::fd_arg_read(1)]]
size_t
tscl_os_file_get_size([[clang::use_handle("os")]] tek_sc_os_handle handle);

//===-- Virtual memory functions ------------------------------------------===//

/// Allocate a region of virtual memory pages.
///
/// @param size
///    Size of the region to allocate, in bytes.
/// @return Pointer to the beginning of allocated region, or `nullptr` if the
///    function fails. Use @ref tsci_os_get_last_error to get the error code.
///    The returned pointer must be freed with @ref tsci_os_mem_free after use.
[[gnu::visibility("internal"), gnu::alloc_size(1), gnu::assume_aligned(4096)]]
void *_Nullable tscl_os_mem_alloc(size_t size);

/// Free a region of virtual memory pages.
///
/// @param addr
///    Pointer to the beginning of memory region to free.
/// @param size
///    Size of the region to free, in bytes.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(none, 1, 2)]]
void tscl_os_mem_free(const void *_Nonnull addr, size_t size);

//===-- Futex functions ---------------------------------------------------===//

/// Wait for a value at @p addr to change from @p old.
///
/// @param [in] addr
///    Pointer to the value to await change for.
/// @param old
///    Value at @p addr that triggers the wait.
/// @param timeout_ms
///    Timeout of the wait operation, in milliseconds.
/// @return Value indicating whether the wait succeeded, `false` on timeout.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1)]]
bool tscl_os_futex_wait(const _Atomic(uint32_t) *_Nonnull addr, uint32_t old,
                        uint32_t timeout_ms);

/// Wake the thread waiting on specified address.
///
/// @param addr
///    Address of the futex to wake the thread for.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(none, 1)]]
void tscl_os_futex_wake(_Atomic(uint32_t) *_Nonnull addr);

//===-- OS string functions -----------------------------------------------===//

/// Read a line of OS characters from stdin.
///
/// @param [out] str
///    Address of buffer that receives read null-terminated string on success.
/// @param size
///    Maximum number of OS characters to read.
/// @return Value indicating whether the function succeeded.
[[gnu::visibility("internal"), gnu::nonnull(1),
  gnu::access(write_only, 1, 2)]] bool
tscl_os_fgets(tek_sc_os_char *_Nonnull str, int size);

/// Find the first occurrence of a character in an OS string.
///
/// @param [in] str
///    Null-terminated OS string to search.
/// @param c
///    The character to search for.
/// @return Pointer to the first occurrence of @p c in @p str if found,
///    otherwise `nullptr`.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
tek_sc_os_char *_Nullable tscl_os_strchr(const tek_sc_os_char *_Nonnull str,
                                         tek_sc_os_char c);

/// Find the last occurrence of a character in an OS string.
///
/// @param [in] str
///    Null-terminated OS string to search.
/// @param c
///    The character to search for.
/// @return Pointer to the last occurrence of @p c in @p str if found, otherwise
///    `nullptr`.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
tek_sc_os_char *_Nullable tscl_os_strrchr(const tek_sc_os_char *_Nonnull str,
                                          tek_sc_os_char c);

/// Three-way compare two null-terminated OS strings.
///
/// @param [in] left
///    The first OS string to compare.
/// @param [in] right
///    The second OS string to compare.
/// @return `0` if the strings are equal, a negative value if @p left is less
///    than @p right, or a positive value if @p left is greater than @p right.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(1),
  gnu::null_terminated_string_arg(2)]]
int tscl_os_strcmp(const tek_sc_os_char *_Nonnull left,
                   const tek_sc_os_char *_Nonnull right);

/// Securely concatenate one null-terminated UTF-8 string to another.
///
/// @param [in, out] str
///    The string to concatenate @p src to.
/// @param [in] src
///    The string to concatenate to @p str.
/// @param size
///    Size of the buffer pointed to by @p str.
[[gnu::visibility("internal"), gnu::nonnull(1, 2),
  gnu::access(read_write, 1, 3), gnu::access(read_only, 2),
  gnu::null_terminated_string_arg(1), gnu::null_terminated_string_arg(2)]]
void tscl_os_strlcat_utf8(char *_Nonnull str, const char *_Nonnull src,
                          size_t size);

/// Get the length of a null-terminated OS string.
///
/// @param [in] str
///    Null-terminated OS string to get length of.
/// @return Length of @p str in OS characters.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
size_t tscl_os_strlen(const tek_sc_os_char *_Nonnull str);

/// Parse a null-terminated base 10 OS string into a number.
///
/// @param [in] str
///    The string to parse.
/// @param [out] endptr
///    Address of variable that receives pointer to the character past the last
///    one parsed.
/// @return The number parsed from @p str, zero otherwise.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1), gnu::access(write_only, 2)]]
unsigned long long
tscl_os_strtoull(const tek_sc_os_char *_Nonnull str,
                 const tek_sc_os_char *_Nonnull *_Nullable endptr);

/// Convert a null-terminated OS string to a UTF-8 heap-allocated
///    null-terminated string.
///
/// @param [in] str
///    Null-terminated OS string to convert.
/// @return Heap-allocated null-terminated UTF-8 string. The returned pointer
///    must be freed with `free` after use.
[[gnu::visibility("internal"), gnu::returns_nonnull, gnu::nonnull(1),
  gnu::access(read_only, 1), gnu::null_terminated_string_arg(1)]] char
    *_Nonnull tscl_os_str_to_utf8(const tek_sc_os_char *_Nonnull str);
