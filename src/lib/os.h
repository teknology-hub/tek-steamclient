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
/// Declarations of macros, types and functions that are implemented
///    differently on different operating systems. Implementations are provided
///    by corresponding os_*.c.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <stdatomic.h> // IWYU pragma: keep
#include <stddef.h>
#include <stdint.h>
#include <stdio.h> // IWYU pragma: keep
#include <time.h>

//===-- OS-specific declarations ------------------------------------------===//

#ifdef _WIN32

#include <ioringapi.h>

/// @def TSCI_OS_ERR_ALREADY_EXISTS
/// @ref tek_sc_os_errc value indicating that target file/directory already
///    exists.
#define TSCI_OS_ERR_ALREADY_EXISTS ERROR_ALREADY_EXISTS
/// @def TSCI_OS_ERR_DIR_NOT_EMPTY
/// @ref tek_sc_os_errc value indicating that target directory is not empty.
#define TSCI_OS_ERR_DIR_NOT_EMPTY ERROR_DIR_NOT_EMPTY
/// @def TSCI_OS_ERR_FILE_NOT_FOUND
/// @ref tek_sc_os_errc value indicating that a file was not found.
#define TSCI_OS_ERR_FILE_NOT_FOUND ERROR_FILE_NOT_FOUND
/// @def TSCI_OS_ERR_NOT_SAME_DEV
/// @ref tek_sc_os_errc value indicating that target location is on a different
///    device/filesystem.
#define TSCI_OS_ERR_NOT_SAME_DEV ERROR_NOT_SAME_DEVICE
/// @def TSCI_OS_INVALID_HANDLE
/// Invalid value for @ref tek_sc_os_handle.
#define TSCI_OS_INVALID_HANDLE INVALID_HANDLE_VALUE
/// @def TSCI_OS_PATH_SEP_CHAR_STR
/// Path separator character for current operating system as a string literal.
#define TSCI_OS_PATH_SEP_CHAR_STR "\\"
/// @def TSCI_OS_SNPRINTF
/// snprintf-like function for @ref tek_sc_os_char string.
#define TSCI_OS_SNPRINTF snwprintf

/// File access modes.
enum tsci_os_file_access {
  TSCI_OS_FILE_ACCESS_read =
      FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
  TSCI_OS_FILE_ACCESS_write =
      FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
  TSCI_OS_FILE_ACCESS_rdwr =
      TSCI_OS_FILE_ACCESS_read | TSCI_OS_FILE_ACCESS_write
};

/// Windows asynchronous I/O context implementation.
struct tsci_os_aio_ctx {
  /// When not using I/O ring API, the capacity of @ref reqs, otherwise `-1`.
  int num_reqs;
  /// When not using I/O ring API, number of currently "submitted" requests.
  int num_submitted;
  union {
    /// When not using I/O ring API, pointer to the array of "submitted" request
    ///    pointers.
    struct tsci_os_aio_req *_Nullable *_Nonnull reqs;
    /// Handle for the I/O ring instance.
    HIORING _Nonnull ring;
  };
  /// Last registered file handle.
  HANDLE _Null_unspecified reg_handle;
  /// Pointer to the registered buffer.
  void *_Nullable reg_buf;
};

#elifdef __linux__ // def _WIN32

#include "config.h" // IWYU pragma: keep

#include <errno.h> // IWYU pragma: keep
#include <fcntl.h>
#ifdef TEK_SCB_IO_URING
#include <liburing.h>
#endif // def TEK_SCB_IO_URING

/// @def TSCI_OS_ERR_ALREADY_EXISTS
/// @ref tek_sc_os_errc value indicating that target file/directory already
///    exists.
#define TSCI_OS_ERR_ALREADY_EXISTS EEXIST
/// @def TSCI_OS_ERR_DIR_NOT_EMPTY
/// @ref tek_sc_os_errc value indicating that target directory is not empty.
#define TSCI_OS_ERR_DIR_NOT_EMPTY ENOTEMPTY
/// @def TSCI_OS_ERR_FILE_NOT_FOUND
/// @ref tek_sc_os_errc value indicating that a file was not found.
#define TSCI_OS_ERR_FILE_NOT_FOUND ENOENT
/// @def TSCI_OS_ERR_NOT_SAME_DEV
/// @ref tek_sc_os_errc value indicating that target location is on a different
///    device/filesystem.
#define TSCI_OS_ERR_NOT_SAME_DEV EXDEV
/// @def TSCI_OS_INVALID_HANDLE
/// Invalid value for @ref tek_sc_os_handle.
#define TSCI_OS_INVALID_HANDLE -1
/// @def TSCI_OS_PATH_SEP_CHAR_STR
/// Path separator character for current operating system as a string literal.
#define TSCI_OS_PATH_SEP_CHAR_STR "/"
/// @def TSCI_OS_SNPRINTF
/// snprintf-like function for @ref tek_sc_os_char string.
#define TSCI_OS_SNPRINTF snprintf

/// File access modes.
enum tsci_os_file_access {
  TSCI_OS_FILE_ACCESS_read = O_RDONLY,
  TSCI_OS_FILE_ACCESS_write = O_WRONLY,
  TSCI_OS_FILE_ACCESS_rdwr = O_RDWR
};

/// GNU/Linux asynchronous I/O context implementation.
struct tsci_os_aio_ctx {
  /// When not using io_uring, the capacity of @ref reqs, otherwise `-1`.
  int num_reqs;
  /// Last registered file descriptor.
  int reg_fd;
  union {
    /// When io_uring is not used, pointer to the array of "submitted" request
    ///    pointers.
    struct tsci_os_aio_req *_Nullable *_Nonnull reqs;
    /// On kernels supporting `IORING_SETUP_NO_MMAP`, pointer to the buffer
    ///    allocated for the ring, otherwise `MAP_FAILED`.
    void *_Nullable buf;
  };
  union {
    /// When io_uring is not used, number of currently "submitted" requests.
    int num_submitted;
    /// Value indicating whether the ring has registered buffer.
    bool buf_registered;
  };
#ifdef TEK_SCB_IO_URING
  /// io_uring instance.
  struct io_uring ring;
#endif // def TEK_SCB_IO_URING
};

#endif // def _WIN32 elifdef __linux__

//===-- OS-independent types ----------------------------------------------===//

/// @copydoc tsci_os_file_access
typedef enum tsci_os_file_access tsci_os_file_access;

/// Extra options for creating/opening files.
enum [[clang::flag_enum]] tsci_os_file_opt {
  TSCI_OS_FILE_OPT_none,
  /// Create/open the file for synchronous I/O.
  TSCI_OS_FILE_OPT_sync = 1 << 0,
  /// If the file already exists, truncate it to 0 bytes.
  TSCI_OS_FILE_OPT_trunc = 1 << 1
};
/// @copydoc tsci_os_file_opt
typedef enum tsci_os_file_opt tsci_os_file_opt;

/// Asynchronous I/O context.
typedef struct tsci_os_aio_ctx tsci_os_aio_ctx;

/// Asynchronous I/O request descriptor for receiving completion data.
typedef struct tsci_os_aio_req tsci_os_aio_req;
/// @copydoc tsci_os_aio_req
struct tsci_os_aio_req {
  /// Handle for the file on which the operation was performed.
  tek_sc_os_handle handle;
  /// Result code of the operation.
  tek_sc_os_errc result;
  /// On success, the number of bytes transferred by the operation.
  int bytes_transferred;
};

/// Arguments for  @ref tsci_os_file_copy_chunk and @ref tsci_os_file_copy.
typedef struct tsci_os_copy_args tsci_os_copy_args;
/// @copydoc tsci_os_copy_args
struct tsci_os_copy_args {
  /// @ref tsci_os_file_copy_chunk: Handle for the file to copy the chunk from.
  /// @ref tsci_os_file_copy: Handle for the directory to copy the file from.
  tek_sc_os_handle src_handle;
  /// @ref tsci_os_file_copy_chunk: Handle for the file to copy the chunk to.
  /// @ref tsci_os_file_copy: Handle for the directory to copy the file to.
  tek_sc_os_handle tgt_handle;
  /// Value indicating whether source and target files/directories are located
  ///    on different filesystems. Used on Linux to switch to
  ///    `pread`+`pwrite`/`sendfile` immediately without attempting to use
  ///    `copy_file_range` first. Set automatically by the function when it
  ///    detects this condition.
  bool not_same_dev;
  /// Pointer to the temporary buffer to use during copying when zero-copy
  ///    methods are not available.
  void *_Nonnull buf;
  /// Size of the buffer pointed to by @ref buf, in bytes.
  size_t buf_size;
  /// Receives I/O error object if @ref tsci_os_file_copy fails.
  tek_sc_err error;
};

/// Operating system version descriptor.
typedef struct tsci_os_version tsci_os_version;
/// @copydoc tsci_os_version
struct tsci_os_version {
  /// Major version number.
  int major;
  /// Minor version number.
  int minor;
  /// Build version number.
  int build;
};

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
static inline tek_sc_err tsci_err_os(tek_sc_errc prim, tek_sc_os_errc errc) {
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

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

//===-- General functions -------------------------------------------------===//

/// Close operating system resource handle.
///
/// @param handle
///    OS handle to close.
[[gnu::visibility("internal"), gnu::fd_arg(1)]]
void tsci_os_close_handle(
    [[clang::release_handle("os")]] tek_sc_os_handle handle);

/// Get path to the cache directory for current user.
///
/// @return Path to the cache directory for current user, as a heap-allocated
///    null-terminated string, or `nullptr` on failure. The returned pointer
///    must be freed with `free` after use.
[[gnu::visibility("internal")]] tek_sc_os_char *_Nullable tsci_os_get_cache_dir(
    void);

/// Get the message for specified error code.
///
/// @param errc
///    OS error code to get the message for.
/// @return Human-readable message for @p errc, as a heap-allocated
///    null-terminated UTF-8 string. It must be freed with `free` after use.
[[gnu::visibility("internal"), gnu::returns_nonnull]]
char *_Nonnull tsci_os_get_err_msg(tek_sc_os_errc errc);

/// Get the last error code set by a system call.
///
/// @return OS-specific error code.
[[gnu::visibility("internal")]] tek_sc_os_errc tsci_os_get_last_error(void);

/// Get the number of available logical processors in the system.
///
/// @return Number of available logical processors.
[[gnu::visibility("internal")]] int tsci_os_get_nproc(void);

/// Get the number of milliseconds passed since some point in the past, where
///    the point is guaranteed to be consistent during program runtime.
///
/// @return Number of milliseconds passed since some point in the past.
[[gnu::visibility("internal")]]
uint64_t tsci_os_get_ticks(void);

/// Get version of the running operating system.
///
/// @return OS version object.
[[gnu::visibility("internal")]] tsci_os_version tsci_os_get_version(void);

/// Get the creation time of current process.
///
/// @return Number of seconds passed since Unix Epoch to process creation.
[[gnu::visibility("internal")]] time_t tsci_os_get_process_start_time(void);

/// Set name of the current thread, to be displayed in e.g. debuggers.
///
/// @param [in] name
///    Thread name, as a null-terminated string.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
void tsci_os_set_thread_name(const tek_sc_os_char *_Nonnull name);

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
tek_sc_err tsci_os_io_err([[clang::use_handle("os")]] tek_sc_os_handle handle,
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
tek_sc_err tsci_os_io_err_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tek_sc_errc prim, tek_sc_os_errc errc,
    tek_sc_err_io_type io_type);

/// Check if a file/subdirectory with specified name exists at specified
///    directory.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Pathname to check existence of.
/// @return `0` if specified pathname exists, @ref TSCI_OS_ERR_FILE_NOT_FOUND if
///    it doesn't, other OS error code values if an error occurs.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
tek_sc_os_errc tsci_os_path_exists_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

//===--- Diectory create/open ---------------------------------------------===//

/// Open a directory, or create it if it doesn't exist.
///
/// @param [in] path
///    Path to the directory to open/create, as a null-terminated string.
/// @return Handle for the opened directory, or @ref TSCI_OS_INVALID_HANDLE if
///    the function fails. Use @ref tsci_os_get_last_error to get the error
///    code. The returned handle must be closed with @ref tsci_os_close_handle
///    after use.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1), clang::acquire_handle("os")]]
tek_sc_os_handle tsci_os_dir_create(const tek_sc_os_char *_Nonnull path);

/// Open a subdirectory at specified directory, or create it if it doesn't
///    exist.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Name of the subdirectory to open/create, as a null-terminated string.
/// @return Handle for the opened subdirectory, or @ref TSCI_OS_INVALID_HANDLE
///    if the function fails. Use @ref tsci_os_get_last_error to get the error
///    code. The returned handle must be closed with @ref tsci_os_close_handle
///    after use.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::acquire_handle("os")]]
tek_sc_os_handle tsci_os_dir_create_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

/// Open a subdirectory at specified directory.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Name of the subdirectory to open, as a null-terminated string.
/// @return Handle for the opened subdirectory, or @ref TSCI_OS_INVALID_HANDLE
///    if the function fails. Use @ref tsci_os_get_last_error to get the error
///    code. The returned handle must be closed with @ref tsci_os_close_handle
///    after use.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::acquire_handle("os")]]
tek_sc_os_handle tsci_os_dir_open_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

//===--- Directory move/delete --------------------------------------------===//

/// Move specified subdirectory from one directory to another.
///
/// @param src_dir_handle
///    Handle for the directory to move the subdirectory from.
/// @param tgt_dir_handle
///    Handle for the directory to move the subdirectory to.
/// @param [in] name
///    Name of the subdirectory to move, as a null-terminated string.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::fd_arg(2), gnu::nonnull(3),
  gnu::access(read_only, 3), gnu::null_terminated_string_arg(3)]]
bool tsci_os_dir_move(
    [[clang::use_handle("os")]] tek_sc_os_handle src_dir_handle,
    [[clang::use_handle("os")]] tek_sc_os_handle tgt_dir_handle,
    const tek_sc_os_char *_Nonnull name);

/// Mark a subdirectory of specified directory for deletion after all active
///    handles for it are closed, if the subdirectory is empty.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Name of the subdirectory to delete, as a null-terminated string.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
bool tsci_os_dir_delete_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

/// Recursively delete a subdirectory of specified directory.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Name of the subdirectory to delete, as a null-terminated string.
/// @param errc
///    Primary error code to return in the error in case of failure.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
tek_sc_err tsci_os_dir_delete_at_rec(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tek_sc_errc errc);

//===--- File create/open -------------------------------------------------===//

/// Open a file at specified directory, or create it if it doesn't exist.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to open/create, as a null-terminated string.
/// @param access
///    Access mode for the file.
/// @param options
///    Extra options.
/// @return Handle for the opened file, or @ref TSCI_OS_INVALID_HANDLE if the
///    function fails. Use @ref tsci_os_get_last_error to get the error code.
///    The returned handle must be closed with @ref tsci_os_close_handle after
///    use.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::acquire_handle("os")]]
tek_sc_os_handle tsci_os_file_create_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tsci_os_file_access access,
    tsci_os_file_opt options);

/// Open a file at specified directory.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to open, as a null-terminated string.
/// @param access
///    Access mode for the file.
/// @param options
///    Extra options.
/// @return Handle for the opened file, or @ref TSCI_OS_INVALID_HANDLE if the
///    function fails. Use @ref tsci_os_get_last_error to get the error code.
///    The returned handle must be closed with @ref tsci_os_close_handle after
///    use.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2),
  clang::acquire_handle("os")]]
tek_sc_os_handle tsci_os_file_open_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tsci_os_file_access access,
    tsci_os_file_opt options);

//===--- File read/write --------------------------------------------------===//

/// Read data from file. Exactly @p n bytes will be read.
///
/// @param handle
///    OS handle for the file.
/// @param [out] buf
///    Pointer to the buffer that receives the read data.
/// @param n
///    Number of bytes to read.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_read(1), gnu::nonnull(2),
  gnu::access(write_only, 2, 3)]]
bool tsci_os_file_read([[clang::use_handle("os")]] tek_sc_os_handle handle,
                       void *_Nonnull buf, size_t n);

/// Read data from file at specified offset. Exactly @p n bytes will be read.
///
/// @param handle
///    OS handle for the file.
/// @param [out] buf
///    Pointer to the buffer that receives the read data.
/// @param n
///    Number of bytes to read.
/// @param offset
///    Offset in the file to read from, in bytes.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_read(1), gnu::nonnull(2),
  gnu::access(write_only, 2, 3)]]
bool tsci_os_file_read_at([[clang::use_handle("os")]] tek_sc_os_handle handle,
                          void *_Nonnull buf, size_t n, int64_t offset);

/// Write data to file. Exactly @p n bytes will be written.
///
/// @param handle
///    OS handle for the file.
/// @param [in] buf
///    Pointer to the buffer containing the data to write.
/// @param n
///    Number of bytes to write.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_write(1), gnu::nonnull(2),
  gnu::access(read_only, 2, 3)]]
bool tsci_os_file_write([[clang::use_handle("os")]] tek_sc_os_handle handle,
                        const void *_Nonnull buf, size_t n);

/// Write data to file at specified offset. Exactly @p n bytes will be written.
///
/// @param handle
///    OS handle for the file.
/// @param [in] buf
///    Pointer to the buffer containing the data to write.
/// @param n
///    Number of bytes to write.
/// @param offset
///    Offset in the file to write to, in bytes.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_write(1), gnu::nonnull(2),
  gnu::access(read_only, 2, 3)]]
bool tsci_os_file_write_at([[clang::use_handle("os")]] tek_sc_os_handle handle,
                           const void *_Nonnull buf, size_t n, int64_t offset);

//===--- File get/set size ------------------------------------------------===//

/// Get the size of file by its handle.
///
/// @param handle
///    OS handle for the file.
/// @return Size of the file in bytes, or `SIZE_MAX` if the function fails. Use
///    @ref tsci_os_get_last_error to get the error code.
[[gnu::visibility("internal"), gnu::fd_arg_read(1)]]
size_t
tsci_os_file_get_size([[clang::use_handle("os")]] tek_sc_os_handle handle);

/// Get the size of file by its parent directory handle and name.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to get size of, as a null-terminated string.
/// @return Size of the file in bytes, or `SIZE_MAX` if the function fails. Use
///    @ref tsci_os_get_last_error to get the error code.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
size_t tsci_os_file_get_size_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

/// Truncate file to specified size.
///
/// @param handle
///    OS handle for the file.
/// @param new_size
///    New size of the file, in bytes.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg_write(1)]]
bool tsci_os_file_truncate([[clang::use_handle("os")]] tek_sc_os_handle handle,
                           int64_t new_size);

//===--- File apply flags -------------------------------------------------===//

/// Apply depot manifest flags to specified file.
///
/// @param handle
///    OS handle for the file.
/// @param flags
///    Flags to apply to the file.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1)]]
bool tsci_os_file_apply_flags(
    [[clang::use_handle("os")]] tek_sc_os_handle handle,
    tek_sc_dm_file_flag flags);

/// Apply depot manifest flags to specified file by its parent directory handle
///    and name.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to apply flags to, as a null-terminated string.
/// @param flags
///    Flags to apply to the file.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
bool tsci_os_file_apply_flags_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name, tek_sc_dm_file_flag flags);

//===--- File copy/move ---------------------------------------------------===//

/// Copy specified chunk of data from one file to another.
///
/// @param [in, out] args
///    Pointer to the arguments structure.
/// @param src_offset
///    Offset in the source file to read the chunk from, in bytes.
/// @param tgt_offset
///    Offset in the target file to write the chunk to, in bytes.
/// @param size
///    Size of the chunk to copy, in bytes.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_write, 1)]]
bool tsci_os_file_copy_chunk(tsci_os_copy_args *_Nonnull args,
                             int64_t src_offset, int64_t tgt_offset,
                             size_t size);

/// Copy specified file from one directory to another.
///
/// @param [in, out] args
///    Pointer to the arguments structure.
/// @param [in] name
///    Name of the file to copy, as a null-terminated string.
/// @param size
///    Size of the file to copy, in bytes.
/// @param errc
///    Primary error code to return in the error in case of failure.
/// @return Value indicating whether the function succeeded. Use `args->error`
///    to get the error information in case of failure.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
bool tsci_os_file_copy(tsci_os_copy_args *_Nonnull args,
                       const tek_sc_os_char *_Nonnull name, int64_t size,
                       tek_sc_errc errc);

/// Move specified file from one directory to another.
///
/// @param src_dir_handle
///    Handle for the directory to move the file from.
/// @param tgt_dir_handle
///    Handle for the directory to move the file to.
/// @param [in] name
///    Name of the file to move, as a null-terminated string.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::fd_arg(2), gnu::nonnull(3),
  gnu::access(read_only, 3), gnu::null_terminated_string_arg(3)]]
bool tsci_os_file_move(
    [[clang::use_handle("os")]] tek_sc_os_handle src_dir_handle,
    [[clang::use_handle("os")]] tek_sc_os_handle tgt_dir_handle,
    const tek_sc_os_char *_Nonnull name);

//===--- File delete ------------------------------------------------------===//

/// Mark a file at specified directory for deletion after all active handles
///    for it are closed.
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file.
/// @param [in] name
///    Name of the file to delete, as a null-terminated string.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::fd_arg(1), gnu::nonnull(2),
  gnu::access(read_only, 2), gnu::null_terminated_string_arg(2)]]
bool tsci_os_file_delete_at(
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

//===--- Symbolic link ----------------------------------------------------===//

/// Create a symbolic link at specified directory.
///
/// @param [in] target
///    Target of the symbolic link, as a null-terminated string.
/// @param parent_dir_handle
///    Handle for the parent directory of the symbolic link.
/// @param [in] name
///    Name of the symbolic link to create, as a null-terminated string.
/// @return Value indicating whether the function succeeded. Use
///    @ref tsci_os_get_last_error to get the error code in case of failure.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1), gnu::fd_arg(2), gnu::access(read_only, 3),
  gnu::null_terminated_string_arg(3)]]
bool tsci_os_symlink_at(
    const tek_sc_os_char *_Nonnull target,
    [[clang::use_handle("os")]] tek_sc_os_handle parent_dir_handle,
    const tek_sc_os_char *_Nonnull name);

//===-- Asynchronous I/O functions ----------------------------------------===//

/// Initialize an asynchronous I/O context.
///
/// @param [out] ctx
///    Pointer to the asynchronous I/O context to initialize.
/// @param num_reqs
///    Number of requests that the context will be able to run concurrently.
/// @param buffer
///    Pointer to the memory region that will be used for I/O
///    (read to/written from).
/// @param buffer_size
///    Size of the buffer pointed to by @p buffer, in bytes.
/// @return A @ref tek_sc_os_errc indicating the result of operation.
///    Successfully initialized context must be destroyed with
///    @ref tsci_os_aio_tctx_destroy after use.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_write, 1),
  gnu::access(none, 3, 4)]]
tek_sc_os_errc tsci_os_aio_ctx_init(tsci_os_aio_ctx *_Nonnull ctx, int num_reqs,
                                    void *_Nonnull buffer, size_t buffer_size);

/// Destroy an asynchronous I/O context.
///
/// @param [in, out] ctx
///    Pointer to the asynchronous I/O context to destroy.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_write, 1)]]
void tsci_os_aio_ctx_destroy(tsci_os_aio_ctx *_Nonnull ctx);

/// Register specified file handle for asynchronous I/O, overriding previous
///    registration if any.
///
/// @param [in, out] ctx
///    Pointer to the asynchronous I/O context to register file on.
/// @param handle
///    Handle for the file to register.
/// @return A @ref tek_sc_os_errc indicating the result of operation.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_write, 1),
  gnu::fd_arg(2)]]
tek_sc_os_errc
tsci_os_aio_register_file(tsci_os_aio_ctx *_Nonnull ctx,
                          [[clang::use_handle("os")]] tek_sc_os_handle handle);

/// Submit a request to perform asynchronous read of data from currently
///    registered file at specified offset.
///
/// @param [in, out] ctx
///    Pointer to the asynchronous I/O context to perform read on.
/// @param [in, out] req
///    Pointer to the request descriptor that will receive completion data.
/// @param [out] buf
///    Pointer to the buffer that receives the read data.
/// @param n
///    Number of bytes to read.
/// @param offset
///    Offset in the file to read from, in bytes.
/// @param submit
///    If `false` and OS supports it, the request won't be submitted to the
///    kernel immediately, instead it'll stay in the queue until
///    @ref tsci_os_aio_get_compls is called.
/// @return A @ref tek_sc_os_errc indicating the result of submission.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(write_only, 3, 4)]]
tek_sc_os_errc tsci_os_aio_submit_read(tsci_os_aio_ctx *_Nonnull ctx,
                                       tsci_os_aio_req *_Nonnull req,
                                       void *_Nonnull buf, size_t n,
                                       int64_t offset, bool submit);

/// Submit a request to perform asynchronous write of data to currently
///    registered file at specified offset.
///
/// @param [in, out] ctx
///    Pointer to the asynchronous I/O context to perform write on.
/// @param [in, out] req
///    Pointer to the request descriptor that will receive completion data.
/// @param [in] buf
///    Pointer to the buffer containing the data to write.
/// @param n
///    Number of bytes to write.
/// @param offset
///    Offset in the file to write to, in bytes.
/// @param submit
///    If `false` and OS supports it, the request won't be submitted to the
///    kernel immediatly, instead it'll stay in the queue until
///    @ref tsci_os_aio_get_compls is called.
/// @return A @ref tek_sc_os_errc indicating the result of submission.
[[gnu::visibility("internal"), gnu::nonnull(1, 2, 3),
  gnu::access(read_write, 1), gnu::access(read_write, 2),
  gnu::access(read_only, 3, 4)]]
tek_sc_os_errc tsci_os_aio_submit_write(tsci_os_aio_ctx *_Nonnull ctx,
                                        tsci_os_aio_req *_Nonnull req,
                                        const void *_Nonnull buf, size_t n,
                                        int64_t offset, bool submit);

/// Submit all pending requests to the kernel and wait until at least
///    @p num_wait completions are available on the context, then peek up to
///    @p num_reqs completions.
///
/// @param [in, out] ctx
///    Pointer to the asynchronous I/O context to get completions from.
/// @param [out] reqs
///    Pointer to the array that on success receives pointers to completed
///    request descriptors.
/// @param num_reqs
///    The maximum number of completions to get.
/// @param num_wait
///    The minimum number of completions that must be available before
///    returning. If there are not enough available completions, the function
///    waits for them.
/// @return The number of received completions. On failure, `-1` is returned,
///    and @ref tsci_os_get_last_error can be used to get the error code.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_write, 1),
  gnu::access(write_only, 2)]]
int tsci_os_aio_get_compls(tsci_os_aio_ctx *_Nonnull ctx,
                           tsci_os_aio_req *_Nullable *_Nullable reqs,
                           int num_reqs, int num_wait);

//===-- Virtual memory functions ------------------------------------------===//

/// Allocate a region of virtual memory pages.
///
/// @param size
///    Size of the region to allocate, in bytes.
/// @return Pointer to the beginning of allocated region, or `nullptr` if the
///    function fails. Use @ref tsci_os_get_last_error to get the error code.
///    The returned pointer must be freed with @ref tsci_os_mem_free after use.
[[gnu::visibility("internal"), gnu::alloc_size(1), gnu::assume_aligned(4096)]]
void *_Nullable tsci_os_mem_alloc(size_t size);

/// Free a region of virtual memory pages.
///
/// @param addr
///    Pointer to the beginning of memory region to free.
/// @param size
///    Size of the region to free, in bytes.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(none, 1, 2)]]
void tsci_os_mem_free(const void *_Nonnull addr, size_t size);

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
bool tsci_os_futex_wait(const _Atomic(uint32_t) *_Nonnull addr, uint32_t old,
                        uint32_t timeout_ms);

/// Wake all threads waiting on specified address.
///
/// @param addr
///    Address of the futex to wake threads for.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(none, 1)]]
void tsci_os_futex_wake(_Atomic(uint32_t) *_Nonnull addr);

//===-- Pathname string functions -----------------------------------------===//

/// Get the number of bytes required to represent specified null-terminated
///    pathname string as a UTF-8 string.
///
/// @param [in] pstr
///    Null-terminated pathname string to process.
/// @return The number of bytes required to represent @p pstr as a UTF-8
///    string.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::null_terminated_string_arg(1)]]
int tsci_os_pstr_strlen(const tek_sc_os_char *_Nonnull pstr);

/// Convert a null-terminated pathname string to a UTF-8 string.
///
/// @param [in] pstr
///    Null-terminated pathname string to convert.
/// @param [out] str
///    Pointer to the buffer that receives the resulting UTF-8 string.
/// @return The number of bytes written to @p str.
[[gnu::visibility("internal"), gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(write_only, 2), gnu::null_terminated_string_arg(1)]]
int tsci_os_pstr_to_str(const tek_sc_os_char *_Nonnull pstr,
                        char *_Nonnull str);

/// Get the number of pathname characters required to represent specified UTF-8
///    string.
///
/// @param [in] str
///    UTF-8 string to process.
/// @param len
///    Number of bytes to read from @p str.
/// @return The number of pathname characters required to represent @p str.
[[gnu::visibility("internal"), gnu::nonnull(1), gnu::access(read_only, 1, 2)]]
int tsci_os_str_pstrlen(const char *_Nonnull str, int len);

/// Convert a UTF-8 string to a pathname string.
///
/// @param [in] str
///    UTF-8 string to convert.
/// @param len
///    Number of bytes to read from @p str.
/// @param [out] pstr
///    Pointer to the buffer that receives the resulting pathname string.
/// @return The number of pathname characters written to @p pstr.
[[gnu::visibility("internal"), gnu::nonnull(1, 3), gnu::access(read_only, 1, 2),
  gnu::access(write_only, 3)]]
int tsci_os_str_to_pstr(const char *_Nonnull str, int len,
                        tek_sc_os_char *_Nonnull pstr);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
