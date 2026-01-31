//===-- os_windows.c - Windows OS functions implementation ----------------===//
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
/// Windows implementation of @ref os.h.
///
//===----------------------------------------------------------------------===//
#include "os.h"

#include "common/error.h"
#include "config.h"               // IWYU pragma: keep
#include "tek-steamclient/base.h" // IWYU pragma: keep
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <ioringapi.h>
#ifdef TEK_SCB_GETTEXT
#include <libintl.h>
#include <locale.h>
#endif // def TEK_SCB_GETTEXT
#include <limits.h>
#include <ntstatus.h>
#include <pthread.h>
#include <shlobj.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <winternl.h>

//===-- Declarations missing from winternl.h ------------------------------===//

#define FileDispositionInformationEx 64
#define FileRenameInformationEx 65
#define ThreadNameInformation 38

#define NtCurrentProcess() ((HANDLE)(LONG_PTR) - 1)

NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                       ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                       ULONG AllocationType,
                                       ULONG PageProtection);

NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                   PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS NTAPI NtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                                     PFILE_BASIC_INFORMATION FileInformation);

NTSTATUS NTAPI
NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes,
                          PFILE_NETWORK_OPEN_INFORMATION FileInformation);

NTSTATUS NTAPI NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event,
                          PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                          PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                          ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event,
                           PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                           PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                           ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

VOID NTAPI RtlGetNtVersionNumbers(PULONG NtMajorVersion, PULONG NtMinorVersion,
                                  PULONG NtBuildNumber);

//===-- I/O ring API variables --------------------------------------------===//

/// Values indicating I/O ring API support on current system.
enum {
  /// I/O ring API availability hasn't been checked yet.
  TSCP_IORING_unchecked,
  /// I/O ring API is not supported on current system.
  TSCP_IORING_unsupported,
  /// I/O ring API is supported on current system.
  TSCP_IORING_supported
} tscp_ioring_support = TSCP_IORING_unchecked;
/// Mutex ensuring that only one thread checks (and possibly modifies)
///    @ref tscp_ioring_support at a time.
static pthread_mutex_t tscp_ioring_init_mtx = PTHREAD_NORMAL_MUTEX_INITIALIZER;

// Function pointers (as they may not be present in older Windows versions)
static typeof(&BuildIoRingReadFile) _Nullable pBuildIoRingReadFile;
static typeof(&BuildIoRingRegisterBuffers) _Nullable pBuildIoRingRegisterBuffers;
static typeof(&BuildIoRingRegisterFileHandles) _Nullable pBuildIoRingRegisterFileHandles;
static typeof(&BuildIoRingWriteFile) _Nullable pBuildIoRingWriteFile;
static typeof(&CloseIoRing) _Nullable pCloseIoRing;
static typeof(&CreateIoRing) _Nullable pCreateIoRing;
static typeof(&PopIoRingCompletion) _Nullable pPopIoRingCompletion;
static typeof(&QueryIoRingCapabilities) _Nullable pQueryIoRingCapabilities;
static typeof(&SubmitIoRing) _Nullable pSubmitIoRing;

/// Latest I/O ring version supported by current system.
static IORING_VERSION tscp_ioring_ver;

//===-- Private functions -------------------------------------------------===//

/// Wrapper around `NtCreateFile`
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file/directory.
/// @param [in] name
///    Name of the file/directory to open/create, as a null-terminated string.
/// @param access
///    Requested file/directory access mask.
/// @param attributes
///    Attributes that the created file/directory will have.
/// @param share_access
///    Type of the share access that the file/directory will have.
/// @param disposition
///    Action to perform on the file/directory.
/// @param options
///    Options to pass to `NtCreateFile`.
/// @return Handle for the opened/created file. On failre,
///    `INVALID_HANDLE_VALUE` is returned and last error value is set.
[[gnu::nonnull(2), gnu::access(read_only, 2),
  gnu::null_terminated_string_arg(2), clang::acquire_handle("os")]]
static inline HANDLE
tscp_nt_create_file([[clang::use_handle("os")]] HANDLE parent_dir_handle,
                    const WCHAR *_Nonnull name, ACCESS_MASK access,
                    ULONG attributes, ULONG share_access, ULONG disposition,
                    ULONG options) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto const status = NtCreateFile(
      &handle, access,
      &(OBJECT_ATTRIBUTES){.Length = sizeof(OBJECT_ATTRIBUTES),
                           .RootDirectory = parent_dir_handle,
                           .ObjectName =
                               &(UNICODE_STRING){.Length = name_size,
                                                 .MaximumLength = name_size,
                                                 .Buffer = (PWSTR)name},
                           .Attributes = OBJ_CASE_INSENSITIVE},
      &isb, nullptr, attributes, share_access, disposition, options, nullptr,
      0);
  if (NT_SUCCESS(status)) {
    return handle;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return INVALID_HANDLE_VALUE;
}

/// Wrapper around `NtOpenFile`
///
/// @param parent_dir_handle
///    Handle for the parent directory of the file/directory.
/// @param [in] name
///    Name of the file/directory to open, as a null-terminated string.
/// @param access
///    Requested file/directory access mask.
/// @param share_access
///    Type of the share access that the file/directory will have.
/// @param options
///    Options to pass to `NtOpenFile`.
/// @return Handle for the opened file. On failre, `INVALID_HANDLE_VALUE` is
///    returned and last error value is set.
[[gnu::nonnull(2), gnu::access(read_only, 2),
  gnu::null_terminated_string_arg(2), clang::acquire_handle("os")]]
static inline HANDLE
tscp_nt_open_file([[clang::use_handle("os")]] HANDLE parent_dir_handle,
                  const WCHAR *_Nonnull name, ACCESS_MASK access,
                  ULONG share_access, ULONG options) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto const status =
      NtOpenFile(&handle, access,
                 &(OBJECT_ATTRIBUTES){
                     .Length = sizeof(OBJECT_ATTRIBUTES),
                     .RootDirectory = parent_dir_handle,
                     .ObjectName = &(UNICODE_STRING){.Length = name_size,
                                                     .MaximumLength = name_size,
                                                     .Buffer = (PWSTR)name},
                     .Attributes = OBJ_CASE_INSENSITIVE},
                 &isb, share_access, options);
  if (NT_SUCCESS(status)) {
    return handle;
  }
  if (status == STATUS_OBJECT_PATH_NOT_FOUND) {
    // To match behavior of Unix-like systems with one ENOENT to rule them all
    status = STATUS_OBJECT_NAME_NOT_FOUND;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return INVALID_HANDLE_VALUE;
}

/// Create an I/O error object for specified parent directory handle, file name,
///    and OS error code.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Pointer to the `UNICODE_STRING` containing name of the file that was
///    subject to failed I/O operation.
/// @param prim
///    Primary error code.
/// @param sec
///    OS error code.
/// @param io_type
///    Type of the I/O operation that failed.
/// @return A @ref tek_sc_err describing the I/O error.
[[gnu::nonnull(2), gnu::access(read_only, 2)]]
static tek_sc_err
tscp_os_io_err_at([[clang::use_handle("os")]] HANDLE parent_dir_handle,
                  const UNICODE_STRING *_Nonnull name, tek_sc_errc prim,
                  tek_sc_os_errc errc, tek_sc_err_io_type io_type) {
  auto const dir_path_len = GetFinalPathNameByHandleW(
      parent_dir_handle, nullptr, 0, FILE_NAME_NORMALIZED);
  char *buf = nullptr;
  if (dir_path_len) {
    const LPWSTR dir_path = malloc(dir_path_len * sizeof *dir_path);
    if (dir_path) {
      if (GetFinalPathNameByHandleW(parent_dir_handle, dir_path, dir_path_len,
                                    FILE_NAME_NORMALIZED)) {
        const int dir_path8_len =
            WideCharToMultiByte(CP_UTF8, 0, dir_path + 4, dir_path_len - 4,
                                nullptr, 0, nullptr, nullptr);
        const int name_len = name->Length / sizeof *name->Buffer;
        const int name8_len = WideCharToMultiByte(
            CP_UTF8, 0, name->Buffer, name_len, nullptr, 0, nullptr, nullptr);
        buf = malloc(dir_path_len + name8_len + 1);
        if (buf) {
          WideCharToMultiByte(CP_UTF8, 0, dir_path + 4, dir_path_len - 5, buf,
                              dir_path8_len, nullptr, nullptr);
          buf[dir_path8_len - 1] = '\\';
          WideCharToMultiByte(CP_UTF8, 0, name->Buffer, name_len,
                              &buf[dir_path8_len], name8_len, nullptr, nullptr);
          buf[dir_path8_len + name8_len] = '\0';
        }
      }
      free(dir_path);
    }
  }
  return (tek_sc_err){.type = TEK_SC_ERR_TYPE_os,
                      .primary = prim,
                      .auxiliary = errc,
                      .extra = io_type,
                      .uri = buf};
}

/// Recursively delete subdirectory of specified directory.
///
/// @param parent_dir_handle
///    Handle for the parent directory.
/// @param [in] name
///    Pointer to the `UNICODE_STRING` containing name of the subdirectory to
///    delete.
/// @param errc
///    Primary error code to return in the error in case of failure.
/// @param [in, out] buf
///    Pointer to the buffer to read file list into. Assumed to have the size
///    of 4 KiB.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::nonnull(2, 4), gnu::access(read_only, 2), gnu::access(read_write, 4)]]
static tek_sc_err
tscp_os_del_dir([[clang::use_handle("os")]] HANDLE parent_dir_handle,
                UNICODE_STRING *_Nonnull name, tek_sc_errc errc,
                void *_Nonnull buf) {
  OBJECT_ATTRIBUTES attrs = {.Length = sizeof attrs,
                             .RootDirectory = parent_dir_handle,
                             .ObjectName = name,
                             .Attributes = OBJ_CASE_INSENSITIVE};
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto status = NtOpenFile(
      &handle, FILE_LIST_DIRECTORY | FILE_TRAVERSE | DELETE | SYNCHRONIZE,
      &attrs, &isb, FILE_SHARE_VALID_FLAGS,
      FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
          FILE_DELETE_ON_CLOSE);
  if (!NT_SUCCESS(status)) {
    return status == STATUS_OBJECT_NAME_NOT_FOUND
               ? tsc_err_ok()
               : tscp_os_io_err_at(parent_dir_handle, name, errc,
                                   RtlNtStatusToDosError(status),
                                   TEK_SC_ERR_IO_TYPE_delete);
  }
  UNICODE_STRING name_str;
  attrs.RootDirectory = handle;
  attrs.ObjectName = &name_str;
  void *child_buf = nullptr;
  auto res = tsc_err_ok();
  for (;;) {
    status = NtQueryDirectoryFile(handle, nullptr, nullptr, nullptr, &isb, buf,
                                  0x1000, FileDirectoryInformation, FALSE,
                                  nullptr, FALSE);
    if (!NT_SUCCESS(status)) {
      if (status == STATUS_NO_MORE_FILES) {
        break;
      }
      res = tsci_os_io_err(handle, errc, RtlNtStatusToDosError(status),
                           TEK_SC_ERR_IO_TYPE_read);
      break;
    }
    for (FILE_DIRECTORY_INFORMATION *ent = buf;;) {
      auto const child_name = ent->FileName;
      if (ent->FileNameLength == sizeof *child_name && child_name[0] == L'.') {
        // Skip .
        goto skip_entry;
      }
      if (ent->FileNameLength == sizeof *child_name * 2 &&
          child_name[0] == L'.' && child_name[1] == L'.') {
        // Skip ..
        goto skip_entry;
      }
      name_str = (UNICODE_STRING){.Length = ent->FileNameLength,
                                  .MaximumLength = ent->FileNameLength,
                                  .Buffer = child_name};
      if (ent->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!child_buf) {
          child_buf = malloc(0x1000);
          if (!child_buf) {
            res = tsc_err_sub(errc, TEK_SC_ERRC_mem_alloc);
            break;
          }
        }
        res = tscp_os_del_dir(handle, &name_str, errc, child_buf);
        if (!tek_sc_err_success(&res)) {
          break;
        }
      } else {
        HANDLE file_handle;
        status = NtOpenFile(&file_handle, DELETE, &attrs, &isb,
                            FILE_SHARE_VALID_FLAGS,
                            FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);
        if (!NT_SUCCESS(status)) {
          res = tscp_os_io_err_at(handle, &name_str, errc,
                                  RtlNtStatusToDosError(status),
                                  TEK_SC_ERR_IO_TYPE_delete);
          break;
        }
        NtClose(file_handle);
      }
    skip_entry:
      if (!ent->NextEntryOffset) {
        break;
      }
      ent = (void *)ent + ent->NextEntryOffset;
    } // for (FILE_DIRECTORY_INFORMATION *ent = buf;;)
  } // for (;;)
  if (child_buf) {
    free(child_buf);
  }
  NtClose(handle);
  return res;
}

//===-- Internal functions ------------------------------------------------===//

//===-- General functions -------------------------------------------------===//

void tsci_os_close_handle(tek_sc_os_handle handle) { NtClose(handle); }

tek_sc_os_char *tsci_os_get_cache_dir(void) {
  PWSTR path;
  if (SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KF_FLAG_CREATE, nullptr,
                           &path) != S_OK) {
    return nullptr;
  }
  auto const buf = _wcsdup(path);
  CoTaskMemFree(path);
  return buf;
}

char *tsci_os_get_err_msg(tek_sc_os_errc errc) {
  LPWSTR msg;
  auto res = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_IGNORE_INSERTS |
                                FORMAT_MESSAGE_FROM_SYSTEM,
                            nullptr, errc, 0, (LPWSTR)&msg, 0, nullptr);
  if (!res) {
    auto const buf = _strdup("Unknown error");
    if (!buf) {
      abort();
    }
    return buf;
  }
  // Remove trailing CRLF
  if (msg[res - 1] == L'\n') {
    msg[--res] = L'\0';
    if (msg[res - 1] == L'\r') {
      msg[--res] = L'\0';
    }
  }
  const int buf_size = WideCharToMultiByte(CP_UTF8, 0, msg, res + 1, nullptr, 0,
                                           nullptr, nullptr);
  char *const buf = malloc(buf_size);
  if (!buf) {
    abort();
  }
  WideCharToMultiByte(CP_UTF8, 0, msg, res + 1, buf, buf_size, nullptr,
                      nullptr);
  LocalFree(msg);
  return buf;
}

tek_sc_os_errc tsci_os_get_last_error(void) { return GetLastError(); }

int tsci_os_get_nproc(void) {
  SYSTEM_INFO info;
  GetSystemInfo(&info);
  return info.dwNumberOfProcessors;
}

uint64_t tsci_os_get_ticks(void) { return GetTickCount64(); }

tsci_os_version tsci_os_get_version(void) {
  tsci_os_version version;
  RtlGetNtVersionNumbers((PULONG)&version.major, (PULONG)&version.minor,
                         (PULONG)&version.build);
  version.build &= 0xFFFF;
  return version;
}

time_t tsci_os_get_process_start_time(void) {
  uint64_t creation_time;
  FILETIME dummy;
  GetProcessTimes(GetCurrentProcess(), (LPFILETIME)&creation_time, &dummy,
                  &dummy, &dummy);
  return creation_time / 10000000 - 11644473600;
}

void tsci_os_set_thread_name(const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  NtSetInformationThread(
      GetCurrentThread(), ThreadNameInformation,
      &(THREAD_NAME_INFORMATION){.ThreadName = {.Length = name_size,
                                                .MaximumLength = name_size,
                                                .Buffer = (PWSTR)name}},
      sizeof(THREAD_NAME_INFORMATION));
}

//===-- I/O functions -----------------------------------------------------===//

tek_sc_err tsci_os_io_err(tek_sc_os_handle handle, tek_sc_errc prim,
                          tek_sc_os_errc errc, tek_sc_err_io_type io_type) {
  auto const path_len =
      GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
  char *buf = nullptr;
  if (path_len) {
    const LPWSTR path = malloc(path_len * sizeof *path);
    if (path) {
      if (GetFinalPathNameByHandleW(handle, path, path_len,
                                    FILE_NAME_NORMALIZED)) {
        const int buf_size = WideCharToMultiByte(
            CP_UTF8, 0, path + 4, path_len - 4, nullptr, 0, nullptr, nullptr);
        buf = malloc(buf_size);
        if (buf) {
          WideCharToMultiByte(CP_UTF8, 0, path + 4, path_len - 4, buf, buf_size,
                              nullptr, nullptr);
        }
      }
      free(path);
    }
  }
  return (tek_sc_err){.type = TEK_SC_ERR_TYPE_os,
                      .primary = prim,
                      .auxiliary = errc,
                      .extra = io_type,
                      .uri = buf};
}

tek_sc_err tsci_os_io_err_at(tek_sc_os_handle parent_dir_handle,
                             const tek_sc_os_char *name, tek_sc_errc prim,
                             tek_sc_os_errc errc, tek_sc_err_io_type io_type) {
  auto const dir_path_len = GetFinalPathNameByHandleW(
      parent_dir_handle, nullptr, 0, FILE_NAME_NORMALIZED);
  char *buf = nullptr;
  if (dir_path_len) {
    const LPWSTR dir_path = malloc(dir_path_len * sizeof *dir_path);
    if (dir_path) {
      if (GetFinalPathNameByHandleW(parent_dir_handle, dir_path, dir_path_len,
                                    FILE_NAME_NORMALIZED)) {
        const int dir_path8_size =
            WideCharToMultiByte(CP_UTF8, 0, dir_path + 4, dir_path_len - 4,
                                nullptr, 0, nullptr, nullptr);
        const int name8_size = WideCharToMultiByte(
            CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
        buf = malloc(dir_path8_size + name8_size);
        if (buf) {
          WideCharToMultiByte(CP_UTF8, 0, dir_path + 4, dir_path_len - 5, buf,
                              dir_path8_size, nullptr, nullptr);
          buf[dir_path8_size - 1] = '\\';
          WideCharToMultiByte(CP_UTF8, 0, name, -1, &buf[dir_path8_size],
                              name8_size, nullptr, nullptr);
        }
      }
      free(dir_path);
    }
  }
  return (tek_sc_err){.type = TEK_SC_ERR_TYPE_os,
                      .primary = prim,
                      .auxiliary = errc,
                      .extra = io_type,
                      .uri = buf};
}

tek_sc_os_errc tsci_os_path_exists_at(tek_sc_os_handle parent_dir_handle,
                                      const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  FILE_BASIC_INFORMATION info;
  auto const status = NtQueryAttributesFile(
      &(OBJECT_ATTRIBUTES){.Length = sizeof(OBJECT_ATTRIBUTES),
                           .RootDirectory = parent_dir_handle,
                           .ObjectName =
                               &(UNICODE_STRING){.Length = name_size,
                                                 .MaximumLength = name_size,
                                                 .Buffer = (PWSTR)name},
                           .Attributes = OBJ_CASE_INSENSITIVE},
      &info);
  return NT_SUCCESS(status) ? 0 : RtlNtStatusToDosError(status);
}

//===--- Diectory create/open ---------------------------------------------===//

tek_sc_os_handle tsci_os_dir_create(const tek_sc_os_char *path) {
  UNICODE_STRING path_str;
  if (!RtlDosPathNameToNtPathName_U(path, &path_str, nullptr, nullptr)) {
    SetLastError(ERROR_BAD_PATHNAME);
    return INVALID_HANDLE_VALUE;
  }
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto const status = NtCreateFile(
      &handle, FILE_TRAVERSE,
      &(OBJECT_ATTRIBUTES){.Length = sizeof(OBJECT_ATTRIBUTES),
                           .ObjectName = &path_str,
                           .Attributes = OBJ_CASE_INSENSITIVE},
      &isb, nullptr, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
      FILE_OPEN_IF, FILE_DIRECTORY_FILE, nullptr, 0);
  RtlFreeUnicodeString(&path_str);
  if (NT_SUCCESS(status)) {
    return handle;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return INVALID_HANDLE_VALUE;
}

tek_sc_os_handle tsci_os_dir_create_at(tek_sc_os_handle parent_dir_handle,
                                       const tek_sc_os_char *name) {
  return tscp_nt_create_file(parent_dir_handle, name, FILE_TRAVERSE,
                             FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
                             FILE_OPEN_IF, FILE_DIRECTORY_FILE);
}

tek_sc_os_handle tsci_os_dir_open_at(tek_sc_os_handle parent_dir_handle,
                                     const tek_sc_os_char *name) {
  return tscp_nt_open_file(parent_dir_handle, name, FILE_TRAVERSE,
                           FILE_SHARE_VALID_FLAGS, FILE_DIRECTORY_FILE);
}

//===--- Directory move/delete --------------------------------------------===//

bool tsci_os_dir_move(tek_sc_os_handle src_dir_handle,
                      tek_sc_os_handle tgt_dir_handle,
                      const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto status =
      NtOpenFile(&handle, DELETE,
                 &(OBJECT_ATTRIBUTES){
                     .Length = sizeof(OBJECT_ATTRIBUTES),
                     .RootDirectory = src_dir_handle,
                     .ObjectName = &(UNICODE_STRING){.Length = name_size,
                                                     .MaximumLength = name_size,
                                                     .Buffer = (PWSTR)name},
                     .Attributes = OBJ_CASE_INSENSITIVE},
                 &isb, FILE_SHARE_VALID_FLAGS, FILE_DIRECTORY_FILE);
  if (!NT_SUCCESS(status)) {
    SetLastError(RtlNtStatusToDosError(status));
    return false;
  }
  auto const info_size = offsetof(FILE_RENAME_INFO, FileName) + name_size;
  FILE_RENAME_INFO *const info = malloc(info_size);
  if (!info) {
    NtClose(handle);
    SetLastError(ERROR_OUTOFMEMORY);
    return false;
  }
  info->ReplaceIfExists = FALSE;
  info->RootDirectory = tgt_dir_handle;
  info->FileNameLength = name_size;
  memcpy(info->FileName, name, name_size);
  status = NtSetInformationFile(handle, &isb, info, info_size,
                                FileRenameInformation);
  free(info);
  NtClose(handle);
  if (NT_SUCCESS(status)) {
    return true;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return false;
}

bool tsci_os_dir_delete_at(tek_sc_os_handle parent_dir_handle,
                           const tek_sc_os_char *name) {
  auto const handle =
      tscp_nt_open_file(parent_dir_handle, name, DELETE, FILE_SHARE_VALID_FLAGS,
                        FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  NtClose(handle);
  return true;
}

tek_sc_err tsci_os_dir_delete_at_rec(tek_sc_os_handle parent_dir_handle,
                                     const tek_sc_os_char *name,
                                     tek_sc_errc errc) {
  auto const buf = malloc(0x1000);
  if (!buf) {
    return tsc_err_sub(errc, TEK_SC_ERRC_mem_alloc);
  }
  const USHORT name_size = wcslen(name) * sizeof *name;
  auto const res = tscp_os_del_dir(parent_dir_handle,
                                   &(UNICODE_STRING){.Length = name_size,
                                                     .MaximumLength = name_size,
                                                     .Buffer = (PWSTR)name},
                                   errc, buf);
  free(buf);
  return res;
}

//===--- File create/open -------------------------------------------------===//

tek_sc_os_handle tsci_os_file_create_at(tek_sc_os_handle parent_dir_handle,
                                        const tek_sc_os_char *name,
                                        tsci_os_file_access access,
                                        tsci_os_file_opt options) {
  return tscp_nt_create_file(
      parent_dir_handle, name, access, FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_DELETE,
      (options & TSCI_OS_FILE_OPT_trunc) ? FILE_OVERWRITE_IF : FILE_OPEN_IF,
      ((options & TSCI_OS_FILE_OPT_sync) || !tscp_ioring_ver)
          ? (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
          : FILE_NON_DIRECTORY_FILE);
}

tek_sc_os_handle tsci_os_file_open_at(tek_sc_os_handle parent_dir_handle,
                                      const tek_sc_os_char *name,
                                      tsci_os_file_access access,
                                      tsci_os_file_opt options) {
  return tscp_nt_open_file(
      parent_dir_handle, name, access, FILE_SHARE_READ | FILE_SHARE_DELETE,
      ((options & TSCI_OS_FILE_OPT_sync) || !tscp_ioring_ver)
          ? (FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE)
          : FILE_NON_DIRECTORY_FILE);
}

//===--- File read/write --------------------------------------------------===//

bool tsci_os_file_read(tek_sc_os_handle handle, void *buf, size_t n) {
  for (IO_STATUS_BLOCK isb;;) {
    auto const status = NtReadFile(handle, nullptr, nullptr, nullptr, &isb, buf,
                                   n, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    n -= isb.Information;
    if (!n) {
      return true;
    }
    if (!isb.Information) {
      SetLastError(ERROR_READ_FAULT);
      return false;
    }
    buf += isb.Information;
  }
}

bool tsci_os_file_read_at(tek_sc_os_handle handle, void *buf, size_t n,
                          int64_t offset) {
  for (IO_STATUS_BLOCK isb;;) {
    auto const status = NtReadFile(handle, nullptr, nullptr, nullptr, &isb, buf,
                                   n, (PLARGE_INTEGER)&offset, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    n -= isb.Information;
    if (!n) {
      return true;
    }
    if (!isb.Information) {
      SetLastError(ERROR_READ_FAULT);
      return false;
    }
    buf += isb.Information;
    offset += isb.Information;
  }
}

bool tsci_os_file_write(tek_sc_os_handle handle, const void *buf, size_t n) {
  for (IO_STATUS_BLOCK isb;;) {
    auto const status = NtWriteFile(handle, nullptr, nullptr, nullptr, &isb,
                                    (PVOID)buf, n, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    n -= isb.Information;
    if (!n) {
      return true;
    }
    if (!isb.Information) {
      SetLastError(ERROR_WRITE_FAULT);
      return false;
    }
    buf += isb.Information;
  }
}

bool tsci_os_file_write_at(tek_sc_os_handle handle, const void *buf, size_t n,
                           int64_t offset) {
  for (IO_STATUS_BLOCK isb;;) {
    auto const status =
        NtWriteFile(handle, nullptr, nullptr, nullptr, &isb, (PVOID)buf, n,
                    (PLARGE_INTEGER)&offset, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    n -= isb.Information;
    if (!n) {
      return true;
    }
    if (!isb.Information) {
      SetLastError(ERROR_WRITE_FAULT);
      return false;
    }
    buf += isb.Information;
    offset += isb.Information;
  }
}

//===--- File get/set size ------------------------------------------------===//

size_t tsci_os_file_get_size(tek_sc_os_handle handle) {
  IO_STATUS_BLOCK isb;
  FILE_STANDARD_INFORMATION info;
  auto const status = NtQueryInformationFile(handle, &isb, &info, sizeof info,
                                             FileStandardInformation);
  if (NT_SUCCESS(status)) {
    return (size_t)info.EndOfFile.QuadPart;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return SIZE_MAX;
}

size_t tsci_os_file_get_size_at(tek_sc_os_handle parent_dir_handle,
                                const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  FILE_NETWORK_OPEN_INFORMATION info;
  auto const status = NtQueryFullAttributesFile(
      &(OBJECT_ATTRIBUTES){.Length = sizeof(OBJECT_ATTRIBUTES),
                           .RootDirectory = parent_dir_handle,
                           .ObjectName =
                               &(UNICODE_STRING){.Length = name_size,
                                                 .MaximumLength = name_size,
                                                 .Buffer = (PWSTR)name},
                           .Attributes = OBJ_CASE_INSENSITIVE},
      &info);
  if (NT_SUCCESS(status)) {
    return (size_t)info.EndOfFile.QuadPart;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return SIZE_MAX;
}

bool tsci_os_file_truncate(tek_sc_os_handle handle, int64_t new_size) {
  IO_STATUS_BLOCK isb;
  auto const status = NtSetInformationFile(
      handle, &isb,
      &(FILE_END_OF_FILE_INFORMATION){.EndOfFile = {.QuadPart = new_size}},
      sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);
  if (NT_SUCCESS(status)) {
    return true;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return false;
}

//===--- File apply flags -------------------------------------------------===//

bool tsci_os_file_apply_flags(tek_sc_os_handle handle,
                              tek_sc_dm_file_flag flags) {
  IO_STATUS_BLOCK isb;
  FILE_BASIC_INFORMATION info;
  auto status = NtQueryInformationFile(handle, &isb, &info, sizeof info,
                                       FileBasicInformation);
  if (!NT_SUCCESS(status)) {
    SetLastError(RtlNtStatusToDosError(status));
    return false;
  }
  info.CreationTime.QuadPart = 0;
  info.LastAccessTime.QuadPart = 0;
  info.LastWriteTime.QuadPart = 0;
  info.ChangeTime.QuadPart = 0;
  auto new_attrs = info.FileAttributes;
  if (flags & TEK_SC_DM_FILE_FLAG_readonly) {
    new_attrs |= FILE_ATTRIBUTE_READONLY;
  } else {
    new_attrs &= ~FILE_ATTRIBUTE_READONLY;
  }
  if (flags & TEK_SC_DM_FILE_FLAG_hidden) {
    new_attrs |= FILE_ATTRIBUTE_HIDDEN;
  } else {
    new_attrs &= ~FILE_ATTRIBUTE_HIDDEN;
  }
  if (new_attrs == info.FileAttributes) {
    return true;
  }
  if ((new_attrs & FILE_ATTRIBUTE_NORMAL) &&
      new_attrs != FILE_ATTRIBUTE_NORMAL) {
    new_attrs &= ~FILE_ATTRIBUTE_NORMAL;
  }
  if (!new_attrs) {
    new_attrs = FILE_ATTRIBUTE_NORMAL;
  }
  info.FileAttributes = new_attrs;
  status = NtSetInformationFile(handle, &isb, &info, sizeof info,
                                FileBasicInformation);
  if (NT_SUCCESS(status)) {
    return true;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return false;
}

bool tsci_os_file_apply_flags_at(tek_sc_os_handle parent_dir_handle,
                                 const tek_sc_os_char *name,
                                 tek_sc_dm_file_flag flags) {
  auto const handle = tscp_nt_open_file(
      parent_dir_handle, name, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
      FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  const bool res = tsci_os_file_apply_flags(handle, flags);
  NtClose(handle);
  return res;
}

//===--- File copy/move ---------------------------------------------------===//

bool tsci_os_file_copy_chunk(tsci_os_copy_args *args, int64_t src_offset,
                             int64_t tgt_offset, size_t size) {
  auto const src_handle = args->src_handle;
  auto const tgt_handle = args->tgt_handle;
  auto const buf = args->buf;
  auto const buf_size = args->buf_size;
  for (IO_STATUS_BLOCK isb; size;) {
    auto status = NtReadFile(src_handle, nullptr, nullptr, nullptr, &isb, buf,
                             size > buf_size ? buf_size : size,
                             (PLARGE_INTEGER)&src_offset, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    status = NtWriteFile(tgt_handle, nullptr, nullptr, nullptr, &isb, buf,
                         isb.Information, (PLARGE_INTEGER)&tgt_offset, nullptr);
    if (!NT_SUCCESS(status)) {
      SetLastError(RtlNtStatusToDosError(status));
      return false;
    }
    if (!isb.Information) {
      SetLastError(ERROR_WRITE_FAULT);
      return false;
    }
    src_offset += isb.Information;
    tgt_offset += isb.Information;
    size -= isb.Information;
  }
  return true;
}

bool tsci_os_file_copy(tsci_os_copy_args *args, const tek_sc_os_char *name,
                       int64_t size, tek_sc_errc errc) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  UNICODE_STRING name_str = {
      .Length = name_size, .MaximumLength = name_size, .Buffer = (PWSTR)name};
  OBJECT_ATTRIBUTES attrs = {.Length = sizeof attrs,
                             .RootDirectory = args->src_handle,
                             .ObjectName = &name_str,
                             .Attributes = OBJ_CASE_INSENSITIVE};
  IO_STATUS_BLOCK isb;
  HANDLE src_handle;
  auto status = NtOpenFile(&src_handle, FILE_READ_DATA | SYNCHRONIZE, &attrs,
                           &isb, FILE_SHARE_READ,
                           FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
                               FILE_NON_DIRECTORY_FILE);
  if (!NT_SUCCESS(status)) {
    args->error = tscp_os_io_err_at(args->src_handle, &name_str, errc,
                                    RtlNtStatusToDosError(status),
                                    TEK_SC_ERR_IO_TYPE_open);
    return false;
  }
  attrs.RootDirectory = args->tgt_handle;
  HANDLE tgt_handle;
  status = NtCreateFile(&tgt_handle, FILE_WRITE_DATA | SYNCHRONIZE, &attrs,
                        &isb, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                        FILE_OVERWRITE_IF,
                        FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
                            FILE_NON_DIRECTORY_FILE,
                        nullptr, 0);
  if (!NT_SUCCESS(status)) {
    NtClose(src_handle);
    args->error = tscp_os_io_err_at(args->tgt_handle, &name_str, errc,
                                    RtlNtStatusToDosError(status),
                                    TEK_SC_ERR_IO_TYPE_open);
    return false;
  }
  auto const buf = args->buf;
  const int64_t buf_size = args->buf_size;
  bool res = true;
  while (size) {
    auto status =
        NtReadFile(src_handle, nullptr, nullptr, nullptr, &isb, buf,
                   size > buf_size ? buf_size : size, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      args->error =
          tsci_os_io_err(src_handle, errc, RtlNtStatusToDosError(status),
                         TEK_SC_ERR_IO_TYPE_read);
      res = false;
      break;
    }
    status = NtWriteFile(tgt_handle, nullptr, nullptr, nullptr, &isb, buf,
                         isb.Information, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
      args->error =
          tsci_os_io_err(tgt_handle, errc, RtlNtStatusToDosError(status),
                         TEK_SC_ERR_IO_TYPE_write);
      res = false;
      break;
    }
    if (!isb.Information) {
      args->error = tsci_os_io_err(tgt_handle, errc, ERROR_WRITE_FAULT,
                                   TEK_SC_ERR_IO_TYPE_write);
      res = false;
      break;
    }
    size -= isb.Information;
  }
  NtClose(tgt_handle);
  NtClose(src_handle);
  return res;
}

bool tsci_os_file_move(tek_sc_os_handle src_dir_handle,
                       tek_sc_os_handle tgt_dir_handle,
                       const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto status =
      NtOpenFile(&handle, DELETE,
                 &(OBJECT_ATTRIBUTES){
                     .Length = sizeof(OBJECT_ATTRIBUTES),
                     .RootDirectory = src_dir_handle,
                     .ObjectName = &(UNICODE_STRING){.Length = name_size,
                                                     .MaximumLength = name_size,
                                                     .Buffer = (PWSTR)name},
                     .Attributes = OBJ_CASE_INSENSITIVE},
                 &isb, FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE);
  if (!NT_SUCCESS(status)) {
    SetLastError(RtlNtStatusToDosError(status));
    return false;
  }
  auto const info_size = offsetof(FILE_RENAME_INFO, FileName) + name_size;
  FILE_RENAME_INFO *const info = malloc(info_size);
  if (!info) {
    NtClose(handle);
    SetLastError(ERROR_OUTOFMEMORY);
    return false;
  }
  info->Flags =
      FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
  info->RootDirectory = tgt_dir_handle;
  info->FileNameLength = name_size;
  memcpy(info->FileName, name, name_size);
  static bool fallback = false;
  if (!fallback) {
    status = NtSetInformationFile(handle, &isb, info, info_size,
                                  FileRenameInformationEx);
    if (status == STATUS_INVALID_PARAMETER) {
      fallback = true;
    }
  }
  if (fallback) {
    info->Flags = 0;
    info->ReplaceIfExists = TRUE;
    status = NtSetInformationFile(handle, &isb, info, info_size,
                                  FileRenameInformation);
  }
  free(info);
  NtClose(handle);
  if (NT_SUCCESS(status)) {
    return true;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return false;
}

//===--- File delete ------------------------------------------------------===//

bool tsci_os_file_delete_at(tek_sc_os_handle parent_dir_handle,
                            const tek_sc_os_char *name) {
  auto const handle =
      tscp_nt_open_file(parent_dir_handle, name, DELETE, FILE_SHARE_VALID_FLAGS,
                        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE);
  if (handle == INVALID_HANDLE_VALUE) {
    return false;
  }
  NtClose(handle);
  return true;
}

//===--- Symbolic link ----------------------------------------------------===//

bool tsci_os_symlink_at(const tek_sc_os_char *, tek_sc_os_handle,
                        const tek_sc_os_char *) {
  // I'm not aware of any Windows apps using symlinks, anyway, it would be
  //    questionable, as creating symlinks on Windows requires admin privileges
  SetLastError(ERROR_NOT_SUPPORTED);
  return false;
}

//===-- Asynchronous I/O functions ----------------------------------------===//

tek_sc_os_errc tsci_os_aio_ctx_init(tsci_os_aio_ctx *ctx, int num_reqs,
                                    void *buffer, size_t buffer_size) {
  pthread_mutex_lock(&tscp_ioring_init_mtx);
  if (tscp_ioring_support == TSCP_IORING_unchecked) {
    auto const module = GetModuleHandleW(L"kernel32.dll");
    if (!module) {
      goto unsupported;
    }
    pBuildIoRingReadFile = (typeof(pBuildIoRingReadFile))GetProcAddress(
        module, "BuildIoRingReadFile");
    if (!pBuildIoRingReadFile) {
      goto unsupported;
    }
    pBuildIoRingRegisterBuffers =
        (typeof(pBuildIoRingRegisterBuffers))GetProcAddress(
            module, "BuildIoRingRegisterBuffers");
    if (!pBuildIoRingRegisterBuffers) {
      goto unsupported;
    }
    pBuildIoRingRegisterFileHandles =
        (typeof(pBuildIoRingRegisterFileHandles))GetProcAddress(
            module, "BuildIoRingRegisterFileHandles");
    if (!pBuildIoRingRegisterFileHandles) {
      goto unsupported;
    }
    pBuildIoRingWriteFile = (typeof(pBuildIoRingWriteFile))GetProcAddress(
        module, "BuildIoRingWriteFile");
    if (!pBuildIoRingWriteFile) {
      goto unsupported;
    }
    pCloseIoRing = (typeof(pCloseIoRing))GetProcAddress(module, "CloseIoRing");
    if (!pCloseIoRing) {
      goto unsupported;
    }
    pCreateIoRing =
        (typeof(pCreateIoRing))GetProcAddress(module, "CreateIoRing");
    if (!pCreateIoRing) {
      goto unsupported;
    }
    pPopIoRingCompletion = (typeof(pPopIoRingCompletion))GetProcAddress(
        module, "PopIoRingCompletion");
    if (!pPopIoRingCompletion) {
      goto unsupported;
    }
    pQueryIoRingCapabilities = (typeof(pQueryIoRingCapabilities))GetProcAddress(
        module, "QueryIoRingCapabilities");
    if (!pQueryIoRingCapabilities) {
      goto unsupported;
    }
    pSubmitIoRing =
        (typeof(pSubmitIoRing))GetProcAddress(module, "SubmitIoRing");
    if (!pSubmitIoRing) {
      goto unsupported;
    }
    IORING_CAPABILITIES capabilities;
    if (FAILED(pQueryIoRingCapabilities(&capabilities)) ||
        capabilities.MaxVersion < 2) {
      // Write opcode is supported only since version 2
      goto unsupported;
    }
    tscp_ioring_ver = capabilities.MaxVersion;
    tscp_ioring_support = TSCP_IORING_supported;
    goto done;
  unsupported:
    tscp_ioring_support = TSCP_IORING_unsupported;
  } // if (tscp_ioring_support == TSCP_IORING_unchecked)
done:
  auto const support = tscp_ioring_support;
  pthread_mutex_unlock(&tscp_ioring_init_mtx);
  if (support == TSCP_IORING_supported) {
    auto res =
        pCreateIoRing(tscp_ioring_ver,
                      (IORING_CREATE_FLAGS){
                          .Required = IORING_CREATE_REQUIRED_FLAGS_NONE,
                          .Advisory = IORING_CREATE_SKIP_BUILDER_PARAM_CHECKS},
                      num_reqs, num_reqs, &ctx->ring);
    if (FAILED(res)) {
      return res;
    }
    res = pBuildIoRingRegisterBuffers(
        ctx->ring, 1,
        &(const IORING_BUFFER_INFO){.Address = buffer, .Length = buffer_size},
        0);
    if (FAILED(res)) {
      goto fail;
    }
    res = pSubmitIoRing(ctx->ring, 1, INFINITE, nullptr);
    if (FAILED(res)) {
      goto fail;
    }
    IORING_CQE cqe;
    res = pPopIoRingCompletion(ctx->ring, &cqe);
    if (res != S_OK) {
      goto fail;
    }
    res = cqe.ResultCode;
    if (FAILED(res)) {
      goto fail;
    }
    ctx->num_reqs = -1;
    ctx->reg_buf = buffer;
    return ERROR_SUCCESS;
  fail:
    pCloseIoRing(ctx->ring);
    return res;
  } // if (support == TSCP_IORING_supported)
  ctx->num_reqs = num_reqs;
  ctx->num_submitted = 0;
  ctx->reqs = malloc(sizeof *ctx->reqs * num_reqs);
  return ctx->reqs ? ERROR_SUCCESS : ERROR_OUTOFMEMORY;
}

void tsci_os_aio_ctx_destroy(tsci_os_aio_ctx *ctx) {
  if (ctx->num_reqs < 0) {
    pCloseIoRing(ctx->ring);
  } else {
    free(ctx->reqs);
  }
}

tek_sc_os_errc tsci_os_aio_register_file(tsci_os_aio_ctx *ctx,
                                         tek_sc_os_handle handle) {
  ctx->reg_handle = handle;
  if (ctx->num_reqs < 0) {
    auto res = pBuildIoRingRegisterFileHandles(ctx->ring, 1, &handle, 0);
    if (FAILED(res)) {
      return res;
    }
    res = pSubmitIoRing(ctx->ring, 1, INFINITE, nullptr);
    if (FAILED(res)) {
      return res;
    }
    IORING_CQE cqe;
    res = pPopIoRingCompletion(ctx->ring, &cqe);
    if (res != S_OK) {
      return res;
    }
    return cqe.ResultCode;
  }
  return ERROR_SUCCESS;
}

tek_sc_os_errc tsci_os_aio_submit_read(tsci_os_aio_ctx *ctx,
                                       tsci_os_aio_req *req, void *buf,
                                       size_t n, int64_t offset, bool submit) {
  req->handle = ctx->reg_handle;
  if (ctx->num_reqs < 0) {
    auto res = pBuildIoRingReadFile(
        ctx->ring, (IORING_HANDLE_REF)IoRingHandleRefFromIndex(0),
        (IORING_BUFFER_REF)IoRingBufferRefFromIndexAndOffset(
            0, buf - ctx->reg_buf),
        n, offset, (UINT_PTR)req, IOSQE_FLAGS_NONE);
    if (FAILED(res)) {
      return res;
    }
    if (submit) {
      res = pSubmitIoRing(ctx->ring, 0, 0, nullptr);
      if (FAILED(res)) {
        return res;
      }
    }
    return ERROR_SUCCESS;
  }
  if (ctx->num_submitted >= ctx->num_reqs) {
    return ERROR_BUSY;
  }
  ctx->reqs[ctx->num_submitted++] = req;
  IO_STATUS_BLOCK isb;
  auto const status =
      NtReadFile(ctx->reg_handle, nullptr, nullptr, nullptr, &isb, buf, n,
                 (PLARGE_INTEGER)&offset, nullptr);
  if (NT_SUCCESS(status)) {
    req->result = ERROR_SUCCESS;
    req->bytes_transferred = isb.Information;
  } else {
    req->result = RtlNtStatusToDosError(status);
    req->bytes_transferred = 0;
  }
  return ERROR_SUCCESS;
}

tek_sc_os_errc tsci_os_aio_submit_write(tsci_os_aio_ctx *ctx,
                                        tsci_os_aio_req *req, const void *buf,
                                        size_t n, int64_t offset, bool submit) {
  req->handle = ctx->reg_handle;
  if (ctx->num_reqs < 0) {
    auto res = pBuildIoRingWriteFile(
        ctx->ring, (IORING_HANDLE_REF)IoRingHandleRefFromIndex(0),
        (IORING_BUFFER_REF)IoRingBufferRefFromIndexAndOffset(
            0, buf - ctx->reg_buf),
        n, offset, FILE_WRITE_FLAGS_NONE, (UINT_PTR)req, IOSQE_FLAGS_NONE);
    if (FAILED(res)) {
      return res;
    }
    if (submit) {
      res = pSubmitIoRing(ctx->ring, 0, 0, nullptr);
      if (FAILED(res)) {
        return res;
      }
    }
    return ERROR_SUCCESS;
  }
  if (ctx->num_submitted >= ctx->num_reqs) {
    return ERROR_BUSY;
  }
  ctx->reqs[ctx->num_submitted++] = req;
  IO_STATUS_BLOCK isb;
  auto const status =
      NtWriteFile(ctx->reg_handle, nullptr, nullptr, nullptr, &isb, (PVOID)buf,
                  n, (PLARGE_INTEGER)&offset, nullptr);
  if (NT_SUCCESS(status)) {
    req->result = ERROR_SUCCESS;
    req->bytes_transferred = isb.Information;
  } else {
    req->result = RtlNtStatusToDosError(status);
    req->bytes_transferred = 0;
  }
  return ERROR_SUCCESS;
}

int tsci_os_aio_get_compls(tsci_os_aio_ctx *ctx, tsci_os_aio_req **reqs,
                           int num_reqs, int num_wait) {
  if (ctx->num_reqs < 0) {
    int num_reqs_out = 0;
    for (int i = 0; i < num_reqs; ++i) {
      IORING_CQE cqe;
      auto res = pPopIoRingCompletion(ctx->ring, &cqe);
      if (FAILED(res)) {
        SetLastError(res);
        return -1;
      }
      if (res != S_OK) {
        if (i < num_wait) {
          res = pSubmitIoRing(ctx->ring, num_wait - i, INFINITE, nullptr);
          if (FAILED(res)) {
            SetLastError(res);
            return -1;
          }
          res = pPopIoRingCompletion(ctx->ring, &cqe);
          if (res != S_OK) {
            SetLastError(res);
            return -1;
          }
        } else {
          break;
        }
      }
      auto const req = (tsci_os_aio_req *)cqe.UserData;
      req->result = cqe.ResultCode;
      req->bytes_transferred = cqe.Information;
      reqs[i] = req;
      ++num_reqs_out;
    }
    return num_reqs_out;
  }
  int num_reqs_out = num_reqs;
  if (num_reqs_out > ctx->num_submitted) {
    num_reqs_out = ctx->num_submitted;
  }
  ctx->num_submitted -= num_reqs_out;
  memcpy(reqs, &ctx->reqs[ctx->num_submitted], sizeof *reqs * num_reqs_out);
  return num_reqs_out;
}

//===-- Virtual memory functions ------------------------------------------===//

void *tsci_os_mem_alloc(size_t size) {
  PVOID addr = nullptr;
  auto const status =
      NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (NT_SUCCESS(status)) {
    return addr;
  } else {
    SetLastError(RtlNtStatusToDosError(status));
    return nullptr;
  }
}

void tsci_os_mem_free(const void *addr, size_t) {
  NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&addr, &(SIZE_T){},
                      MEM_RELEASE);
}

//===-- Futex functions ---------------------------------------------------===//

bool tsci_os_futex_wait(const _Atomic(uint32_t) *addr, uint32_t old,
                        uint32_t timeout_ms) {
  do {
    if (!WaitOnAddress((volatile void *)addr, &old, sizeof *addr, timeout_ms) &&
        GetLastError() == ERROR_TIMEOUT) {
      return false;
    }
  } while (atomic_load_explicit(addr, memory_order_relaxed) == old);
  return true;
}

void tsci_os_futex_wake(_Atomic(uint32_t) *addr) { WakeByAddressAll(addr); }

//===-- Pathname string functions -----------------------------------------===//

int tsci_os_pstr_strlen(const tek_sc_os_char *pstr) {
  return WideCharToMultiByte(CP_UTF8, 0, pstr, -1, nullptr, 0, nullptr,
                             nullptr) -
         1;
}

int tsci_os_pstr_to_str(const tek_sc_os_char *restrict pstr,
                        char *restrict str) {
  return WideCharToMultiByte(CP_UTF8, 0, pstr, wcslen(pstr), str, INT_MAX,
                             nullptr, nullptr);
}

int tsci_os_str_pstrlen(const char *str, int len) {
  return MultiByteToWideChar(CP_UTF8, 0, str, len, nullptr, 0);
}

int tsci_os_str_to_pstr(const char *restrict str, int len,
                        tek_sc_os_char *restrict pstr) {
  return MultiByteToWideChar(CP_UTF8, 0, str, len, pstr, INT_MAX);
}

//===-- Public function ---------------------------------------------------===//

#ifndef TEK_SC_STATIC

#ifdef TEK_SCB_GETTEXT

void tek_sc_load_locale(const tek_sc_os_char *path) {
  setlocale(LC_ALL, ".UTF-8");
  HMODULE module;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCWSTR)tek_sc_load_locale, &module)) {
    return;
  }
  auto const list_res_info =
      FindResourceW(module, MAKEINTRESOURCEW(1000), RT_RCDATA);
  if (!list_res_info) {
    return;
  }
  auto const list_res = LoadResource(module, list_res_info);
  if (!list_res) {
    return;
  }
  const PCWSTR list = LockResource(list_res);
  if (!list || !*list) {
    return;
  }
  UNICODE_STRING path_str;
  if (!RtlDosPathNameToNtPathName_U(path, &path_str, nullptr, nullptr)) {
    return;
  }
  OBJECT_ATTRIBUTES attrs = {.Length = sizeof attrs,
                             .ObjectName = &path_str,
                             .Attributes = OBJ_CASE_INSENSITIVE};
  IO_STATUS_BLOCK isb;
  HANDLE dir_handle;
  auto status = NtOpenFile(&dir_handle, FILE_TRAVERSE, &attrs, &isb,
                           FILE_SHARE_VALID_FLAGS, FILE_DIRECTORY_FILE);
  RtlFreeUnicodeString(&path_str);
  if (!NT_SUCCESS(status)) {
    return;
  }
  int res_id = 1001;
  for (auto loc_name = list; *loc_name;
       loc_name += wcslen(loc_name) + 1, ++res_id) {
    auto const loc_res_info =
        FindResourceW(module, MAKEINTRESOURCEW(res_id), RT_RCDATA);
    if (!loc_res_info) {
      break;
    }
    auto const loc_res = LoadResource(module, loc_res_info);
    if (!loc_res) {
      continue;
    }
    auto loc_data = LockResource(loc_res);
    if (!loc_data) {
      continue;
    }
    auto loc_data_size = SizeofResource(module, loc_res_info);
    if (!loc_data_size) {
      continue;
    }
    attrs.RootDirectory = dir_handle;
    auto name_size = wcslen(loc_name) * sizeof *loc_name;
    path_str = (UNICODE_STRING){.Length = name_size,
                                .MaximumLength = name_size,
                                .Buffer = (PWSTR)loc_name};
    HANDLE sub_handle;
    status = NtCreateFile(&sub_handle, FILE_TRAVERSE, &attrs, &isb, nullptr,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
                          FILE_OPEN_IF, FILE_DIRECTORY_FILE, nullptr, 0);
    if (!NT_SUCCESS(status)) {
      continue;
    }
    attrs.RootDirectory = sub_handle;
    name_size = wcslen(L"LC_MESSAGES") * sizeof(WCHAR);
    path_str = (UNICODE_STRING){.Length = name_size,
                                .MaximumLength = name_size,
                                .Buffer = L"LC_MESSAGES"};
    status = NtCreateFile(&sub_handle, FILE_TRAVERSE, &attrs, &isb, nullptr,
                          FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
                          FILE_OPEN_IF, FILE_DIRECTORY_FILE, nullptr, 0);
    NtClose(attrs.RootDirectory);
    if (!NT_SUCCESS(status)) {
      continue;
    }
    attrs.RootDirectory = sub_handle;
    name_size = wcslen(L"tek-steamclient.mo") * sizeof(WCHAR);
    path_str = (UNICODE_STRING){.Length = name_size,
                                .MaximumLength = name_size,
                                .Buffer = L"tek-steamclient.mo"};
    status = NtCreateFile(&sub_handle,
                          FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                          &attrs, &isb, nullptr, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ, FILE_OPEN_IF,
                          FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
                              FILE_NON_DIRECTORY_FILE,
                          nullptr, 0);
    NtClose(attrs.RootDirectory);
    if (!NT_SUCCESS(status)) {
      continue;
    }
    while (loc_data_size) {
      if (!NT_SUCCESS(NtWriteFile(sub_handle, nullptr, nullptr, nullptr, &isb,
                                  loc_data, loc_data_size, nullptr, nullptr)) ||
          !isb.Information) {
        break;
      }
      loc_data += isb.Information;
      loc_data_size -= isb.Information;
    }
    NtClose(sub_handle);
  } // for (auto loc_name : list)
  NtClose(dir_handle);
  libintl_wbindtextdomain("tek-steamclient", path);
}

#else // def TEK_SCB_GETTEXT

void tek_sc_load_locale(const tek_sc_os_char *) {}

#endif // def TEK_SCB_GETTEXT else

#endif // ndef TEK_SC_STATIC
