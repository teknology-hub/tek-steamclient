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

#include "common.h"
#include "config.h" // IWYU pragma: keep
#include "tek-steamclient/os.h"

#ifdef TEK_SCB_GETTEXT
#include <libintl.h>
#endif // TEK_SCB_GETTEXT
#include <process.h>
#include <shlobj.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <winternl.h>

/// Currently registered signal handler.
void (*_Nullable tscl_cur_sig_handler)(void);

//===-- Declarations missing from winternl.h ------------------------------===//

NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event,
                          PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                          PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                          ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event,
                           PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
                           PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                           ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

//===-- Private functions -------------------------------------------------===//

/// Console control signal handler.
///
/// @param type
///    Control signal type
/// @return `TRUE`.
static BOOL tscl_console_ctrl_handler(DWORD type) {
  if (!tscl_cur_sig_handler) {
    return TRUE;
  }
  switch (type) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
    tscl_cur_sig_handler();
    break;
  default:
    atomic_store_explicit(&tscl_g_ctx.terminating, 1, memory_order_relaxed);
    tscl_cur_sig_handler();
    tscl_os_futex_wait(&tscl_g_ctx.terminating, 1, 120000);
  }
  return TRUE;
}

/// Window procedure for handling OS shutdown events.
static LRESULT CALLBACK tscl_wnd_proc(HWND hWnd, UINT msg, WPARAM wParam,
                                      LPARAM lParam) {
  switch (msg) {
  case WM_QUERYENDSESSION:
    atomic_store_explicit(&tscl_g_ctx.terminating, 1, memory_order_relaxed);
    if (tscl_cur_sig_handler) {
      tscl_cur_sig_handler();
    }
    return TRUE;
  case WM_ENDSESSION:
    tscl_os_futex_wait(&tscl_g_ctx.terminating, 1, 120000);
    return 0;
  default:
    return DefWindowProcW(hWnd, msg, wParam, lParam);
  }
}

/// Thread procedure that creates a hidden window and processes its messages in
///    a loop.
///
/// @return `0`.
static unsigned tscl_wnd_thrd_proc(void *) {
  auto const class = RegisterClassExW(
      &(const WNDCLASSEXW){.cbSize = sizeof(WNDCLASSEXW),
                           .lpfnWndProc = tscl_wnd_proc,
                           .lpszClassName = L"TEK_SteamClient_CLI"});
  if (!class) {
    fputs(tsc_gettext("Warning: Failed to register window class\n"), stderr);
    return 0;
  }
  auto const hwnd = CreateWindowExW(
      0, MAKEINTATOM(class), nullptr, 0, CW_USEDEFAULT, CW_USEDEFAULT,
      CW_USEDEFAULT, CW_USEDEFAULT, nullptr, nullptr, nullptr, nullptr);
  if (!hwnd) {
    fputs(tsc_gettext("Warning: Failed to create window instance\n"), stderr);
    return 0;
  }
  ShowWindow(hwnd, SW_HIDE);
  for (MSG msg; GetMessageW(&msg, nullptr, 0, 0);) {
    DispatchMessageW(&msg);
  }
  return 0;
}

//===-- Internal functions ------------------------------------------------===//

//===-- General functions -------------------------------------------------===//

void tscl_os_win_setup(void) {
  SetConsoleCP(CP_UTF8);
  SetConsoleOutputCP(CP_UTF8);
#ifdef TEK_SCB_GETTEXT
  // Extract localization files
  auto const module = GetModuleHandleW(
#ifdef TEK_SC_STATIC
      nullptr
#else  // def TEK_SC_STATIC
      L"libtek-steamclient-" TEK_SCB_SOVERSION ".dll"
#endif // def TEK_SC_STATIC else
  );
  if (!module) {
    goto skip_loc;
  }
  auto const list_res_info =
      FindResourceW(module, MAKEINTRESOURCEW(1000), RT_RCDATA);
  if (!list_res_info) {
    goto skip_loc;
  }
  auto const list_res = LoadResource(module, list_res_info);
  if (!list_res) {
    goto skip_loc;
  }
  const PCWSTR list = LockResource(list_res);
  if (!list || !*list) {
    goto skip_loc;
  }
  PWSTR path;
  if (SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KF_FLAG_CREATE, nullptr,
                           &path) != S_OK) {
    goto skip_loc;
  }
  UNICODE_STRING path_str;
  if (!RtlDosPathNameToNtPathName_U(path, &path_str, nullptr, nullptr)) {
    goto free_path;
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
    goto free_path;
  }
  attrs.RootDirectory = dir_handle;
  USHORT name_size = wcslen(L"tek-steamclient") * sizeof(WCHAR);
  path_str = (UNICODE_STRING){.Length = name_size,
                              .MaximumLength = name_size,
                              .Buffer = L"tek-steamclient"};
  status = NtCreateFile(&dir_handle, FILE_TRAVERSE, &attrs, &isb, nullptr,
                        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
                        FILE_OPEN_IF, FILE_DIRECTORY_FILE, nullptr, 0);
  NtClose(attrs.RootDirectory);
  if (!NT_SUCCESS(status)) {
    goto free_path;
  }
  attrs.RootDirectory = dir_handle;
  name_size = wcslen(L"locale") * sizeof(WCHAR);
  path_str = (UNICODE_STRING){
      .Length = name_size, .MaximumLength = name_size, .Buffer = L"locale"};
  status = NtCreateFile(&dir_handle, FILE_TRAVERSE, &attrs, &isb, nullptr,
                        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS,
                        FILE_OPEN_IF, FILE_DIRECTORY_FILE, nullptr, 0);
  NtClose(attrs.RootDirectory);
  if (!NT_SUCCESS(status)) {
    goto free_path;
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
    name_size = wcslen(loc_name) * sizeof *loc_name;
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
  auto const path_len = wcslen(path);
  auto const path_size = path_len * sizeof *path;
  static const WCHAR rel_path[] = L"\\tek-steamclient\\locale";
  const PWSTR buf = malloc(path_size + sizeof rel_path);
  if (!buf) {
    goto free_path;
  }
  memcpy(buf, path, path_size);
  memcpy(&buf[path_len], rel_path, sizeof rel_path);
  libintl_wbindtextdomain("tek-steamclient", buf);
  free(buf);
free_path:
  CoTaskMemFree(path);
skip_loc:
#endif // TEK_SCB_GETTEXT
  _beginthreadex(nullptr, 0, tscl_wnd_thrd_proc, nullptr, 0, nullptr);
}

void tscl_os_close_handle(tek_sc_os_handle handle) { NtClose(handle); }

tek_sc_os_char *tscl_os_get_cwd(void) {
  auto const buf_len = GetCurrentDirectoryW(0, nullptr);
  if (!buf_len) {
    return nullptr;
  }
  LPWSTR buf = malloc(sizeof *buf * buf_len);
  if (!GetCurrentDirectoryW(buf_len, buf)) {
    auto const errc = GetLastError();
    free(buf);
    SetLastError(errc);
    return nullptr;
  }
  return buf;
}

int64_t tscl_os_get_disk_free_space(const tek_sc_os_char *path) {
  ULARGE_INTEGER sz;
  if (GetDiskFreeSpaceExW(path, &sz, nullptr, nullptr)) {
    return sz.QuadPart;
  } else {
    return -1;
  }
}

char *tscl_os_get_err_msg(tek_sc_os_errc errc) {
  LPWSTR msg;
  auto const res = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                      FORMAT_MESSAGE_IGNORE_INSERTS |
                                      FORMAT_MESSAGE_FROM_SYSTEM,
                                  nullptr, errc, 0, (LPWSTR)&msg, 0, nullptr);
  if (!res) {
    static const char unk_msg[] = "Unknown error";
    char *const buf = malloc(sizeof unk_msg);
    if (!buf) {
      abort();
    }
    memcpy(buf, unk_msg, sizeof unk_msg);
    return buf;
  }
  auto const buf_size = WideCharToMultiByte(CP_UTF8, 0, msg, res + 1, nullptr,
                                            0, nullptr, nullptr);
  char *const buf = malloc(buf_size);
  if (!buf) {
    abort();
  }
  WideCharToMultiByte(CP_UTF8, 0, msg, res + 1, buf, buf_size, nullptr,
                      nullptr);
  LocalFree(msg);
  return buf;
}

tek_sc_os_errc tscl_os_get_last_error(void) { return GetLastError(); }

uint64_t tscl_os_get_ticks(void) { return GetTickCount64(); }

void tscl_os_reg_sig_handler(void (*handler)(void)) {
  tscl_cur_sig_handler = handler;
  SetConsoleCtrlHandler(tscl_console_ctrl_handler, TRUE);
}

void tscl_os_unreg_sig_handler(void) {
  SetConsoleCtrlHandler(tscl_console_ctrl_handler, FALSE);
  tscl_cur_sig_handler = nullptr;
}

//===-- I/O functions -----------------------------------------------------===//

tek_sc_err tscl_os_io_err(tek_sc_os_handle handle, tek_sc_errc prim,
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

tek_sc_err tscl_os_io_err_at(tek_sc_os_handle parent_dir_handle,
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

tek_sc_os_handle tscl_os_file_open_at(tek_sc_os_handle parent_dir_handle,
                                      const tek_sc_os_char *name) {
  const USHORT name_size = wcslen(name) * sizeof *name;
  IO_STATUS_BLOCK isb;
  HANDLE handle;
  auto const status =
      NtOpenFile(&handle, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                 &(OBJECT_ATTRIBUTES){
                     .Length = sizeof(OBJECT_ATTRIBUTES),
                     .RootDirectory = parent_dir_handle,
                     .ObjectName = &(UNICODE_STRING){.Length = name_size,
                                                     .MaximumLength = name_size,
                                                     .Buffer = (PWSTR)name},
                     .Attributes = OBJ_CASE_INSENSITIVE},
                 &isb, FILE_SHARE_READ,
                 FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT |
                     FILE_NON_DIRECTORY_FILE);
  if (NT_SUCCESS(status)) {
    return handle;
  }
  SetLastError(RtlNtStatusToDosError(status));
  return INVALID_HANDLE_VALUE;
}

bool tscl_os_file_read(tek_sc_os_handle handle, void *buf, size_t n) {
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

size_t tscl_os_file_get_size(tek_sc_os_handle handle) {
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

//===-- Virtual memory functions ------------------------------------------===//

void *tscl_os_mem_alloc(size_t size) {
  return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

void tscl_os_mem_free(const void *addr, size_t) {
  VirtualFree((LPVOID)addr, 0, MEM_RELEASE);
}

//===-- Futex functions ---------------------------------------------------===//

bool tscl_os_futex_wait(const _Atomic(uint32_t) *addr, uint32_t old,
                        uint32_t timeout_ms) {
  do {
    if (!WaitOnAddress((volatile void *)addr, &old, sizeof *addr, timeout_ms) &&
        GetLastError() == ERROR_TIMEOUT) {
      return false;
    }
  } while (atomic_load_explicit(addr, memory_order_relaxed) == old);
  return true;
}

void tscl_os_futex_wake(_Atomic(uint32_t) *addr) { WakeByAddressAll(addr); }

//===-- OS string functions -----------------------------------------------===//

bool tscl_os_fgets(tek_sc_os_char *str, int size) {
  return fgetws(str, size, stdin) != nullptr;
}

tek_sc_os_char *tscl_os_strchr(const tek_sc_os_char *str, tek_sc_os_char c) {
  return wcschr(str, c);
}

tek_sc_os_char *tscl_os_strrchr(const tek_sc_os_char *str, tek_sc_os_char c) {
  return wcsrchr(str, c);
}

int tscl_os_strcmp(const tek_sc_os_char *restrict left,
                   const tek_sc_os_char *restrict right) {
  return wcscmp(left, right);
}

void tscl_os_strlcat_utf8(char *str, const char *src, size_t size) {
  strcat_s(str, size, src);
}

size_t tscl_os_strlen(const tek_sc_os_char *str) { return wcslen(str); }

unsigned long long tscl_os_strtoull(const tek_sc_os_char *str,
                                    const tek_sc_os_char **endptr) {
  return wcstoull(str, (wchar_t **)endptr, 10);
}

char *tscl_os_str_to_utf8(const tek_sc_os_char *str) {
  auto const buf_size =
      WideCharToMultiByte(CP_UTF8, 0, str, -1, nullptr, 0, nullptr, nullptr);
  char *const buf = malloc(buf_size);
  if (!buf) {
    abort();
  }
  WideCharToMultiByte(CP_UTF8, 0, str, -1, buf, buf_size, nullptr, nullptr);
  return buf;
}
