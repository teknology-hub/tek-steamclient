//===-- os_linux.c - GNU/Linux OS functions implementation ----------------===//
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
/// GNU/Linux implementation of @ref os.h.
///
//===----------------------------------------------------------------------===//
#include "os.h"

#include "common.h"
#include "tek-steamclient/os.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/// Currently registered signal handler.
void (*_Nullable tscl_cur_sig_handler)(void);

//===-- Private function --------------------------------------------------===//

/// SIGINT/SIGTERM signal handler.
static void tscl_sig_handler(int sig) {
  if (!tscl_cur_sig_handler) {
    return;
  }
  if (sig == SIGTERM) {
    atomic_store_explicit(&tscl_g_ctx.terminating, 1, memory_order_relaxed);
  }
  tscl_cur_sig_handler();
}

//===-- Internal functions ------------------------------------------------===//

//===-- General functions -------------------------------------------------===//

void tscl_os_close_handle(tek_sc_os_handle handle) { close(handle); }

tek_sc_os_char *tscl_os_get_cwd(void) { return get_current_dir_name(); }

int64_t tscl_os_get_disk_free_space(const tek_sc_os_char *path) {
  struct statvfs stvfs;
  if (statvfs(path, &stvfs) < 0) {
    return -1;
  }
  return stvfs.f_bavail * stvfs.f_frsize;
}

char *tscl_os_get_err_msg(tek_sc_os_errc errc) {
  char *const buf = malloc(256);
  if (!buf) {
    abort();
  }
  auto const res = strerror_r(errc, buf, 256);
  if (res != buf) {
    strlcpy(buf, res, 256);
  }
  return buf;
}

tek_sc_os_errc tscl_os_get_last_error(void) { return errno; }

uint64_t tscl_os_get_ticks(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void tscl_os_reg_sig_handler(void (*handler)(void)) {
  tscl_cur_sig_handler = handler;
  const struct sigaction act = {.sa_handler = tscl_sig_handler};
  sigaction(SIGINT, &act, nullptr);
  sigaction(SIGTERM, &act, nullptr);
}

void tscl_os_unreg_sig_handler(void) {
  const struct sigaction act = {.sa_handler = SIG_DFL};
  sigaction(SIGINT, &act, nullptr);
  sigaction(SIGTERM, &act, nullptr);
  tscl_cur_sig_handler = nullptr;
}

//===-- I/O functions -----------------------------------------------------===//

tek_sc_err tscl_os_io_err(tek_sc_os_handle handle, tek_sc_errc prim,
                          tek_sc_os_errc errc, tek_sc_err_io_type io_type) {
  char *buf = malloc(PATH_MAX);
  if (buf) {
    char path[25];
    snprintf(path, sizeof path, "/proc/self/fd/%u", handle);
    auto const res = readlink(path, buf, PATH_MAX);
    if (res >= 0) {
      buf[res] = '\0';
    } else {
      free(buf);
      buf = nullptr;
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
  char *buf = malloc(PATH_MAX);
  if (buf) {
    char path[25];
    snprintf(path, sizeof path, "/proc/self/fd/%u", parent_dir_handle);
    auto const res = readlink(path, buf, PATH_MAX);
    if (res < 0) {
      free(buf);
      buf = nullptr;
    } else {
      buf[res] = '/';
      strlcpy(&buf[res + 1], name, PATH_MAX - res - 1);
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
  return openat(parent_dir_handle, name, O_RDONLY | O_CLOEXEC);
}

bool tscl_os_file_read(tek_sc_os_handle handle, void *buf, size_t n) {
  for (;;) {
    auto const bytes_read = read(handle, buf, n);
    if (bytes_read < 0) {
      return false;
    }
    n -= bytes_read;
    if (!n) {
      return true;
    }
    if (!bytes_read) {
      // Intentionally picked an errno value unused by read(), this branch helps
      //     avoiding a deadlock if early EOF is encountered
      errno = ERANGE;
      return false;
    }
    buf += bytes_read;
  }
}

size_t tscl_os_file_get_size(tek_sc_os_handle handle) {
  struct statx stx;
  if (statx(handle, "", AT_EMPTY_PATH, STATX_SIZE, &stx) < 0) {
    return SIZE_MAX;
  }
  if (!(stx.stx_mask & STATX_SIZE)) {
    errno = EINVAL;
    return SIZE_MAX;
  }
  return stx.stx_size;
}

//===-- Virtual memory functions ------------------------------------------===//

void *tscl_os_mem_alloc(size_t size) {
  auto const addr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    return nullptr;
  }
  if (size >= 0x200000) {
    // 2 MiB is usually the smallest supported hugepage size
    madvise(addr, size, MADV_HUGEPAGE);
  }
  return addr;
}

void tscl_os_mem_free(const void *addr, size_t size) {
  munmap((void *)addr, size);
}

//===-- Futex functions ---------------------------------------------------===//

bool tscl_os_futex_wait(const _Atomic(uint32_t) *addr, uint32_t old,
                        uint32_t timeout_ms) {
  const struct timespec ts = {.tv_sec = timeout_ms / 1000,
                              .tv_nsec = (timeout_ms % 1000) * 1000000};
  do {
    if (syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, old, &ts) < 0) {
      return errno == EAGAIN;
    }
  } while (atomic_load_explicit(addr, memory_order_relaxed) == old);
  return true;
}

void tscl_os_futex_wake(_Atomic(uint32_t) *addr) {
  syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, 1);
}

//===-- OS string functions -----------------------------------------------===//

bool tscl_os_fgets(tek_sc_os_char *str, int size) {
  return fgets(str, size, stdin) != nullptr;
}

tek_sc_os_char *tscl_os_strchr(tek_sc_os_char *str, tek_sc_os_char c) {
  return strchr(str, c);
}

tek_sc_os_char *tscl_os_strrchr(tek_sc_os_char *str, tek_sc_os_char c) {
  return strrchr(str, c);
}

int tscl_os_strcmp(const tek_sc_os_char *restrict left,
                   const tek_sc_os_char *restrict right) {
  return strcmp(left, right);
}

void tscl_os_strlcat_utf8(char *str, const char *src, size_t size) {
  strlcat(str, src, size);
}

size_t tscl_os_strlen(const tek_sc_os_char *str) { return strlen(str); }

unsigned long long tscl_os_strtoull(const tek_sc_os_char *str,
                                    const tek_sc_os_char **endptr) {
  return strtoull(str, (char **)endptr, 10);
}

char *tscl_os_str_to_utf8(const tek_sc_os_char *str) {
  auto const res = strdup(str);
  if (!res) {
    abort();
  }
  return res;
}
