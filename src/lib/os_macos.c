//===-- os_macos.c - MacOS functions implementation -----------------------===//
//
// Copyright (c) 2026 Nuclearist <nuclearist@teknology-hub.com>,
//    ksagameng2 <fordealisbad@gmail.com>
// Part of tek-steamclient, under the GNU General Public License v3.0 or later
// See https://github.com/teknology-hub/tek-steamclient/blob/main/COPYING for
//    license information.
// SPDX-License-Identifier: GPL-3.0-or-later
//
//===----------------------------------------------------------------------===//
///
/// @file
/// MacOS implementation of @ref os.h.
///
//===----------------------------------------------------------------------===//
#include "os.h"

#include "common/error.h"
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <os/os_sync_wait_on_address.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

//===-- General functions -------------------------------------------------===//

void tsci_os_close_handle(tek_sc_os_handle handle) { close(handle); }

tek_sc_os_char *tsci_os_get_cache_dir(void) {
  // Try getting value of $XDG_CACHE_HOME first
  auto const xdg_cache_home = getenv("XDG_CACHE_HOME");
  if (xdg_cache_home) {
    if (!xdg_cache_home[0]) {
      goto try_home;
    }
    // Expand the value since it may contain other variables e.g. $HOME
    wordexp_t we;
    if (wordexp(xdg_cache_home, &we, WRDE_NOCMD) != 0) {
      goto try_home;
    }
    if (!we.we_wordc) {
      wordfree(&we);
      goto try_home;
    }
    auto const path = strdup(we.we_wordv[0]);
    wordfree(&we);
    return path;
  }
  // Otherwise use "/var/cache" for root, or try "$HOME/.cache"
  if (geteuid() == 0) {
    return strdup("/var/cache");
  }
try_home:
  auto const home = getenv("HOME");
  static const char rel_path[] = "/.cache";
  if (home && home[0]) {
    auto const path_size = strlen(home) + sizeof rel_path;
    char *const path = malloc(path_size);
    if (!path) {
      return nullptr;
    }
    strlcpy(path, home, path_size);
    strlcat(path, rel_path, path_size);
    return path;
  }
  // If even $HOME is not set, fallback to home directory from passwd entry of
  //    current user
  auto buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (buf_size <= 0) {
    buf_size = 1024;
  }
  auto buf = malloc(buf_size);
  if (!buf) {
    return nullptr;
  }
  for (auto const euid = geteuid();;) {
    struct passwd pw;
    struct passwd *pw_res;
    const int res = getpwuid_r(euid, &pw, buf, buf_size, &pw_res);
    if (res == ERANGE) {
      // Buffer is too small, double it and try again
      buf_size *= 2;
      free(buf);
      buf = malloc(buf_size);
      if (!buf) {
        return nullptr;
      }
      continue;
    }
    if (res != 0 || !pw_res) {
      // An error has occurred
      free(buf);
      return nullptr;
    }
    // Successfully got the passwd entry
    auto const path_size = strlen(pw.pw_dir) + sizeof rel_path;
    char *const path = malloc(path_size);
    if (!path) {
      free(buf);
      return nullptr;
    }
    strlcpy(path, pw.pw_dir, path_size);
    free(buf);
    strlcat(path, rel_path, path_size);
    return path;
  }
}

char *tsci_os_get_err_msg(tek_sc_os_errc errc) {
  char *const buf = malloc(256);
  if (!buf) {
    abort();
  }
  if (strerror_r(errc, buf, 256)) {
    static const char unk_msg[] = "Unknown error";
    memcpy(buf, unk_msg, sizeof unk_msg);
  }
  return buf;
}

tek_sc_os_errc tsci_os_get_last_error(void) { return errno; }

int tsci_os_get_nproc(void) { return sysconf(_SC_NPROCESSORS_CONF); }

uint64_t tsci_os_get_ticks(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

tsci_os_version tsci_os_get_version(void) {
  struct utsname utsname;
  uname(&utsname);
  tsci_os_version version = {};
  char *endptr;
  version.major = strtoul(utsname.release, &endptr, 10);
  // endptr should point to a '.' separating numbers, if not then return
  if (*endptr != '.') {
    return version;
  }
  version.minor = strtoul(endptr + 1, &endptr, 10);
  if (*endptr != '.') {
    return version;
  }
  version.build = strtoul(endptr + 1, nullptr, 10);
  return version;
}

time_t tsci_os_get_process_start_time(void) {
  // There's no good way to get the process creation time without objective-c
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec;
}

void tsci_os_set_thread_name(const tek_sc_os_char *name) {
  pthread_setname_np(name);
}

//===-- I/O functions -----------------------------------------------------===//

tek_sc_err tsci_os_io_err(tek_sc_os_handle handle, tek_sc_errc prim,
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

tek_sc_err tsci_os_io_err_at(tek_sc_os_handle parent_dir_handle,
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

tek_sc_os_errc tsci_os_path_exists_at(tek_sc_os_handle parent_dir_handle,
                                      const tek_sc_os_char *name) {
  return faccessat(parent_dir_handle, name, F_OK, AT_EACCESS) < 0 ? errno : 0;
}

//===--- Diectory create/open ---------------------------------------------===//

tek_sc_os_handle tsci_os_dir_create(const tek_sc_os_char *path) {
  const int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    return fd;
  }
  if (errno != ENOENT) {
    return -1;
  }
  if (mkdir(path, 0755) < 0) {
    return -1;
  }
  return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

tek_sc_os_handle tsci_os_dir_create_at(tek_sc_os_handle parent_dir_handle,
                                       const tek_sc_os_char *name) {
  const int fd =
      openat(parent_dir_handle, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    return fd;
  }
  if (errno != ENOENT) {
    return -1;
  }
  if (mkdirat(parent_dir_handle, name, 0755) < 0) {
    return -1;
  }
  return openat(parent_dir_handle, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

tek_sc_os_handle tsci_os_dir_open_at(tek_sc_os_handle parent_dir_handle,
                                     const tek_sc_os_char *name) {
  return openat(parent_dir_handle, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

//===--- Directory move/delete --------------------------------------------===//

bool tsci_os_dir_move(tek_sc_os_handle src_dir_handle,
                      tek_sc_os_handle tgt_dir_handle,
                      const tek_sc_os_char *name) {
  return !renameatx_np(src_dir_handle, name, tgt_dir_handle, name, RENAME_EXCL);
}

bool tsci_os_dir_delete_at(tek_sc_os_handle parent_dir_handle,
                           const tek_sc_os_char *name) {
  return !unlinkat(parent_dir_handle, name, AT_REMOVEDIR);
}

tek_sc_err tsci_os_dir_delete_at_rec(tek_sc_os_handle parent_dir_handle,
                                     const tek_sc_os_char *name,
                                     tek_sc_errc errc) {
  const int fd =
      openat(parent_dir_handle, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    const int err = errno;
    return err == ENOENT ? tsc_err_ok()
                         : tsci_os_io_err_at(parent_dir_handle, name, errc, err,
                                             TEK_SC_ERR_IO_TYPE_open);
  }
  auto const dir = fdopendir(fd);
  if (!dir) {
    close(fd);
    return tsci_os_io_err(fd, errc, errno, TEK_SC_ERR_IO_TYPE_open);
  }
  tek_sc_err res;
  struct dirent *ent;
  errno = 0; // readdir doesn't zero errno on success
  // Iterate directory children
  while ((ent = readdir(dir))) {
    auto const name16 = *((const uint16_t *)ent->d_name);
    if (name16 == 0x002E || (name16 == 0x2E2E && !ent->d_name[2])) {
      // Skip "." and ".."
      continue;
    }
    if (ent->d_type == DT_UNKNOWN) {
      // Determine file type
      struct stat st;
      if (fstatat(fd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
        res = tsci_os_io_err_at(fd, ent->d_name, errc, errno,
                                TEK_SC_ERR_IO_TYPE_get_type);
        goto close_dir;
      }
      ent->d_type = S_ISDIR(st.st_mode) ? DT_DIR : DT_REG;
    }
    if (ent->d_type == DT_DIR) {
      res = tsci_os_dir_delete_at_rec(fd, ent->d_name, errc);
      if (!tek_sc_err_success(&res)) {
        goto close_dir;
      }
    } else if (unlinkat(fd, ent->d_name, 0) < 0) {
      res = tsci_os_io_err_at(fd, ent->d_name, errc, errno,
                              TEK_SC_ERR_IO_TYPE_delete);
      goto close_dir;
    }
    errno = 0; // readdir doesn't zero errno on success
  } // while ((ent = readdir(dir)))
  const int err = errno;
  res = err ? tsci_os_io_err(fd, errc, err, TEK_SC_ERR_IO_TYPE_read)
            : tsc_err_ok();
close_dir:
  closedir(dir);
  if (tek_sc_err_success(&res) &&
      unlinkat(parent_dir_handle, name, AT_REMOVEDIR) < 0) {
    res = tsci_os_io_err(fd, errc, errno, TEK_SC_ERR_IO_TYPE_delete);
  }
  close(fd);
  return res;
}

//===--- File create/open -------------------------------------------------===//

tek_sc_os_handle tsci_os_file_create_at(tek_sc_os_handle parent_dir_handle,
                                        const tek_sc_os_char *name,
                                        tsci_os_file_access access,
                                        tsci_os_file_opt options) {
  int flags = access | O_CREAT | O_CLOEXEC;
  if (options & TSCI_OS_FILE_OPT_trunc) {
    flags |= O_TRUNC;
  }
  return openat(parent_dir_handle, name, flags, 0644);
}

tek_sc_os_handle tsci_os_file_open_at(tek_sc_os_handle parent_dir_handle,
                                      const tek_sc_os_char *name,
                                      tsci_os_file_access access,
                                      tsci_os_file_opt) {
  return openat(parent_dir_handle, name, access | O_CLOEXEC);
}

//===--- File read/write --------------------------------------------------===//

bool tsci_os_file_read(tek_sc_os_handle handle, void *buf, size_t n) {
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

bool tsci_os_file_read_at(tek_sc_os_handle handle, void *buf, size_t n,
                          int64_t offset) {
  for (;;) {
    auto const bytes_read = pread(handle, buf, n, offset);
    if (bytes_read < 0) {
      return false;
    }
    n -= bytes_read;
    if (!n) {
      return true;
    }
    if (!bytes_read) {
      // Intentionally picked an errno value unused by pread(), this branch
      //    helps avoiding a deadlock if early EOF is encountered
      errno = ERANGE;
      return false;
    }
    buf += bytes_read;
    offset += bytes_read;
  }
}

bool tsci_os_file_write(tek_sc_os_handle handle, const void *buf, size_t n) {
  for (;;) {
    auto const bytes_written = write(handle, buf, n);
    if (bytes_written < 0) {
      return false;
    }
    n -= bytes_written;
    if (!n) {
      return true;
    }
    if (!bytes_written) {
      // Intentionally picked an errno value unused by write(), this branch
      //    helps avoiding a deadlock if early EOF is encountered
      errno = ERANGE;
      return false;
    }
    buf += bytes_written;
  }
}

bool tsci_os_file_write_at(tek_sc_os_handle handle, const void *buf, size_t n,
                           int64_t offset) {
  for (;;) {
    auto const bytes_written = pwrite(handle, buf, n, offset);
    if (bytes_written < 0) {
      return false;
    }
    n -= bytes_written;
    if (!n) {
      return true;
    }
    if (!bytes_written) {
      // Intentionally picked an errno value unused by pwrite(), this branch
      //    helps avoiding a deadlock if early EOF is encountered
      errno = ERANGE;
      return false;
    }
    buf += bytes_written;
    offset += bytes_written;
  }
}

//===--- File get/set size ------------------------------------------------===//

size_t tsci_os_file_get_size(tek_sc_os_handle handle) {
  struct stat st;
  if (fstat(handle, &st) < 0) {
    return SIZE_MAX;
  }
  return st.st_size;
}

size_t tsci_os_file_get_size_at(tek_sc_os_handle parent_dir_handle,
                                const tek_sc_os_char *name) {
  struct stat st;
  if (fstatat(parent_dir_handle, name, &st, 0) < 0) {
    return SIZE_MAX;
  }
  return st.st_size;
}

bool tsci_os_file_truncate(tek_sc_os_handle handle, int64_t new_size) {
  return !ftruncate(handle, new_size);
}

//===--- File apply flags -------------------------------------------------===//

bool tsci_os_file_apply_flags(tek_sc_os_handle handle,
                              tek_sc_dm_file_flag flags) {
  struct stat st;
  if (fstat(handle, &st) < 0) {
    return false;
  }
  const int perms = st.st_mode & ACCESSPERMS;
  if (flags & TEK_SC_DM_FILE_FLAG_executable) {
    if (perms & 0100) {
      return true;
    }
    return !fchmod(handle, perms | 0111);
  } else {
    if (!(perms & 0111)) {
      return true;
    }
    return !fchmod(handle, perms & ~0111);
  }
}

bool tsci_os_file_apply_flags_at(tek_sc_os_handle parent_dir_handle,
                                 const tek_sc_os_char *name,
                                 tek_sc_dm_file_flag flags) {
  struct stat st;
  if (fstatat(parent_dir_handle, name, &st, 0) < 0) {
    return false;
  }
  const int perms = st.st_mode & ACCESSPERMS;
  if (flags & TEK_SC_DM_FILE_FLAG_executable) {
    if (perms & 0100) {
      return true;
    }
    return !fchmodat(parent_dir_handle, name, perms | 0111, 0);
  } else {
    if (!(perms & 0111)) {
      return true;
    }
    return !fchmodat(parent_dir_handle, name, perms & ~0111, 0);
  }
}

//===--- File copy/move ---------------------------------------------------===//

bool tsci_os_file_copy_chunk(tsci_os_copy_args *args, int64_t src_offset,
                             int64_t tgt_offset, size_t size) {
  const int src_fd = args->src_handle;
  const int tgt_fd = args->tgt_handle;
  auto const buf = args->buf;
  auto const buf_size = args->buf_size;
  while (size) {
    auto const bytes_read =
        pread(src_fd, buf, size > buf_size ? buf_size : size, src_offset);
    if (bytes_read <= 0) {
      if (!bytes_read) {
        // Intentionally picked an errno value unused by pread(), this branch
        //    helps avoiding a deadlock if early EOF is encountered
        errno = ERANGE;
      }
      return false;
    }
    auto const bytes_written = pwrite(tgt_fd, buf, bytes_read, tgt_offset);
    if (bytes_written < 0) {
      return false;
    }
    src_offset += bytes_written;
    tgt_offset += bytes_written;
    size -= bytes_written;
  } // while (size)
  return true;
}

bool tsci_os_file_copy(tsci_os_copy_args *args, const tek_sc_os_char *name,
                       int64_t size, tek_sc_errc errc) {
  const int src_fd = openat(args->src_handle, name, O_RDONLY | O_CLOEXEC);
  if (src_fd < 0) {
    args->error = tsci_os_io_err_at(args->src_handle, name, errc, errno,
                                    TEK_SC_ERR_IO_TYPE_open);
    return false;
  }
  const int tgt_fd = openat(args->tgt_handle, name,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (tgt_fd < 0) {
    args->error = tsci_os_io_err_at(args->tgt_handle, name, errc, errno,
                                    TEK_SC_ERR_IO_TYPE_open);
    close(src_fd);
    return false;
  }
  auto const buf = args->buf;
  auto const buf_size = args->buf_size;
  bool res = true;
  for (int64_t offset = 0; size;) {
    auto const bytes_read =
        pread(src_fd, buf, (size_t)size > buf_size ? buf_size : size, offset);
    if (bytes_read <= 0) {
      args->error = tsci_os_io_err(src_fd, errc, bytes_read ? errno : ERANGE,
                                   TEK_SC_ERR_IO_TYPE_read);
      res = false;
      break;
    }
    auto const bytes_written = pwrite(tgt_fd, buf, bytes_read, offset);
    if (bytes_written < 0) {
      args->error =
          tsci_os_io_err(tgt_fd, errc, errno, TEK_SC_ERR_IO_TYPE_write);
      res = false;
      break;
    }
    offset += bytes_written;
    size -= bytes_written;
  } // for (int64_t offset = 0; size;)
  close(tgt_fd);
  close(src_fd);
  return res;
}

bool tsci_os_file_move(tek_sc_os_handle src_dir_handle,
                       tek_sc_os_handle tgt_dir_handle,
                       const tek_sc_os_char *name) {
  return !renameat(src_dir_handle, name, tgt_dir_handle, name);
}

//===--- File delete ------------------------------------------------------===//

bool tsci_os_file_delete_at(tek_sc_os_handle parent_dir_handle,
                            const tek_sc_os_char *name) {
  return !unlinkat(parent_dir_handle, name, 0);
}

//===--- Symbolic link ----------------------------------------------------===//

bool tsci_os_symlink_at(const tek_sc_os_char *target,
                        tek_sc_os_handle parent_dir_handle,
                        const tek_sc_os_char *name) {
  return !symlinkat(target, parent_dir_handle, name);
}

//===-- Asynchronous I/O functions ----------------------------------------===//

tek_sc_os_errc tsci_os_aio_ctx_init(tsci_os_aio_ctx *ctx, int num_reqs,
                                    [[maybe_unused]] void *buffer,
                                    [[maybe_unused]] size_t buffer_size) {
  ctx->num_reqs = num_reqs;
  ctx->num_submitted = 0;
  ctx->reqs = malloc(sizeof *ctx->reqs * num_reqs);
  return ctx->reqs ? 0 : ENOMEM;
}

void tsci_os_aio_ctx_destroy(tsci_os_aio_ctx *ctx) { free(ctx->reqs); }

tek_sc_os_errc tsci_os_aio_register_file(tsci_os_aio_ctx *ctx,
                                         tek_sc_os_handle handle) {
  ctx->reg_fd = handle;
  return 0;
}

tek_sc_os_errc tsci_os_aio_submit_read(tsci_os_aio_ctx *ctx,
                                       tsci_os_aio_req *req, void *buf,
                                       size_t n, int64_t offset,
                                       [[maybe_unused]] bool submit) {
  req->handle = ctx->reg_fd;
  if (ctx->num_submitted >= ctx->num_reqs) {
    return EBUSY;
  }
  ctx->reqs[ctx->num_submitted++] = req;
  auto const res = pread(ctx->reg_fd, buf, n, offset);
  if (res < 0) {
    req->result = errno;
    req->bytes_transferred = 0;
  } else {
    req->result = 0;
    req->bytes_transferred = res;
  }
  return 0;
}

tek_sc_os_errc tsci_os_aio_submit_write(tsci_os_aio_ctx *ctx,
                                        tsci_os_aio_req *req, const void *buf,
                                        size_t n, int64_t offset,
                                        [[maybe_unused]] bool submit) {
  req->handle = ctx->reg_fd;
  if (ctx->num_submitted >= ctx->num_reqs) {
    return EBUSY;
  }
  ctx->reqs[ctx->num_submitted++] = req;
  auto const res = pwrite(ctx->reg_fd, buf, n, offset);
  if (res < 0) {
    req->result = errno;
    req->bytes_transferred = 0;
  } else {
    req->result = 0;
    req->bytes_transferred = res;
  }
  return 0;
}

int tsci_os_aio_get_compls(tsci_os_aio_ctx *ctx, tsci_os_aio_req **reqs,
                           int num_reqs, [[maybe_unused]] int num_wait) {
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
  auto const addr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (addr == MAP_FAILED) {
    return nullptr;
  }
  return addr;
}

void tsci_os_mem_free(const void *addr, size_t size) {
  munmap((void *)addr, size);
}

//===-- Futex functions ---------------------------------------------------===//

bool tsci_os_futex_wait(const _Atomic(uint32_t) *addr, uint32_t old,
                        uint32_t timeout_ms) {
  return timeout_ms == UINT32_MAX
             ? os_sync_wait_on_address(addr, old, sizeof old,
                                       OS_SYNC_WAIT_ON_ADDRESS_NONE) >= 0
             : os_sync_wait_on_address_with_timeout(
                   addr, old, sizeof old, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                   OS_CLOCK_MACH_ABSOLUTE_TIME,
                   (uint64_t)timeout_ms * 1000000) >= 0;
}

void tsci_os_futex_wake(_Atomic(uint32_t) *addr) {
  os_sync_wake_by_address_all(addr, sizeof *addr, OS_SYNC_WAKE_BY_ADDRESS_NONE);
}

//===-- Pathname string functions -----------------------------------------===//

int tsci_os_pstr_strlen(const tek_sc_os_char *pstr) { return strlen(pstr); }

int tsci_os_pstr_to_str(const tek_sc_os_char *restrict pstr,
                        char *restrict str) {
  auto const len = strlen(pstr);
  memcpy(str, pstr, len);
  return len;
}

int tsci_os_str_pstrlen(const char *, int len) { return len; }

int tsci_os_str_to_pstr(const char *restrict str, int len,
                        tek_sc_os_char *restrict pstr) {
  memcpy(pstr, str, len);
  return len;
}
