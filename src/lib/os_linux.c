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

#include "common/error.h"
#include "config.h" // IWYU pragma: keep
#include "tek-steamclient/content.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#ifdef TEK_SCB_IO_URING
#include <liburing.h>
#endif // def TEK_SCB_IO_URING
#include <limits.h>
#include <linux/futex.h>
#include <linux/limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

/// @def TSCP_IO_URING_MMAP_SIZE
/// Size of the mapping allocated for io_uring when `IORING_SETUP_NO_MMAP` is
///    available. In tek-steamclient's use cases, neither of the queues should
///    ever exceed page size.
#define TSCP_IO_URING_MMAP_SIZE 0x2000

//===-- General functions -------------------------------------------------===//

void tsci_os_close_handle(tek_sc_os_handle handle) { close(handle); }

tek_sc_os_char *tsci_os_get_cache_dir(void) {
  // Try getting value of $XDG_CACHE_HOME first
  auto const xdg_cache_home = secure_getenv("XDG_CACHE_HOME");
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
  auto const home = secure_getenv("HOME");
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
  auto const res = strerror_r(errc, buf, 256);
  if (res != buf) {
    strlcpy(buf, res, 256);
  }
  return buf;
}

tek_sc_os_errc tsci_os_get_last_error(void) { return errno; }

int tsci_os_get_nproc(void) { return get_nprocs_conf(); }

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
  char proc_path[17];
  snprintf(proc_path, sizeof proc_path, "/proc/%u", getpid());
  struct statx stx;
  // stx_ctim of /proc/<pid> in most cases is the time of process creation, even
  //    if it's not, or the syscall fails, the use cases of this function don't
  //    require the precise time and will work just fine with any other number,
  //    so using more complicated methods is not justified
  if (statx(-1, proc_path, 0, STATX_CTIME, &stx) == 0 &&
      (stx.stx_mask & STATX_CTIME)) {
    return stx.stx_ctime.tv_sec;
  } else {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
  }
}

void tsci_os_set_thread_name(const tek_sc_os_char *name) {
  pthread_setname_np(pthread_self(), name);
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
  const int fd = open(path, O_DIRECTORY | O_CLOEXEC | O_PATH);
  if (fd >= 0) {
    return fd;
  }
  if (errno != ENOENT) {
    return -1;
  }
  if (mkdir(path, 0755) < 0) {
    return -1;
  }
  return open(path, O_DIRECTORY | O_CLOEXEC | O_PATH);
}

tek_sc_os_handle tsci_os_dir_create_at(tek_sc_os_handle parent_dir_handle,
                                       const tek_sc_os_char *name) {
  const int fd =
      openat(parent_dir_handle, name, O_DIRECTORY | O_CLOEXEC | O_PATH);
  if (fd >= 0) {
    return fd;
  }
  if (errno != ENOENT) {
    return -1;
  }
  if (mkdirat(parent_dir_handle, name, 0755) < 0) {
    return -1;
  }
  return openat(parent_dir_handle, name, O_DIRECTORY | O_CLOEXEC | O_PATH);
}

tek_sc_os_handle tsci_os_dir_open_at(tek_sc_os_handle parent_dir_handle,
                                     const tek_sc_os_char *name) {
  return openat(parent_dir_handle, name, O_DIRECTORY | O_CLOEXEC | O_PATH);
}

//===--- Directory delete -------------------------------------------------===//

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
      struct statx stx;
      if (statx(fd, ent->d_name, AT_SYMLINK_NOFOLLOW, STATX_MODE, &stx) < 0) {
        res = tsci_os_io_err_at(fd, ent->d_name, errc, errno,
                                TEK_SC_ERR_IO_TYPE_get_type);
        goto close_dir;
      }
      if (!(stx.stx_mask & STATX_MODE)) {
        res = tsci_os_io_err_at(fd, ent->d_name, errc, EINVAL,
                                TEK_SC_ERR_IO_TYPE_get_type);
        goto close_dir;
      }
      ent->d_type = S_ISDIR(stx.stx_mode) ? DT_DIR : DT_REG;
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

size_t tsci_os_file_get_size_at(tek_sc_os_handle parent_dir_handle,
                                const tek_sc_os_char *name) {
  struct statx stx;
  if (statx(parent_dir_handle, name, 0, STATX_SIZE, &stx) < 0) {
    return SIZE_MAX;
  }
  if (!(stx.stx_mask & STATX_SIZE)) {
    errno = EINVAL;
    return SIZE_MAX;
  }
  return stx.stx_size;
}

bool tsci_os_file_truncate(tek_sc_os_handle handle, int64_t new_size) {
  return !ftruncate(handle, new_size);
}

//===--- File apply flags -------------------------------------------------===//

bool tsci_os_file_apply_flags(tek_sc_os_handle handle,
                              tek_sc_dm_file_flag flags) {
  struct statx stx;
  if (statx(handle, "", AT_EMPTY_PATH, STATX_MODE, &stx) < 0) {
    return false;
  }
  if (!(stx.stx_mask & STATX_MODE)) {
    errno = EINVAL;
    return false;
  }
  const int perms = stx.stx_mode & ACCESSPERMS;
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
  struct statx stx;
  if (statx(parent_dir_handle, name, 0, STATX_MODE, &stx) < 0) {
    return false;
  }
  if (!(stx.stx_mask & STATX_MODE)) {
    errno = EINVAL;
    return false;
  }
  const int perms = stx.stx_mode & ACCESSPERMS;
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
  const int64_t src_end = src_offset + size;
  const int64_t tgt_end = tgt_offset + size;
  // Copying within the same file requires intermediate RAM buffer as well if
  //    source and target regions overlap
  bool xdev = args->not_same_dev || (src_fd == tgt_fd && src_offset < tgt_end &&
                                     tgt_offset < src_end);
  while (size) {
    ssize_t bytes_copied;
    if (xdev) {
      auto const bytes_read =
          pread(src_fd, buf, size > buf_size ? buf_size : size, src_offset);
      if (bytes_read < 0) {
        return false;
      }
      bytes_copied = pwrite(tgt_fd, buf, bytes_read, tgt_offset);
      if (bytes_copied < 0) {
        return false;
      }
      src_offset += bytes_copied;
      tgt_offset += bytes_copied;
    } else {
      bytes_copied =
          copy_file_range(src_fd, &src_offset, tgt_fd, &tgt_offset, size, 0);
      if (bytes_copied < 0) {
        if (errno == EXDEV) {
          xdev = true;
          args->not_same_dev = true;
          continue;
        }
        return false;
      }
    }
    if (!bytes_copied) {
      // Intentionally picked an errno value unused by pread(), pwrite(), and
      //    copy_file_range(), this branch helps avoiding a deadlock if early
      //    EOF is encountered
      errno = ERANGE;
      return false;
    }
    size -= bytes_copied;
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
  bool xdev = args->not_same_dev;
  bool res = true;
  while (size) {
    auto const bytes_copied =
        xdev ? sendfile(tgt_fd, src_fd, nullptr, size)
             : copy_file_range(src_fd, nullptr, tgt_fd, nullptr, size, 0);
    if (bytes_copied < 0) {
      auto const err = errno;
      if (err == EXDEV) {
        xdev = true;
        args->not_same_dev = true;
        continue;
      }
      args->error = tsci_os_io_err(src_fd, errc, err, TEK_SC_ERR_IO_TYPE_copy);
      res = false;
      break;
    }
    if (!bytes_copied) {
      // Intentionally picked an errno value unused by copy_file_range() and
      //    sendfile(), this branch helps avoiding a deadlock if early EOF is
      //    encountered
      args->error =
          tsci_os_io_err(src_fd, errc, ERANGE, TEK_SC_ERR_IO_TYPE_copy);
      res = false;
      break;
    }
    size -= bytes_copied;
  } // while (size)
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
#ifdef TEK_SCB_IO_URING
  auto const version = tsci_os_get_version();
  const int ver_num = version.major * 1000 + version.minor;
  if (ver_num < 5005) {
    // Kernels before 5.5 do not support IORING_REGISTER_FILES_UPDATE
    goto skip_uring;
  }
  unsigned flags = 0;
  // Set flags supported by current kernel version
  if (ver_num >= 5018) {
    flags |= IORING_SETUP_SUBMIT_ALL;
  }
  if (ver_num >= 5019) {
    flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
  }
  if (ver_num >= 6000) {
    flags |= IORING_SETUP_SINGLE_ISSUER;
  }
  if (ver_num >= 6001) {
    flags |= IORING_SETUP_DEFER_TASKRUN;
  }
  if (ver_num >= 6006) {
    flags |= IORING_SETUP_NO_SQARRAY;
  }
  int res;
  if (ver_num >= 6005) {
    flags |= IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY;
    ctx->buf = mmap(nullptr, TSCP_IO_URING_MMAP_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (ctx->buf == MAP_FAILED) {
      return errno;
    }
    res = io_uring_queue_init_mem(num_reqs, &ctx->ring,
                                  &(struct io_uring_params){.flags = flags},
                                  ctx->buf, TSCP_IO_URING_MMAP_SIZE);
  } else {
    ctx->buf = MAP_FAILED;
    res = io_uring_queue_init(num_reqs, &ctx->ring, flags);
  }
  if (res < 0) {
    if (-res == ENOSYS) {
      goto skip_uring;
    } else {
      return -res;
    }
  }
  res = io_uring_register_buffers(
      &ctx->ring,
      &(const struct iovec){.iov_base = buffer, .iov_len = buffer_size}, 1);
  switch (res) {
  case 0:
    ctx->buf_registered = true;
    break;
  case -ENOMEM:
    ctx->buf_registered = false;
    break;
  default:
    goto fail;
  }
  res = io_uring_register_files_sparse(&ctx->ring, 1);
  if (res < 0) {
    goto fail;
  }
  ctx->num_reqs = -1;
  return 0;
fail:
  io_uring_queue_exit(&ctx->ring);
  if (ctx->buf != MAP_FAILED) {
    munmap(ctx->buf, TSCP_IO_URING_MMAP_SIZE);
  }
  return -res;
skip_uring:
#endif // def TEK_SCB_IO_URING
  ctx->num_reqs = num_reqs;
  ctx->num_submitted = 0;
  ctx->reqs = malloc(sizeof *ctx->reqs * num_reqs);
  return ctx->reqs ? 0 : ENOMEM;
}

void tsci_os_aio_ctx_destroy(tsci_os_aio_ctx *ctx) {
#ifdef TEK_SCB_IO_URING
  if (ctx->num_reqs < 0) {
    io_uring_queue_exit(&ctx->ring);
    if (ctx->buf != MAP_FAILED) {
      munmap(ctx->buf, TSCP_IO_URING_MMAP_SIZE);
    }
    return;
  }
#endif // def TEK_SCB_IO_URING
  free(ctx->reqs);
}

tek_sc_os_errc tsci_os_aio_register_file(tsci_os_aio_ctx *ctx,
                                         tek_sc_os_handle handle) {
  ctx->reg_fd = handle;
#ifdef TEK_SCB_IO_URING
  if (ctx->num_reqs < 0) {
    const int res = io_uring_register_files_update(&ctx->ring, 0, &handle, 1);
    return res < 0 ? -res : 0;
  }
#endif // def TEK_SCB_IO_URING
  return 0;
}

tek_sc_os_errc tsci_os_aio_submit_read(tsci_os_aio_ctx *ctx,
                                       tsci_os_aio_req *req, void *buf,
                                       size_t n, int64_t offset,
                                       [[maybe_unused]] bool submit) {
  req->handle = ctx->reg_fd;
#ifdef TEK_SCB_IO_URING
  if (ctx->num_reqs < 0) {
    auto const sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
      return EBUSY;
    }
    if (ctx->buf_registered) {
      io_uring_prep_read_fixed(sqe, 0, buf, n, offset, 0);
    } else {
      io_uring_prep_read(sqe, 0, buf, n, offset);
    }
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, req);
    if (submit) {
      const int res = io_uring_submit_and_get_events(&ctx->ring);
      if (res < 0) {
        return -res;
      }
    }
    return 0;
  }
#endif // def TEK_SCB_IO_URING
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
#ifdef TEK_SCB_IO_URING
  if (ctx->num_reqs < 0) {
    auto const sqe = io_uring_get_sqe(&ctx->ring);
    if (!sqe) {
      return EBUSY;
    }
    if (ctx->buf_registered) {
      io_uring_prep_write_fixed(sqe, 0, buf, n, offset, 0);
    } else {
      io_uring_prep_write(sqe, 0, buf, n, offset);
    }
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);
    io_uring_sqe_set_data(sqe, req);
    if (submit) {
      const int res = io_uring_submit_and_get_events(&ctx->ring);
      if (res < 0) {
        return -res;
      }
    }
    return 0;
  }
#endif // def TEK_SCB_IO_URING
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
#ifdef TEK_SCB_IO_URING
  if (ctx->num_reqs < 0) {
    if (!num_reqs) {
      return 0;
    }
    if (num_wait && (int)io_uring_cq_ready(&ctx->ring) < num_wait) {
      const int res = io_uring_submit_and_wait(&ctx->ring, num_wait);
      if (res < 0) {
        errno = -res;
        return -1;
      }
    }
    unsigned head;
    struct io_uring_cqe *cqe;
    int i = 0;
    io_uring_for_each_cqe(&ctx->ring, head, cqe) {
      const int res = cqe->res;
      tsci_os_aio_req *req = io_uring_cqe_get_data(cqe);
      req->result = res < 0 ? -res : 0;
      req->bytes_transferred = res < 0 ? 0 : res;
      reqs[i] = req;
      if (++i == num_reqs) {
        break;
      }
    }
    io_uring_cq_advance(&ctx->ring, i);
    return i;
  }
#endif // def TEK_SCB_IO_URING
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
  if (size >= 0x200000) {
    // 2 MiB is usually the smallest supported hugepage size
    madvise(addr, size, MADV_HUGEPAGE);
  }
  return addr;
}

void tsci_os_mem_free(const void *addr, size_t size) {
  munmap((void *)addr, size);
}

//===-- Futex functions ---------------------------------------------------===//

bool tsci_os_futex_wait(const _Atomic(uint32_t) *addr, uint32_t old,
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

void tsci_os_futex_wake(_Atomic(uint32_t) *addr) {
  syscall(SYS_futex, addr, FUTEX_WAKE_PRIVATE, INT_MAX);
}

//===-- Pathname string functions -----------------------------------------===//

int tsci_os_pstrcmp(const tek_sc_os_char *restrict left,
                    const tek_sc_os_char *restrict right) {
  return strcmp(left, right);
}

int tsci_os_pstr_strlen(const tek_sc_os_char *pstr) {
  // Modern Linux filesystems already use UTF-8 or implicitly convert to it
  return strlen(pstr);
}

int tsci_os_pstr_to_str(const tek_sc_os_char *restrict pstr,
                        char *restrict str) {
  auto const len = strlen(pstr);
  memcpy(str, pstr, len);
  return len;
}

int tsci_os_str_pstrlen(const char *, int len) {
  // Modern Linux filesystems already use UTF-8 or implicitly convert from it
  return len;
}

int tsci_os_str_to_pstr(const char *restrict str, int len,
                        tek_sc_os_char *restrict pstr) {
  memcpy(pstr, str, len);
  return len;
}
