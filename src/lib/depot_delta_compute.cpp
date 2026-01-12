//===-- depot_delta_compute.cpp - depot delta computation -----------------===//
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
/// Implementation of @ref tek_sc_dd_compute.
///
/// General algorithm description:
/// Delta is created in 2 passes: count and write. The count pass counts the
///    numbers of entries (and child entries for each entry) to create, and the
///    write pass repeats iterations but writes entries' data to the final
///    buffer. In both cases it walks both manifest trees simultaneously in a
///    specific manner that allows finding removed, equal, and added entries
///    from both manifests without significant overhead.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "content_ops.hpp"
#include "os.h"
#include "tek-steamclient/base.h" // IWYU pragma: keep

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <ranges>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

namespace tek::steamclient::content {

namespace {

//===-- Private types -----------------------------------------------------===//

/// Staging entry descriptor, preserves the flags and numbers of children
///    entries between count and write passes.
union entry_desc {
  /// File descriptor.
  struct {
    /// Discovered file operation flags.
    tek_sc_dd_file_flag flags;
    /// Number of chunk delta entries assigned to the file.
    int num_chunks;
    /// Number of transfer operation entries assigned to the file.
    int num_trans_op_grps;
  } file;
  /// Directory descriptor.
  struct {
    /// Discovered directory operation flags.
    tek_sc_dd_dir_flag flags;
    /// Number of file delta entries assigned to the directory.
    int num_files;
    /// Number of assigned subdirectory delta entries.
    int num_subdirs;
  } dir;
};

/// Staging transfer operation descriptor, used for grouping and order
///    optimization.
struct transfer_op_desc {
  /// Offset of the beginning of the source region, in bytes.
  std::int64_t src_off;
  /// Offset of the end of the source region (exclusive), in bytes.
  std::int64_t src_end;
  /// Offset of the beginning of the target region, in bytes.
  std::int64_t tgt_off;
  /// Offset of the end of the target region (exclusive), in bytes.
  std::int64_t tgt_end;
  /// Pointer to the corresponding patch chunk, for patch operations.
  const tek_sc_dp_chunk *_Nullable pchunk;
  /// Value indicating whether this entry has been visited by graph traversal
  ///    routines yet. Helps avoiding recursive loops.
  bool visited;
  /// Value indicating whether this entry has been written to the delta yet and
  ///    as such should be ignored for optimizations.
  bool written;
  /// Pointers to transfer operations whose source range is intersected by this
  ///    operation's target range.
  std::vector<transfer_op_desc *> intersects_with;
  /// Pointers to transfer operations whose target range intersects this
  ///    operation's source range.
  std::vector<transfer_op_desc *> intersected_by;
};

/// Count pass context, shared across recursion levels of @ref count_dir.
struct count_ctx {
  /// Pointer to the next available staging entry descriptor in the buffer.
  entry_desc *_Nonnull next_desc;
  /// Pointer to the patch to use, if provided.
  const tek_sc_depot_patch *_Nullable patch;
  /// Pointer to the buffer for storing pointers to source file's chunks sorted
  ///    by `sha`.
  const tek_sc_dm_chunk *_Nonnull *_Nonnull src_chunk_ptrs;
  /// Pointer to the buffer for storing pointers to target file's chunks sorted
  ///    by `sha`.
  const tek_sc_dm_chunk *_Nonnull *_Nonnull tgt_chunk_ptrs;
  /// Staging transfer operation buffer.
  std::vector<transfer_op_desc> &transfer_ops;
};

/// Write pass context, shared across recursion levels of @ref write_dir.
struct write_ctx {
  /// Pointer to the next available staging entry descriptor in the buffer.
  const entry_desc *_Nonnull next_desc;
  /// Pointer to the next available chunk entry in the delta's buffer.
  tek_sc_dd_chunk *_Nonnull next_chunk;
  /// Pointer to the next available transfer operation entry in the delta's
  ///    buffer.
  tek_sc_dd_transfer_op *_Nonnull next_transfer_op;
  /// Pointer to the next available transfer operation group entry in the
  ///    delta's buffer.
  tek_sc_dd_trans_op_grp *_Nonnull next_trans_op_grp;
  /// Pointer to the next available file entry in the delta's buffer.
  tek_sc_dd_file *_Nonnull next_file;
  /// Pointer to the next available directory entry in the delta's buffer.
  tek_sc_dd_dir *_Nonnull next_dir;
  /// Delta object to compute numbers for.
  tek_sc_depot_delta &delta;
  /// Chunk buffer file offset to assign to the next chunk needing it.
  int64_t chunk_buf_off;
  /// Pointer to the patch to use, if provided.
  const tek_sc_depot_patch *_Nullable patch;
  /// Pointer to the buffer for storing pointers to source file's chunks sorted
  ///    by `sha`.
  const tek_sc_dm_chunk *_Nonnull *_Nonnull src_chunk_ptrs;
  /// Pointer to the buffer for storing pointers to target file's chunks sorted
  ///    by `sha`.
  const tek_sc_dm_chunk *_Nonnull *_Nonnull tgt_chunk_ptrs;
  /// Staging transfer operation buffer.
  std::vector<transfer_op_desc> &transfer_ops;
  /// Pointers to transfer operations belonging to the group currently being
  ///    processed.
  std::vector<transfer_op_desc *> group;
};

static constexpr std::int64_t max_reloc_size{0x20000000}; // 512 MiB

//===-- Private functions -------------------------------------------------===//

static constexpr tek_sc_dd_file_flag
operator|(tek_sc_dd_file_flag left, tek_sc_dd_file_flag right) noexcept {
  return static_cast<tek_sc_dd_file_flag>(static_cast<int>(left) |
                                          static_cast<int>(right));
}

static constexpr tek_sc_dd_file_flag &
operator|=(tek_sc_dd_file_flag &left, tek_sc_dd_file_flag right) noexcept {
  return left = left | right;
}

static constexpr tek_sc_dd_dir_flag
operator&(tek_sc_dd_dir_flag left, tek_sc_dd_dir_flag right) noexcept {
  return static_cast<tek_sc_dd_dir_flag>(static_cast<int>(left) &
                                         static_cast<int>(right));
}

static constexpr tek_sc_dd_dir_flag
operator|(tek_sc_dd_dir_flag left, tek_sc_dd_dir_flag right) noexcept {
  return static_cast<tek_sc_dd_dir_flag>(static_cast<int>(left) |
                                         static_cast<int>(right));
}

static constexpr tek_sc_dd_dir_flag &
operator|=(tek_sc_dd_dir_flag &left, tek_sc_dd_dir_flag right) noexcept {
  return left = left | right;
}

/// Discover all transfer operations in a group.
///
/// @param [in, out] desc
///    Pointer to the transfer operation descriptor whose group should be
///    discovered.
[[using gnu: nonnull(1), access(read_only, 1)]]
static void discover_group(transfer_op_desc *_Nonnull desc) {
  for (auto peer : desc->intersects_with) {
    if (!peer->visited) {
      peer->visited = true;
      discover_group(peer);
    }
  }
  for (auto peer : desc->intersected_by) {
    if (!peer->visited) {
      peer->visited = true;
      discover_group(peer);
    }
  }
}

/// Get all transfer operations in a group.
///
/// @param [in, out] group
///    Vector that receives pointers to descriptors that are in the group.
/// @param [in, out] desc
///    Pointer to the transfer operation descriptor whose group should be
///    discovered.
[[using gnu: nonnull(2), access(read_only, 2)]]
static void get_group(std::vector<transfer_op_desc *> &group,
                      transfer_op_desc *_Nonnull desc) {
  group.emplace_back(desc);
  for (auto peer : desc->intersects_with) {
    if (!peer->visited) {
      peer->visited = true;
      get_group(group, peer);
    }
  }
  for (auto peer : desc->intersected_by) {
    if (!peer->visited) {
      peer->visited = true;
      get_group(group, peer);
    }
  }
}

/// Count the numbers of delta entries for specified delisted directory.
///
/// @param [in, out] ctx
///    Count pass context to use.
/// @param [in] dir
///    Source manifest directory entry to process.
/// @param [in, out] delta
///    Delta object to compute numbers for.
static void count_del_dir(count_ctx &ctx, const tek_sc_dm_dir &dir,
                          tek_sc_depot_delta &delta) noexcept {
  delta.num_files += dir.num_files;
  ++delta.num_dirs;
  delta.num_deletions += 1 + dir.num_files;
  for (const auto &subdir :
       std::span{dir.subdirs, static_cast<std::size_t>(dir.num_subdirs)}) {
    count_del_dir(ctx, subdir, delta);
  }
}

/// Count the numbers of delta entries for specified new directory.
///
/// @param [in, out] ctx
///    Count pass context to use.
/// @param [in] dir
///    Target manifest directory entry to process.
/// @param [in, out] delta
///    Delta object to compute numbers for.
/// @return The children flags for the directory.
static tek_sc_dd_dir_flag count_new_dir(count_ctx &ctx,
                                        const tek_sc_dm_dir &dir,
                                        tek_sc_depot_delta &delta) noexcept {
  auto flags{TEK_SC_DD_DIR_FLAG_children_new};
  delta.num_files += dir.num_files;
  ++delta.num_dirs;
  for (const auto &file :
       std::span{dir.files, static_cast<std::size_t>(dir.num_files)}) {
    if (!file.num_chunks) {
      continue;
    }
    flags |= TEK_SC_DD_DIR_FLAG_children_download;
    delta.num_chunks += file.num_chunks;
    delta.download_size = std::ranges::fold_left(
        std::span{file.chunks, static_cast<std::size_t>(file.num_chunks)},
        delta.download_size,
        [](auto acc, const auto &chunk) { return acc + chunk.comp_size; });
  }
  for (const auto &subdir :
       std::span{dir.subdirs, static_cast<std::size_t>(dir.num_subdirs)}) {
    flags |= count_new_dir(ctx, subdir, delta);
  }
  return flags;
}

/// Count the numbers of delta entries and get operation flags for specified
///    directory.
///
/// @param [in, out] ctx
///    Count pass context to use.
/// @param [in] src_dir
///    Source manifest directory entry to process.
/// @param [in] tgt_dir
///    Target manifest directory entry to process.
/// @param [in, out] delta
///    Delta object to compute numbers for.
/// @return Operation flags for the directory.
static tek_sc_dd_dir_flag count_dir(count_ctx &ctx,
                                    const tek_sc_dm_dir &src_dir,
                                    const tek_sc_dm_dir &tgt_dir,
                                    tek_sc_depot_delta &delta) {
  const std::span pchunks{
      ctx.patch ? ctx.patch->chunks : nullptr,
      ctx.patch ? static_cast<std::size_t>(ctx.patch->num_chunks) : 0};
  auto &dir_desc{ctx.next_desc++->dir};
  const std::span src_files{src_dir.files,
                            static_cast<std::size_t>(src_dir.num_files)};
  const std::span tgt_files{tgt_dir.files,
                            static_cast<std::size_t>(tgt_dir.num_files)};
  // Iterate the intersecting range, that may contain matching files
  auto src_file_it{src_files.begin()};
  auto tgt_file_it{tgt_files.begin()};
  while (src_file_it < src_files.end() && tgt_file_it < tgt_files.end()) {
    const auto &src_file{*src_file_it};
    const auto &tgt_file{*tgt_file_it};
    const auto file_diff{cmp_pstr(src_file.name, tgt_file.name)};
    if (file_diff == std::strong_ordering::less) {
      // The file has been delisted and is to be deleted
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
      ++dir_desc.num_files;
      ++delta.num_files;
      ++delta.num_deletions;
      ++src_file_it;
      continue;
    }
    const std::span tgt_chunks{tgt_file.chunks,
                               static_cast<std::size_t>(tgt_file.num_chunks)};
    if (file_diff == std::strong_ordering::greater) {
      // The file has been added to the directory
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new;
      ++dir_desc.num_files;
      ++delta.num_files;
      if (tgt_file.num_chunks) {
        dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_download;
        delta.num_chunks += tgt_file.num_chunks;
        delta.download_size = std::ranges::fold_left(
            tgt_chunks, delta.download_size,
            [](auto acc, const auto &chunk) { return acc + chunk.comp_size; });
      }
      ++tgt_file_it;
      continue;
    }
    // Now we have entries for the same file from both manifests
    if (!tgt_file.num_chunks) {
      // Shortcut for special case of empty target file (including symlinks)
      if (src_file.num_chunks) {
        // The file is to be truncated to zero bytes
        dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_patch;
        ++dir_desc.num_files;
        ++delta.num_files;
      }
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    if (!src_file.num_chunks) {
      // Shortcut for another special case of empty source file. The target file
      //    is guaranteed to be non-empty at this point, so it can be treated
      //    as new
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new |
                        TEK_SC_DD_DIR_FLAG_children_download;
      ++dir_desc.num_files;
      ++delta.num_files;
      delta.num_chunks += tgt_file.num_chunks;
      delta.download_size = std::ranges::fold_left(
          tgt_chunks, delta.download_size,
          [](auto acc, const auto &chunk) { return acc + chunk.comp_size; });
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    auto &file_desc{ctx.next_desc++->file};
    int num_dw_chunks{};
    // Populate chunk pointer buffers and sort them by sha/offset
    const std::span src_chunk_ptrs{
        ctx.src_chunk_ptrs, static_cast<std::size_t>(src_file.num_chunks)};
    std::ranges::transform(std::span{src_file.chunks, static_cast<std::size_t>(
                                                          src_file.num_chunks)},
                           src_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(src_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    const std::span tgt_chunk_ptrs{
        ctx.tgt_chunk_ptrs, static_cast<std::size_t>(tgt_file.num_chunks)};
    std::ranges::transform(tgt_chunks, tgt_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(tgt_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    // Iterate the intersecting range of chunks
    auto tgt_chunk_it{tgt_chunk_ptrs.begin()};
    for (auto src_chunk_it{src_chunk_ptrs.begin()};
         src_chunk_it < src_chunk_ptrs.end() &&
         tgt_chunk_it < tgt_chunk_ptrs.end();) {
      const auto &src_chunk{**src_chunk_it};
      const auto &tgt_chunk{**tgt_chunk_it};
      const auto chunk_diff{src_chunk <=> tgt_chunk};
      if (chunk_diff == std::strong_ordering::less) {
        // The chunk has been removed from the file, might result in file
        //    truncation, which will be checked for later
        ++src_chunk_it;
        continue;
      }
      if (chunk_diff == std::strong_ordering::greater) {
        // The chunk has been added to the file, or patched from another one
        if (src_chunk_it > src_chunk_ptrs.begin() &&
            src_chunk_it[-1]->sha == tgt_chunk.sha) {
          // The chunk is a duplicate of the previous one
          const auto &prev_chunk{*src_chunk_it[-1]};
          ctx.transfer_ops.emplace_back(
              prev_chunk.offset, prev_chunk.offset + prev_chunk.size,
              tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr,
              false, false, std::vector<transfer_op_desc *>{},
              std::vector<transfer_op_desc *>{});
        } else {
          const auto pchunk{std::ranges::lower_bound(
              pchunks, &tgt_chunk, {}, &tek_sc_dp_chunk::target_chunk)};
          if (pchunk == pchunks.end() || pchunk->target_chunk != &tgt_chunk) {
            // The chunk is to be downloaded
            ++num_dw_chunks;
            delta.download_size += tgt_chunk.comp_size;
          } else {
            // The chunk has been produced by patching
            const auto &psrc_chunk{*pchunk->source_chunk};
            delta.transfer_buf_size = std::max(
                delta.transfer_buf_size, psrc_chunk.size + tgt_chunk.size);
            ctx.transfer_ops.emplace_back(
                psrc_chunk.offset, psrc_chunk.offset + psrc_chunk.size,
                tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size,
                std::to_address(pchunk), false, false,
                std::vector<transfer_op_desc *>{},
                std::vector<transfer_op_desc *>{});
          }
        }
        ++tgt_chunk_it;
        continue;
      }
      // Now we have entries for a chunk with the same sha from both manifests
      // Check if there is a source chunk with the same offset as target one, if
      //    there isn't, then it's been relocated
      if (src_chunk.offset != tgt_chunk.offset &&
          !std::ranges::binary_search(src_chunk_ptrs, &tgt_chunk,
                                      cmp_dm_chunk_sha_and_off)) {
        ctx.transfer_ops.emplace_back(
            src_chunk.offset, src_chunk.offset + src_chunk.size,
            tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr, false,
            false, std::vector<transfer_op_desc *>{},
            std::vector<transfer_op_desc *>{});
      }
      ++src_chunk_it;
      ++tgt_chunk_it;
    } // for (intersecting chunks)
    // There is no reason for iterating remaining source chunks, so use the
    //    last one to compare remaining target chunks against
    const auto &last_src_chunk{*src_chunk_ptrs.back()};
    // Iterate remaining target chunks
    for (; tgt_chunk_it < tgt_chunk_ptrs.end(); ++tgt_chunk_it) {
      const auto &tgt_chunk{**tgt_chunk_it};
      if (last_src_chunk.sha == tgt_chunk.sha) {
        if (last_src_chunk.offset == tgt_chunk.offset) {
          continue;
        }
        // The chunk is a duplicate of the last source chunk
        ctx.transfer_ops.emplace_back(
            last_src_chunk.offset, last_src_chunk.offset + last_src_chunk.size,
            tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr, false,
            false, std::vector<transfer_op_desc *>{},
            std::vector<transfer_op_desc *>{});
      } else {
        const auto pchunk{std::ranges::lower_bound(
            pchunks, &tgt_chunk, {}, &tek_sc_dp_chunk::target_chunk)};
        if (pchunk == pchunks.end() || pchunk->target_chunk != &tgt_chunk) {
          // The chunk is to be downloaded
          ++num_dw_chunks;
          delta.download_size += tgt_chunk.comp_size;
        } else {
          // The chunk has been produced by patching
          const auto &psrc_chunk{*pchunk->source_chunk};
          delta.transfer_buf_size = std::max(delta.transfer_buf_size,
                                             psrc_chunk.size + tgt_chunk.size);
          ctx.transfer_ops.emplace_back(
              psrc_chunk.offset, psrc_chunk.offset + psrc_chunk.size,
              tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size,
              std::to_address(pchunk), false, false,
              std::vector<transfer_op_desc *>{},
              std::vector<transfer_op_desc *>{});
        }
      }
    } // for (remaining target chunks)
    // Summarize the data
    if (num_dw_chunks) {
      file_desc.flags |= TEK_SC_DD_FILE_FLAG_download;
      file_desc.num_chunks += num_dw_chunks;
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_download;
      delta.num_chunks += num_dw_chunks;
      if (num_dw_chunks == tgt_file.num_chunks) {
        file_desc.flags |= TEK_SC_DD_FILE_FLAG_new;
        dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new;
      }
    }
    if (tgt_file.size < src_file.size && num_dw_chunks < tgt_file.num_chunks) {
      file_desc.flags |= TEK_SC_DD_FILE_FLAG_truncate;
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_patch;
    }
    if (!ctx.transfer_ops.empty()) {
      file_desc.flags |= TEK_SC_DD_FILE_FLAG_patch;
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_patch;
      // Separate relocations (while also sorting them) from patch chunks and
      //    put patch chunks ahead, so unused relocations can be safely cropped
      //    out after batching
      std::ranges::sort(
          ctx.transfer_ops, [](const auto &left, const auto &right) {
            const bool left_is_patch{left.pchunk == nullptr};
            const bool right_is_patch{right.pchunk == nullptr};
            return std::tie(left_is_patch, left.src_off, left.tgt_off) <
                   std::tie(right_is_patch, right.src_off, right.tgt_off);
          });
      auto batched_it{std::ranges::find(ctx.transfer_ops, nullptr,
                                        &transfer_op_desc::pchunk)};
      if (batched_it != ctx.transfer_ops.end()) {
        // Batch adjacent relocations together
        for (auto it{batched_it + 1}; it < ctx.transfer_ops.end(); ++it) {
          if (batched_it->src_end == it->src_off &&
              batched_it->tgt_end == it->tgt_off) {
            batched_it->src_end = it->src_end;
            batched_it->tgt_end = it->tgt_end;
          } else if (++batched_it != it) {
            // Shift entries to fill the gaps created by batching
            *batched_it = std::move(*it);
          }
        }
        // Crop leftover entries
        ctx.transfer_ops.resize(
            std::distance(ctx.transfer_ops.begin(), batched_it) + 1);
      }
      // Count the actual number of transfer operations, and transfer buffer
      //    size
      for (const auto &desc : ctx.transfer_ops) {
        if (desc.pchunk) {
          ++delta.num_transfer_ops;
        } else {
          const auto size{desc.src_end - desc.src_off};
          const auto [quot, rem]{std::div(size, max_reloc_size)};
          delta.num_transfer_ops += quot + (rem != 0);
          delta.transfer_buf_size =
              std::max(delta.transfer_buf_size,
                       static_cast<int>(std::min(size, max_reloc_size)));
        }
      }
      delta.num_transfer_ops += ctx.transfer_ops.size();
      // Build the intersection graph
      for (auto i{ctx.transfer_ops.begin()}; i < ctx.transfer_ops.end(); ++i) {
        for (auto j{i + 1}; j < ctx.transfer_ops.end(); ++j) {
          if (i->tgt_off < j->src_end && j->src_off < i->tgt_end) {
            i->intersects_with.emplace_back(std::to_address(j));
            j->intersected_by.emplace_back(std::to_address(i));
          }
          if (j->tgt_off < i->src_end && i->src_off < j->tgt_end) {
            j->intersects_with.emplace_back(std::to_address(i));
            i->intersected_by.emplace_back(std::to_address(j));
          }
        }
      }
      // Count the number of transfer operation groups
      for (auto &desc : ctx.transfer_ops) {
        if (!desc.visited) {
          ++file_desc.num_trans_op_grps;
          desc.visited = true;
          discover_group(&desc);
        }
      }
      delta.num_trans_op_grps += file_desc.num_trans_op_grps;
      ctx.transfer_ops.clear();
    } // if (!ctx.transfer_ops.empty())
    if (file_desc.flags) {
      ++dir_desc.num_files;
      ++delta.num_files;
    }
    ++src_file_it;
    ++tgt_file_it;
  } // while (intersecting files)
  // Account remaining source files
  const auto num_rem_src_files{std::distance(src_file_it, src_files.end())};
  if (num_rem_src_files) {
    dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
    dir_desc.num_files += num_rem_src_files;
    delta.num_files += num_rem_src_files;
    delta.num_deletions += num_rem_src_files;
  }
  // Iterate remaining target files
  const auto num_rem_tgt_files{std::distance(tgt_file_it, tgt_files.end())};
  if (num_rem_tgt_files) {
    dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dir_desc.num_files += num_rem_tgt_files;
    delta.num_files += num_rem_tgt_files;
    for (const auto &tgt_file :
         std::ranges::subrange{tgt_file_it, tgt_files.end()}) {
      if (tgt_file.num_chunks) {
        dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_download;
        delta.num_chunks += tgt_file.num_chunks;
        delta.download_size = std::ranges::fold_left(
            std::span{tgt_file.chunks,
                      static_cast<std::size_t>(tgt_file.num_chunks)},
            delta.download_size,
            [](auto acc, const auto &chunk) { return acc + chunk.comp_size; });
      }
    }
  }
  const std::span src_subdirs{src_dir.subdirs,
                              static_cast<std::size_t>(src_dir.num_subdirs)};
  const std::span tgt_subdirs{tgt_dir.subdirs,
                              static_cast<std::size_t>(tgt_dir.num_subdirs)};
  // Iterate the intersecting range, that may contain matching subdirectories
  auto src_subdir_it{src_subdirs.begin()};
  auto tgt_subdir_it{tgt_subdirs.begin()};
  while (src_subdir_it < src_subdirs.end() &&
         tgt_subdir_it < tgt_subdirs.end()) {
    const auto &src_subdir{*src_subdir_it};
    const auto &tgt_subdir{*tgt_subdir_it};
    const auto subdir_diff{cmp_pstr(src_subdir.name, tgt_subdir.name)};
    if (subdir_diff == std::strong_ordering::less) {
      // The subdirectory has been delisted and is to be deleted
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
      ++dir_desc.num_subdirs;
      count_del_dir(ctx, src_subdir, delta);
      ++src_subdir_it;
      continue;
    }
    if (subdir_diff == std::strong_ordering::greater) {
      // The subdirectory has been added to the directory
      dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new;
      ++dir_desc.num_subdirs;
      dir_desc.flags |= count_new_dir(ctx, tgt_subdir, delta);
      ++tgt_subdir_it;
      continue;
    }
    const auto next_desc_after_subdir{ctx.next_desc + 1};
    const auto subdir_flags{count_dir(ctx, src_subdir, tgt_subdir, delta)};
    if (subdir_flags) {
      dir_desc.flags |= subdir_flags;
      ++dir_desc.num_subdirs;
      ++delta.num_dirs;
    } else {
      // Keep the subidrectory's descriptor so write pass can check it and
      //    ignore its children, clear all the following descriptors as they
      //    are unused and may interfere with further iterations
      std::ranges::fill(next_desc_after_subdir, ctx.next_desc, entry_desc{});
      ctx.next_desc = next_desc_after_subdir;
    }
    ++src_subdir_it;
    ++tgt_subdir_it;
  } // while (intersecting subdirs)
  // Iterate remaining source subdirectories
  const auto num_rem_src_subdirs{
      std::distance(src_subdir_it, src_subdirs.end())};
  if (num_rem_src_subdirs) {
    dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
    dir_desc.num_subdirs += num_rem_src_subdirs;
    for (const auto &src_subdir :
         std::ranges::subrange{src_subdir_it, src_subdirs.end()}) {
      count_del_dir(ctx, src_subdir, delta);
    }
  }
  // Iterate remaining target subdirectories
  const auto num_rem_tgt_subdirs{
      std::distance(tgt_subdir_it, tgt_subdirs.end())};
  if (num_rem_tgt_subdirs) {
    dir_desc.flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dir_desc.num_subdirs += num_rem_tgt_subdirs;
    for (const auto &tgt_subdir :
         std::ranges::subrange{tgt_subdir_it, tgt_subdirs.end()}) {
      dir_desc.flags |= count_new_dir(ctx, tgt_subdir, delta);
    }
  }
  return dir_desc.flags;
}

/// Initialize delta file entry fields that do not depend on delta computation.
///
/// @param file
///    Manifest file entry to bind to.
/// @param [out] dd_file
///    Delta file entry to initialize.
static constexpr void init_dd_file(const tek_sc_dm_file &file,
                                   tek_sc_dd_file &dd_file) noexcept {
  dd_file.file = &file;
  dd_file.status = TEK_SC_JOB_ENTRY_STATUS_pending;
  dd_file.handle = TSCI_OS_INVALID_HANDLE;
}

/// Initialize delta directory entry fields that do not depend on delta
///    computation.
///
/// @param dir
///    Manifest directory entry to bind to.
/// @param [out] dd_dir
///    Delta directory entry to initialize.
static constexpr void init_dd_dir(const tek_sc_dm_dir &dir,
                                  tek_sc_dd_dir &dd_dir) noexcept {
  dd_dir.dir = &dir;
  dd_dir.status = TEK_SC_JOB_ENTRY_STATUS_pending;
  dd_dir.handle = TSCI_OS_INVALID_HANDLE;
  dd_dir.cache_handle = TSCI_OS_INVALID_HANDLE;
}

/// Write delta entries for specified delisted directory.
///
/// @param [in, out] ctx
///    Write pass context to use.
/// @param [in] dir
///    Source manifest directory entry to process.
/// @param parent
///    Parent directory entry.
/// @param [out] dd_dir
///    Delta directory entry to write.
static void write_del_dir(write_ctx &ctx, const tek_sc_dm_dir &dir,
                          tek_sc_dd_dir &parent,
                          tek_sc_dd_dir &dd_dir) noexcept {
  init_dd_dir(dir, dd_dir);
  dd_dir.parent = &parent;
  dd_dir.flags = TEK_SC_DD_DIR_FLAG_delete;
  if (dir.num_files) {
    dd_dir.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
    dd_dir.files = ctx.next_file;
    ctx.next_file += dir.num_files;
  } else {
    dd_dir.files = nullptr;
  }
  if (dir.num_subdirs) {
    dd_dir.flags |= TEK_SC_DD_DIR_FLAG_children_delete;
    dd_dir.subdirs = ctx.next_dir;
    ctx.next_dir += dir.num_subdirs;
  } else {
    dd_dir.subdirs = nullptr;
  }
  dd_dir.num_files = dir.num_files;
  dd_dir.num_subdirs = dir.num_subdirs;
  // Iterate files
  for (auto &&[file, dd_file] : std::views::zip(
           std::span{dir.files, static_cast<std::size_t>(dir.num_files)},
           std::span{dd_dir.files, static_cast<std::size_t>(dir.num_files)})) {
    init_dd_file(file, dd_file);
    dd_file.parent = &dd_dir;
    dd_file.flags = TEK_SC_DD_FILE_FLAG_delete;
    dd_file.chunks = nullptr;
    dd_file.trans_op_grps = nullptr;
    dd_file.num_chunks = 0;
    dd_file.num_trans_op_grps = 0;
  }
  // Iterate subdirectories
  for (auto &&[subdir, dd_subdir] : std::views::zip(
           std::span{dir.subdirs, static_cast<std::size_t>(dir.num_subdirs)},
           std::span{dd_dir.subdirs,
                     static_cast<std::size_t>(dir.num_subdirs)})) {
    write_del_dir(ctx, subdir, dd_dir, dd_subdir);
  }
}

/// Write delta entries for specified new directory.
///
/// @param [in, out] ctx
///    Write pass context to use.
/// @param [in] dir
///    Target manifest directory entry to process.
/// @param parent
///    Parent directory entry.
/// @param [out] dd_dir
///    Delta directory entry to write.
/// @return @ref TEK_SC_DD_DIR_FLAG_children_download if there are any chunks
///    present among directory's children, @ref TEK_SC_DD_DIR_FLAG_none
///    otherwise.
static tek_sc_dd_dir_flag write_new_dir(write_ctx &ctx,
                                        const tek_sc_dm_dir &dir,
                                        tek_sc_dd_dir &parent,
                                        tek_sc_dd_dir &dd_dir) noexcept {
  init_dd_dir(dir, dd_dir);
  dd_dir.parent = &parent;
  dd_dir.flags = TEK_SC_DD_DIR_FLAG_new;
  if (dir.num_files) {
    dd_dir.flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dd_dir.files = ctx.next_file;
    ctx.next_file += dir.num_files;
  } else {
    dd_dir.files = nullptr;
  }
  if (dir.num_subdirs) {
    dd_dir.flags |= TEK_SC_DD_DIR_FLAG_children_new;
    dd_dir.subdirs = ctx.next_dir;
    ctx.next_dir += dir.num_subdirs;
  } else {
    dd_dir.subdirs = nullptr;
  }
  dd_dir.num_files = dir.num_files;
  dd_dir.num_subdirs = dir.num_subdirs;
  // Iterate files
  for (auto &&[file, dd_file] : std::views::zip(
           std::span{dir.files, static_cast<std::size_t>(dir.num_files)},
           std::span{dd_dir.files, static_cast<std::size_t>(dir.num_files)})) {
    init_dd_file(file, dd_file);
    dd_file.parent = &dd_dir;
    dd_file.flags = TEK_SC_DD_FILE_FLAG_new;
    if (file.num_chunks) {
      dd_file.flags |= TEK_SC_DD_FILE_FLAG_download;
      dd_file.chunks = ctx.next_chunk;
      dd_dir.flags |= TEK_SC_DD_DIR_FLAG_children_download;
      ctx.next_chunk += file.num_chunks;
    } else {
      dd_file.chunks = nullptr;
    }
    dd_file.trans_op_grps = nullptr;
    dd_file.num_chunks = file.num_chunks;
    dd_file.num_trans_op_grps = 0;
    std::ranges::transform(
        std::span{file.chunks, static_cast<std::size_t>(file.num_chunks)},
        dd_file.chunks, [&dd_file](const auto &chunk) {
          return tek_sc_dd_chunk{&chunk, dd_file,
                                 TEK_SC_JOB_ENTRY_STATUS_pending, -1};
        });
  }
  // Iterate subdirectories
  for (auto &&[subdir, dd_subdir] : std::views::zip(
           std::span{dir.subdirs, static_cast<std::size_t>(dir.num_subdirs)},
           std::span{dd_dir.subdirs,
                     static_cast<std::size_t>(dir.num_subdirs)})) {
    dd_dir.flags |= write_new_dir(ctx, subdir, dd_dir, dd_subdir);
  }
  return dd_dir.flags & TEK_SC_DD_DIR_FLAG_children_download;
}

/// Write delta entries for specified directory.
///
/// @param [in, out] ctx
///    Write pass context to use.
/// @param [in] src_dir
///    Source manifest directory entry to process.
/// @param [in] tgt_dir
///    Target manifest directory entry to process.
/// @param parent
///    Pointer to the parent directory entry, or `nullptr`.
/// @param [out] dd_dir
///    Delta directory entry to write.
[[gnu::access(none, 4)]]
static void write_dir(write_ctx &ctx, const tek_sc_dm_dir &src_dir,
                      const tek_sc_dm_dir &tgt_dir,
                      tek_sc_dd_dir *_Nullable parent,
                      tek_sc_dd_dir &dd_dir) noexcept {
  const std::span pchunks{
      ctx.patch ? ctx.patch->chunks : nullptr,
      ctx.patch ? static_cast<std::size_t>(ctx.patch->num_chunks) : 0};
  const auto &dir_desc{ctx.next_desc++->dir};
  init_dd_dir(tgt_dir, dd_dir);
  dd_dir.parent = parent;
  dd_dir.flags = dir_desc.flags;
  dd_dir.files = dir_desc.num_files ? ctx.next_file : nullptr;
  if (dir_desc.num_subdirs) {
    dd_dir.subdirs = ctx.next_dir;
    ctx.next_dir += dir_desc.num_subdirs;
  } else {
    dd_dir.subdirs = nullptr;
  }
  dd_dir.num_files = dir_desc.num_files;
  dd_dir.num_subdirs = dir_desc.num_subdirs;
  const std::span src_files{src_dir.files,
                            static_cast<std::size_t>(src_dir.num_files)};
  const std::span tgt_files{tgt_dir.files,
                            static_cast<std::size_t>(tgt_dir.num_files)};
  // Iterate the intersecting range, that may contain matching files
  auto src_file_it{src_files.begin()};
  auto tgt_file_it{tgt_files.begin()};
  while (src_file_it < src_files.end() && tgt_file_it < tgt_files.end()) {
    const auto &src_file{*src_file_it};
    const auto &tgt_file{*tgt_file_it};
    const auto file_diff{cmp_pstr(src_file.name, tgt_file.name)};
    if (file_diff == std::strong_ordering::less) {
      // The file has been delisted and is to be deleted
      auto &dd_file{*ctx.next_file++};
      init_dd_file(src_file, dd_file);
      dd_file.parent = &dd_dir;
      dd_file.flags = TEK_SC_DD_FILE_FLAG_delete;
      dd_file.chunks = nullptr;
      dd_file.trans_op_grps = nullptr;
      dd_file.num_chunks = 0;
      dd_file.num_trans_op_grps = 0;
      ++src_file_it;
      continue;
    }
    const std::span tgt_chunks{tgt_file.chunks,
                               static_cast<std::size_t>(tgt_file.num_chunks)};
    if (file_diff == std::strong_ordering::greater) {
      // The file has been added to the directory
      auto &dd_file{*ctx.next_file++};
      init_dd_file(tgt_file, dd_file);
      dd_file.parent = &dd_dir;
      dd_file.flags = TEK_SC_DD_FILE_FLAG_new;
      dd_file.chunks = tgt_file.num_chunks ? ctx.next_chunk : nullptr;
      dd_file.trans_op_grps = nullptr;
      dd_file.num_chunks = tgt_file.num_chunks;
      dd_file.num_trans_op_grps = 0;
      if (tgt_file.num_chunks) {
        dd_file.flags |= TEK_SC_DD_FILE_FLAG_download;
        ctx.next_chunk =
            std::ranges::transform(tgt_chunks, ctx.next_chunk,
                                   [&dd_file](const auto &chunk) {
                                     return tek_sc_dd_chunk{
                                         &chunk, dd_file,
                                         TEK_SC_JOB_ENTRY_STATUS_pending, -1};
                                   })
                .out;
      }
      ++tgt_file_it;
      continue;
    }
    // Now we have entries for the same file from both manifests
    if (!tgt_file.num_chunks) {
      // Shortcut for special case of empty target file (including symlinks)
      if (src_file.num_chunks) {
        // The file is to be truncated to zero bytes
        auto &dd_file{*ctx.next_file++};
        init_dd_file(tgt_file, dd_file);
        dd_file.parent = &dd_dir;
        dd_file.flags = TEK_SC_DD_FILE_FLAG_truncate;
        dd_file.chunks = nullptr;
        dd_file.trans_op_grps = nullptr;
        dd_file.num_chunks = 0;
        dd_file.num_trans_op_grps = 0;
      }
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    if (!src_file.num_chunks) {
      // Shortcut for another special case of empty source file. The target file
      //    is guaranteed to be non-empty at this point, so it can be treated
      //    as new
      auto &dd_file{*ctx.next_file++};
      init_dd_file(tgt_file, dd_file);
      dd_file.parent = &dd_dir;
      dd_file.flags = TEK_SC_DD_FILE_FLAG_new | TEK_SC_DD_FILE_FLAG_download;
      dd_file.chunks = ctx.next_chunk;
      dd_file.trans_op_grps = nullptr;
      dd_file.num_chunks = tgt_file.num_chunks;
      dd_file.num_trans_op_grps = 0;
      ctx.next_chunk =
          std::ranges::transform(tgt_chunks, ctx.next_chunk,
                                 [&dd_file](const auto &chunk) {
                                   return tek_sc_dd_chunk{
                                       &chunk, dd_file,
                                       TEK_SC_JOB_ENTRY_STATUS_pending, -1};
                                 })
              .out;
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    const auto &file_desc{ctx.next_desc++->file};
    if (!file_desc.flags) {
      // Nothing interesting about this file
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    auto &dd_file{*ctx.next_file++};
    init_dd_file(tgt_file, dd_file);
    dd_file.parent = &dd_dir;
    dd_file.flags = file_desc.flags;
    dd_file.chunks = file_desc.num_chunks ? ctx.next_chunk : nullptr;
    dd_file.trans_op_grps =
        file_desc.num_trans_op_grps ? ctx.next_trans_op_grp : nullptr;
    dd_file.num_chunks = file_desc.num_chunks;
    dd_file.num_trans_op_grps = file_desc.num_trans_op_grps;
    if (file_desc.flags & TEK_SC_DD_FILE_FLAG_new) {
      // No need to do complex computations when all you need is simply
      //    downloading all chunks
      ctx.next_chunk =
          std::ranges::transform(tgt_chunks, ctx.next_chunk,
                                 [&dd_file](const auto &chunk) {
                                   return tek_sc_dd_chunk{
                                       &chunk, dd_file,
                                       TEK_SC_JOB_ENTRY_STATUS_pending, -1};
                                 })
              .out;
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    const auto size_diff{tgt_file.size - src_file.size};
    if (size_diff > 0) {
      ctx.delta.total_file_growth += size_diff;
    }
    // Populate chunk pointer buffers and sort them by sha/offset
    const std::span src_chunk_ptrs{
        ctx.src_chunk_ptrs, static_cast<std::size_t>(src_file.num_chunks)};
    std::ranges::transform(std::span{src_file.chunks, static_cast<std::size_t>(
                                                          src_file.num_chunks)},
                           src_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(src_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    const std::span tgt_chunk_ptrs{
        ctx.tgt_chunk_ptrs, static_cast<std::size_t>(tgt_file.num_chunks)};
    std::ranges::transform(tgt_chunks, tgt_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(tgt_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    // Iterate the intersecting range of chunks
    auto tgt_chunk_it{tgt_chunk_ptrs.begin()};
    for (auto src_chunk_it{src_chunk_ptrs.begin()};
         src_chunk_it < src_chunk_ptrs.end() &&
         tgt_chunk_it < tgt_chunk_ptrs.end();) {
      const auto &src_chunk{**src_chunk_it};
      const auto &tgt_chunk{**tgt_chunk_it};
      const auto chunk_diff{src_chunk <=> tgt_chunk};
      if (chunk_diff == std::strong_ordering::less) {
        // The chunk has been removed from the file, might result in file
        //    truncation, which will be checked for later
        ++src_chunk_it;
        continue;
      }
      if (chunk_diff == std::strong_ordering::greater) {
        // The chunk has been added to the file, or patched from another one
        if (src_chunk_it > src_chunk_ptrs.begin() &&
            src_chunk_it[-1]->sha == tgt_chunk.sha) {
          // The chunk is a duplicate of the previous one
          const auto &prev_chunk{*src_chunk_it[-1]};
          ctx.transfer_ops.emplace_back(
              prev_chunk.offset, prev_chunk.offset + prev_chunk.size,
              tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr,
              false, false, std::vector<transfer_op_desc *>{},
              std::vector<transfer_op_desc *>{});
        } else {
          const auto pchunk{std::ranges::lower_bound(
              pchunks, &tgt_chunk, {}, &tek_sc_dp_chunk::target_chunk)};
          if (pchunk == pchunks.end() || pchunk->target_chunk != &tgt_chunk) {
            // The chunk is to be downloaded
            auto &dd_chunk{*ctx.next_chunk++};
            dd_chunk.chunk = &tgt_chunk;
            dd_chunk.parent = &dd_file;
            dd_chunk.status = TEK_SC_JOB_ENTRY_STATUS_pending;
          } else {
            // The chunk has been produced by patching
            const auto &psrc_chunk{*pchunk->source_chunk};
            ctx.transfer_ops.emplace_back(
                psrc_chunk.offset, psrc_chunk.offset + psrc_chunk.size,
                tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size,
                std::to_address(pchunk), false, false,
                std::vector<transfer_op_desc *>{},
                std::vector<transfer_op_desc *>{});
          }
        }
        ++tgt_chunk_it;
        continue;
      }
      // Now we have entries for a chunk with the same sha from both manifests
      // Check if there is a source chunk with the same offset as target one, if
      //    there isn't, then it's been relocated
      if (src_chunk.offset != tgt_chunk.offset &&
          !std::ranges::binary_search(src_chunk_ptrs, &tgt_chunk,
                                      cmp_dm_chunk_sha_and_off)) {
        ctx.transfer_ops.emplace_back(
            src_chunk.offset, src_chunk.offset + src_chunk.size,
            tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr, false,
            false, std::vector<transfer_op_desc *>{},
            std::vector<transfer_op_desc *>{});
      }
      ++src_chunk_it;
      ++tgt_chunk_it;
    } // for (intersecting chunks)
    // There is no reason for iterating remaining source chunks, so use the
    //    last one to compare remaining target chunks against
    const auto &last_src_chunk{*src_chunk_ptrs.back()};
    // Iterate remaining target chunks
    for (; tgt_chunk_it < tgt_chunk_ptrs.end(); ++tgt_chunk_it) {
      const auto &tgt_chunk{**tgt_chunk_it};
      if (last_src_chunk.sha == tgt_chunk.sha) {
        if (last_src_chunk.offset == tgt_chunk.offset) {
          continue;
        }
        // The chunk is a duplicate of the last source chunk
        ctx.transfer_ops.emplace_back(
            last_src_chunk.offset, last_src_chunk.offset + last_src_chunk.size,
            tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size, nullptr, false,
            false, std::vector<transfer_op_desc *>{},
            std::vector<transfer_op_desc *>{});
      } else {
        const auto pchunk{std::ranges::lower_bound(
            pchunks, &tgt_chunk, {}, &tek_sc_dp_chunk::target_chunk)};
        if (pchunk == pchunks.end() || pchunk->target_chunk != &tgt_chunk) {
          // The chunk is to be downloaded
          auto &dd_chunk{*ctx.next_chunk++};
          dd_chunk.chunk = &tgt_chunk;
          dd_chunk.parent = &dd_file;
          dd_chunk.status = TEK_SC_JOB_ENTRY_STATUS_pending;
        } else {
          // The chunk has been produced by patching
          const auto &psrc_chunk{*pchunk->source_chunk};
          ctx.transfer_ops.emplace_back(
              psrc_chunk.offset, psrc_chunk.offset + psrc_chunk.size,
              tgt_chunk.offset, tgt_chunk.offset + tgt_chunk.size,
              std::to_address(pchunk), false, false,
              std::vector<transfer_op_desc *>{},
              std::vector<transfer_op_desc *>{});
        }
      }
    } // for (remaining target chunks)
    const std::span dd_chunks{dd_file.chunks,
                              static_cast<std::size_t>(dd_file.num_chunks)};
    // Sort delta chunk entries by offset
    std::ranges::sort(dd_chunks, {},
                      [](const auto &chunk) { return chunk.chunk->offset; });
    // Assign chunk buffer offsets to chunk entries
    ctx.chunk_buf_off = std::ranges::fold_left(dd_chunks, ctx.chunk_buf_off,
                                               [](auto off, auto &chunk) {
                                                 chunk.chunk_buf_offset = off;
                                                 return off + chunk.chunk->size;
                                               });
    // Process transfer operations
    if (!ctx.transfer_ops.empty()) {
      // Separate relocations (while also sorting them) from patch chunks and
      //    put patch chunks ahead, so unused relocations can be safely cropped
      //    out after batching
      std::ranges::sort(
          ctx.transfer_ops, [](const auto &left, const auto &right) {
            const bool left_is_patch{left.pchunk == nullptr};
            const bool right_is_patch{right.pchunk == nullptr};
            return std::tie(left_is_patch, left.src_off, left.tgt_off) <
                   std::tie(right_is_patch, right.src_off, right.tgt_off);
          });
      auto batched_it{std::ranges::find(ctx.transfer_ops, nullptr,
                                        &transfer_op_desc::pchunk)};
      if (batched_it != ctx.transfer_ops.end()) {
        // Batch adjacent relocations together
        for (auto it{batched_it + 1}; it < ctx.transfer_ops.end(); ++it) {
          if (batched_it->src_end == it->src_off &&
              batched_it->tgt_end == it->tgt_off) {
            batched_it->src_end = it->src_end;
            batched_it->tgt_end = it->tgt_end;
          } else if (++batched_it != it) {
            // Shift entries to fill the gaps created by batching
            *batched_it = std::move(*it);
          }
        }
        // Crop leftover entries
        ctx.transfer_ops.resize(
            std::distance(ctx.transfer_ops.begin(), batched_it) + 1);
      }
      // Attempt to optimize the order of operations so there are as few
      //    overlaps of target regions with source regions of consequent
      //    operations as possible. This is where all the disk space usage
      //    optimization happens.
      // First, build the intersection graph
      for (auto i{ctx.transfer_ops.begin()}; i < ctx.transfer_ops.end(); ++i) {
        for (auto j{i + 1}; j < ctx.transfer_ops.end(); ++j) {
          if (i->tgt_off < j->src_end && j->src_off < i->tgt_end) {
            i->intersects_with.emplace_back(std::to_address(j));
            j->intersected_by.emplace_back(std::to_address(i));
          }
          if (j->tgt_off < i->src_end && i->src_off < j->tgt_end) {
            j->intersects_with.emplace_back(std::to_address(i));
            i->intersected_by.emplace_back(std::to_address(j));
          }
        }
      }
      // Now, find distinct groups that don't intersect each other, and process
      //    them. Each iteration of the loop will correspond to its own group.
      for (auto &desc : ctx.transfer_ops) {
        if (desc.visited) {
          continue;
        }
        desc.visited = true;
        get_group(ctx.group, &desc);
        auto &grp{*ctx.next_trans_op_grp++};
        grp = {.status = TEK_SC_JOB_ENTRY_STATUS_pending,
               .num_transfer_ops = 0,
               .transfer_ops = ctx.next_transfer_op};
        // Group is discovered, now start reaping entries from it
        int64_t transfer_buf_off{};
        auto write_transfer_op{
            [&ctx, &grp, &transfer_buf_off](auto &&self,
                                            transfer_op_desc &desc) -> bool {
              if (desc.pchunk) {
                // Patch chunk
                ++grp.num_transfer_ops;
                auto &dd_transfer_op{*ctx.next_transfer_op++};
                dd_transfer_op.status = TEK_SC_JOB_ENTRY_STATUS_pending;
                dd_transfer_op.type = TEK_SC_DD_TRANSFER_OP_TYPE_patch;
                dd_transfer_op.data.patch_chunk = desc.pchunk;
                const int src_size{desc.pchunk->source_chunk->size};
                const int tgt_size{desc.pchunk->target_chunk->size};
                ctx.delta.patching_size += src_size + tgt_size;
                if (desc.intersects_with.empty()) {
                  dd_transfer_op.transfer_buf_offset = -1;
                } else {
                  dd_transfer_op.transfer_buf_offset = transfer_buf_off;
                  const int min_size{std::min(src_size, tgt_size)};
                  transfer_buf_off += min_size;
                  ctx.delta.patching_size += min_size * 2;
                }
              } else {
                // Relocation
                // Write an entry for every 0.5 GiB of data
                const bool forward{desc.tgt_off > desc.src_off};
                // The order of 0.5 GiB sub-entries depends on the direction of
                //    relocation, this is done in order to avoid them
                //    overlapping each other
                for (auto src{forward ? desc.src_end : desc.src_off},
                     tgt{forward ? desc.tgt_end : desc.tgt_off};
                     forward ? (src > desc.src_off) : (src < desc.src_end);) {
                  ++grp.num_transfer_ops;
                  const auto size{std::min(forward ? (src - desc.src_off)
                                                   : (desc.src_end - src),
                                           max_reloc_size)};
                  if (forward) {
                    src -= size;
                    tgt -= size;
                  }
                  auto &dd_transfer_op{*ctx.next_transfer_op++};
                  dd_transfer_op.status = TEK_SC_JOB_ENTRY_STATUS_pending;
                  dd_transfer_op.type = TEK_SC_DD_TRANSFER_OP_TYPE_reloc;
                  dd_transfer_op.data.relocation.source_offset = src;
                  dd_transfer_op.data.relocation.target_offset = tgt;
                  dd_transfer_op.data.relocation.size = size;
                  ctx.delta.patching_size += size * 2;
                  if (desc.intersects_with.empty()) {
                    dd_transfer_op.transfer_buf_offset = -1;
                  } else {
                    dd_transfer_op.transfer_buf_offset = transfer_buf_off;
                    transfer_buf_off += size;
                    ctx.delta.patching_size += size * 2;
                  }
                  if (!forward) {
                    src += size;
                    tgt += size;
                  }
                }
              } // if (transfer_op.pchunk) else
              desc.written = true;
              // Update the graph and write peers that become dead ends
              for (auto peer : desc.intersects_with) {
                std::erase(peer->intersected_by, &desc);
              }
              desc.intersects_with = {};
              for (auto peer : desc.intersected_by) {
                std::erase(peer->intersects_with, &desc);
              }
              bool res{};
              for (auto peer : desc.intersected_by) {
                if (!peer->written && peer->intersects_with.empty()) {
                  res = true;
                  self(self, *peer);
                }
              }
              desc.intersected_by = {};
              return res;
            }}; // auto &&write_transfer_op
        // Start with the dead end nodes that don't intersect anything
        for (auto desc : ctx.group) {
          if (desc->written) {
            continue;
          }
          if (desc->intersects_with.empty()) {
            write_transfer_op(write_transfer_op, *desc);
          }
        }
        // Remove written nodes from the group
        std::erase_if(ctx.group, [](auto desc) { return desc->written; });
        while (!ctx.group.empty()) {
          // Find the node that intersects with the smallest number of other
          //    nodes, and reap those other nodes
          for (auto desc :
               (*std::ranges::min_element(ctx.group, {}, [](auto desc) {
                 return desc->intersects_with.size();
               }))->intersects_with) {
            if (write_transfer_op(write_transfer_op, *desc)) {
              // If more than one node ended up being reaped, re-evaluation is
              //    needed because:
              //  1) loop iterator may become invalid if the min_element node
              //    was affected
              //  2) Current min_element node may not intersect the smallest
              //    number of nodes anymore
              break;
            }
          }
          // Remove written nodes from the group
          std::erase_if(ctx.group, [](auto desc) { return desc->written; });
        }
      } // for (auto &desc : ctx.transfer_ops)
      ctx.transfer_ops.clear();
    } // if (!ctx.transfer_ops.empty())
    ++src_file_it;
    ++tgt_file_it;
  } // while (intersecting files)
  // Iterate remaining source files
  for (const auto &src_file :
       std::ranges::subrange{src_file_it, src_files.end()}) {
    auto &dd_file{*ctx.next_file++};
    init_dd_file(src_file, dd_file);
    dd_file.parent = &dd_dir;
    dd_file.flags = TEK_SC_DD_FILE_FLAG_delete;
    dd_file.chunks = nullptr;
    dd_file.trans_op_grps = nullptr;
    dd_file.num_chunks = 0;
    dd_file.num_trans_op_grps = 0;
  }
  // Iterate remaining target files
  for (const auto &tgt_file :
       std::ranges::subrange{tgt_file_it, tgt_files.end()}) {
    auto &dd_file = *ctx.next_file++;
    init_dd_file(tgt_file, dd_file);
    dd_file.parent = &dd_dir;
    dd_file.flags = TEK_SC_DD_FILE_FLAG_new;
    dd_file.chunks = tgt_file.num_chunks ? ctx.next_chunk : nullptr;
    dd_file.trans_op_grps = nullptr;
    dd_file.num_chunks = tgt_file.num_chunks;
    dd_file.num_trans_op_grps = 0;
    if (tgt_file.num_chunks) {
      dd_file.flags |= TEK_SC_DD_FILE_FLAG_download;
      ctx.next_chunk =
          std::ranges::transform(
              std::span{tgt_file.chunks,
                        static_cast<std::size_t>(tgt_file.num_chunks)},
              ctx.next_chunk,
              [&dd_file](const auto &chunk) {
                return tek_sc_dd_chunk{&chunk, dd_file,
                                       TEK_SC_JOB_ENTRY_STATUS_pending, -1};
              })
              .out;
    }
  }
  const std::span src_subdirs{src_dir.subdirs,
                              static_cast<std::size_t>(src_dir.num_subdirs)};
  const std::span tgt_subdirs{tgt_dir.subdirs,
                              static_cast<std::size_t>(tgt_dir.num_subdirs)};
  // Iterate the intersecting range, that may contain matching subdirectories
  auto next_dd_subdir{dd_dir.subdirs};
  auto src_subdir_it{src_subdirs.begin()};
  auto tgt_subdir_it{tgt_subdirs.begin()};
  while (src_subdir_it < src_subdirs.end() &&
         tgt_subdir_it < tgt_subdirs.end()) {
    const auto &src_subdir{*src_subdir_it};
    const auto &tgt_subdir{*tgt_subdir_it};
    const auto subdir_diff{cmp_pstr(src_subdir.name, tgt_subdir.name)};
    if (subdir_diff == std::strong_ordering::less) {
      // The subdirectory has been delisted and is to be deleted
      write_del_dir(ctx, src_subdir, dd_dir, *next_dd_subdir++);
      ++src_subdir_it;
      continue;
    }
    if (subdir_diff == std::strong_ordering::greater) {
      // The subdirectory has been added to the directory
      write_new_dir(ctx, tgt_subdir, dd_dir, *next_dd_subdir++);
      ++tgt_subdir_it;
      continue;
    }
    if (ctx.next_desc->dir.flags) {
      write_dir(ctx, src_subdir, tgt_subdir, &dd_dir, *next_dd_subdir++);
    } else {
      // Skip the subdirectory, there's no delta for it
      ++ctx.next_desc;
    }
    ++src_subdir_it;
    ++tgt_subdir_it;
  } // while (intersecting subdirs)
  // Iterate remaining source subdirectories
  for (const auto &src_subdir :
       std::ranges::subrange{src_subdir_it, src_subdirs.end()}) {
    write_del_dir(ctx, src_subdir, dd_dir, *next_dd_subdir);
    ++next_dd_subdir;
  }
  // Iterate remaining target subdirectories
  for (const auto &tgt_subdir :
       std::ranges::subrange{tgt_subdir_it, tgt_subdirs.end()}) {
    write_new_dir(ctx, tgt_subdir, dd_dir, *next_dd_subdir);
    ++next_dd_subdir;
  }
}

} // namespace

} // namespace tek::steamclient::content

//===-- Public function ---------------------------------------------------===//

using namespace tek::steamclient::content;

extern "C" tek_sc_depot_delta
tek_sc_dd_compute(const tek_sc_depot_manifest *source_manifest,
                  const tek_sc_depot_manifest *target_manifest,
                  const tek_sc_depot_patch *patch) {
  tek_sc_depot_delta res{.source_manifest = source_manifest,
                         .target_manifest = target_manifest,
                         .patch = patch,
                         .chunks = nullptr,
                         .transfer_ops = nullptr,
                         .trans_op_grps = nullptr,
                         .files = nullptr,
                         .dirs = nullptr,
                         .num_chunks = 0,
                         .num_transfer_ops = 0,
                         .num_trans_op_grps = 0,
                         .num_files = 0,
                         .num_dirs = 1,
                         .stage = TEK_SC_DD_STAGE_downloading,
                         .num_deletions = 0,
                         .transfer_buf_size = 0,
                         .download_size = 0,
                         .patching_size = 0,
                         .total_file_growth = 0};
  // Allocate staging entry buffer
  const auto descs{std::make_unique<entry_desc[]>(
      std::min(source_manifest->num_files, target_manifest->num_files) +
      std::min(source_manifest->num_dirs, target_manifest->num_dirs))};
  // Allocate chunk pointer buffers
  const auto src_chunk_ptrs{
      std::make_unique_for_overwrite<const tek_sc_dm_chunk *_Nonnull[]>(
          std::ranges::max_element(
              std::span{source_manifest->files,
                        static_cast<std::size_t>(source_manifest->num_files)},
              {}, &tek_sc_dm_file::num_chunks)
              ->num_chunks)};
  const auto tgt_chunk_ptrs{
      std::make_unique_for_overwrite<const tek_sc_dm_chunk *_Nonnull[]>(
          target_manifest->num_files
              ? std::ranges::max_element(
                    std::span{
                        target_manifest->files,
                        static_cast<std::size_t>(target_manifest->num_files)},
                    {}, &tek_sc_dm_file::num_chunks)
                    ->num_chunks
              : 0)};
  std::vector<transfer_op_desc> transfer_ops;
  // Run count pass
  count_ctx count_ctx{.next_desc = descs.get(),
                      .patch = patch,
                      .src_chunk_ptrs = src_chunk_ptrs.get(),
                      .tgt_chunk_ptrs = tgt_chunk_ptrs.get(),
                      .transfer_ops = transfer_ops};
  count_dir(count_ctx, *source_manifest->dirs, *target_manifest->dirs, res);
  // Allocate the buffer and set array pointers
  res.chunks = reinterpret_cast<tek_sc_dd_chunk *>(tsci_os_mem_alloc(
      sizeof *res.chunks * res.num_chunks +
      sizeof *res.transfer_ops * res.num_transfer_ops +
      sizeof *res.trans_op_grps * res.num_trans_op_grps +
      sizeof *res.files * res.num_files + sizeof *res.dirs * res.num_dirs));
  if (!res.chunks) {
    throw std::bad_alloc{};
  }
  res.transfer_ops =
      reinterpret_cast<tek_sc_dd_transfer_op *>(res.chunks + res.num_chunks);
  res.trans_op_grps = reinterpret_cast<tek_sc_dd_trans_op_grp *>(
      res.transfer_ops + res.num_transfer_ops);
  res.files = reinterpret_cast<tek_sc_dd_file *>(res.trans_op_grps +
                                                 res.num_trans_op_grps);
  res.dirs = reinterpret_cast<tek_sc_dd_dir *>(res.files + res.num_files);
  // Run write pass
  write_ctx write_ctx{.next_desc = descs.get(),
                      .next_chunk = res.chunks,
                      .next_transfer_op = res.transfer_ops,
                      .next_trans_op_grp = res.trans_op_grps,
                      .next_file = res.files,
                      .next_dir = &res.dirs[1],
                      .delta = res,
                      .chunk_buf_off = 0,
                      .patch = patch,
                      .src_chunk_ptrs = src_chunk_ptrs.get(),
                      .tgt_chunk_ptrs = tgt_chunk_ptrs.get(),
                      .transfer_ops = transfer_ops,
                      .group = {}};
  write_dir(write_ctx, *source_manifest->dirs, *target_manifest->dirs, nullptr,
            *res.dirs);
  // Set the correct initial stage
  if (!(res.dirs[0].flags &
        (TEK_SC_DD_DIR_FLAG_new | TEK_SC_DD_DIR_FLAG_children_new |
         TEK_SC_DD_DIR_FLAG_children_download))) {
    if (res.dirs[0].flags & TEK_SC_DD_DIR_FLAG_children_patch) {
      res.stage = TEK_SC_DD_STAGE_patching;
    } else {
      res.stage = (res.dirs[0].flags & TEK_SC_DD_DIR_FLAG_children_new)
                      ? TEK_SC_DD_STAGE_installing
                      : TEK_SC_DD_STAGE_deleting;
    }
  }
  return res;
}
