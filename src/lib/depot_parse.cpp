//===-- depot_parse.cpp - Steam depot manifest and patch parsing ----------===//
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
/// Implementation of @ref tek_sc_dm_parse and @ref tek_sc_dp_parse.
///
/// SteamPipe provides manifests and patches in Protobuf format with encrypted
///    and/or compressed data, tek-steamclient parses them into its own formats
///    that are better optimized for its tasks. Manifests are organized into a
///    tree structure that allows skipping whole branches during various
///    operations, and patch chunks are binded to manifest chunks on parse-time
///    to significantly speed up lookups later.
///
//===----------------------------------------------------------------------===//
#include "tek-steamclient/content.h"

#include "common/error.h"
#include "content_ops.hpp"
#include "delta_chunks.h"
#include "os.h"
#include "tek-steamclient/base.h"
#include "tek-steamclient/error.h"
#include "tek-steamclient/os.h"
#include "tek/steamclient/content/manifest_metadata.pb.h"
#include "tek/steamclient/content/manifest_payload.pb.h"
#include "tek/steamclient/content/patch_payload.pb.h"
#include "utils.h"

#include <algorithm>
#include <compare>
#include <cstdint>
#include <cstring>
#include <google/protobuf/arena.h>
#include <iterator>
#include <map>
#include <memory>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <ranges>
#include <span>
#include <string_view>
#include <zip.h>

namespace tek::steamclient::content {

using google::protobuf::RepeatedPtrField;

namespace {

//===-- SteamPipe magic numbers -------------------------------------------===//

static constexpr std::uint32_t manifest_metadata_magic = 0x1F4812BE;
static constexpr std::uint32_t manifest_payload_magic = 0x71F617D0;
static constexpr std::uint32_t patch_payload_magic = 0x502F15E5;

//===-- Private types -----------------------------------------------------===//

/// SteamPipe header identifying various sections in the files.
struct file_section_hdr {
  /// Magic number indicating section type.
  std::uint32_t magic;
  /// Size of the section data, in bytes.
  std::uint32_t size;
};

/// Manifest directory tree node.
struct dm_dir_node {
  std::map<std::string_view, const ManifestFile &> files;
  std::map<std::string_view, dm_dir_node> subdirs;
};

/// Depot manifest parsing context, shared across recursion levels of
///    @ref dm_process_dir.
struct dm_parse_ctx {
  /// Pointer to the next available character in the manifest's name buffer.
  tek_sc_os_char *_Nonnull next_name;
  /// Pointer to the next available chunk entry in the manifest's buffer.
  tek_sc_dm_chunk *_Nonnull next_chunk;
  /// Pointer to the next available file entry in the manifest's buffer.
  tek_sc_dm_file *_Nonnull next_file;
  /// Pointer to the next available directory entry in the manifest's buffer.
  tek_sc_dm_dir *_Nonnull next_dir;
};

/// Depot patch parsing context, shared across recursion levels of
///    @ref dp_count_dir and @ref dp_write_dir.
struct [[gnu::visibility("internal")]] dp_parse_ctx {
  /// Buffer for storing pointers to source file's chunks sorted by `sha`.
  std::unique_ptr<const tek_sc_dm_chunk *_Nonnull[]> src_chunk_ptrs;
  /// Buffer for storing pointers to target file's chunks sorted by `sha`.
  std::unique_ptr<const tek_sc_dm_chunk *_Nonnull[]> tgt_chunk_ptrs;
  /// Pointer to the next available chunk entry in the patch's buffer.
  tek_sc_dp_chunk *_Nonnull next_chunk;

  dp_parse_ctx(int max_num_src_chunks, int max_num_tgt_chunks)
      : src_chunk_ptrs(new const tek_sc_dm_chunk *[max_num_src_chunks]),
        tgt_chunk_ptrs(new const tek_sc_dm_chunk *[max_num_tgt_chunks]) {}
};

//===-- Private functions -------------------------------------------------===//

//===--- Depot manifest parsing -------------------------------------------===//

static constexpr tek_sc_dm_file_flag &
operator|=(tek_sc_dm_file_flag &left, tek_sc_dm_file_flag right) noexcept {
  return left = static_cast<tek_sc_dm_file_flag>(static_cast<int>(left) |
                                                 static_cast<int>(right));
}

/// Process a manifest directory tree node and write parsed data to
///    @ref tek_sc_depot_manifest arrays.
///
/// @param [in, out] ctx
///    Parsing context to use.
/// @param [in] node
///    Manifest directory tree node to process.
/// @param [out] dm_dir
///    Directory entry that receives the parsed data.
static void dm_process_dir(dm_parse_ctx &ctx, const dm_dir_node &node,
                           tek_sc_dm_dir &dm_dir) noexcept {
  auto cur_file = ctx.next_file;
  auto cur_subdir = ctx.next_dir;
  // Initialize directory fields
  if (node.files.empty()) {
    dm_dir.files = nullptr;
  } else {
    dm_dir.files = ctx.next_file;
    ctx.next_file += node.files.size();
  }
  if (node.subdirs.empty()) {
    dm_dir.subdirs = nullptr;
  } else {
    dm_dir.subdirs = ctx.next_dir;
    ctx.next_dir += node.subdirs.size();
  }
  dm_dir.num_files = node.files.size();
  dm_dir.num_subdirs = node.subdirs.size();
  // Process files
  for (const auto &[name, file] : node.files) {
    auto &dm_file = *cur_file++;
    dm_file.name = ctx.next_name;
    ctx.next_name +=
        tsci_os_str_to_pstr(name.data(), name.length(), ctx.next_name);
    *ctx.next_name++ = TEK_SC_OS_STR('\0');
    dm_file.parent = &dm_dir;
    // Set flags
    dm_file.flags = TEK_SC_DM_FILE_FLAG_none;
    if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_READ_ONLY) {
      dm_file.flags = TEK_SC_DM_FILE_FLAG_readonly;
    }
    if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_HIDDEN) {
      dm_file.flags |= TEK_SC_DM_FILE_FLAG_hidden;
    }
    if ((file.flags() &
         (ManifestFileFlag::MANIFEST_FILE_FLAG_EXECUTABLE |
          ManifestFileFlag::MANIFEST_FILE_FLAG_CUSTOM_EXECUTABLE))) {
      dm_file.flags |= TEK_SC_DM_FILE_FLAG_executable;
    }
    if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_SYMLINK) {
      dm_file.flags |= TEK_SC_DM_FILE_FLAG_symlink;
      // Set link target and zero everything else
      ctx.next_name +=
          tsci_os_str_to_pstr(file.link_target().data(),
                              file.link_target().length() + 1, ctx.next_name);
      dm_file.size = 0;
      dm_file.chunks = nullptr;
      dm_file.num_chunks = 0;
    } else { // if (symlink)
      // Set remaining fields and process chunks
      dm_file.size = file.size();
      dm_file.num_chunks = file.chunks_size();
      if (!file.chunks_size()) {
        dm_file.chunks = nullptr;
        continue;
      }
      dm_file.chunks = ctx.next_chunk;
      const std::span dm_chunks(ctx.next_chunk, file.chunks_size());
      ctx.next_chunk += file.chunks_size();
      for (auto &&[chunk, dm_chunk] :
           std::views::zip(file.chunks(), dm_chunks)) {
        std::ranges::move(
            std::span(chunk.sha().data(), sizeof dm_chunk.sha.bytes),
            dm_chunk.sha.bytes);
        dm_chunk.parent = &dm_file;
        dm_chunk.offset = chunk.offset();
        dm_chunk.size = chunk.size();
        dm_chunk.comp_size = chunk.comp_size();
      }
      // Sort chunks by offset
      std::ranges::sort(dm_chunks, {}, &tek_sc_dm_chunk::offset);
    } // if (symlink) else
  } // for (const auto &[name, file] : node.files)
  // Process subdirectories
  for (const auto &[name, subnode] : node.subdirs) {
    auto &dm_subdir = *cur_subdir++;
    dm_subdir.name = ctx.next_name;
    ctx.next_name +=
        tsci_os_str_to_pstr(name.data(), name.length(), ctx.next_name);
    *ctx.next_name++ = TEK_SC_OS_STR('\0');
    dm_subdir.parent = &dm_dir;
    dm_process_dir(ctx, subnode, dm_subdir);
  }
}

/// Create a manifest parsing error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for the specified manifest parsing error.
static constexpr tek_sc_err dm_parse_err(tek_sc_errc errc) noexcept {
  return tsc_err_sub(TEK_SC_ERRC_manifest_parse, errc);
}

//===--- Depot patch parsing ----------------------------------------------===//

/// Compare two @ref tek_sc_sha1_hash values.
///
/// @param [in] left
///    The first SHA-1 hash to compare.
/// @param [in] right
///    The second SHA-1 hash to compare.
/// @return Value indicating whether @p left is smaller than @p right.
static constexpr bool cmp_sha(const tek_sc_sha1_hash &left,
                              const tek_sc_sha1_hash &right) noexcept {
  return std::tie(left.high32, left.low128) <
         std::tie(right.high32, right.low128);
}

/// Project a pointer to a manifest chunk entry as its SHA-1 hash.
///
/// @param [in] chunk
///    Pointer to the manifest chunk entry to project.
/// @return Projection of `sha` in @p chunk.
[[using gnu: nonnull(1), access(read_only, 1)]]
static constexpr const tek_sc_sha1_hash &
proj_dm_ptr_sha(const tek_sc_dm_chunk *_Nonnull chunk) noexcept {
  return chunk->sha;
}

/// Project a Protobuf patch chunk entry as SHA-1 hash of its source chunk.
///
/// @param [in] pchunk
///    Protobuf patch chunk entry to project.
/// @return Projection of source chunk's SHA-1 hash in @p pchunk.
static inline const tek_sc_sha1_hash &
proj_proto_src_sha(const PatchChunk &pchunk) noexcept {
  return *reinterpret_cast<const tek_sc_sha1_hash *>(
      pchunk.source_sha().data());
}

/// Project a Protobuf patch chunk entry as SHA-1 hash of its target chunk.
///
/// @param [in] pchunk
///    Protobuf patch chunk entry to project.
/// @return Projection of target chunk's SHA-1 hash in @p pchunk.
static inline const tek_sc_sha1_hash &
proj_proto_tgt_sha(const PatchChunk &pchunk) noexcept {
  return *reinterpret_cast<const tek_sc_sha1_hash *>(
      pchunk.target_sha().data());
}

/// Count the total number of chunk patch operations in specified directory.
///
/// @param [in, out] ctx
///    Parsing context to use.
/// @param [in] chunks
///    Protobuf patch chunk entries.
/// @param [in] src_dir
///    Source manifest directory entry to process.
/// @param [in] tgt_dir
///    Target manifest directory entry to process.
/// @return Total number of chunk patch operations in the directory.
static int dp_count_dir(dp_parse_ctx &ctx,
                        const RepeatedPtrField<PatchChunk> &chunks,
                        const tek_sc_dm_dir &src_dir,
                        const tek_sc_dm_dir &tgt_dir) noexcept {
  int res = 0;
  const std::span src_files(src_dir.files, src_dir.num_files);
  const std::span tgt_files(tgt_dir.files, tgt_dir.num_files);
  // Iterate only the intersecting range that may contain matching files
  for (auto src_file_it = src_files.begin(), tgt_file_it = tgt_files.begin();
       src_file_it < src_files.end() && tgt_file_it < tgt_files.end();) {
    const auto &src_file = *src_file_it;
    const auto &tgt_file = *tgt_file_it;
    const int file_diff = tsci_os_pstrcmp(src_file.name, tgt_file.name);
    // Ignore mismatching files
    if (file_diff < 0) {
      ++src_file_it;
      continue;
    }
    if (file_diff > 0) {
      ++tgt_file_it;
      continue;
    }
    // Now we have entries for the same file from both manifests, proceed
    //    to processing chunks
    if (!src_file.num_chunks || !tgt_file.num_chunks) {
      // Ignore files with no chunks to patch, this also includes symlinks
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    // Populate chunk pointer buffers and sort them by sha/offset
    const std::span src_chunk_ptrs(ctx.src_chunk_ptrs.get(),
                                   src_file.num_chunks);
    std::ranges::transform(std::span(src_file.chunks, src_file.num_chunks),
                           src_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(src_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    const std::span tgt_chunk_ptrs(ctx.tgt_chunk_ptrs.get(),
                                   tgt_file.num_chunks);
    std::ranges::transform(std::span(tgt_file.chunks, tgt_file.num_chunks),
                           tgt_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(tgt_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    // Iterate intersecting and target-only ranges that may contain new chunks
    auto tgt_chunk_it = tgt_chunk_ptrs.begin();
    for (auto src_chunk_it = src_chunk_ptrs.begin();
         src_chunk_it < src_chunk_ptrs.end() &&
         tgt_chunk_it < tgt_chunk_ptrs.end();) {
      const auto &tgt_chunk = **tgt_chunk_it;
      const auto chunk_diff = **src_chunk_it <=> tgt_chunk;
      // Ignore non-new chunks
      if (chunk_diff == std::strong_ordering::equal) {
        ++src_chunk_it;
        ++tgt_chunk_it;
        continue;
      }
      if (chunk_diff == std::strong_ordering::less) {
        ++src_chunk_it;
        continue;
      }
      // Check if target chunk sha is present among patch chunk target shas
      const auto pchunk = std::ranges::lower_bound(chunks, tgt_chunk.sha,
                                                   cmp_sha, proj_proto_tgt_sha);
      if (pchunk == chunks.cend() ||
          proj_proto_tgt_sha(*pchunk) != tgt_chunk.sha) {
        ++tgt_chunk_it;
        continue;
      }
      // Verify that a chunk with pchunk's source sha exists in the source file
      if (!std::ranges::binary_search(src_chunk_ptrs,
                                      proj_proto_src_sha(*pchunk), cmp_sha,
                                      proj_dm_ptr_sha)) {
        ++tgt_chunk_it;
        continue;
      }
      // Increment the counter for every successive target chunk with the same
      //    sha, if any
      do {
        ++res;
        ++tgt_chunk_it;
      } while (tgt_chunk_it < tgt_chunk_ptrs.end() &&
               (*tgt_chunk_it)->sha == tgt_chunk.sha);
    } // for (intersecting chunks)
    while (tgt_chunk_it < tgt_chunk_ptrs.end()) {
      const auto &tgt_chunk = **tgt_chunk_it;
      // Check if target chunk sha is present among patch chunk target shas
      const auto pchunk = std::ranges::lower_bound(chunks, tgt_chunk.sha,
                                                   cmp_sha, proj_proto_tgt_sha);
      if (pchunk == chunks.cend() ||
          proj_proto_tgt_sha(*pchunk) != tgt_chunk.sha) {
        ++tgt_chunk_it;
        continue;
      }
      // Verify that a chunk with pchunk's source sha exists in the source file
      if (!std::ranges::binary_search(src_chunk_ptrs,
                                      proj_proto_src_sha(*pchunk), cmp_sha,
                                      proj_dm_ptr_sha)) {
        ++tgt_chunk_it;
        continue;
      }
      // Increment the counter for every successive target chunk with the same
      //    sha, if any
      do {
        ++res;
        ++tgt_chunk_it;
      } while (tgt_chunk_it < tgt_chunk_ptrs.end() &&
               (*tgt_chunk_it)->sha == tgt_chunk.sha);
    } // while (remaining new chunks)
    ++src_file_it;
    ++tgt_file_it;
  } // for (intersecting files)
  const std::span src_subdirs(src_dir.subdirs, src_dir.num_subdirs);
  const std::span tgt_subdirs(tgt_dir.subdirs, tgt_dir.num_subdirs);
  // Iterate only the intersecting range that may contain matching
  //    subdirectories
  for (auto src_subdir_it = src_subdirs.begin(),
            tgt_subdir_it = tgt_subdirs.begin();
       src_subdir_it < src_subdirs.end() &&
       tgt_subdir_it < tgt_subdirs.end();) {
    const auto &src_subdir = *src_subdir_it;
    const auto &tgt_subdir = *tgt_subdir_it;
    const int subdir_diff = tsci_os_pstrcmp(src_subdir.name, tgt_subdir.name);
    // Ignore mismatching subdirectories
    if (subdir_diff < 0) {
      ++src_subdir_it;
      continue;
    }
    if (subdir_diff > 0) {
      ++tgt_subdir_it;
      continue;
    }
    // Recurse into the subdirectory
    res += dp_count_dir(ctx, chunks, src_subdir, tgt_subdir);
    ++src_subdir_it;
    ++tgt_subdir_it;
  }
  return res;
}

/// Write patch chunk entries for specified directory to
///    @ref tek_sc_depot_patch array.
///
/// @param [in, out] ctx
///    Parsing context to use.
/// @param [in] chunks
///    Protobuf patch chunk entries.
/// @param [in] src_dir
///    Source manifest directory entry to process.
/// @param [in] tgt_dir
///    Target manifest directory entry to process.
static void dp_write_dir(dp_parse_ctx &ctx,
                         const RepeatedPtrField<PatchChunk> &chunks,
                         const tek_sc_dm_dir &src_dir,
                         const tek_sc_dm_dir &tgt_dir) noexcept {
  const std::span src_files(src_dir.files, src_dir.num_files);
  const std::span tgt_files(tgt_dir.files, tgt_dir.num_files);
  // Iterate only the intersecting range that may contain matching files
  for (auto src_file_it = src_files.begin(), tgt_file_it = tgt_files.begin();
       src_file_it < src_files.end() && tgt_file_it < tgt_files.end();) {
    const auto &src_file = *src_file_it;
    const auto &tgt_file = *tgt_file_it;
    const int file_diff = tsci_os_pstrcmp(src_file.name, tgt_file.name);
    // Ignore mismatching files
    if (file_diff < 0) {
      ++src_file_it;
      continue;
    }
    if (file_diff > 0) {
      ++tgt_file_it;
      continue;
    }
    // Now we have entries for the same file from both manifests, proceed
    //    to processing chunks
    if (!src_file.num_chunks || !tgt_file.num_chunks) {
      // Ignore files with no chunks to patch, this also includes symlinks
      ++src_file_it;
      ++tgt_file_it;
      continue;
    }
    // Populate chunk pointer buffers and sort them by sha/offset
    const std::span src_chunk_ptrs(ctx.src_chunk_ptrs.get(),
                                   src_file.num_chunks);
    std::ranges::transform(std::span(src_file.chunks, src_file.num_chunks),
                           src_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(src_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    const std::span tgt_chunk_ptrs(ctx.tgt_chunk_ptrs.get(),
                                   tgt_file.num_chunks);
    std::ranges::transform(std::span(tgt_file.chunks, tgt_file.num_chunks),
                           tgt_chunk_ptrs.begin(), dm_chunk_to_ptr);
    std::ranges::sort(tgt_chunk_ptrs, cmp_dm_chunk_sha_and_off);
    // Iterate intersecting and target-only ranges that may contain new chunks
    auto tgt_chunk_it = tgt_chunk_ptrs.begin();
    for (auto src_chunk_it = src_chunk_ptrs.begin();
         src_chunk_it < src_chunk_ptrs.end() &&
         tgt_chunk_it < tgt_chunk_ptrs.end();) {
      const auto &tgt_chunk = **tgt_chunk_it;
      const auto chunk_diff = **src_chunk_it <=> tgt_chunk;
      // Ignore non-new chunks
      if (chunk_diff == std::strong_ordering::equal) {
        ++src_chunk_it;
        ++tgt_chunk_it;
        continue;
      }
      if (chunk_diff == std::strong_ordering::less) {
        ++src_chunk_it;
        continue;
      }
      // Check if target chunk sha is present among patch chunk target shas
      const auto pchunk = std::ranges::lower_bound(chunks, tgt_chunk.sha,
                                                   cmp_sha, proj_proto_tgt_sha);
      if (pchunk == chunks.cend() ||
          proj_proto_tgt_sha(*pchunk) != tgt_chunk.sha) {
        ++tgt_chunk_it;
        continue;
      }
      // Find the chunk with pchunk's source sha in the source file
      const auto psrc_chunk_ptr =
          std::ranges::lower_bound(src_chunk_ptrs, proj_proto_src_sha(*pchunk),
                                   cmp_sha, proj_dm_ptr_sha);
      if (psrc_chunk_ptr == src_chunk_ptrs.end() ||
          (*psrc_chunk_ptr)->sha != proj_proto_src_sha(*pchunk)) {
        ++tgt_chunk_it;
        continue;
      }
      // Write an entry for every successive target chunk with the same sha
      do {
        *ctx.next_chunk++ = {
            .source_chunk = *psrc_chunk_ptr,
            .target_chunk = *tgt_chunk_it,
            .delta_chunk = *reinterpret_cast<const void *const *>(
                pchunk->delta_chunk().data()),
            .delta_chunk_size = static_cast<int>(pchunk->delta_chunk_size()),
            .type = TEK_SC_DP_CHUNK_TYPE_vzd};
        ++tgt_chunk_it;
      } while (tgt_chunk_it < tgt_chunk_ptrs.end() &&
               (*tgt_chunk_it)->sha == tgt_chunk.sha);
    } // for (intersecting chunks)
    while (tgt_chunk_it < tgt_chunk_ptrs.end()) {
      const auto &tgt_chunk = **tgt_chunk_it;
      // Check if target chunk sha is present among patch chunk target shas
      const auto pchunk = std::ranges::lower_bound(chunks, tgt_chunk.sha,
                                                   cmp_sha, proj_proto_tgt_sha);
      if (pchunk == chunks.cend() ||
          proj_proto_tgt_sha(*pchunk) != tgt_chunk.sha) {
        ++tgt_chunk_it;
        continue;
      }
      // Find the chunk with pchunk's source sha in the source file
      const auto psrc_chunk_ptr =
          std::ranges::lower_bound(src_chunk_ptrs, proj_proto_src_sha(*pchunk),
                                   cmp_sha, proj_dm_ptr_sha);
      if (psrc_chunk_ptr == src_chunk_ptrs.end() ||
          (*psrc_chunk_ptr)->sha != proj_proto_src_sha(*pchunk)) {
        ++tgt_chunk_it;
        continue;
      }
      // Write an entry for every successive target chunk with the same sha
      do {
        *ctx.next_chunk++ = {
            .source_chunk = *psrc_chunk_ptr,
            .target_chunk = *tgt_chunk_it,
            .delta_chunk = *reinterpret_cast<const void *const *>(
                pchunk->delta_chunk().data()),
            .delta_chunk_size = static_cast<int>(pchunk->delta_chunk_size()),
            .type = TEK_SC_DP_CHUNK_TYPE_vzd};
        ++tgt_chunk_it;
      } while (tgt_chunk_it < tgt_chunk_ptrs.end() &&
               (*tgt_chunk_it)->sha == tgt_chunk.sha);
    } // while (remaining new chunks)
    ++src_file_it;
    ++tgt_file_it;
  } // for (intersecting files)
  const std::span src_subdirs(src_dir.subdirs, src_dir.num_subdirs);
  const std::span tgt_subdirs(tgt_dir.subdirs, tgt_dir.num_subdirs);
  // Iterate only the intersecting range that may contain matching
  //    subdirectories
  for (auto src_subdir_it = src_subdirs.begin(),
            tgt_subdir_it = tgt_subdirs.begin();
       src_subdir_it < src_subdirs.end() &&
       tgt_subdir_it < tgt_subdirs.end();) {
    const auto &src_subdir = *src_subdir_it;
    const auto &tgt_subdir = *tgt_subdir_it;
    const int subdir_diff = tsci_os_pstrcmp(src_subdir.name, tgt_subdir.name);
    // Ignore mismatching subdirectories
    if (subdir_diff < 0) {
      ++src_subdir_it;
      continue;
    }
    if (subdir_diff > 0) {
      ++tgt_subdir_it;
      continue;
    }
    // Recurse into the subdirectory
    dp_write_dir(ctx, chunks, src_subdir, tgt_subdir);
    ++src_subdir_it;
    ++tgt_subdir_it;
  }
}

/// Create a patch parsing error.
///
/// @param errc Error code identifying failed operation.
/// @return A @ref tek_sc_err for the specified patch parsing error.
static constexpr tek_sc_err dp_parse_err(tek_sc_errc errc) noexcept {
  return tsc_err_sub(TEK_SC_ERRC_patch_parse, errc);
}

} // namespace

//===-- Public functions --------------------------------------------------===//

extern "C" {

tek_sc_err tek_sc_dm_parse(const void *data, int data_size,
                           const tek_sc_aes256_key depot_key,
                           tek_sc_depot_manifest *manifest) {
  std::unique_ptr<unsigned char[]> unzipped_data;
  zip_uint64_t unzipped_data_size;
  // Unzip the manifest
  {
    const std::unique_ptr<zip_source_t, decltype(&zip_source_close)> zip_source(
        zip_source_buffer_create(data, data_size, 0, nullptr),
        zip_source_close);
    if (!zip_source) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
    const std::unique_ptr<zip_t, decltype(&zip_close)> zip_archive(
        zip_open_from_source(zip_source.get(), ZIP_RDONLY, nullptr), zip_close);
    if (!zip_archive) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
    zip_stat_t zip_stat;
    if (zip_stat_index(zip_archive.get(), 0, 0, &zip_stat) < 0) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
    if (!(zip_stat.valid & ZIP_STAT_SIZE) ||
        zip_stat.size < sizeof(file_section_hdr) * 2) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
    unzipped_data_size = zip_stat.size;
    const std::unique_ptr<zip_file_t, decltype(&zip_fclose)> zip_file(
        zip_fopen_index(zip_archive.get(), 0, 0), zip_fclose);
    if (!zip_file) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
    unzipped_data.reset(new unsigned char[unzipped_data_size]);
    if (zip_fread(zip_file.get(), unzipped_data.get(), unzipped_data_size) !=
        static_cast<zip_int64_t>(unzipped_data_size)) {
      return dm_parse_err(TEK_SC_ERRC_zip);
    }
  } // Unzip scope
  // Check section headers and sizes
  const auto &payload_hdr =
      *reinterpret_cast<const file_section_hdr *>(unzipped_data.get());
  if (payload_hdr.magic != manifest_payload_magic) {
    return dm_parse_err(TEK_SC_ERRC_magic_mismatch);
  }
  if (sizeof(file_section_hdr) * 2 + payload_hdr.size > unzipped_data_size) {
    return dm_parse_err(TEK_SC_ERRC_invalid_data);
  }
  file_section_hdr metadata_hdr;
  std::memcpy(&metadata_hdr,
              &unzipped_data[sizeof payload_hdr + payload_hdr.size],
              sizeof metadata_hdr);
  if (metadata_hdr.magic != manifest_metadata_magic) {
    return dm_parse_err(TEK_SC_ERRC_magic_mismatch);
  }
  if (sizeof payload_hdr + payload_hdr.size + sizeof metadata_hdr +
          metadata_hdr.size >
      unzipped_data_size) {
    return dm_parse_err(TEK_SC_ERRC_invalid_data);
  }
  // Parse Protobuf data
  bool paths_encrypted;
  if (ManifestMetadata metadata; metadata.ParseFromArray(
          &unzipped_data[sizeof payload_hdr + payload_hdr.size +
                         sizeof metadata_hdr],
          metadata_hdr.size)) {
    manifest->id = metadata.manifest_id();
    manifest->data_size = metadata.data_size();
    paths_encrypted = metadata.paths_encrypted();
  } else {
    return dm_parse_err(TEK_SC_ERRC_protobuf_deserialize);
  }
  {
    google::protobuf::Arena arena;
    auto &payload = *google::protobuf::Arena::Create<ManifestPayload>(&arena);
    if (!payload.ParseFromArray(&unzipped_data[sizeof payload_hdr],
                                payload_hdr.size)) {
      return dm_parse_err(TEK_SC_ERRC_protobuf_deserialize);
    }
    auto &files = *payload.mutable_files();
    // Decrypt paths if necessary
    if (paths_encrypted) {
      const auto aes_ecb = EVP_aes_256_ecb();
      const auto aes_cbc = EVP_aes_256_cbc();
      const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
          EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
      if (!ctx) {
        return dm_parse_err(TEK_SC_ERRC_aes_decryption);
      }
      for (auto &file : files) {
        // Both Base64 decoding and AES decryption are performed in-situ
        // because
        //    they don't increase data size
        auto &path = *file.mutable_path();
        const auto udata = reinterpret_cast<unsigned char *>(path.data());
        const int bin_size =
            tsci_u_base64_decode(path.data(), path.length(), udata);
        if (!EVP_DecryptInit_ex2(ctx.get(), aes_ecb, depot_key, nullptr,
                                 nullptr)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
        int decrypted_size;
        if (!EVP_DecryptUpdate(ctx.get(), udata, &decrypted_size, udata, 16)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        int last_block_len;
        if (!EVP_DecryptFinal_ex(ctx.get(), &udata[decrypted_size],
                                 &last_block_len)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        if (!EVP_DecryptInit_ex2(ctx.get(), aes_cbc, depot_key, udata,
                                 nullptr)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 1);
        if (!EVP_DecryptUpdate(ctx.get(), udata, &decrypted_size, &udata[16],
                               bin_size - 16)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        if (!EVP_DecryptFinal_ex(ctx.get(), &udata[decrypted_size],
                                 &last_block_len)) {
          return dm_parse_err(TEK_SC_ERRC_aes_decryption);
        }
        decrypted_size += last_block_len;
        path.resize(decrypted_size - 1);
        // Warning: I don't know if link target paths actually are encrypted
        //    as well, so assuming that they are
        if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_SYMLINK) {
          auto &link_target = *file.mutable_link_target();
          const auto udata =
              reinterpret_cast<unsigned char *>(link_target.data());
          const int bin_size = tsci_u_base64_decode(
              link_target.data(), link_target.length(), udata);
          if (!EVP_DecryptInit_ex2(ctx.get(), aes_ecb, depot_key, nullptr,
                                   nullptr)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
          if (!EVP_DecryptUpdate(ctx.get(), udata, &decrypted_size, udata,
                                 16)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          if (!EVP_DecryptFinal_ex(ctx.get(), &udata[decrypted_size],
                                   &last_block_len)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          if (!EVP_DecryptInit_ex2(ctx.get(), aes_cbc, depot_key, udata,
                                   nullptr)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          EVP_CIPHER_CTX_set_padding(ctx.get(), 1);
          if (!EVP_DecryptUpdate(ctx.get(), udata, &decrypted_size, &udata[16],
                                 bin_size - 16)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          if (!EVP_DecryptFinal_ex(ctx.get(), &udata[decrypted_size],
                                   &last_block_len)) {
            return dm_parse_err(TEK_SC_ERRC_aes_decryption);
          }
          decrypted_size += last_block_len;
          link_target.resize(decrypted_size - 1);
        } // if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_SYMLINK)
      } // for (files)
    } // if (paths_encrypted)
    // Replace backslashes with forward slashes in paths
    for (auto &file : files) {
      auto &path = *file.mutable_path();
      std::ranges::replace(path, '\\', '/');
      if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_SYMLINK) {
        // Link target paths need OS-defined separators
        auto &link_target = *file.mutable_link_target();
#ifdef _WIN32
        std::ranges::replace(link_target, '/', '\\');
#else
        std::ranges::replace(link_target, '\\', '/');
#endif
      }
    }
    // Build the directory tree
    dm_dir_node root;
    for (const auto &file : files) {
      auto segments = file.path() | std::views::split('/') |
                      std::views::transform([](auto &&segment) {
                        return std::string_view(segment);
                      });
      auto cur_node = &root;
      auto it = segments.begin();
      for (const auto end = segments.end(); std::ranges::next(it) != end;
           ++it) {
        cur_node = &cur_node->subdirs.try_emplace(*it).first->second;
      }
      if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_DIRECTORY) {
        cur_node->subdirs.try_emplace(*it);
      } else {
        cur_node->files.emplace(*it, file);
      }
    }
    // Count the number of entries
    int name_buf_len = 0;
    int num_chunks = 0;
    int num_files = 0;
    int num_dirs = 1; // Root dir included here
    auto count = [&name_buf_len, &num_chunks, &num_files,
                  &num_dirs](auto &&self, const dm_dir_node &node) -> void {
      num_files += node.files.size();
      for (const auto &[name, file] : node.files) {
        name_buf_len += tsci_os_str_pstrlen(name.data(), name.length()) + 1;
        if (file.flags() & ManifestFileFlag::MANIFEST_FILE_FLAG_SYMLINK) {
          name_buf_len += tsci_os_str_pstrlen(file.link_target().data(),
                                              file.link_target().length());
        }
        num_chunks += file.chunks_size();
      }
      num_dirs += node.subdirs.size();
      for (const auto &[name, subnode] : node.subdirs) {
        name_buf_len += tsci_os_str_pstrlen(name.data(), name.length()) + 1;
        self(self, subnode);
      }
    };
    count(count, root);
    manifest->num_chunks = num_chunks;
    manifest->num_files = num_files;
    manifest->num_dirs = num_dirs;
    // Allocate the buffer and set array pointers
    // Typical manifest size justifies use of direct page allocation
    manifest->buf_size = sizeof *manifest->chunks * num_chunks +
                         sizeof *manifest->files * num_files +
                         sizeof *manifest->dirs * num_dirs +
                         sizeof(tek_sc_os_char) * name_buf_len;
    manifest->chunks = reinterpret_cast<tek_sc_dm_chunk *>(
        tsci_os_mem_alloc(manifest->buf_size));
    if (!manifest->chunks) {
      return tsci_err_os(TEK_SC_ERRC_manifest_parse, tsci_os_get_last_error());
    }
    manifest->files =
        reinterpret_cast<tek_sc_dm_file *>(manifest->chunks + num_chunks);
    manifest->dirs =
        reinterpret_cast<tek_sc_dm_dir *>(manifest->files + num_files);
    auto next_name =
        reinterpret_cast<tek_sc_os_char *>(manifest->dirs + num_dirs);
    // Build the manifest tree
    const auto root_dir = manifest->dirs;
    root_dir->name = nullptr;
    root_dir->parent = nullptr;
    dm_parse_ctx ctx{.next_name = next_name,
                     .next_chunk = manifest->chunks,
                     .next_file = manifest->files,
                     .next_dir = root_dir + 1};
    dm_process_dir(ctx, root, *root_dir);
  } // Payload parsing scope
  return tsc_err_ok();
}

tek_sc_err tek_sc_dp_parse(const void *data, int data_size,
                           const tek_sc_aes256_key depot_key,
                           const tek_sc_depot_manifest *source_manifest,
                           const tek_sc_depot_manifest *target_manifest,
                           tek_sc_depot_patch *patch) {
  if (data_size < static_cast<int>(16 + sizeof(file_section_hdr))) {
    return dp_parse_err(TEK_SC_ERRC_invalid_data);
  }
  const auto decrypted_data =
      std::make_unique_for_overwrite<unsigned char[]>(data_size - 16);
  int decrypted_data_size;
  // Decrypt the patch
  {
    const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    if (!EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_ecb(), depot_key, nullptr,
                             nullptr)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    const auto udata = reinterpret_cast<const unsigned char *>(data);
    if (!EVP_DecryptUpdate(ctx.get(), decrypted_data.get(),
                           &decrypted_data_size, udata, 16)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    int last_block_len;
    if (!EVP_DecryptFinal_ex(ctx.get(), &decrypted_data[decrypted_data_size],
                             &last_block_len)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    if (!EVP_DecryptInit_ex2(ctx.get(), EVP_aes_256_cbc(), depot_key,
                             decrypted_data.get(), nullptr)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    EVP_CIPHER_CTX_set_padding(ctx.get(), 1);
    if (!EVP_DecryptUpdate(ctx.get(), decrypted_data.get(),
                           &decrypted_data_size, udata + 16, data_size - 16)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    if (!EVP_DecryptFinal_ex(ctx.get(), &decrypted_data[decrypted_data_size],
                             &last_block_len)) {
      return dp_parse_err(TEK_SC_ERRC_aes_decryption);
    }
    decrypted_data_size += last_block_len;
  } // Decrypt scope
  // Check section headers and sizes
  const auto &payload_hdr =
      *reinterpret_cast<const file_section_hdr *>(decrypted_data.get());
  if (payload_hdr.magic != patch_payload_magic) {
    return dp_parse_err(TEK_SC_ERRC_magic_mismatch);
  }
  const int payload_size = sizeof payload_hdr + payload_hdr.size;
  if (payload_size > decrypted_data_size) {
    return dp_parse_err(TEK_SC_ERRC_invalid_data);
  }
  // Parse Protobuf data
  {
    google::protobuf::Arena arena;
    auto &payload = *google::protobuf::Arena::Create<PatchPayload>(&arena);
    if (!payload.ParseFromArray(&decrypted_data[sizeof payload_hdr],
                                payload_hdr.size)) {
      return dp_parse_err(TEK_SC_ERRC_protobuf_deserialize);
    }
    if (payload.source_manifest_id() != source_manifest->id ||
        payload.target_manifest_id() != target_manifest->id) {
      return dp_parse_err(TEK_SC_ERRC_patch_manifests_mismatch);
    }
    patch->source_manifest = source_manifest;
    patch->target_manifest = target_manifest;
    auto &chunks = *payload.mutable_chunks();
    if (payload.delta_chunk_location() ==
        DeltaChunkLocation::DELTA_CHUNK_LOCATION_IN_PROTOBUF) {
      for (auto &chunk : chunks) {
        // Prepend delta chunk with pointer to it, to be consistent with
        //    location-after-protobuf behavior
        chunk.mutable_delta_chunk()->insert(0, sizeof(char *), '\0');
        const auto data = chunk.mutable_delta_chunk()->data();
        *reinterpret_cast<const char **>(data) = data + sizeof(char *);
      }
    } else { // if (delta_chunk_location in protobuf)
      // Ensure that all delta chunk data is in the buffer
      if (static_cast<int>(payload_size + sizeof(std::uint32_t)) >
          decrypted_data_size) {
        return dp_parse_err(TEK_SC_ERRC_invalid_data);
      }
      std::uint32_t delta_data_size;
      std::memcpy(&delta_data_size, &decrypted_data[payload_size],
                  sizeof delta_data_size);
      if (static_cast<int>(payload_size + sizeof(std::uint32_t) +
                           delta_data_size) > decrypted_data_size) {
        return dp_parse_err(TEK_SC_ERRC_invalid_data);
      }
      // Assign delta chunk pointers to chunks so they don't get messed after
      //    sorting
      auto cur_delta_chunk =
          decrypted_data.get() + payload_size + sizeof(std::uint32_t);
      for (auto &chunk : chunks) {
        chunk.mutable_delta_chunk()->assign(
            reinterpret_cast<const char *>(&cur_delta_chunk),
            sizeof cur_delta_chunk);
        cur_delta_chunk += chunk.delta_chunk_size();
      }
    } // if (delta_chunk_location in protobuf) else
    // Sort chunks by target_sha for binary search to work
    std::ranges::sort(chunks, cmp_sha, proj_proto_tgt_sha);
    // Setup parsing context
    dp_parse_ctx ctx(
        std::ranges::max_element(
            std::span(source_manifest->files, source_manifest->num_files), {},
            &tek_sc_dm_file::num_chunks)
            ->num_chunks,
        std::ranges::max_element(
            std::span(target_manifest->files, target_manifest->num_files), {},
            &tek_sc_dm_file::num_chunks)
            ->num_chunks);
    // Count the number of patch chunk entries to create
    const int num_chunks = dp_count_dir(ctx, chunks, *source_manifest->dirs,
                                        *target_manifest->dirs);
    patch->num_chunks = num_chunks;
    if (!num_chunks) {
      // This should be nearly impossible, but handling it just in case
      patch->chunks = nullptr;
      patch->delta_size = 0;
      return tsc_err_ok();
    }
    // Allocate temporary buffer for patch chunk entries and write them
    auto dp_chunks =
        std::make_unique_for_overwrite<tek_sc_dp_chunk[]>(num_chunks);
    ctx.next_chunk = dp_chunks.get();
    dp_write_dir(ctx, chunks, *source_manifest->dirs, *target_manifest->dirs);
    ctx.src_chunk_ptrs.reset();
    ctx.tgt_chunk_ptrs.reset();
    // Sort dp_chunks by delta_chunk to make it easier to determine chunks that
    //    share the same delta chunk
    std::ranges::sort(std::span(dp_chunks.get(), num_chunks), {},
                      &tek_sc_dp_chunk::delta_chunk);
    // Compute total size of delta chunks, may be smaller than provided by
    //    SteamPipe due to not all chunks being used
    int delta_size = dp_chunks[0].delta_chunk_size;
    for (int i = 1; i < num_chunks; ++i) {
      if (dp_chunks[i].delta_chunk != dp_chunks[i - 1].delta_chunk) {
        delta_size += dp_chunks[i].delta_chunk_size;
      }
    }
    patch->delta_size = delta_size;
    // Allocate the buffer
    // Typical patch size justifies use of direct page allocation
    patch->chunks = reinterpret_cast<tek_sc_dp_chunk *>(
        tsci_os_mem_alloc(sizeof *patch->chunks * num_chunks + delta_size));
    if (!patch->chunks) {
      return tsci_err_os(TEK_SC_ERRC_patch_parse, tsci_os_get_last_error());
    }
    // Verify delta chunks, copy them over and adjust the pointers in patch
    //    chunk entries
    auto cur_delta_chunk =
        reinterpret_cast<unsigned char *>(patch->chunks + num_chunks);
    for (int i = 0; i < num_chunks;) {
      auto &chunk = dp_chunks[i];
      // Determine chunk format and verify magics
      const auto magic =
          *reinterpret_cast<const std::uint32_t *>(chunk.delta_chunk);
      if ((magic & 0x00FFFFFF) == TSCI_VZD_HDR_MAGIC) {
        // "VZd" - VZd (ValveZip delta?)
        chunk.type = TEK_SC_DP_CHUNK_TYPE_vzd;
        if (reinterpret_cast<const tsci_vzd_ftr *>(
                reinterpret_cast<const char *>(chunk.delta_chunk) +
                chunk.delta_chunk_size - sizeof(tsci_vzd_ftr))
                ->magic != TSCI_VZD_FTR_MAGIC) {
          return dp_parse_err(TEK_SC_ERRC_magic_mismatch);
        }
      } else if (magic == TSCI_VSZD_HDR_MAGIC) {
        // "VSZd" - VSZ (Valve zStandard Zip delta?)
        chunk.type = TEK_SC_DP_CHUNK_TYPE_vszd;
        if (const auto magic =
                reinterpret_cast<const tsci_vszd_ftr *>(
                    reinterpret_cast<const char *>(chunk.delta_chunk) +
                    chunk.delta_chunk_size - sizeof(tsci_vszd_ftr))
                    ->magic;
            (magic[0] | (magic[1] << 8) | (magic[2] << 16)) !=
            TSCI_VSZD_FTR_MAGIC) {
          return dp_parse_err(TEK_SC_ERRC_magic_mismatch);
        }
      } else {
        return dp_parse_err(TEK_SC_ERRC_sp_unknown_comp);
      }
      std::memcpy(cur_delta_chunk, chunk.delta_chunk, chunk.delta_chunk_size);
      for (++i; i < num_chunks; ++i) {
        auto &next_chunk = dp_chunks[i];
        if (next_chunk.delta_chunk != chunk.delta_chunk) {
          break;
        }
        next_chunk.delta_chunk = cur_delta_chunk;
        next_chunk.type = chunk.type;
      }
      chunk.delta_chunk = cur_delta_chunk;
      cur_delta_chunk += chunk.delta_chunk_size;
    }
    // Copy patch chunk entries over as well
    std::ranges::move(std::span(dp_chunks.get(), num_chunks), patch->chunks);
    dp_chunks.reset();
    // Sort patch chunks by target_chunk for binary search to work
    std::ranges::sort(std::span(patch->chunks, num_chunks), {},
                      &tek_sc_dp_chunk::target_chunk);
  } // Payload parsing scope
  return tsc_err_ok();
}

} // extern "C"

} // namespace tek::steamclient::content
