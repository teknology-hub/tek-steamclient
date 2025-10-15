//===-- sp.h - SteamPipe downloader interface -----------------------------===//
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
/// Declarations of types and functions for downloading and decoding content
///    from SteamPipe - Steam content delivery system.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "base.h"
#include "cm.h"
#include "content.h"
#include "error.h"

#include <stdatomic.h>
#include <stdint.h>

//===-- Types -------------------------------------------------------------===//

/// Prototype of SteamPipe download progress handler function. It's called in
///    context of `tek_sc_sp_*` functions.
///
/// @param [in, out] data
///    Pointer to the input/output data structure that the progress applies to.
/// @param current
///    Current download progress value, in bytes.
/// @param total
///    Total size of the file being downloaded, in bytes.
typedef void tek_sc_sp_progress_func(void *_Nonnull data, int current,
                                     int total);

/// Common part for SteamPipe download input/output data structures.
typedef struct tek_sc_sp_data tek_sc_sp_data;
/// @copydoc tek_sc_sp_data
struct tek_sc_sp_data {
  /// [In] Pointer to an array of SteamPipe server entries. The functions will
  ///    attempt downloading from the first server in the list, and resort to
  ///    others in case of a connection timeout or server reporting being
  ///    unavailable.
  const tek_sc_cm_sp_srv_entry *_Nonnull srvs;
  /// [In] Number of entries pointed to by @ref srvs.
  int num_srvs;
  /// [In] Optional pointer to the progress handler function.
  tek_sc_sp_progress_func *_Nullable progress_handler;
  /// [Out] On success, pointer to the buffer containing the data. Must be freed
  ///    with `free` after use.
  void *_Nullable data;
  /// [Out] Size of the buffer pointed to by @ref data, in bytes.
  int data_size;
  /// [In] ID of the depot that the file to download belongs to.
  uint32_t depot_id;
};

/// Input/output data for depot manifest downloads.
typedef struct tek_sc_sp_data_dm tek_sc_sp_data_dm;
/// @copydoc tek_sc_sp_data_dm
struct tek_sc_sp_data_dm {
  /// Common part of the data.
  tek_sc_sp_data common;
  /// [In] ID of the manifest to download.
  uint64_t manifest_id;
  /// [In] Current request code for the manifest. Steam refreshes this value on
  ///    every *4 and *9 minute, that is every 5 minutes with offset of 240
  ///    seconds from 5-minute boundary. Can be obtained via
  ///    @ref tek_sc_cm_get_mrc.
  uint64_t request_code;
};

/// Input/output data for depot patch downloads.
typedef struct tek_sc_sp_data_dp tek_sc_sp_data_dp;
/// @copydoc tek_sc_sp_data_dp
struct tek_sc_sp_data_dp {
  /// Common part of the data.
  tek_sc_sp_data common;
  /// [In] ID of the source manifest for patch.
  uint64_t src_manifest_id;
  /// [In] ID of the target manifest for patch.
  uint64_t tgt_manifest_id;
};

/// Input/output data for chunk downloads.
typedef struct tek_sc_sp_data_chunk tek_sc_sp_data_chunk;
/// @copydoc tek_sc_sp_data_chunk
struct tek_sc_sp_data_chunk {
  /// [In] Optional pointer to the progress handler function.
  tek_sc_sp_progress_func *_Nullable progress_handler;
  /// [Out] Pointer to the caller-supplied buffer that receives downloaded data.
  ///    Assumed to have size of at least `chunk->comp_size`.
  void *_Nonnull data;
  /// [In] ID of the depot that the chunk to download belongs to.
  uint32_t depot_id;
  /// [In] Pointer to the manifest entry for the chunk to download.
  const tek_sc_dm_chunk *_Nonnull chunk;
};

/// Opaque context for chunk decryption and decompression. Intended to be reused
///    across multiple calls.
typedef struct tek_sc_sp_dec_ctx tek_sc_sp_dec_ctx;

/// Opaque multi downloader instance type.
/// It is used to download multiple chunks in multiple threads from multiple
///    servers simultaneously while automatically decoding them, and reusing as
///    much context as possible.
typedef struct tek_sc_sp_multi_dlr tek_sc_sp_multi_dlr;

/// Multi downloader descriptor, providing data used by all multi downloader's
///    components. User must not modify its contents after calling
///    @ref tek_sc_sp_multi_dlr_create and before calling
///    @ref tek_sc_sp_multi_dlr_destroy, or things will break.
typedef struct tek_sc_sp_multi_dlr_desc tek_sc_sp_multi_dlr_desc;

/// Prototype of SteamPipe multi downloader progress handler function. It's
///    called in context of @ref tek_sc_sp_multi_process and is not thread-safe.
///
/// @param [in, out] desc
///    Pointer to the @ref tek_sc_sp_multi_dlr_desc instance containing the
///    progress value that has updated.
typedef void
tek_sc_sp_multi_progress_func(tek_sc_sp_multi_dlr_desc *_Nonnull desc);

/// @copydoc tek_sc_sp_multi_dlr_desc
struct tek_sc_sp_multi_dlr_desc {
  /// On input, maximum number of threads that will run downloads (call
  ///    @ref tek_sc_sp_multi_process). After calling
  ///    @ref tek_sc_sp_multi_dlr_create, the number of thread entries created,
  ///    which may be smaller, the user should use that many threads.
  int num_threads;
  /// Number of entries pointed to by @ref srvs.
  int num_srvs;
  /// Pointer to the array of entries for SteamPipe servers to download chunks
  ///    from. The downloader will evenly assign them to threads.
  const tek_sc_cm_sp_srv_entry *_Nonnull srvs;
  /// Current download progress value accumulated from all requests.
  _Atomic(int64_t) progress;
  /// Optional pointer to the progress handler function.
  tek_sc_sp_multi_progress_func *_Nullable progress_handler;
  /// After calling @ref tek_sc_sp_multi_dlr_create, maximum number of
  ///    concurrent requests per thread.
  int num_reqs_per_thread;
  /// After calling @ref tek_sc_sp_multi_dlr_create, maximum number of
  ///    concurrent requests for the last thread, may be equal to or smaller
  ///    than @ref num_reqs_per_thread.
  int num_reqs_last_thread;
};

/// Chunk download and decode request/response data for multi downloader.
typedef struct tek_sc_sp_multi_chunk_req tek_sc_sp_multi_chunk_req;
/// @copydoc tek_sc_sp_multi_chunk_req
struct tek_sc_sp_multi_chunk_req {
  /// Pointer to the manifest entry for the chunk to download.
  const tek_sc_dm_chunk *_Nonnull chunk;
  /// Pointer to the buffer that temporarily stores downloaded chunk data
  ///    before decoding. Assumed to have the size of at least
  ///    `chunk->comp_size`.
  void *_Nonnull comp_data;
  /// Pointer to the buffer that receives decoded chunk data on success.
  ///    Assumed to have the size of at least `chunk->size`.
  void *_Nonnull data;
  /// Result codes for the response.
  tek_sc_err result;
};

//===-- Functions ---------------------------------------------------------===//

#ifdef __cplusplus
extern "C" {
#endif // def __cplusplus

//===--- Simple download functions ----------------------------------------===//

/// Download a depot manifest from SteamPipe.
///
/// @param [in, out] data
///    Pointer to the input/output data for the request.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param [in] cancel_flag
///    Optional pointer to the flag that may be set by another thread to cancel
///    the operation.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(read_only, 3)]]
tek_sc_err tek_sc_sp_download_dm(tek_sc_sp_data_dm *_Nonnull data,
                                 long timeout_ms,
                                 const atomic_bool *_Nullable cancel_flag);

/// Download a depot patch from SteamPipe.
///
/// @param [in, out] data
///    Pointer to the input/output data for the request.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param [in] cancel_flag
///    Optional pointer to the flag that may be set by another thread to cancel
///    the operation.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_only, 1),
  gnu::access(read_only, 3)]]
tek_sc_err tek_sc_sp_download_dp(tek_sc_sp_data_dp *_Nonnull data,
                                 long timeout_ms,
                                 const atomic_bool *_Nullable cancel_flag);

/// Download a chunk from a SteamPipe server.
///
/// @param [in] srv
///    Pointer to the entry for the SteamPipe server to download chunk from.
/// @param [in, out] data
///    Pointer to the input/output data for the request.
/// @param timeout_ms
///    Timeout for the operation, in milliseconds.
/// @param [in] cancel_flag
///    Optional pointer to the flag that may be set by another thread to cancel
///    the operation.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2), gnu::access(read_only, 1),
  gnu::access(read_write, 2), gnu::access(read_only, 4)]]
tek_sc_err tek_sc_sp_download_chunk(const tek_sc_cm_sp_srv_entry *_Nonnull srv,
                                    tek_sc_sp_data_chunk *_Nonnull data,
                                    long timeout_ms,
                                    const atomic_bool *_Nullable cancel_flag);

//===--- Chunk decoding functions -----------------------------------------===//

/// Create a chunk decoding context.
///
/// @param [in] decryption_key
///    Pointer to the AES-256 decryption key for the depot, which is used by
///    @ref tek_sc_sp_decode_chunk, but not by @ref tek_sc_sp_patch_chunk. If
///    provided, must stay valid until context destruction.
/// @return Pointer to created context that can be passed to
///    @ref tek_sc_sp_decode_chunk. It must be destroyed with
///    @ref tek_sc_sp_dec_ctx_destroy after use. `nullptr` is returned if
///    context allocation fails.
[[gnu::TEK_SC_API, gnu::access(read_only, 1)]] tek_sc_sp_dec_ctx
    *_Nullable tek_sc_sp_dec_ctx_create(
        const tek_sc_aes256_key _Nullable decryption_key);

/// Destroy a chunk decoding context and free its resources.
///
/// @param [in, out] ctx
///    Pointer to the chunk decoding context to destroy.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_sp_dec_ctx_destroy(tek_sc_sp_dec_ctx *_Nonnull ctx);

/// Decrypt and decompress a chunk.
///
/// @param [in, out] ctx
///    Pointer to the chunk decoding context to use.
/// @param [in, out] enc_data
///    Pointer to the buffer containing encrypted chunk data. Decryption is
///    performed in-situ. Assumed to have size of `chunk->comp_size`.
/// @param [out] dec_data
///    Pointer to the buffer that receives decompressed chunk data. Assumed to
///    have size of at least `chunk->size`.
/// @param [in] chunk
///    Pointer to the manifest entry for the chunk to decode.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3, 4), gnu::access(read_write, 1),
  gnu::access(read_write, 2), gnu::access(read_write, 3),
  gnu::access(read_only, 4)]]
tek_sc_err tek_sc_sp_decode_chunk(tek_sc_sp_dec_ctx *_Nonnull ctx,
                                  void *_Nonnull enc_data,
                                  void *_Nonnull dec_data,
                                  const tek_sc_dm_chunk *_Nonnull chunk);

/// Patch a chunk.
///
/// @param [in, out] ctx
///    Pointer to the chunk decoding context to use.
/// @param [in] src_chunk
///    Pointer to the buffer containing source chunk data. Assumed to have size
///    of `pchunk->source_chunk->size`.
/// @param [out] tgt_chunk
///    Pointer to the buffer that receives target chunk data. Assumed to have
///    size of at least `pchunk->target_chunk->size`.
/// @param [in] pchunk
///    Pointer to the patch chunk entry to apply.
/// @return A @ref tek_sc_err indicating the result of operation.
[[gnu::TEK_SC_API, gnu::nonnull(1, 2, 3, 4), gnu::access(read_write, 1),
  gnu::access(read_only, 2), gnu::access(read_write, 3),
  gnu::access(read_only, 4)]]
tek_sc_err tek_sc_sp_patch_chunk(tek_sc_sp_dec_ctx *_Nonnull ctx,
                                 const void *_Nonnull src_chunk,
                                 void *_Nonnull tgt_chunk,
                                 const tek_sc_dp_chunk *_Nonnull pchunk);

//===--- Multi downloader functions ---------------------------------------===//

/// Create a multi downloader instance.
///
/// @param [in, out] desc
///    Pointer to the multi downloader descriptor.
/// @param depot_id
///    ID of the depot to download chunks from.
/// @param [in] decryption_key
///    Pointer to the AES-256 decryption key for the depot. Must stay valid
///    until downloader destruction.
/// @param [out] err
///    Address of variable that receives the error on failure.
/// @return Pointer to created multi downloader instance that can be passed to
///    other functions. It must be destroyed with
///    @ref tek_sc_sp_multi_dlr_destroy after use. `nullptr` may be returned on
///    failure, check @p err for details.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3, 4), gnu::access(read_only, 1),
  gnu::access(read_only, 3), gnu::access(write_only, 4)]]
tek_sc_sp_multi_dlr *_Nullable tek_sc_sp_multi_dlr_create(
    tek_sc_sp_multi_dlr_desc *_Nonnull desc, uint32_t depot_id,
    const tek_sc_aes256_key _Nonnull decryption_key, tek_sc_err *_Nonnull err);

/// Destroy a multi downloader instance and free its resources.
///
/// @param [in, out] dlr
///    Pointer to the multi downloader instance to destroy.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_sp_multi_dlr_destroy(tek_sc_sp_multi_dlr *_Nonnull dlr);

/// Submit a chunk download and decode request to a multi downloader.
///
/// @param [in, out] dlr
///    Pointer to the multi downloader instance to submit the request to.
/// @param thrd_index
///    Index of the thread submitting the request.
/// @param [in] req
///    Pointer to the request to submit.
/// @return A @ref tek_sc_err indicating the result of operation. `type` value
///    of @ref TEK_SC_ERR_TYPE_sub and `auxiliary` value of
///    @ref TEK_SC_ERRC_sp_max_reqs indicates that there is no error, but a
///    maximum number of active requests on the thread has already been
///    reached, and @ref tek_sc_sp_multi_dlr_process should be called to
///    process them.
[[gnu::TEK_SC_API, gnu::nonnull(1, 3), gnu::access(read_only, 1),
  gnu::access(read_only, 3)]]
tek_sc_err
tek_sc_sp_multi_dlr_submit_req(const tek_sc_sp_multi_dlr *_Nonnull dlr,
                               int thrd_index,
                               tek_sc_sp_multi_chunk_req *_Nonnull req);

/// Process multi downloader's pending requests.
///
/// @param [in, out] dlr
///    Pointer to the multi downloader instance to process requests for.
/// @param thrd_index
///    Index of the thread processing the requests.
/// @param poll
///    If `true` and there are no completed requests at the moment, wait for at
///    least to complete.
/// @param [out] err
///    Address of variable that receives the error on failure.
/// @return Pointer to a completed request. Call the function again to get other
///    requests if there are any. `nullptr` is returned when there are no more
///    requests to process for now, or an error has occurred (which is indicated
///    by @p err).
[[gnu::TEK_SC_API, gnu::nonnull(1, 4), gnu::access(read_only, 1),
  gnu::access(write_only, 4)]]
tek_sc_sp_multi_chunk_req *_Nullable tek_sc_sp_multi_dlr_process(
    const tek_sc_sp_multi_dlr *_Nonnull dlr, int thrd_index, bool poll,
    tek_sc_err *_Nonnull err);

/// Cancel all running downloads on multi downloader. This will also prevent
///    further downloads from running properly, so the instance should be
///    destroyed after calling this. Safe to call from any thread, will make
///    all running @ref tek_sc_sp_multi_dlr_process calls return ASAP.
///
/// @param [in, out] dlr
///    Pointer to the multi downloader to cancel downloads on.
[[gnu::TEK_SC_API, gnu::nonnull(1), gnu::access(read_write, 1)]]
void tek_sc_sp_multi_dlr_cancel(tek_sc_sp_multi_dlr *_Nonnull dlr);

#ifdef __cplusplus
} // extern "C"
#endif // def __cplusplus
