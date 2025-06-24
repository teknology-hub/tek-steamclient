//===-- am_vdf.cpp - Steam application manager app info parser ------------===//
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
/// Implementation of @ref tsci_am_parse_app_info.
///
//===----------------------------------------------------------------------===//
#include "common/am.h"

#include "tek-steamclient/am.h"

#include <charconv>
#include <cstdint>
#include <memory>
#include <pthread.h>
#include <sqlite3.h>
#include <string_view>
#include <system_error>
#include <vdf_parser.hpp>

static constexpr tek_sc_am_item_status &
operator|=(tek_sc_am_item_status &left, tek_sc_am_item_status right) noexcept {
  return left = static_cast<tek_sc_am_item_status>(static_cast<int>(left) |
                                                   static_cast<int>(right));
}

extern "C" bool tsci_am_parse_app_info(tek_sc_am *am, const char *buf,
                                       int len) {
  std::string_view view(buf, len);
  std::error_code ec;
  const auto vdf = tyti::vdf::read(view.begin(), view.end(), ec);
  if (ec != std::error_code{}) {
    return false;
  }
  const auto appid = vdf.attribs.find("appid");
  if (appid == vdf.attribs.cend()) {
    return false;
  }
  view = appid->second;
  std::uint32_t app_id;
  if (std::from_chars(view.begin(), view.end(), app_id).ec != std::errc{}) {
    return false;
  }
  const auto depots = vdf.childs.find("depots");
  if (depots == vdf.childs.cend()) {
    return true;
  }
  pthread_mutex_lock(&am->item_descs_mtx);
  // Find the range of item state descriptors belonging to the app, assuming
  //    that they are sorted by app_id in the linked list
  auto descs_begin = reinterpret_cast<tek_sc_am_item_desc *>(am->item_descs);
  while (descs_begin && descs_begin->id.app_id != app_id) {
    descs_begin = descs_begin->next;
  }
  if (!descs_begin) {
    pthread_mutex_unlock(&am->item_descs_mtx);
    return false;
  }
  auto descs_end = descs_begin->next;
  while (descs_end && descs_end->id.app_id == app_id) {
    descs_end = descs_end->next;
  }
  sqlite3_exec(am->db, "BEGIN", nullptr, nullptr, nullptr);
  constexpr char query[] = "UPDATE items SET status = ?, latest_manifest_id = "
                           "? WHERE app_id = ? AND depot_id = ?";
  sqlite3_stmt *stmt_ptr;
  if (sqlite3_prepare_v2(am->db, query, sizeof query, &stmt_ptr, nullptr) !=
      SQLITE_OK) {
    stmt_ptr = nullptr;
  }
  const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> stmt(
      stmt_ptr, sqlite3_finalize);
  // Parse the depots
  for (const auto &[id, depot] : depots->second->childs) {
    view = id;
    std::uint32_t depot_id;
    if (std::from_chars(view.begin(), view.end(), depot_id).ec != std::errc{}) {
      continue;
    }
    const auto &depot_children = depot->childs;
    const auto manifests = depot_children.find("manifests");
    if (manifests == depot_children.cend()) {
      continue;
    }
    const auto &manifests_children = manifests->second->childs;
    const auto public_man = manifests_children.find("public");
    if (public_man == manifests_children.cend()) {
      continue;
    }
    const auto &public_attrs = public_man->second->attribs;
    const auto gid = public_attrs.find("gid");
    if (gid == public_attrs.cend()) {
      continue;
    }
    view = gid->second;
    std::uint64_t manifest_id;
    if (std::from_chars(view.begin(), view.end(), manifest_id).ec !=
        std::errc{}) {
      continue;
    }
    for (auto desc = descs_begin; desc != descs_end; desc = desc->next) {
      if (desc->id.depot_id != depot_id) {
        continue;
      }
      desc->latest_manifest_id = manifest_id;
      if (desc->current_manifest_id &&
          desc->latest_manifest_id != desc->current_manifest_id) {
        desc->status |= TEK_SC_AM_ITEM_STATUS_upd_available;
      }
      if (stmt) {
        sqlite3_bind_int(stmt.get(), 1, static_cast<int>(desc->status));
        sqlite3_bind_int64(stmt.get(), 2,
                           static_cast<sqlite3_int64>(manifest_id));
        sqlite3_bind_int(stmt.get(), 3, static_cast<int>(app_id));
        sqlite3_bind_int(stmt.get(), 4, static_cast<int>(depot_id));
        sqlite3_step(stmt.get());
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
      }
      break;
    }
  } // for (const auto &[id, depot] : depots->second->childs)
  sqlite3_exec(am->db, "COMMIT", nullptr, nullptr, nullptr);
  pthread_mutex_unlock(&am->item_descs_mtx);
  return true;
}
