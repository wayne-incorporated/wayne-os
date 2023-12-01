// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/ufs_storage.h"

#include <optional>
#include <utility>

#include <base/containers/fixed_flat_set.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <brillo/strings/string_utils.h>

#include "runtime_probe/utils/file_utils.h"
#include "runtime_probe/utils/value_utils.h"

namespace runtime_probe {
namespace {
// Storage-specific fields to probe for UFS.
constexpr auto kUfsFields =
    base::MakeFixedFlatSet<base::StringPiece>({"vendor", "model"});
constexpr auto kUfsType = "UFS";
constexpr auto kUfsPrefix = "ufs_";

bool CheckStorageTypeMatch(const base::FilePath& node_path) {
  if (node_path.empty())
    return false;
  const auto ufs_bsg_path_glob =
      Glob(node_path.Append("device/../../ufs-bsg*"));

  if (ufs_bsg_path_glob.size() == 0)
    return false;

  for (const auto& ufs_bsg_path : ufs_bsg_path_glob) {
    VLOG(2) << "Find ufs-bsg path: " << ufs_bsg_path.value();
  }
  return true;
}

}  // namespace

std::optional<base::Value> UfsStorageFunction::ProbeFromSysfs(
    const base::FilePath& node_path) const {
  VLOG(2) << "Processing the node \"" << node_path.value() << "\"";

  if (!CheckStorageTypeMatch(node_path))
    return std::nullopt;

  const auto ufs_path = node_path.Append("device");

  if (!base::PathExists(ufs_path)) {
    VLOG(1) << "UFS-specific path does not exist on storage device \""
            << node_path.value() << "\"";
    return std::nullopt;
  }

  std::optional<base::Value> ufs_res = MapFilesToDict(ufs_path, kUfsFields);

  if (!ufs_res) {
    VLOG(1) << "UFS-specific fields do not exist on storage \""
            << node_path.value() << "\"";
    return std::nullopt;
  }
  PrependToDVKey(&*ufs_res, kUfsPrefix);
  ufs_res->GetDict().Set("type", kUfsType);
  return ufs_res;
}

std::optional<base::Value> UfsStorageFunction::ProbeFromStorageTool(
    const base::FilePath&) const {
  // No-op currently.
  return base::Value{base::Value::Type::DICT};
}

}  // namespace runtime_probe
