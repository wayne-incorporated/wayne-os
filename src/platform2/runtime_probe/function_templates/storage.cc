// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/function_templates/storage.h"

#include <optional>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/strings/string_utils.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/file_utils.h"
#include "runtime_probe/utils/type_utils.h"

namespace runtime_probe {
namespace {
constexpr auto kStorageDirPath("sys/class/block/*");
constexpr auto kReadFileMaxSize = 1024;
constexpr auto kDefaultBytesPerSector = 512;

// Get paths of all non-removeable physical storage.
std::vector<base::FilePath> GetFixedDevices() {
  std::vector<base::FilePath> res{};
  const auto rooted_storage_dir_pattern =
      Context::Get()->root_dir().Append(kStorageDirPath);
  for (const auto& storage_path : Glob(rooted_storage_dir_pattern)) {
    // Only return non-removable devices.
    const auto storage_removable_path = storage_path.Append("removable");
    std::string removable_res;
    if (!base::ReadFileToString(storage_removable_path, &removable_res)) {
      VLOG(2) << "Storage device " << storage_path.value()
              << " does not specify the removable property. May be a partition "
                 "of a storage device.";
      continue;
    }

    if (base::TrimWhitespaceASCII(removable_res,
                                  base::TrimPositions::TRIM_ALL) != "0") {
      VLOG(2) << "Storage device " << storage_path.value() << " is removable.";
      continue;
    }

    // Skip loopback or dm-verity device.
    if (base::StartsWith(storage_path.BaseName().value(), "loop",
                         base::CompareCase::SENSITIVE) ||
        base::StartsWith(storage_path.BaseName().value(), "dm-",
                         base::CompareCase::SENSITIVE))
      continue;

    res.push_back(storage_path);
  }

  return res;
}

// Get storage size based on |node_path|.
std::optional<int64_t> GetStorageSectorCount(const base::FilePath& node_path) {
  // The sysfs entry for size info.
  const auto size_path = node_path.Append("size");
  std::string size_content;
  if (!base::ReadFileToStringWithMaxSize(size_path, &size_content,
                                         kReadFileMaxSize)) {
    LOG(WARNING) << "Storage device " << node_path.value()
                 << " does not specify size.";
    return std::nullopt;
  }

  int64_t sector_int;
  if (!StringToInt64(size_content, &sector_int)) {
    LOG(ERROR) << "Failed to parse recorded sector of" << node_path.value()
               << " to integer!";
    return std::nullopt;
  }

  return sector_int;
}

}  // namespace

StorageFunction::DataType StorageFunction::EvalImpl() const {
  const auto storage_nodes_path_list = GetFixedDevices();
  StorageFunction::DataType result{};

  for (const auto& node_path : storage_nodes_path_list) {
    VLOG(2) << "Processing the node " << node_path.value();

    // Get type specific fields and their values.
    auto node_res = ProbeFromSysfs(node_path);
    if (!node_res || !node_res->is_dict())
      continue;

    // Report the absolute path we probe the reported info from.
    auto& dict = node_res->GetDict();
    dict.Set("path", node_path.value());

    // Get size of storage.
    const auto sector_count = GetStorageSectorCount(node_path);
    if (!sector_count) {
      dict.Set("sectors", "-1");
      dict.Set("size", "-1");
    } else {
      dict.Set("sectors", base::NumberToString(sector_count.value()));
      dict.Set("size", base::NumberToString(sector_count.value() *
                                            kDefaultBytesPerSector));
    }

    result.Append(std::move(*node_res));
  }

  return result;
}

void StorageFunction::PostHelperEvalImpl(
    StorageFunction::DataType* result) const {
  for (auto& storage_res : *result) {
    auto& dict = storage_res.GetDict();
    auto* node_path = dict.FindString("path");
    if (!node_path) {
      LOG(ERROR) << "No path in storage probe result";
      continue;
    }
    auto storage_aux_res = ProbeFromStorageTool(base::FilePath(*node_path));
    if (storage_aux_res)
      dict.Merge(std::move(storage_aux_res->GetDict()));
  }
}

}  // namespace runtime_probe
