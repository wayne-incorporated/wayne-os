// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/mmc_host.h"

#include <set>
#include <string>
#include <utility>

#include <base/files/file_util.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/bus_utils.h"
#include "runtime_probe/utils/file_utils.h"

namespace runtime_probe {

std::set<std::string> GetEmmcAttachedHosts() {
  std::set<std::string> result;
  base::FilePath pattern =
      Context::Get()->root_dir().Append("sys/bus/mmc/devices/*");
  for (const auto& mmc_path : Glob(pattern)) {
    std::string type;
    if (!ReadAndTrimFileToString(mmc_path.Append("type"), type) ||
        type != "MMC") {
      continue;
    }
    base::FilePath mmc_host_path =
        base::MakeAbsoluteFilePath(mmc_path.Append(".."));
    std::string mmc_host_name = mmc_host_path.BaseName().value();
    result.insert(mmc_host_name);
  }
  return result;
}

MmcHostFunction::DataType MmcHostFunction::EvalImpl() const {
  DataType results;

  std::set<std::string> mmc_attached_hosts = GetEmmcAttachedHosts();
  base::FilePath pattern =
      Context::Get()->root_dir().Append("sys/class/mmc_host/*");
  for (const auto& mmc_host_path : Glob(pattern)) {
    auto node_res = GetDeviceBusDataFromSysfsNode(mmc_host_path);
    if (!node_res) {
      continue;
    }
    std::string mmc_host_name = mmc_host_path.BaseName().value();
    bool is_emmc_attached = mmc_attached_hosts.count(mmc_host_name);
    if (!is_emmc_attached_.has_value() ||
        is_emmc_attached_ == is_emmc_attached) {
      node_res->GetDict().Set("is_emmc_attached", is_emmc_attached ? "1" : "0");
      results.Append(std::move(*node_res));
    }
  }

  return results;
}

}  // namespace runtime_probe
