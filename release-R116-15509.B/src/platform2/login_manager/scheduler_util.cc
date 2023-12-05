// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/scheduler_util.h"

#include <algorithm>
#include <map>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>

namespace {

// Size of the prefix 'cpu'.
constexpr size_t kCpuPrefixSize = 3;

constexpr char kCpuBusDir[] = "/sys/bus/cpu/devices";
constexpr const char* kPerfAttributeFiles[] = {
    "cpu_capacity", "cpufreq/cpuinfo_max_freq", "acpi_cppc/highest_perf"};
constexpr char kCpusetNonUrgentDir[] =
    "/sys/fs/cgroup/cpuset/chrome/non-urgent";

}  // namespace

namespace login_manager {

std::vector<std::string> GetSmallCoreCpuIdsFromAttr(
    const base::FilePath& cpu_bus_dir, base::StringPiece attribute) {
  base::FilePath cpu0_attr_file = cpu_bus_dir.Append("cpu0").Append(attribute);
  if (!base::PathExists(cpu0_attr_file))
    return {};

  // Gets attribute values through traversing the attribute of each cpu, and
  // stores them into a map.
  base::FileEnumerator enumerator(cpu_bus_dir, false /*recursive*/,
                                  base::FileEnumerator::DIRECTORIES);
  std::map<int, std::vector<std::string>> attr_to_cpu_ids_map;

  for (base::FilePath subdir = enumerator.Next(); !subdir.empty();
       subdir = enumerator.Next()) {
    std::string item_str;
    if (base::ReadFileToString(subdir.Append(attribute), &item_str)) {
      std::string subdir_name = subdir.BaseName().value();
      DCHECK_GT(subdir_name.size(), kCpuPrefixSize);

      int item = atoi(item_str.c_str());
      if (item <= 0) {
        LOG(ERROR) << "Invalid value read from " << subdir_name
                   << " attribute file!";
        continue;
      }
      std::string cpu_id = subdir_name.substr(kCpuPrefixSize);

      attr_to_cpu_ids_map[item].emplace_back(cpu_id);
    }
  }

  // If the number of attribute value is 1, the cpu arch is not hybrid, the
  // small core cpu id list is empty.
  if (attr_to_cpu_ids_map.size() <= 1)
    return {};

  auto it = attr_to_cpu_ids_map.begin();
  std::vector<std::string> small_cpu_ids = it->second;
  // If the map has more than 2 attribute values, we consider the cpus with two
  // smallest capacities / freqs as small cores.
  if (attr_to_cpu_ids_map.size() > 2) {
    ++it;
    small_cpu_ids.insert(small_cpu_ids.end(), it->second.begin(),
                         it->second.end());
  }

  std::sort(small_cpu_ids.begin(), small_cpu_ids.end());

  return small_cpu_ids;
}

std::vector<std::string> CalculateSmallCoreCpusIfHybrid(
    const base::FilePath& cpu_bus_dir) {
  // sysfs attributes are probed in order they are appear in
  // #kPerfAttributeFiles
  for (const auto& perf_attr : kPerfAttributeFiles) {
    if (std::vector<std::string> small_cpu_ids =
            GetSmallCoreCpuIdsFromAttr(cpu_bus_dir, perf_attr);
        !small_cpu_ids.empty()) {
      return small_cpu_ids;
    }
  }
  return {};
}

bool ConfigureNonUrgentCpuset(brillo::CrosConfigInterface* cros_config) {
  base::FilePath nonurgent_path(kCpusetNonUrgentDir);
  if (!base::PathExists(nonurgent_path)) {
    LOG(WARNING) << "The path of non-urgent cpuset doesn't exist!";
    return false;
  }

  std::string cpuset_conf;

  // Writes cpuset-nonurgent to non-urgent cpuset if it's specified in
  // cros_config.
  if (cros_config &&
      cros_config->GetString("/scheduler-tune", "cpuset-nonurgent",
                             &cpuset_conf) &&
      !cpuset_conf.empty()) {
    if (!base::WriteFile(nonurgent_path.Append("cpus"), cpuset_conf)) {
      LOG(ERROR) << "Error writing non urgent cpuset!";
      return false;
    }
    LOG(INFO) << "Non-urgent cpuset is " << cpuset_conf << " from cros_config";
    return true;
  }

  // Use all small cores as non-urgent cpuset, if cpuset-nonurgent isn't
  // specified in cros_config.
  std::vector<std::string> ecpu_ids =
      CalculateSmallCoreCpusIfHybrid(base::FilePath(kCpuBusDir));
  if (ecpu_ids.empty())
    return false;

  std::string ecpu_mask = base::JoinString(ecpu_ids, ",");
  LOG(INFO) << "The board has hybrid arch cpu, the non-urgent cpuset is "
            << ecpu_mask << ".";

  if (!base::WriteFile(nonurgent_path.Append("cpus"), ecpu_mask)) {
    LOG(ERROR) << "Error writing mask of small cores to non urgent cpuset!";
    return false;
  }

  return true;
}

}  // namespace login_manager
