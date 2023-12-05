// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SCHEDULER_UTIL_H_
#define LOGIN_MANAGER_SCHEDULER_UTIL_H_

#include <string>
#include <vector>

#include <chromeos-config/libcros_config/cros_config_interface.h>

namespace base {
class FilePath;
}

namespace login_manager {

// Implementation func to retrieve a small core cpu id list based on the
// provided attribute. If there are more than two unique attribute values read
// from the cpu set, the cpus with two smallest values are returned.
// For example: [cpu0 : 166, cpu1: 186, cpu2: 186, cpu3: 171] --> cpu0, cpu3
// Returns non-empty cpu id list on success. Returns an empty list on any error
// or non-hybrid cpu arch.
std::vector<std::string> GetSmallCoreCpuIdsFromAttr(
    const base::FilePath& cpu_bus_dir, base::StringPiece attribute);

// Detects whether or not the system is running on a hybrid cpu architecture by
// reading various cpu attributes in sysfs. If any of the attributes differ
// between cpus, the lower performing cpus are returned.
// sysfs attributes are probed in the following order:
// - cpu_capacity
// - cpuinfo_max_freq
// - highest_perf (CPPC)
// It calls the impl func GetSmallCoreCpuIdsFromAttr to perform the
// calculations.
// Returns non-empty cpu id list on success. Returns an empty list on any error
// or non-hybrid cpu arch.
std::vector<std::string> CalculateSmallCoreCpusIfHybrid(
    const base::FilePath& cpu_bus_dir);

// If the cpu arch is hybrid, writes the mask of small cores to non-urgent
// cpuset and restricts non-urgent threads to small cores.
// Returns true on success.
bool ConfigureNonUrgentCpuset(brillo::CrosConfigInterface* cros_config);

}  // namespace login_manager

#endif  // LOGIN_MANAGER_SCHEDULER_UTIL_H_
