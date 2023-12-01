// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_CPU_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_CPU_FETCHER_H_

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>

#include "diagnostics/cros_healthd/executor/constants.h"
#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/cros_healthd/mojom/executor.mojom.h"
#include "diagnostics/cros_healthd/utils/callback_barrier.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"

namespace diagnostics {

// Directory containing SoC ID info.
inline constexpr char kRelativeSoCDevicesDir[] = "sys/bus/soc/devices/";
// File containing Arm device tree compatible string.
inline constexpr char kRelativeCompatibleFile[] =
    "sys/firmware/devicetree/base/compatible";

// Relative path from root of the CPU directory.
inline constexpr char kRelativeCpuDir[] = "sys/devices/system/cpu";
// File read from the CPU directory.
inline constexpr char kPresentFileName[] = "present";
// Files read from the C-state directory.
inline constexpr char kCStateNameFileName[] = "name";
inline constexpr char kCStateTimeFileName[] = "time";
// Files read from the CPU policy directory.
inline constexpr char kScalingMaxFreqFileName[] = "scaling_max_freq";
inline constexpr char kScalingCurFreqFileName[] = "scaling_cur_freq";
inline constexpr char kCpuinfoMaxFreqFileName[] = "cpuinfo_max_freq";
// Path from relative cpu dir to the vulnerabilities directory.
inline constexpr char kVulnerabilityDirName[] = "vulnerabilities";
// Path from relative cpu dir to the SMT directory.
inline constexpr char kSmtDirName[] = "smt";
// File to find the status of SMT.
inline constexpr char kSmtActiveFileName[] = "active";
inline constexpr char kSmtControlFileName[] = "control";

// File to read Keylocker information.
inline constexpr char kRelativeCryptoFilePath[] = "proc/crypto";

// File to see if KVM exists.
inline constexpr char kRelativeKvmFilePath[] = "dev/kvm";

// The different bits that indicates what kind of CPU virtualization is enabled
// and locked.
inline constexpr uint64_t kIA32FeatureLocked = 1llu << 0;
inline constexpr uint64_t kIA32FeatureEnableVmxInsideSmx = 1llu << 1;
inline constexpr uint64_t kIA32FeatureEnableVmxOutsideSmx = 1llu << 2;
inline constexpr uint64_t kVmCrLockedBit = 1llu << 3;
inline constexpr uint64_t kVmCrSvmeDisabledBit = 1llu << 4;

// Returns an absolute path to the C-state directory for the logical CPU with ID
// |logical_id|. On a real device, this will be
// /sys/devices/system/cpu/cpu|logical_id|/cpuidle.
base::FilePath GetCStateDirectoryPath(const base::FilePath& root_dir,
                                      int logical_id);

// Returns an absolute path to the CPU freq directory for the logical CPU with
// ID |logical_id|. On a real device, this will be
// /sys/devices/system/cpu/cpufreq/policy|logical_id| if the CPU has a governing
// policy, or /sys/devices/system/cpu/|logical_id|/cpufreq without.
base::FilePath GetCpuFreqDirectoryPath(const base::FilePath& root_dir,
                                       int logical_id);

// Returns an absolute path to the CPU Physical package ID file for the logical
// CPU with ID |logical_id|. On a real device, this will be
// /sys/devices/system/cpu/cpu|logical_id|/topology/physical_package_id.
base::FilePath GetPhysicalPackageIdPath(const base::FilePath& root_dir,
                                        int logical_id);

// Returns an absolute path to the CPU Core ID file for the logical CPU with ID
// |logical_id|. On a real device, this will be
// /sys/devices/system/cpu/cpu|logical_id|/topology/core_id.
base::FilePath GetCoreIdPath(const base::FilePath& root_dir, int logical_id);

// Returns the parsed vulnerability status from reading the vulnerability
// message. This function is exported for testing.
ash::cros_healthd::mojom::VulnerabilityInfo::Status
GetVulnerabilityStatusFromMessage(const std::string& message);

using FetchCpuInfoCallback =
    base::OnceCallback<void(ash::cros_healthd::mojom::CpuResultPtr)>;

// Fetches cpu info and pass the result to the callback. Returns either a
// structure with the cpu information or the error that occurred fetching the
// information.
void FetchCpuInfo(Context* context, FetchCpuInfoCallback callback);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_CPU_FETCHER_H_
