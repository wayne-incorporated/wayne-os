// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/suspend_configurator.h"

#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/util.h"

namespace power_manager::system {

constexpr char kCpuInfoPath[] = "/proc/cpuinfo";
constexpr char kCryptoPath[] = "/proc/crypto";

// The feature name for Hibernate gradual rollout and experiments.
constexpr char kSuspendToHibernateFeatureName[] =
    "CrOSLateBootSuspendToHibernate";

// Path to read to figure out the hibernation resume device.
// This file is absent on kernels without hibernation support.
constexpr char kSnapshotDevicePath[] = "/dev/snapshot";

// Path to the hiberman executable responsible for coordinating hibernate/resume
// activities.
constexpr char kHibermanExecutablePath[] = "/usr/sbin/hiberman";

namespace {
// Path to write to configure system suspend mode.
static constexpr char kSuspendModePath[] = "/sys/power/mem_sleep";

// suspend to idle (S0iX) suspend mode
static constexpr char kSuspendModeFreeze[] = "s2idle";

// shallow/standby(S1) suspend mode
static constexpr char kSuspendModeShallow[] = "shallow";

// deep sleep(S3) suspend mode
static constexpr char kSuspendModeDeep[] = "deep";

// Last resume result as reported by ChromeOS EC.
static constexpr char kECLastResumeResultPath[] =
    "/sys/kernel/debug/cros_ec/last_resume_result";

// Bit that is set in |kECLastResumeResultPath| when EC times out waiting for AP
// s0ix transition after suspend.  Please look at
// Documentation/ABI/testing/debugfs-cros-ec kernel documentation for more info.
static constexpr unsigned kECResumeResultHangBit = 1 << 31;
}  // namespace

const VariationsFeature kSuspendToHibernateFeature{
    kSuspendToHibernateFeatureName, FEATURE_DISABLED_BY_DEFAULT};

// Static.
const base::FilePath SuspendConfigurator::kConsoleSuspendPath(
    "/sys/module/printk/parameters/console_suspend");

void SuspendConfigurator::Init(
    feature::PlatformFeaturesInterface* platform_features,
    PrefsInterface* prefs) {
  DCHECK(prefs);
  platform_features_ = platform_features;
  prefs_ = prefs;
  ConfigureConsoleForSuspend();
  ReadSuspendMode();
}

// TODO(crbug.com/941298) Move powerd_suspend script here eventually.
void SuspendConfigurator::PrepareForSuspend(
    const base::TimeDelta& suspend_duration) {
  base::FilePath suspend_mode_path = base::FilePath(kSuspendModePath);
  if (!base::PathExists(GetPrefixedFilePath(suspend_mode_path))) {
    LOG(INFO) << "File " << kSuspendModePath
              << " does not exist. Not configuring suspend mode";
  } else if (base::WriteFile(GetPrefixedFilePath(suspend_mode_path),
                             suspend_mode_.c_str(),
                             suspend_mode_.size()) != suspend_mode_.size()) {
    PLOG(ERROR) << "Failed to write " << suspend_mode_ << " to "
                << kSuspendModePath;
  } else {
    LOG(INFO) << "Suspend mode configured to " << suspend_mode_;
  }

  // Do this at the end so that system spends close to |suspend_duration| in
  // suspend.
  if (!alarm_) {
    LOG(ERROR) << "System doesn't support CLOCK_REALTIME_ALARM.";
    return;
  }
  if (suspend_duration != base::TimeDelta()) {
    alarm_->Start(FROM_HERE, suspend_duration, base::DoNothing());
  }
}

bool SuspendConfigurator::UndoPrepareForSuspend() {
  base::FilePath resume_result_path =
      GetPrefixedFilePath(base::FilePath(kECLastResumeResultPath));
  unsigned resume_result = 0;
  if (base::PathExists(resume_result_path) &&
      util::ReadHexUint32File(resume_result_path, &resume_result) &&
      resume_result & kECResumeResultHangBit) {
    // EC woke the system due to SLP_S0 transition timeout.
    LOG(INFO) << "Suspend failure. EC woke the system due to a timeout when "
                 "watching for SLP_S0 transitions";
    return false;
  }
  return true;
}

bool SuspendConfigurator::IsHibernateAvailable() {
  // Check if the hiberman binary is available on the device.
  base::FilePath snapshot_device_path =
      GetPrefixedFilePath(base::FilePath(kSnapshotDevicePath));
  base::FilePath hiberman_executable_path =
      GetPrefixedFilePath(base::FilePath(kHibermanExecutablePath));

  if (base::PathExists(snapshot_device_path) &&
      base::PathExists(hiberman_executable_path)) {
    LOG(INFO) << "Hibernate binary is available";
  } else {
    LOG(INFO) << "Hibernate binary is not available on this machine";
    return false;
  }

  // Systems with Keylocker can only suspend to S4. S4 is not an allowed
  // transition for hibernate at the moment, so any system with AESKL will be
  // unable to hibernate. We're disabling hibernate when using AESKL.
  if (HasAESKL()) {
    LOG(INFO) << "Hibernate is not available: system has aeskl.";
    return false;
  }

  return IsHibernateEnabled();
}

bool SuspendConfigurator::IsHibernateEnabled() {
  return platform_features_->IsEnabledBlocking(kSuspendToHibernateFeature);
}

void SuspendConfigurator::ConfigureConsoleForSuspend() {
  bool pref_val = true;
  bool enable_console = true;

  // Limit disabling console for S0iX to Intel CPUs (b/175428322).
  if (HasIntelCpu()) {
    if (IsSerialConsoleEnabled()) {
      // If S0iX is enabled, default to disabling console (b/63737106).
      if (prefs_->GetBool(kSuspendToIdlePref, &pref_val) && pref_val)
        enable_console = false;
    }
  }

  // Overwrite the default if the pref is set.
  if (prefs_->GetBool(kEnableConsoleDuringSuspendPref, &pref_val))
    enable_console = pref_val;

  const char console_suspend_val = enable_console ? 'N' : 'Y';
  base::FilePath console_suspend_path =
      GetPrefixedFilePath(SuspendConfigurator::kConsoleSuspendPath);
  if (base::WriteFile(console_suspend_path, &console_suspend_val, 1) != 1) {
    PLOG(ERROR) << "Failed to write " << console_suspend_val << " to "
                << console_suspend_path.value();
  }
  LOG(INFO) << "Console during suspend is "
            << (enable_console ? "enabled" : "disabled");
}

void SuspendConfigurator::ReadSuspendMode() {
  bool pref_val = true;

  // If s2idle is enabled, we write "freeze" to "/sys/power/state". Let us also
  // write "s2idle" to "/sys/power/mem_sleep" just to be safe.
  if (prefs_->GetBool(kSuspendToIdlePref, &pref_val) && pref_val) {
    suspend_mode_ = kSuspendModeFreeze;
  } else if (prefs_->GetString(kSuspendModePref, &suspend_mode_)) {
    if (suspend_mode_ != kSuspendModeDeep &&
        suspend_mode_ != kSuspendModeShallow &&
        suspend_mode_ != kSuspendModeFreeze) {
      LOG(WARNING) << "Invalid suspend mode pref : " << suspend_mode_;
      suspend_mode_ = kSuspendModeDeep;
    }
  } else {
    suspend_mode_ = kSuspendModeDeep;
  }
}

base::FilePath SuspendConfigurator::GetPrefixedFilePath(
    const base::FilePath& file_path) const {
  if (prefix_path_for_testing_.empty())
    return file_path;
  DCHECK(file_path.IsAbsolute());
  return prefix_path_for_testing_.Append(file_path.value().substr(1));
}

bool SuspendConfigurator::IsSerialConsoleEnabled() {
  std::string contents;

  if (!base::ReadFileToString(base::FilePath("/proc/consoles"), &contents)) {
    return false;
  }

  std::vector<std::string> consoles = base::SplitString(
      contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  bool rc = false;

  for (const std::string& con : consoles) {
    if (base::StartsWith(con, "ttynull", base::CompareCase::SENSITIVE)) {
      continue;
    } else if (base::StartsWith(con, "tty", base::CompareCase::SENSITIVE)) {
      rc = true;
      break;
    }
  }

  return rc;
}

bool SuspendConfigurator::HasAESKL() {
  base::FilePath file_path = GetPrefixedFilePath(base::FilePath(kCryptoPath));

  std::string crypto_info;
  if (!base::ReadFileToString(base::FilePath(file_path), &crypto_info)) {
    PLOG(ERROR) << "Failed to read from: " << file_path;
    return false;
  }

  return (crypto_info.find("aeskl") != std::string::npos);
}

bool SuspendConfigurator::ReadCpuInfo(std::string& cpuInfo) {
  base::FilePath cpuInfoPath =
      GetPrefixedFilePath(base::FilePath(kCpuInfoPath));

  if (!base::ReadFileToString(base::FilePath(cpuInfoPath), &cpuInfo)) {
    LOG(WARNING) << "Failed to read from: " << cpuInfoPath;
    return false;
  }
  return true;
}

bool SuspendConfigurator::HasIntelCpu() {
  std::string contents;

  if (!ReadCpuInfo(contents)) {
    return false;
  }

  std::vector<std::string> lines = base::SplitString(
      contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const std::string& line : lines) {
    if (base::StartsWith(line, "vendor_id", base::CompareCase::SENSITIVE)) {
      std::vector<std::string> vendorIdInfo = base::SplitString(
          line, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
      if (vendorIdInfo.size() != 2 || vendorIdInfo[0] != "vendor_id") {
        LOG(WARNING) << "Unexpected vendor_id format detected";
        continue;
      }
      // Found a vendor_id label. Assume other vendor_id labels have the same
      // value.
      return vendorIdInfo[1] == "GenuineIntel";
    }
  }
  LOG(WARNING) << "No vendor_id found";
  return false;
}

}  // namespace power_manager::system
