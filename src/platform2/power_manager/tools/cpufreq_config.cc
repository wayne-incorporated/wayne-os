// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <optional>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/process/process.h>
#include <libec/ec_command_factory.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/power_supply.h"
#include "power_manager/powerd/system/udev_stub.h"

namespace {

const char kCpufreqConfPath[] = "/etc/cpufreq.conf";
const char kKeyGovernor[] = "CPUFREQ_GOVERNOR";
const char kKeyGovernorCharging[] = "CPUFREQ_GOVERNOR_BATTERY_CHARGE";
const char kKeyGovernorDischarging[] = "CPUFREQ_GOVERNOR_BATTERY_DISCHARGE";

const char kCpuBaseDir[] = "/sys/devices/system/cpu";
const char kCpufreqDir[] = "/sys/devices/system/cpu/cpufreq";

const char kSELinuxEnforcePath[] = "/sys/fs/selinux/enforce";

class CpufreqConf {
 public:
  explicit CpufreqConf(std::string path);
  std::optional<std::string> GetValue(std::string key) const;

 private:
  base::StringPairs pairs_;
};

CpufreqConf::CpufreqConf(std::string path) {
  std::string contents;
  if (!base::ReadFileToString(base::FilePath(path), &contents)) {
    PLOG(ERROR) << "Failed to read file: " << path;
    return;
  }

  base::SplitStringIntoKeyValuePairs(contents, '=', '\n', &pairs_);
  // Shell-like syntax, so strip any quotes.
  for (auto& pair : pairs_) {
    base::TrimString(pair.second, "\"", &pair.second);
  }
}

std::optional<std::string> CpufreqConf::GetValue(std::string key) const {
  for (const auto& pair : pairs_)
    if (key == pair.first)
      return pair.second;

  return std::nullopt;
}

bool BatteryStateIsCharging() {
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  power_manager::Prefs prefs;
  CHECK(prefs.Init(power_manager::Prefs::GetDefaultStore(),
                   power_manager::Prefs::GetDefaultSources()));

  power_manager::system::UdevStub udev;
  power_manager::system::DBusWrapperStub dbus_wrapper;
  base::FilePath path(power_manager::kPowerStatusPath);
  base::FilePath cros_ec_path(ec::kCrosEcPath);
  ec::EcCommandFactory ec_command_factory;

  auto battery_percentage_converter =
      power_manager::BatteryPercentageConverter::CreateFromPrefs(&prefs);

  power_manager::system::PowerSupply power_supply;
  power_supply.Init(path, cros_ec_path, &ec_command_factory, &prefs, &udev,
                    &dbus_wrapper, battery_percentage_converter.get());

  CHECK(power_supply.RefreshImmediately());
  const power_manager::system::PowerStatus status =
      power_supply.GetPowerStatus();

  // Other values (e.g., FULL, NOT_PRESENT, and CHARGING) all mean we're OK to
  // use "high power."
  return status.battery_state !=
         power_manager::PowerSupplyProperties_BatteryState_DISCHARGING;
}

// Determine which governor we should use.
std::optional<std::string> GetGovernor(const CpufreqConf& conf) {
  auto governor = conf.GetValue(kKeyGovernor);
  if (governor.has_value())
    return governor;

  // No (fixed) governor? Look for charge/discharge choices.

  std::string key;
  if (BatteryStateIsCharging()) {
    key = kKeyGovernorCharging;
  } else {
    key = kKeyGovernorDischarging;
  }
  return conf.GetValue(key);
}

// Set governor for all CPUs.
bool SetGovernor(const std::string& governor) {
  bool ret = true;
  base::FileEnumerator enumerator(base::FilePath(kCpuBaseDir), false,
                                  base::FileEnumerator::DIRECTORIES,
                                  "cpu[0-9]*");
  for (auto file = enumerator.Next(); !file.empty(); file = enumerator.Next()) {
    base::FilePath cpufreqPath = file.Append("cpufreq");
    if (!base::PathExists(cpufreqPath))
      continue;

    base::FilePath governorPath = cpufreqPath.Append("scaling_governor");
    if (!base::WriteFile(governorPath, governor)) {
      PLOG(ERROR) << "Failed to write " << governor << " to " << governorPath;
      ret = false;
    }
  }

  return ret;
}

std::optional<std::string> GetConfigValue(const CpufreqConf& conf,
                                          const std::string& setting) {
  return conf.GetValue("CPUFREQ_" + base::ToUpperASCII(setting));
}

// Optionally write a setting in a multi-policy directory structure.
// If the setting isn't found in the conf file or not available on the
// system, ignore it.
bool MultiPolicySetOptional(const CpufreqConf& conf,
                            const std::string& setting) {
  std::optional<std::string> value = GetConfigValue(conf, setting);
  if (!value.has_value())
    return true;

  base::FileEnumerator enumerator(base::FilePath(kCpuBaseDir), false,
                                  base::FileEnumerator::DIRECTORIES,
                                  "cpu[0-9]*");
  for (auto file = enumerator.Next(); !file.empty(); file = enumerator.Next()) {
    base::FilePath path = file.Append("cpufreq").Append(setting);
    if (!base::PathExists(path))
      continue;
    if (!base::WriteFile(path, value.value())) {
      PLOG(ERROR) << "Failed to write " << setting << " to " << path;
      return false;
    }
  }

  return true;
}

// Set a governor-specific setting, optionally. If the setting isn't found in
// the conf file, or it's not available on the system, ignore it.
bool GovernorSetOptional(const CpufreqConf& conf,
                         const std::string& governor,
                         const std::string& setting) {
  std::optional<std::string> value = GetConfigValue(conf, setting);
  if (!value.has_value())
    return true;

  base::FilePath path =
      base::FilePath(kCpufreqDir).Append(governor).Append(setting);

  if (base::PathExists(path)) {
    if (!base::WriteFile(path, value.value())) {
      PLOG(ERROR) << "Failed to write " << setting << " to " << path;
      return false;
    }
  } else {
    base::FileEnumerator enumerator(base::FilePath(kCpufreqDir), false,
                                    base::FileEnumerator::DIRECTORIES,
                                    "policy[0-9]*");
    for (auto file = enumerator.Next(); !file.empty();
         file = enumerator.Next()) {
      path = file.Append(governor).Append(setting);

      if (!base::PathExists(path))
        continue;
      if (!base::WriteFile(path, value.value())) {
        PLOG(ERROR) << "Failed to write " << setting << " to " << path;
        return false;
      }
    }
  }

  return true;
}

// These are settings specific to the intel_pstate driver.
bool ConfigureIntelPstate(const CpufreqConf& conf) {
  const std::vector<std::string> settings = {
      "energy_performance_preference",
  };
  bool ret = true;

  for (const auto& setting : settings) {
    if (!MultiPolicySetOptional(conf, setting))
      ret = false;
  }

  return ret;
}

bool GovernorIsConfigurable(std::string governor) {
  const std::vector<std::string> configurableGovernors = {
      "interactive",
      "ondemand",
      "conservative",
      "schedutil",
  };

  for (const auto& cg : configurableGovernors) {
    if (cg == governor)
      return true;
  }

  return false;
}

bool ConfigureGovernorSettings(const CpufreqConf& conf, std::string governor) {
  const std::vector<std::string> settings = {
      // "interactive" settings:
      "input_boost",
      "above_hispeed_delay",
      "go_hispeed_load",
      "hispeed_freq",
      "min_sample_time",
      "target_loads",
      "timer_rate",

      // "ondemand" settings:
      "sampling_rate",
      "up_threshold",
      "ignore_nice_load",
      "io_is_busy",
      "sampling_down_factor",
      "powersave_bias",

      // "conservative" settings:
      "freq_step",
      "down_threshold",

      // "schedutil" settings:
      "rate_limit_us",
  };
  bool ret = true;

  for (const auto& setting : settings) {
    if (!GovernorSetOptional(conf, governor, setting))
      ret = false;
  }

  return ret;
}

// Restores SELinux context on destruction.
struct SELinuxRestorer {
  ~SELinuxRestorer() {
    if (!base::PathExists(base::FilePath(kSELinuxEnforcePath)))
      return;

    brillo::ProcessImpl p;

    p.SetSearchPath(true);

    p.AddArg("restorecon");
    p.AddArg("-R");
    p.AddArg(kCpuBaseDir);

    int ret = p.Run();
    if (ret != 0)
      LOG(ERROR) << "restorecon failed with exit code: " << ret;
  }
};

}  // namespace

int main(int argc, char* argv[]) {
  if (!base::PathExists(base::FilePath(kCpufreqConfPath)))
    return 0;

  CpufreqConf conf(kCpufreqConfPath);

  if (!ConfigureIntelPstate(conf)) {
    LOG(ERROR) << "Failed to configure intel_pstate settings";
    return EXIT_FAILURE;
  }

  std::optional<std::string> governorOption = GetGovernor(conf);
  // No governor == do nothing.
  if (!governorOption.has_value())
    return 0;
  std::string& governor = governorOption.value();

  // In case we do any useful work (even in failure), prepare to clean up.
  SELinuxRestorer selinux;

  if (!SetGovernor(governor)) {
    LOG(ERROR) << "Could not set governor: " << governor;
    return EXIT_FAILURE;
  }

  if (GovernorIsConfigurable(governor) &&
      !ConfigureGovernorSettings(conf, governor)) {
    LOG(ERROR) << "Failed to configure " << governor << " settings";
    return EXIT_FAILURE;
  }

  return 0;
}
