// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/cros_ec_prefs_source.h"

#include <fcntl.h>

#include <utility>

#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>

#include "power_manager/common/power_constants.h"

namespace power_manager {
namespace {

std::unique_ptr<ec::DisplayStateOfChargeCommand>
CreateDisplayStateOfChargeCommand() {
  base::ScopedFD ec_fd(open(ec::kCrosEcPath, O_RDWR));
  if (!ec_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
    return nullptr;
  }

  auto cmd = std::make_unique<ec::DisplayStateOfChargeCommand>();
  if (cmd->Run(ec_fd.get()))
    return cmd;

  return nullptr;
}

}  // namespace

CrosEcPrefsSource::CrosEcPrefsSource()
    : CrosEcPrefsSource(CreateDisplayStateOfChargeCommand()) {}

CrosEcPrefsSource::CrosEcPrefsSource(
    std::unique_ptr<ec::DisplayStateOfChargeCommand> cmd) {
  if (cmd) {
    low_battery_shutdown_percent_ = cmd->ShutdownPercentCharge();
    power_supply_full_factor_ = cmd->FullFactor();
  }
}

// static
bool CrosEcPrefsSource::IsSupported() {
  return base::PathExists(base::FilePath(ec::kCrosEcPath));
}

std::string CrosEcPrefsSource::GetDescription() const {
  return "<cros_ec>";
}

bool CrosEcPrefsSource::ReadPrefString(const std::string& name,
                                       std::string* value_out) {
  if (low_battery_shutdown_percent_ && name == kLowBatteryShutdownPercentPref) {
    *value_out = base::NumberToString(*low_battery_shutdown_percent_);
    return true;
  }
  if (power_supply_full_factor_ && name == kPowerSupplyFullFactorPref) {
    *value_out = base::NumberToString(*power_supply_full_factor_);
    return true;
  }
  return false;
}

bool CrosEcPrefsSource::ReadExternalString(const std::string& path,
                                           const std::string& name,
                                           std::string* value_out) {
  return false;
}

}  // namespace power_manager
