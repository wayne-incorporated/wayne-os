// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_CROS_EC_PREFS_SOURCE_H_
#define POWER_MANAGER_COMMON_CROS_EC_PREFS_SOURCE_H_

#include <memory>
#include <string>

#include <libec/display_soc_command.h>

#include "power_manager/common/prefs.h"

namespace power_manager {

// PrefsSourceInterface implementation that reflects prefs controlled by the EC.
class CrosEcPrefsSource : public PrefsSourceInterface {
 public:
  CrosEcPrefsSource();

  // Injectable command for testing.
  explicit CrosEcPrefsSource(
      std::unique_ptr<ec::DisplayStateOfChargeCommand> cmd);

  CrosEcPrefsSource(const CrosEcPrefsSource&) = delete;
  CrosEcPrefsSource& operator=(const CrosEcPrefsSource&) = delete;

  ~CrosEcPrefsSource() override = default;

  static bool IsSupported();

  // PrefsSourceInterface:
  std::string GetDescription() const override;
  bool ReadPrefString(const std::string& name, std::string* value_out) override;
  bool ReadExternalString(const std::string& path,
                          const std::string& name,
                          std::string* value_out) override;

 private:
  std::optional<double> low_battery_shutdown_percent_;
  std::optional<double> power_supply_full_factor_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_CROS_EC_PREFS_SOURCE_H_
