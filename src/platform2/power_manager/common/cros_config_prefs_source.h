// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_CROS_CONFIG_PREFS_SOURCE_H_
#define POWER_MANAGER_COMMON_CROS_CONFIG_PREFS_SOURCE_H_

#include <memory>
#include <string>

#include <cros_config/cros_config_interface.h>

#include "power_manager/common/prefs.h"

namespace power_manager {

// PrefsSourceInterface implementation that uses libcros_config to read
// preferences.
class CrosConfigPrefsSource : public PrefsSourceInterface {
 public:
  explicit CrosConfigPrefsSource(
      std::unique_ptr<brillo::CrosConfigInterface> config);
  CrosConfigPrefsSource(const CrosConfigPrefsSource&) = delete;
  CrosConfigPrefsSource& operator=(const CrosConfigPrefsSource&) = delete;

  ~CrosConfigPrefsSource() override = default;

  // PrefsSourceInterface:
  std::string GetDescription() const override;
  bool ReadPrefString(const std::string& name, std::string* value_out) override;
  bool ReadExternalString(const std::string& path,
                          const std::string& name,
                          std::string* value_out) override;

 private:
  std::unique_ptr<brillo::CrosConfigInterface> config_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_CROS_CONFIG_PREFS_SOURCE_H_
