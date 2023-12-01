// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/common/cros_config_prefs_source.h"

#include <base/strings/string_util.h>
#include <utility>

namespace {
constexpr char kPowerConfigPath[] = "/power";
}

namespace power_manager {

CrosConfigPrefsSource::CrosConfigPrefsSource(
    std::unique_ptr<brillo::CrosConfigInterface> config)
    : config_(std::move(config)) {}

std::string CrosConfigPrefsSource::GetDescription() const {
  return "<cros_config>";
}

bool CrosConfigPrefsSource::ReadPrefString(const std::string& name,
                                           std::string* value_out) {
  std::string prop_name;
  base::ReplaceChars(name, "_", "-", &prop_name);
  if (!config_->GetString(kPowerConfigPath, prop_name, value_out))
    return false;

  // Trim trailing whitespace to match FilePrefsStore::ReadPrefString().
  base::TrimWhitespaceASCII(*value_out, base::TRIM_TRAILING, value_out);
  return true;
}

bool CrosConfigPrefsSource::ReadExternalString(const std::string& path,
                                               const std::string& name,
                                               std::string* value_out) {
  if (!config_->GetString(path, name, value_out))
    return false;

  // Trim trailing whitespace to be consistent with ReadPrefString().
  base::TrimWhitespaceASCII(*value_out, base::TRIM_TRAILING, value_out);
  return true;
}

}  // namespace power_manager
