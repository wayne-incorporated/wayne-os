// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libsar/sar_config_reader.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>

namespace libsar {

namespace {

constexpr char kCellular[] = "cellular";
// TODO(b/280013155): Drop it after all boards are updated.
constexpr char kLte[] = "lte";
constexpr char kWifi[] = "wifi";

constexpr int kSystemPathIndexLimit = 100;

}  // namespace

SarConfigReader::SarConfigReader(brillo::CrosConfigInterface* cros_config,
                                 std::string devlink,
                                 Delegate* delegate)
    : cros_config_(cros_config),
      devlink_(std::move(devlink)),
      delegate_(delegate) {}

SarConfigReader::~SarConfigReader() = default;

bool SarConfigReader::isCellular() const {
  return devlink_.find(kCellular) != std::string::npos ||
         devlink_.find(kLte) != std::string::npos;
}

bool SarConfigReader::isWifi() const {
  return devlink_.find(kWifi) != std::string::npos;
}

std::optional<base::Value::Dict> SarConfigReader::GetSarConfigDict() const {
  std::string config_filename = "";
  for (int i = 0; i < kSystemPathIndexLimit; ++i) {
    std::string system_path;
    if (!cros_config_->GetString(
            base::StringPrintf("/proximity-sensor/semtech-config/%i/file", i),
            kSystemPathProperty, &system_path)) {
      // Checked all system paths.
      continue;
    }

    // It should have the format of "/.../semtech_config_|xxx|.json" based on
    // the type.
    std::string system_path_base =
        base::FilePath(system_path).BaseName().value();

    if (isCellular() &&
        (system_path_base.find(kCellular) == std::string::npos &&
         system_path_base.find(kLte) == std::string::npos)) {
      continue;
    }

    if (isWifi() && system_path_base.find(kWifi) == std::string::npos)
      continue;

    config_filename = system_path;
    break;
  }

  if (config_filename.empty()) {
    LOG(ERROR) << "Failed to find the config in CrosConfig";
    return std::nullopt;
  }

  auto config_json_data =
      delegate_->ReadFileToString(base::FilePath(config_filename));
  if (!config_json_data.has_value()) {
    LOG(ERROR) << "Failed to read config from " << config_filename;
    return std::nullopt;
  }

  auto config_root = base::JSONReader::ReadAndReturnValueWithError(
      config_json_data.value(), base::JSON_PARSE_RFC);
  if (!config_root.has_value()) {
    LOG(ERROR) << "Failed to parse : " << config_json_data.value();
    return std::nullopt;
  }
  if (!config_root->is_dict()) {
    LOG(ERROR) << "Failed to parse root dictionary from "
               << config_json_data.value();
    return std::nullopt;
  }

  return std::move(*config_root).TakeDict();
}

}  // namespace libsar
