/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "camera/features/feature_profile.h"

#include <iomanip>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_util.h>

#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/device_config.h"

namespace cros {

namespace {

constexpr char kKeyFeatureSet[] = "feature_set";
constexpr char kKeyType[] = "type";
constexpr char kKeyConfigFilePath[] = "config_file_path";
constexpr char kKeyEnableOn[] = "enable_on";
constexpr char kKeyModuleId[] = "module_id";
constexpr char kKeySensorId[] = "sensor_id";

std::optional<FeatureProfile::FeatureType> GetFeatureType(
    const std::string& feature_key) {
  if (feature_key == "auto_framing") {
    return FeatureProfile::FeatureType::kAutoFraming;
  } else if (feature_key == "face_detection") {
    return FeatureProfile::FeatureType::kFaceDetection;
  } else if (feature_key == "gcam_ae") {
    return FeatureProfile::FeatureType::kGcamAe;
  } else if (feature_key == "hdrnet") {
    return FeatureProfile::FeatureType::kHdrnet;
  } else if (feature_key == "effects") {
    return FeatureProfile::FeatureType::kEffects;
  }
  return std::nullopt;
}

std::optional<FeatureProfile::DeviceMetadata> ProbeDeviceMetadata() {
  auto conf = DeviceConfig::Create();
  if (!conf) {
    return std::nullopt;
  }
  FeatureProfile::DeviceMetadata m = {
      .model_name = conf->GetModelName(),
      .camera_info = {},
  };
  for (const auto& info : conf->GetPlatformCameraInfo()) {
    m.camera_info.push_back(
        {.module_id = info.module_id(), .sensor_id = info.sensor_id()});
  }
  return m;
}

struct EnableConditions {
  const std::string* module_id;
  const std::string* sensor_id;
};

bool HasMatchingCameraModule(const EnableConditions& m,
                             const FeatureProfile::DeviceMetadata& metadata) {
  if (!m.module_id && !m.sensor_id) {
    // Match any camera module if neither module nor sensor id is specified.
    return true;
  }
  for (const auto& d : metadata.camera_info) {
    if (m.module_id && *m.module_id != d.module_id) {
      continue;
    }
    if (m.sensor_id && *m.sensor_id != d.sensor_id) {
      continue;
    }
    return true;
  }
  return false;
}

}  // namespace

FeatureProfile::FeatureProfile(std::optional<base::Value::Dict> feature_config,
                               std::optional<DeviceMetadata> device_metadata)
    : config_file_(ReloadableConfigFile::Options{
          base::FilePath(kFeatureProfileFilePath), base::FilePath()}),
      device_metadata_(device_metadata ? std::move(device_metadata).value()
                                       : ProbeDeviceMetadata()) {
  if (feature_config.has_value()) {
    OnOptionsUpdated(feature_config.value());
  } else {
    config_file_.SetCallback(base::BindRepeating(
        &FeatureProfile::OnOptionsUpdated, base::Unretained(this)));
  }
}

bool FeatureProfile::IsEnabled(FeatureType feature) const {
  switch (feature) {
    case FeatureType::kHdrnet:
    case FeatureType::kGcamAe:
      if (base::PathExists(
              base::FilePath(constants::kForceDisableHdrNetPath))) {
        return false;
      }
      if (base::PathExists(base::FilePath(constants::kForceEnableHdrNetPath))) {
        return true;
      }
      break;
    case FeatureType::kAutoFraming:
      if (base::PathExists(
              base::FilePath(constants::kForceDisableAutoFramingPath))) {
        return false;
      }
      if (base::PathExists(
              base::FilePath(constants::kForceEnableAutoFramingPath))) {
        return true;
      }
      break;
    case FeatureType::kEffects:
      if (base::PathExists(
              base::FilePath(constants::kForceDisableEffectsPath))) {
        return false;
      }
      if (base::PathExists(
              base::FilePath(constants::kForceEnableEffectsPath))) {
        return true;
      }
      break;
    default:
      break;
  }
  return feature_settings_.contains(feature);
}

base::FilePath FeatureProfile::GetConfigFilePath(FeatureType feature) const {
  auto setting = feature_settings_.find(feature);
  if (setting == feature_settings_.end()) {
    return base::FilePath();
  }
  return setting->second.config_file_path;
}

bool FeatureProfile::ShouldEnableFeature(
    const base::Value::Dict& feature_descriptor) {
  const base::Value* enable_on = feature_descriptor.Find(kKeyEnableOn);
  if (!enable_on) {
    return true;
  }
  if (!enable_on->is_dict()) {
    LOGF(ERROR) << "Attribute " << std::quoted(kKeyEnableOn)
                << " must be a dict";
    return false;
  }
  const auto& enable_on_dict = enable_on->GetDict();

  EnableConditions m = {
      .module_id = enable_on_dict.FindString(kKeyModuleId),
      .sensor_id = enable_on_dict.FindString(kKeySensorId),
  };

  if (!HasMatchingCameraModule(m, device_metadata_.value())) {
    return false;
  }

  return true;
}

void FeatureProfile::OnOptionsUpdated(const base::Value::Dict& json_values) {
  if (!device_metadata_.has_value()) {
    LOGF(WARNING) << "Device config is invalid, cannot determine model name";
    return;
  }

  // Get the per-model feature profile from the top-level.
  const base::Value::Dict* feature_profile =
      json_values.FindDict(device_metadata_->model_name);
  if (feature_profile == nullptr) {
    LOGF(INFO) << "Cannot find feature profile as dict for device model "
               << std::quoted(device_metadata_->model_name);
    return;
  }

  // Extract "feature_set" info from the feature profile.
  const base::Value::List* feature_set =
      feature_profile->FindList(kKeyFeatureSet);
  if (feature_set == nullptr) {
    LOGF(ERROR) << "Cannot find " << std::quoted(kKeyFeatureSet)
                << " as list in the feature profile of "
                << std::quoted(device_metadata_->model_name);
    return;
  }

  // Construct the complete feature settings.
  for (const auto& v : *feature_set) {
    if (!v.is_dict()) {
      LOGF(ERROR) << "Feature setting in " << std::quoted(kKeyFeatureSet)
                  << " must be a dict";
      continue;
    }
    const std::string* type_str = v.GetDict().FindString(kKeyType);
    if (type_str == nullptr) {
      LOGF(ERROR) << "Malformed feature setting: Cannot find key "
                  << std::quoted(kKeyType);
      continue;
    }
    std::optional<FeatureType> type = GetFeatureType(*type_str);
    if (!type.has_value()) {
      LOGF(ERROR) << "Unknown feature " << std::quoted(*type_str);
      continue;
    }
    const std::string* path_str = v.GetDict().FindString(kKeyConfigFilePath);
    if (type_str == nullptr) {
      LOGF(ERROR) << "Malformed feature setting: Cannot find key "
                  << std::quoted(kKeyConfigFilePath);
      continue;
    }
    if (!ShouldEnableFeature(v.GetDict())) {
      continue;
    }
    feature_settings_.insert(
        {*type, {.config_file_path = base::FilePath(*path_str)}});
  }
}

}  // namespace cros
