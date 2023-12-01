/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FEATURE_PROFILE_H_
#define CAMERA_FEATURES_FEATURE_PROFILE_H_

#include <optional>
#include <string>
#include <vector>

#include <base/values.h>

#include "common/reloadable_config_file.h"
#include "cros-camera/export.h"

namespace cros {

// FeatureProfile is a utility class that parses the device/model specific
// feature profile configs and exposes the feature settings.
//
// Feature config file schema:
//
// {
//   <model>: {
//     "feature_set": [ {
//       "type": <feature_type>,
//       "config_file_path": <config_file_path>,
//       "enable_on" : {
//         "module_id": <optional_module_id>,
//         "sensor_id": <optional_sensor_id>
//       }
//     }, {
//       ...
//     } ]
//   },
//   ...
// }
//
// <model>: String of device model name, e.g. "redrix".
// <feature_type>: String for the type of the feature, e.g. "face_detection"
//                 or "hdrnet".
// <config_file_path>: String specifying the path to the feature config file.
//
// The `enable_on` attribute is optional and is used to selectively enable a
// feature if all the given conditions are met. Currently we support:
//
//   <optional_module_id>: Optional module identifier to selectively enable
//                         the feature on. Matches any module if unspecified.
//   <optional_sensor_id>: Optional sensor identifier to selectively enable
//                         the feature on. Matches any sensor if unspecified.
class CROS_CAMERA_EXPORT FeatureProfile {
 public:
  static constexpr char kFeatureProfileFilePath[] =
      "/etc/camera/feature_profile.json";

  enum class FeatureType {
    // CrOS auto-framing with key "auto_framing".
    kAutoFraming,

    // CrOS face detection with key "face_detection".
    kFaceDetection,

    // CrOS Gcam AE with key "gcam_ae".
    kGcamAe,

    // CrOS HDRnet with key "hdrnet".
    kHdrnet,

    // CrOS Effect with key "effects".
    kEffects,
  };

  struct CameraInfo {
    // Camera module identifier string.
    std::string module_id;

    // Camera sensor identifier string.
    std::string sensor_id;
  };

  struct DeviceMetadata {
    // Device model name as reported by cros_config.
    std::string model_name;

    // List of know camera modules on the device.
    std::vector<CameraInfo> camera_info;
  };

  // Creates a FeatureProfile instance with the given |feature_config| JSON data
  // and |device_config| hardware device configuration.
  //
  // If |feature_config| is nullopt, then by default the config stored in
  // kFeatureProfileFilePath will be loaded. If |device_config| is nullopt, then
  // the default DeviceConfig instance from DeviceConfig::Create() will be used.
  explicit FeatureProfile(
      std::optional<base::Value::Dict> feature_config = std::nullopt,
      std::optional<DeviceMetadata> device_matadata = std::nullopt);

  // Checks if |feature| is enabled.
  bool IsEnabled(FeatureType feature) const;

  // Gets the file path of the feature config file for |feature|. Returns an
  // empty path if there's not config path set for |feature|.
  base::FilePath GetConfigFilePath(FeatureType feature) const;

 private:
  bool ShouldEnableFeature(const base::Value::Dict& feature_descriptor);

  void OnOptionsUpdated(const base::Value::Dict& json_values);

  struct FeatureSetting {
    // File path to the feature config file.
    base::FilePath config_file_path;
  };

  ReloadableConfigFile config_file_;
  std::optional<DeviceMetadata> device_metadata_;

  // The parsed feature settings.
  base::flat_map<FeatureType, FeatureSetting> feature_settings_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_FEATURE_PROFILE_H_
