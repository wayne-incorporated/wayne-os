// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include <base/base64.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/process/process.h>

#include "libsegmentation/device_info.pb.h"
#include "libsegmentation/feature_management_interface.h"
#include "libsegmentation/feature_management_util.h"

namespace segmentation {

// Writes |device_info| as base64 to |file_path|. Returns false if the write
// isn't successful.
std::optional<libsegmentation::DeviceInfo>
FeatureManagementUtil::ReadDeviceInfoFromFile(const base::FilePath& file_path) {
  std::string encoded;
  if (!base::ReadFileToString(file_path, &encoded)) {
    LOG(ERROR) << "Failed to read protobuf string from file: " << file_path;
    return std::nullopt;
  }

  // The value is expected to be in the base64 format.
  std::string decoded;
  base::Base64Decode(encoded, &decoded);
  libsegmentation::DeviceInfo device_info;
  if (!device_info.ParseFromString(decoded)) {
    LOG(ERROR) << "Failed to parse device info from the protobuf";
    return std::nullopt;
  }
  return device_info;
}

bool FeatureManagementUtil::WriteDeviceInfoToFile(
    const libsegmentation::DeviceInfo& device_info,
    const base::FilePath& file_path) {
  std::string serialized = device_info.SerializeAsString();
  std::string base64_encoded;
  base::Base64Encode(serialized, &base64_encoded);
  return base::WriteFile(file_path, base64_encoded);
}

FeatureManagementInterface::FeatureLevel
FeatureManagementUtil::ConvertProtoFeatureLevel(
    libsegmentation::DeviceInfo_FeatureLevel feature_level) {
  switch (feature_level) {
    case libsegmentation::DeviceInfo_FeatureLevel::
        DeviceInfo_FeatureLevel_FEATURE_LEVEL_UNKNOWN:
      return FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_UNKNOWN;
    case libsegmentation::DeviceInfo_FeatureLevel::
        DeviceInfo_FeatureLevel_FEATURE_LEVEL_0:
      return FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_0;
    case libsegmentation::DeviceInfo_FeatureLevel::
        DeviceInfo_FeatureLevel_FEATURE_LEVEL_1:
      return FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_1;
    default:
      return FeatureManagementInterface::FeatureLevel::FEATURE_LEVEL_UNKNOWN;
  }
}

FeatureManagementInterface::ScopeLevel
FeatureManagementUtil::ConvertProtoScopeLevel(
    libsegmentation::DeviceInfo_ScopeLevel scope_level) {
  switch (scope_level) {
    case libsegmentation::DeviceInfo_ScopeLevel::
        DeviceInfo_ScopeLevel_SCOPE_LEVEL_UNKNOWN:
      return FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_UNKNOWN;
    case libsegmentation::DeviceInfo_ScopeLevel::
        DeviceInfo_ScopeLevel_SCOPE_LEVEL_0:
      return FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_0;
    case libsegmentation::DeviceInfo_ScopeLevel::
        DeviceInfo_ScopeLevel_SCOPE_LEVEL_1:
      return FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_1;
    default:
      return FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_UNKNOWN;
  }
}

}  // namespace segmentation
