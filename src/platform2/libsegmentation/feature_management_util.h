// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSEGMENTATION_FEATURE_MANAGEMENT_UTIL_H_
#define LIBSEGMENTATION_FEATURE_MANAGEMENT_UTIL_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

#include "base/files/file.h"
#include "libsegmentation/device_info.pb.h"
#include "libsegmentation/feature_management_interface.h"

namespace segmentation {

// An implementation that invokes the corresponding functions provided
// in feature_management_interface.h.
class BRILLO_EXPORT FeatureManagementUtil {
 public:
  // Reads device info from |file_path|. Returns std::nullopt if the read wasn't
  // successful.
  static std::optional<libsegmentation::DeviceInfo> ReadDeviceInfoFromFile(
      const base::FilePath& file_path);

  // Writes |device_info| as base64 to |file_path|. Returns false if the write
  // isn't successful.
  static bool WriteDeviceInfoToFile(
      const libsegmentation::DeviceInfo& device_info,
      const base::FilePath& file_path);

  // Converts feature level from the internal proto to the external API.
  static FeatureManagementInterface::FeatureLevel ConvertProtoFeatureLevel(
      libsegmentation::DeviceInfo_FeatureLevel feature_level);

  // Converts scope level from the internal proto to the external API.
  static FeatureManagementInterface::ScopeLevel ConvertProtoScopeLevel(
      libsegmentation::DeviceInfo_ScopeLevel scope_level);
};

}  // namespace segmentation

#endif  // LIBSEGMENTATION_FEATURE_MANAGEMENT_UTIL_H_
