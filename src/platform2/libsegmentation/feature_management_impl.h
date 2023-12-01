// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSEGMENTATION_FEATURE_MANAGEMENT_IMPL_H_
#define LIBSEGMENTATION_FEATURE_MANAGEMENT_IMPL_H_

#include <set>
#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

#include "libsegmentation/device_info.pb.h"
#include "libsegmentation/feature_management_interface.h"
#include "proto/feature_management.pb.h"

using chromiumos::feature_management::api::software::FeatureBundle;

namespace segmentation {

// An implementation that invokes the corresponding functions provided
// in feature_management_interface.h.
class BRILLO_EXPORT FeatureManagementImpl : public FeatureManagementInterface {
 public:
  // Default implementation that use the database created by package
  // feature-management-data.
  FeatureManagementImpl();

  FeatureManagementImpl(const base::FilePath& device_info_file_path,
                        const char* feature_db);

  bool IsFeatureEnabled(const std::string& name) override;

  FeatureLevel GetFeatureLevel() override;
  ScopeLevel GetScopeLevel() override;

  const std::set<std::string> ListFeatures(const FeatureUsage usage) override;

 private:
  // Represents the file that houses the device info. This will be read to
  // populate |cached_device_info|.
  //
  // In production we will write to this path via the "vpd" binary and read it
  // as a regular file. For testing, we read and write from a test file stored
  // in this variable.
  base::FilePath device_info_file_path_;

  // Internal feature database
  FeatureBundle bundle_;

  // Use the "vpd" binary to persist the state.
  bool persist_via_vpd_ = false;

#if USE_FEATURE_MANAGEMENT
  // Reads device info from the stateful partition, if not present reads it from
  // the hardware and then writes it to the stateful partition. After this it
  // tries to cache it to |cached_device_info_|.
  //
  // If we fail to write it to the stateful partition then this function will
  // return false and not set |cached_device_info_|.
  bool CacheDeviceInfo();

  // Cache valid device information read from the stateful partition.
  std::optional<libsegmentation::DeviceInfo> cached_device_info_;

  // Hashed version of the current chromeos version (CHROMEOS_RELEASE_VERSION)
  uint32_t current_version_hash_;
#endif
};

}  // namespace segmentation

#endif  // LIBSEGMENTATION_FEATURE_MANAGEMENT_IMPL_H_
