// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBSEGMENTATION_FEATURE_MANAGEMENT_INTERFACE_H_
#define LIBSEGMENTATION_FEATURE_MANAGEMENT_INTERFACE_H_

#include <set>
#include <string>

namespace segmentation {

// Copy of protobuf usage interface to avoid including the autogenerate
// protobuf
enum FeatureUsage {
  USAGE_LOCAL = 0,
  USAGE_CHROME = 1,
  USAGE_ANDROID = 2,
};

class FeatureManagementInterface {
 public:
  virtual ~FeatureManagementInterface() = default;

  // Check if a feature can be enabled on the device.
  //
  // @param name The name of the feature to check
  // @return |false| if the feature should not be used, |true| otherwise.
  virtual bool IsFeatureEnabled(const std::string& name) = 0;

  // Return the feature level for the device
  //
  // @return 0 when no additional features can be used,
  //         >0 when some feature can be used.
  enum FeatureLevel {
    FEATURE_LEVEL_UNKNOWN = 0,
    FEATURE_LEVEL_VALID_OFFSET = 1,
    FEATURE_LEVEL_0 = 1,
    FEATURE_LEVEL_1 = 2,
  };
  virtual FeatureLevel GetFeatureLevel() = 0;

  // Return the scope level for the device
  //
  // @return 0 when its unknown.
  //         > 0 otherwise.
  enum ScopeLevel {
    SCOPE_LEVEL_UNKNOWN = 0,
    SCOPE_LEVEL_VALID_OFFSET = 1,
    SCOPE_LEVEL_0 = 1,
    SCOPE_LEVEL_1 = 2,
  };
  virtual ScopeLevel GetScopeLevel() = 0;

  // List features supported on the device.
  // |usage| narrows down the list to a specific subsystem (ChromeOS, Chrome
  // or Android).
  virtual const std::set<std::string> ListFeatures(
      const FeatureUsage usage) = 0;
};

}  // namespace segmentation

#endif  // LIBSEGMENTATION_FEATURE_MANAGEMENT_INTERFACE_H_
