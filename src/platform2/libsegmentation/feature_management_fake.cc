// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libsegmentation/feature_management_fake.h"
#include "libsegmentation/feature_management_interface.h"

#include <set>

namespace segmentation {

namespace fake {

bool FeatureManagementFake::IsFeatureEnabled(const std::string& name) {
  for (auto feature_set : system_features_properties_) {
    if (feature_set.second.count(name) > 0)
      return true;
  }

  return false;
}

FeatureManagementInterface::FeatureLevel
FeatureManagementFake::GetFeatureLevel() {
  return system_features_level_;
}

FeatureManagementInterface::ScopeLevel FeatureManagementFake::GetScopeLevel() {
  return system_scope_level_;
}

void FeatureManagementFake::SetFeatureLevel(FeatureLevel level) {
  system_features_level_ = level;
}

void FeatureManagementFake::SetScopeLevel(ScopeLevel level) {
  system_scope_level_ = level;
}

void FeatureManagementFake::SetFeature(const std::string& name,
                                       const FeatureUsage usage) {
  system_features_properties_[usage].insert(name);
}

void FeatureManagementFake::UnsetFeature(const std::string& name) {
  for (auto feature_set : system_features_properties_) {
    feature_set.second.erase(name);
  }
}

const std::set<std::string> FeatureManagementFake::ListFeatures(
    const FeatureUsage usage) {
  auto feature_set = system_features_properties_.find(usage);
  if (feature_set != system_features_properties_.end())
    return feature_set->second;

  return std::set<std::string>();
}

}  // namespace fake

}  // namespace segmentation
