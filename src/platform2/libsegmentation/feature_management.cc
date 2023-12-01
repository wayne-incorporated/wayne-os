// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>
#include <string>

#include <base/files/file_path.h>

#include "libsegmentation/feature_management.h"
#include "libsegmentation/feature_management_impl.h"

namespace segmentation {

FeatureManagement::FeatureManagement()
    : FeatureManagement(std::make_unique<FeatureManagementImpl>()) {}

FeatureManagement::FeatureManagement(
    std::unique_ptr<FeatureManagementInterface> impl)
    : impl_(std::move(impl)) {}

bool FeatureManagement::IsFeatureEnabled(const std::string& name) {
  return impl_->IsFeatureEnabled(name);
}

int FeatureManagement::GetFeatureLevel() const {
  auto level = impl_->GetFeatureLevel();
  if (level == FeatureManagementInterface::FEATURE_LEVEL_UNKNOWN) {
    level = FeatureManagementInterface::FEATURE_LEVEL_0;
  }
  return level - FeatureManagementInterface::FEATURE_LEVEL_VALID_OFFSET;
}

int FeatureManagement::GetScopeLevel() const {
  auto level = impl_->GetScopeLevel();
  if (level == FeatureManagementInterface::SCOPE_LEVEL_UNKNOWN) {
    level = FeatureManagementInterface::SCOPE_LEVEL_0;
  }
  return level -
         FeatureManagementInterface::ScopeLevel::SCOPE_LEVEL_VALID_OFFSET;
}

const std::set<std::string> FeatureManagement::ListFeatures(
    const FeatureUsage usage) {
  return impl_->ListFeatures(usage);
}

}  // namespace segmentation
