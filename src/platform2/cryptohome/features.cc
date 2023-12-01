// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/features.h"

#include <memory>
#include <utility>
#include "base/functional/bind.h"

#include <base/check.h>
#include <base/no_destructor.h>
#include <featured/fake_platform_features.h>
#include <featured/feature_library.h>

namespace cryptohome {

Features::Features(scoped_refptr<dbus::Bus> bus,
                   feature::PlatformFeaturesInterface* feature_lib)
    : feature_lib_(feature_lib) {}

bool Features::IsFeatureEnabled(ActiveFeature active_feature) const {
  const auto& variations_feature = GetVariationFeatureFor(active_feature);
  if (feature_lib_) {
    return feature_lib_->IsEnabledBlocking(variations_feature);
  }
  return variations_feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
}

AsyncInitFeatures::AsyncInitFeatures(
    base::RepeatingCallback<Features*()> getter)
    : getter_(std::move(getter)) {}

AsyncInitFeatures::AsyncInitFeatures(Features& features)
    : AsyncInitFeatures(base::BindRepeating(
          [](Features* features) { return features; }, &features)) {}

bool AsyncInitFeatures::IsFeatureEnabled(
    Features::ActiveFeature active_feature) const {
  if (Features* features = getter_.Run()) {
    return features->IsFeatureEnabled(active_feature);
  }
  const auto& variations_feature = GetVariationFeatureFor(active_feature);
  return variations_feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
}

const VariationsFeature& GetVariationFeatureFor(
    Features::ActiveFeature active_feature) {
  switch (active_feature) {
    case Features::kUSSMigration:
      return kCrOSLateBootMigrateToUserSecretStash;
    case Features::kModernPin:
      return kCrOSLateBootEnableModernPin;
    case Features::kMigratePin:
      return kCrOSLateBootMigrateToModernPin;
  }
}

}  // namespace cryptohome
