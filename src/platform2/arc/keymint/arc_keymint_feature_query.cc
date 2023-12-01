// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <vector>

#include "featured/c_feature_library.h"

#include <featured/feature_library.h>
#include <base/logging.h>

constexpr char kFeatureName[] = "CrOSLateBootArcSwitchToKeyMintDaemon";

int main(int argc, char** argv) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

  CHECK(feature::PlatformFeatures::Initialize(bus))
      << "Failed to initialize lib";
  feature::PlatformFeatures* feature_lib = feature::PlatformFeatures::Get();
  CHECK(feature_lib) << "Failed to get a valid handle";

  const VariationsFeature feature{kFeatureName, FEATURE_DISABLED_BY_DEFAULT};
  std::vector<const VariationsFeature*> features;
  features.push_back(&feature);
  feature::PlatformFeatures::ParamsResult result =
      feature_lib->GetParamsAndEnabledBlocking(features);
  auto iter = result.find(kFeatureName);
  if (iter == result.end()) {
    LOG(ERROR) << "could not find value for feature: " << kFeatureName;
    return 1;
  }
  std::cout << (iter->second.enabled ? "on" : "off") << std::endl;

  return 0;
}
