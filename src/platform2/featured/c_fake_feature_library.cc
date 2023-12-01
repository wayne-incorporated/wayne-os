// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "featured/c_fake_feature_library.h"

#include <dbus/bus.h>

#include "featured/c_feature_library.h"
#include "featured/fake_platform_features.h"

extern "C" CFeatureLibrary FakeCFeatureLibraryNew() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

  return reinterpret_cast<CFeatureLibrary>(
      new feature::FakePlatformFeatures(bus));
}

extern "C" void FakeCFeatureLibraryDelete(CFeatureLibrary handle) {
  auto* library = dynamic_cast<feature::FakePlatformFeatures*>(
      reinterpret_cast<feature::PlatformFeaturesInterface*>(handle));
  library->ShutdownBus();
  delete library;
}

extern "C" void FakeCFeatureLibrarySetEnabled(CFeatureLibrary handle,
                                              const char* const feature,
                                              int enabled) {
  auto* library = dynamic_cast<feature::FakePlatformFeatures*>(
      reinterpret_cast<feature::PlatformFeaturesInterface*>(handle));
  library->SetEnabled(feature, enabled);
}

extern "C" void FakeCFeatureLibraryClearEnabled(CFeatureLibrary handle,
                                                const char* const feature) {
  auto* library = dynamic_cast<feature::FakePlatformFeatures*>(
      reinterpret_cast<feature::PlatformFeaturesInterface*>(handle));
  library->ClearEnabled(feature);
}

extern "C" void FakeCFeatureLibrarySetParam(CFeatureLibrary handle,
                                            const char* const feature,
                                            const char* const key,
                                            const char* const value) {
  auto* library = dynamic_cast<feature::FakePlatformFeatures*>(
      reinterpret_cast<feature::PlatformFeaturesInterface*>(handle));
  library->SetParam(feature, key, value);
}

extern "C" void FakeCFeatureLibraryClearParams(CFeatureLibrary handle,
                                               const char* const feature) {
  auto* library = dynamic_cast<feature::FakePlatformFeatures*>(
      reinterpret_cast<feature::PlatformFeaturesInterface*>(handle));
  library->ClearParams(feature);
}
