// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test utilities for more easily setting up mockable/testable Features objects.
// Note that we don't actually provide a direct FakeFeatures object, but we do
// provide some objects that make it much easier to put together all the fakes
// you need to make a test instance.

#ifndef CRYPTOHOME_FAKE_FEATURES_H_
#define CRYPTOHOME_FAKE_FEATURES_H_

#include <memory>

#include <base/memory/scoped_refptr.h>
#include <dbus/mock_bus.h>
#include <gmock/gmock.h>

#include "cryptohome/features.h"

namespace cryptohome {

// Setting up a testable features interface requires setting up a fake D-Bus
// object and so to make that easier we bundle together all the needed setup. We
// also pair the Features object with an AsyncInitFeatures object, for testing
// objects that require the latter.
struct FakeFeaturesForTesting {
 public:
  // SetDefaultForFeature will set the default value for test for the feature.
  // This will be passed down to the feature library which inturn returns the
  // defaults.
  void SetDefaultForFeature(Features::ActiveFeature active_feature,
                            bool enabled) {
    fake_feature_lib->SetEnabled(GetVariationFeatureFor(active_feature).name,
                                 enabled);
  }

  scoped_refptr<::testing::NiceMock<dbus::MockBus>> mock_bus =
      base::MakeRefCounted<::testing::NiceMock<dbus::MockBus>>(
          dbus::Bus::Options());
  std::unique_ptr<feature::FakePlatformFeatures> fake_feature_lib =
      std::make_unique<feature::FakePlatformFeatures>(mock_bus);
  Features object{mock_bus, fake_feature_lib.get()};
  AsyncInitFeatures async{object};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FAKE_FEATURES_H_
