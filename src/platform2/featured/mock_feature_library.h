// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_MOCK_FEATURE_LIBRARY_H_
#define FEATURED_MOCK_FEATURE_LIBRARY_H_

#include "featured/feature_library.h"

#include <gmock/gmock.h>

namespace feature {

class PlatformFeaturesMock : public PlatformFeaturesInterface {
 public:
  MOCK_METHOD(void,
              IsEnabled,
              (const VariationsFeature& feature, IsEnabledCallback callback),
              (override));
  MOCK_METHOD(bool,
              IsEnabledBlocking,
              (const VariationsFeature& feature),
              (override));
};

}  // namespace feature

#endif  // FEATURED_MOCK_FEATURE_LIBRARY_H_
