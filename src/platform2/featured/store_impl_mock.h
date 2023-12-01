// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEATURED_STORE_IMPL_MOCK_H_
#define FEATURED_STORE_IMPL_MOCK_H_

#include <string>
#include <vector>

#include <featured/proto_bindings/featured.pb.h>
#include <gmock/gmock.h>

#include "featured/store_impl.h"
#include "featured/store_interface.h"

namespace featured {
class MockStoreImpl : public StoreInterface {
 public:
  MOCK_METHOD(uint32_t, GetBootAttemptsSinceLastUpdate, (), (override));
  MOCK_METHOD(bool, IncrementBootAttemptsSinceLastUpdate, (), (override));
  MOCK_METHOD(bool, ClearBootAttemptsSinceLastUpdate, (), (override));
  MOCK_METHOD(SeedDetails, GetLastGoodSeed, (), (override));
  MOCK_METHOD(bool, SetLastGoodSeed, (const SeedDetails&), (override));
  MOCK_METHOD(std::vector<FeatureOverride>, GetOverrides, (), (override));
  MOCK_METHOD(void, AddOverride, (const FeatureOverride&), (override));
  MOCK_METHOD(void, RemoveOverrideFor, (const std::string&), (override));
};
}  // namespace featured
#endif  // FEATURED_STORE_IMPL_MOCK_H_
