// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_POLICIES_FEATURES_BROKER_H_
#define SECAGENTD_TEST_MOCK_POLICIES_FEATURES_BROKER_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "base/time/time.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "secagentd/policies_features_broker.h"

namespace secagentd::testing {

class MockPoliciesFeaturesBroker : public PoliciesFeaturesBrokerInterface {
 public:
  MOCK_METHOD(void,
              StartAndBlockForSync,
              (base::TimeDelta poll_duration),
              (override));
  MOCK_METHOD(bool, GetFeature, (Feature feature), (const override));

  MOCK_METHOD(bool, GetDeviceReportXDREventsPolicy, (), (const override));
};

}  // namespace secagentd::testing

#endif  // SECAGENTD_TEST_MOCK_POLICIES_FEATURES_BROKER_H_
