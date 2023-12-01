// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/policies_features_broker.h"

#include <memory>
#include <optional>

#include "base/memory/scoped_refptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "dbus/mock_bus.h"
#include "featured/fake_platform_features.h"
#include "gmock/gmock.h"  // IWYU pragma:keep
#include "gtest/gtest.h"
#include "policy/mock_device_policy.h"
#include "policy/mock_libpolicy.h"

namespace secagentd::testing {

using ::dbus::MockBus;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;
using Feature = PoliciesFeaturesBroker::Feature;

class PoliciesFeaturesBrokerTestFixture : public ::testing::Test {
 protected:
  static constexpr base::TimeDelta kFakePollDuration = base::Minutes(10);
  PoliciesFeaturesBrokerTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}

  void SetUp() override {
    auto policy_provider =
        std::make_unique<StrictMock<policy::MockPolicyProvider>>();
    mock_policy_provider_ = policy_provider.get();
    dbus_bus_ = base::MakeRefCounted<NiceMock<MockBus>>(dbus::Bus::Options());
    // Cheekily required by FakePlatformFeatures.
    ON_CALL(*dbus_bus_, GetOriginTaskRunner())
        .WillByDefault(
            Return(task_environment_.GetMainThreadTaskRunner().get()));
    fake_features_ = std::make_unique<feature::FakePlatformFeatures>(dbus_bus_);

    broker_ = base::MakeRefCounted<PoliciesFeaturesBroker>(
        std::move(policy_provider), fake_features_.get(),
        base::BindLambdaForTesting([this]() { VerifyExpectations(); }));
  }

  void TearDown() override {
    num_poll_done_cb_calls_ = 0;
    expected_xdr_events_policy_ = false;
    expected_feature_enabled_.clear();
  }

  void VerifyExpectations() {
    num_poll_done_cb_calls_++;
    EXPECT_EQ(expected_xdr_events_policy_,
              broker_->GetDeviceReportXDREventsPolicy());
    for (const auto& [k, v] : expected_feature_enabled_) {
      EXPECT_EQ(v, broker_->GetFeature(k));
    }
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(mock_policy_provider_));
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(&mock_device_policy_));
  }

  void SetActualXDREventsPolicy(std::optional<bool> value) {
    EXPECT_CALL(*mock_policy_provider_, Reload());
    EXPECT_CALL(*mock_policy_provider_, device_policy_is_loaded())
        .WillOnce(Return(value.has_value()));
    if (value.has_value()) {
      EXPECT_CALL(*mock_policy_provider_, GetDevicePolicy())
          .WillOnce(ReturnRef(mock_device_policy_));
      EXPECT_CALL(mock_device_policy_, GetDeviceReportXDREvents())
          .WillOnce(Return(value.value()));
    }
  }

  void SetActualFeatureEnabled(Feature feature, std::optional<bool> value) {
    const auto& it = broker_->feature_values_.find(feature);
    ASSERT_NE(broker_->feature_values_.end(), it);
    auto& name = it->second.variation.name;
    if (value.has_value()) {
      fake_features_->SetEnabled(name, value.value());
    } else {
      fake_features_->ClearEnabled(name);
    }
  }

  void SetExpectedXDREventsPolicy(bool value) {
    expected_xdr_events_policy_ = value;
  }

  void SetExpectedFeatureEnabled(Feature feature, bool value) {
    expected_feature_enabled_[feature] = value;
  }

  scoped_refptr<NiceMock<MockBus>> dbus_bus_;
  base::test::TaskEnvironment task_environment_;
  StrictMock<policy::MockPolicyProvider>* mock_policy_provider_ = nullptr;
  StrictMock<policy::MockDevicePolicy> mock_device_policy_;
  std::unique_ptr<feature::FakePlatformFeatures> fake_features_;
  scoped_refptr<PoliciesFeaturesBroker> broker_;
  int num_poll_done_cb_calls_ = 0;
  bool expected_xdr_events_policy_;
  std::map<Feature, bool> expected_feature_enabled_;
};

TEST_F(PoliciesFeaturesBrokerTestFixture, StartAndPollAFewTimes) {
  int expected_num_poll_done_cb_calls = 0;

  SetActualXDREventsPolicy(true);
  SetExpectedXDREventsPolicy(true);
  SetActualFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, true);
  SetExpectedFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, true);
  broker_->StartAndBlockForSync(kFakePollDuration);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(++expected_num_poll_done_cb_calls, num_poll_done_cb_calls_);

  // Set the same expectations again.
  SetActualXDREventsPolicy(true);
  SetExpectedXDREventsPolicy(true);
  SetActualFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, true);
  SetExpectedFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, true);
  task_environment_.AdvanceClock(kFakePollDuration);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(++expected_num_poll_done_cb_calls, num_poll_done_cb_calls_);

  // Policy is unchanged. Feature is set to false.
  SetActualXDREventsPolicy(true);
  SetExpectedXDREventsPolicy(true);
  SetActualFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, false);
  SetExpectedFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, false);
  task_environment_.AdvanceClock(kFakePollDuration);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(++expected_num_poll_done_cb_calls, num_poll_done_cb_calls_);

  // Both policy and feature are set to false.
  SetActualXDREventsPolicy(false);
  SetExpectedXDREventsPolicy(false);
  SetActualFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, false);
  SetExpectedFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, false);
  task_environment_.AdvanceClock(kFakePollDuration);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(++expected_num_poll_done_cb_calls, num_poll_done_cb_calls_);

  // Policy fails to load and feature is cleared.
  // Policy defaults to false.
  // CrOSLateBootSecagentdXDRReporting is ENABLED_BY_DEFAULT.
  SetActualXDREventsPolicy(std::nullopt);
  SetActualFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting,
                          std::nullopt);
  SetExpectedFeatureEnabled(Feature::kCrOSLateBootSecagentdXDRReporting, true);

  task_environment_.AdvanceClock(kFakePollDuration);
  task_environment_.RunUntilIdle();
  EXPECT_EQ(++expected_num_poll_done_cb_calls, num_poll_done_cb_calls_);
}

}  // namespace secagentd::testing
