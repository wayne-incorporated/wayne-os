// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_auth_stack_manager.h"

#include <utility>

#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gtest/gtest.h>

#include "biod/mock_biod_metrics.h"
#include "biod/mock_cros_fp_device.h"
#include "biod/mock_cros_fp_record_manager.h"
#include "biod/power_button_filter.h"

namespace biod {

using Mode = ec::FpMode::Mode;

using testing::Return;
using testing::SaveArg;

class CrosFpAuthStackManagerTest : public ::testing::Test {
 public:
  void SetUp() override {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    const auto mock_bus = base::MakeRefCounted<dbus::MockBus>(options);

    const auto power_manager_proxy =
        base::MakeRefCounted<dbus::MockObjectProxy>(
            mock_bus.get(), power_manager::kPowerManagerServiceName,
            dbus::ObjectPath(power_manager::kPowerManagerServicePath));
    EXPECT_CALL(*mock_bus,
                GetObjectProxy(
                    power_manager::kPowerManagerServiceName,
                    dbus::ObjectPath(power_manager::kPowerManagerServicePath)))
        .WillOnce(testing::Return(power_manager_proxy.get()));

    auto mock_cros_dev = std::make_unique<MockCrosFpDevice>();
    // Keep a pointer to the fake device to manipulate it later.
    mock_cros_dev_ = mock_cros_dev.get();

    auto mock_record_manager = std::make_unique<MockCrosFpRecordManager>();
    // Keep a pointer to record manager, to manipulate it later.
    mock_record_manager_ = mock_record_manager.get();

    // Always support positive match secret
    EXPECT_CALL(*mock_cros_dev_, SupportsPositiveMatchSecret())
        .WillRepeatedly(Return(true));

    cros_fp_auth_stack_manager_ = std::make_unique<CrosFpAuthStackManager>(
        PowerButtonFilter::Create(mock_bus), std::move(mock_cros_dev),
        &mock_metrics_, std::move(mock_record_manager));
  }

 protected:
  metrics::MockBiodMetrics mock_metrics_;
  std::unique_ptr<CrosFpAuthStackManager> cros_fp_auth_stack_manager_;
  MockCrosFpRecordManager* mock_record_manager_;
  MockCrosFpDevice* mock_cros_dev_;
};

TEST_F(CrosFpAuthStackManagerTest, TestGetType) {
  EXPECT_EQ(cros_fp_auth_stack_manager_->GetType(), BIOMETRIC_TYPE_FINGERPRINT);
}

}  // namespace biod
