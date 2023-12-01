// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/write_protect_utils_impl.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/utils/mock_crossystem_utils.h"
#include "rmad/utils/mock_ec_utils.h"
#include "rmad/utils/mock_futility_utils.h"

using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;

namespace rmad {

class WriteProtectUtilsTest : public testing::Test {
 public:
  WriteProtectUtilsTest() = default;
  ~WriteProtectUtilsTest() override = default;

  std::unique_ptr<WriteProtectUtilsImpl> CreateWriteProtectUtils(
      bool hwwp_success,
      bool hwwp_enabled,
      bool apwp_success,
      bool apwp_enabled,
      bool ecwp_success,
      bool ecwp_enabled) {
    // Mock |CrosSystemUtils|.
    auto mock_crossystem_utils =
        std::make_unique<NiceMock<MockCrosSystemUtils>>();
    ON_CALL(*mock_crossystem_utils,
            GetInt(Eq(CrosSystemUtils::kHwwpStatusProperty), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(hwwp_enabled), Return(hwwp_success)));

    // Mock |EcUtils|.
    auto mock_ec_utils = std::make_unique<NiceMock<MockEcUtils>>();
    // Use |ecwp_success| to control the return value of enabling EC SWWP.
    ON_CALL(*mock_ec_utils, EnableEcSoftwareWriteProtection())
        .WillByDefault(Return(ecwp_success));
    ON_CALL(*mock_ec_utils, DisableEcSoftwareWriteProtection())
        .WillByDefault(Return(true));
    ON_CALL(*mock_ec_utils, GetEcWriteProtectionStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(ecwp_enabled), Return(ecwp_success)));

    // Mock |FutilityUtils|.
    auto mock_futility_utils = std::make_unique<NiceMock<MockFutilityUtils>>();
    ON_CALL(*mock_futility_utils, GetApWriteProtectionStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(apwp_enabled), Return(apwp_success)));
    ON_CALL(*mock_futility_utils, DisableApSoftwareWriteProtection())
        .WillByDefault(Return(true));
    // Use |apwp_success| to control the return value of enabling AP SWWP.
    ON_CALL(*mock_futility_utils, EnableApSoftwareWriteProtection())
        .WillByDefault(Return(apwp_success));

    return std::make_unique<WriteProtectUtilsImpl>(
        std::move(mock_crossystem_utils), std::move(mock_ec_utils),
        std::move(mock_futility_utils));
  }
};

TEST_F(WriteProtectUtilsTest, GetHwwp_Enabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_TRUE(utils->GetHardwareWriteProtectionStatus(&wp_status));
  ASSERT_TRUE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetHwwp_Disabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ false,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_TRUE(utils->GetHardwareWriteProtectionStatus(&wp_status));
  ASSERT_FALSE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetHwwp_Fail) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ false, /*hwwp_enabled*/ false,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_FALSE(utils->GetHardwareWriteProtectionStatus(&wp_status));
}

TEST_F(WriteProtectUtilsTest, GetApwp_Enabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_TRUE(utils->GetApWriteProtectionStatus(&wp_status));
  ASSERT_TRUE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetApwp_Disabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ false,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_TRUE(utils->GetApWriteProtectionStatus(&wp_status));
  ASSERT_FALSE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetApwp_Fail) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ false, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_FALSE(utils->GetApWriteProtectionStatus(&wp_status));
}

TEST_F(WriteProtectUtilsTest, GetEcwp_Enabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_TRUE(utils->GetEcWriteProtectionStatus(&wp_status));
  ASSERT_TRUE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetEcwp_Disabled_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ false);
  bool wp_status;
  ASSERT_TRUE(utils->GetEcWriteProtectionStatus(&wp_status));
  ASSERT_FALSE(wp_status);
}

TEST_F(WriteProtectUtilsTest, GetEcwp_Fail) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ false, /*ecwp_enabled*/ true);
  bool wp_status;
  ASSERT_FALSE(utils->GetEcWriteProtectionStatus(&wp_status));
}

TEST_F(WriteProtectUtilsTest, DisableWp_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  ASSERT_TRUE(utils->DisableSoftwareWriteProtection());
}

TEST_F(WriteProtectUtilsTest, EnableWp_Success) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  ASSERT_TRUE(utils->EnableSoftwareWriteProtection());
}

TEST_F(WriteProtectUtilsTest, EnableWp_Failed_Ap) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ false, /*apwp_enabled*/ true,
                              /*ecwp_success*/ true, /*ecwp_enabled*/ true);
  ASSERT_FALSE(utils->EnableSoftwareWriteProtection());
}

TEST_F(WriteProtectUtilsTest, EnableWp_Failed_Ec) {
  auto utils =
      CreateWriteProtectUtils(/*hwwp_success*/ true, /*hwwp_enabled*/ true,
                              /*apwp_success*/ true, /*apwp_enabled*/ true,
                              /*ecwp_success*/ false, /*ecwp_enabled*/ true);
  ASSERT_FALSE(utils->EnableSoftwareWriteProtection());
}

}  // namespace rmad
