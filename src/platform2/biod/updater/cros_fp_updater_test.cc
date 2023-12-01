// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/updater/cros_fp_updater.h"

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/types/cxx23_to_underlying.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <chromeos/ec/ec_commands.h>
#include <cros_config/fake_cros_config.h>

#include "base/command_line.h"
#include "base/process/launch.h"
#include "base/time/time.h"
#include "biod/biod_config.h"
#include "biod/cros_fp_firmware.h"
#include "biod/mock_biod_system.h"
#include "biod/updater/update_reason.h"
#include "biod/updater/update_status.h"
#include "biod/utils.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DefaultValue;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::NotNull;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace {

constexpr char kTestImageROVersion[] = "nocturne_fp_v2.2.64-58cf5974e";
constexpr char kTestImageRWVersion[] = "nocturne_fp_v2.2.110-b936c0a3c";

const std::vector<enum ec_image> kEcCurrentImageEnums = {
    EC_IMAGE_UNKNOWN,
    EC_IMAGE_RO,
    EC_IMAGE_RW,
};

class MockCrosFpDeviceUpdate : public biod::CrosFpDeviceUpdate {
 public:
  MOCK_METHOD(std::optional<ec::CrosFpDeviceInterface::EcVersion>,
              GetVersion,
              (),
              (const, override));
  MOCK_METHOD(bool, IsFlashProtectEnabled, (bool*), (const, override));
  MOCK_METHOD(bool,
              Flash,
              (const biod::CrosFpFirmware&, enum ec_image),
              (const, override));
};

class MockCrosFpBootUpdateCtrl : public biod::CrosFpBootUpdateCtrl {
 public:
  MOCK_METHOD(bool, TriggerBootUpdateSplash, (), (const, override));
  MOCK_METHOD(bool, ScheduleReboot, (), (const, override));
};

class MockCrosFpFirmware : public biod::CrosFpFirmware {
 public:
  MockCrosFpFirmware() { set_status(biod::CrosFpFirmware::Status::kOk); }

  void SetMockFwVersion(const ImageVersion& version) { set_version(version); }
};

}  // namespace

namespace biod {
namespace updater {

class CrosFpUpdaterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    DefaultValue<bool>::Set(true);
    // Lay down default rules to ensure an error is logged if an interface
    // if called without explicitly specifying it.
    EXPECT_CALL(dev_update_, GetVersion()).Times(0);
    EXPECT_CALL(dev_update_, IsFlashProtectEnabled(_)).Times(0);
    EXPECT_CALL(dev_update_, Flash(_, _)).Times(0);
    EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(0);
    EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  }

  void TearDown() override { DefaultValue<bool>::Clear(); }

  // Setup an environment where a device GetVersion and IsFlashProtected
  // always succeed and report preset values corresponding to a preset
  // mock firmware.
  void SetupEnvironment(bool flash_protect,
                        bool ro_mismatch,
                        bool rw_mismatch,
                        enum ec_image ec_image = EC_IMAGE_RW) {
    CrosFpFirmware::ImageVersion img_ver = {kTestImageROVersion,
                                            kTestImageRWVersion};

    if (ro_mismatch) {
      img_ver.ro_version += "NEW";
    }
    if (rw_mismatch) {
      img_ver.rw_version += "NEW";
    }
    fw_.SetMockFwVersion(img_ver);

    EXPECT_CALL(dev_update_, GetVersion())
        .WillOnce(Return(ec::CrosFpDeviceInterface::EcVersion{
            .ro_version = kTestImageROVersion,
            .rw_version = kTestImageRWVersion,
            .current_image = ec_image,
        }));
    EXPECT_CALL(dev_update_, IsFlashProtectEnabled(NotNull()))
        .WillOnce(DoAll(SetArgPointee<0>(flash_protect), Return(true)));
    EXPECT_CALL(system_, HardwareWriteProtectIsEnabled())
        .WillRepeatedly(Return(flash_protect));
  }

  UpdateResult RunUpdater() {
    return DoUpdate(dev_update_, boot_ctrl_, fw_, system_, &cros_config_);
  }

  CrosFpUpdaterTest() = default;
  CrosFpUpdaterTest(const CrosFpUpdaterTest&) = delete;
  CrosFpUpdaterTest& operator=(const CrosFpUpdaterTest&) = delete;

  ~CrosFpUpdaterTest() override = default;

  MockCrosFpDeviceUpdate dev_update_;
  MockCrosFpBootUpdateCtrl boot_ctrl_;
  MockCrosFpFirmware fw_;
  MockBiodSystem system_;
  brillo::FakeCrosConfig cros_config_;
};

// EcCurrentImageToString Tests

TEST(CrosFpDeviceUpdateTest, NonblankEcCurrentImageString) {
  // Given a EC Image enumeration
  for (auto image : kEcCurrentImageEnums) {
    // when we ask for the human readable string
    std::string msg = CrosFpDeviceUpdate::EcCurrentImageToString(image);
    // expect it to not be "".
    EXPECT_FALSE(msg.empty()) << "Status " << base::to_underlying(image)
                              << " converts to a blank status string.";
  }
}

TEST(CrosFpDeviceUpdateTest, UniqueEcCurrentImageString) {
  // Given a set of EC Image enumeration strings
  std::unordered_set<std::string> status_msgs;
  for (auto image : kEcCurrentImageEnums) {
    status_msgs.insert(CrosFpDeviceUpdate::EcCurrentImageToString(image));
  }

  // expect the set to contain the same number of unique strings
  // as there are original ec image enumerations.
  EXPECT_EQ(status_msgs.size(), kEcCurrentImageEnums.size())
      << "There are one or more non-unique ec image strings.";
}

// DoUpdate Tests

// Failure code paths

TEST_F(CrosFpUpdaterTest, GetDeviceVersionFails) {
  // Given a device which fails to report its version,
  EXPECT_CALL(dev_update_, GetVersion()).WillOnce(Return(std::nullopt));

  // expect the updater to report a get version failure with no update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateFailedGetVersion);
  EXPECT_EQ(result.reason, UpdateReason::kNone);
}

TEST_F(CrosFpUpdaterTest, GetFlashProtectFails) {
  // Given a device which reports its version, but fails to
  // report its flash protect status,
  EXPECT_CALL(dev_update_, GetVersion())
      .WillOnce(Return(ec::CrosFpDeviceInterface::EcVersion()));
  EXPECT_CALL(dev_update_, IsFlashProtectEnabled(NotNull()))
      .WillOnce(Return(false));

  // expect the updater to report a flash protect failure
  // with no update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateFailedFlashProtect);
  EXPECT_EQ(result.reason, UpdateReason::kNone);
}

TEST_F(CrosFpUpdaterTest, FPDisabled_ROMismatch_ROUpdateFail) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is disabled,
      false,
      // RO needs to be updated,
      true, false);
  // and flashing operations fail,
  ON_CALL(dev_update_, Flash(_, _)).WillByDefault(Return(false));

  // expect the boot splash to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  // but no reboot requested (avoid boot loop),
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // an attempted RO flash,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RO));
  // and the updater to report an RO update failure with
  // an RO version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateFailedRO);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchROVersion);
}

TEST_F(CrosFpUpdaterTest, FPDisabled_RORWMismatch_ROUpdateFail) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is disabled,
      false,
      // RO needs to be updated,
      true,
      // RW needs to be updated,
      true);
  // flashing operations fail,
  ON_CALL(dev_update_, Flash(_, _)).WillByDefault(Return(false));

  // expect the boot splash to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  // but no reboot requested (avoid boot loop),
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // an attempted RO flash (but no RW flash),
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RO));
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW)).Times(0);
  // and the updater to report an RO update failure with
  // an RO version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateFailedRO);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchROVersion);
}

TEST_F(CrosFpUpdaterTest, FPEnabled_RWMismatch_RWUpdateFail) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is enabled,
      true, false,
      // RW needs to be updated,
      true);
  // flashing operations fail,
  ON_CALL(dev_update_, Flash(_, _)).WillByDefault(Return(false));

  // expect the boot splash to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  // but no reboot requested (avoid boot loop),
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // an attempted RW flash,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report an RW update failure with
  // an RW version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateFailedRW);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchRWVersion);
}

TEST_F(CrosFpUpdaterTest, FPDisabled_RORWMismatch_BootCtrlsBothFail) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is disabled,
      false,
      // RO needs to be updated,
      true,
      // RW needs to be updated,
      true);
  // both boot control functions fail,
  ON_CALL(boot_ctrl_, TriggerBootUpdateSplash()).WillByDefault(Return(false));
  ON_CALL(boot_ctrl_, ScheduleReboot()).WillByDefault(Return(false));

  // expect both boot control functions to be attempted,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(AtLeast(1));
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(AtLeast(1));
  // both firmware images to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RO));
  // and the updater to report a success with an
  // RO and RW version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchROVersion |
                               UpdateReason::kMismatchRWVersion);
}

// Abnormal code paths

TEST_F(CrosFpUpdaterTest, CurrentROImage_RORWMatch_UpdateRW) {
  // Given an environment where
  SetupEnvironment(true, false, false,
                   // the current boot is stuck in RO,
                   EC_IMAGE_RO);

  // expect both boot controls to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // an attempted RW flash,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success with an
  // RO active image update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kActiveImageRO);
}

TEST_F(CrosFpUpdaterTest, CurrentROImage_RORWMatch_UpdateRW_ResetNeeded) {
  // Given an environment where
  SetupEnvironment(true, false, false,
                   // the current boot is stuck in RO,
                   EC_IMAGE_RO);

  // hardware write protect is disabled,
  EXPECT_CALL(system_, HardwareWriteProtectIsEnabled())
      .WillRepeatedly(Return(false));

  // board is dartmonkey
  cros_config_.SetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                         kFpBoardDartmonkey);

  // expect both boot controls to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // an attempted RW flash,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success (but reset is needed) with an
  // RO active image update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceededNeedPowerReset);
  EXPECT_EQ(result.reason, UpdateReason::kActiveImageRO);
}

TEST_F(CrosFpUpdaterTest, CurrentROImage_RORWMatch_UpdateRW_ResetNotNeeded) {
  // Given an environment where
  SetupEnvironment(true, false, false,
                   // the current boot is stuck in RO,
                   EC_IMAGE_RO);

  // hardware write protect is disabled,
  EXPECT_CALL(system_, HardwareWriteProtectIsEnabled())
      .WillRepeatedly(Return(false));

  // board is bloonchipper
  cros_config_.SetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                         kFpBoardBloonchipper);

  // expect both boot controls to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // an attempted RW flash,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success with an
  // RO active image update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kActiveImageRO);
}

// Normal code paths

TEST_F(CrosFpUpdaterTest, FPDisabled_RORWMatch_NoUpdate) {
  // Given an environment where no updates are necessary
  SetupEnvironment(
      // and flash-protect is disabled,
      false, false, false);

  // expect neither boot control functions to be attempted,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(0);
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // no firmware images flashed,
  EXPECT_CALL(dev_update_, Flash(_, _)).Times(0);
  // and the updater to report an update not necessary with
  // no update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateNotNecessary);
  EXPECT_EQ(result.reason, UpdateReason::kNone);
}

TEST_F(CrosFpUpdaterTest, FPEnabled_RORWMatch_NoUpdate) {
  // Given an environment where no updates are necessary
  SetupEnvironment(
      // and flash-protect is enabled,
      true, false, false);

  // expect neither boot control functions to be attempted,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(0);
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // no firmware images flashed,
  EXPECT_CALL(dev_update_, Flash(_, _)).Times(0);
  // and the updater to report an update not necessary with
  // no update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateNotNecessary);
  EXPECT_EQ(result.reason, UpdateReason::kNone);
}

TEST_F(CrosFpUpdaterTest, FPEnabled_ROMismatch_NoUpdate) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is enabled
      true,
      // and RO needs to be updated,
      true, false);

  // expect neither boot control functions to be attempted,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(0);
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(0);
  // no firmware images flashed,
  EXPECT_CALL(dev_update_, Flash(_, _)).Times(0);
  // and the updater to report an update not necessary with
  // no update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateNotNecessary);
  EXPECT_EQ(result.reason, UpdateReason::kNone);
}

TEST_F(CrosFpUpdaterTest, RWMismatch_UpdateRW) {
  // Given an environment where
  SetupEnvironment(true, false,
                   // RW needs to be updated,
                   true);

  // expect both boot control functions to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // RW to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success with an
  // RW version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchRWVersion);
}

TEST_F(CrosFpUpdaterTest, RWMismatch_UpdateRW_ResetNeeded) {
  // Given an environment where
  SetupEnvironment(true, false,
                   // RW needs to be updated,
                   true);

  // hardware write protect is disabled,
  EXPECT_CALL(system_, HardwareWriteProtectIsEnabled())
      .WillRepeatedly(Return(false));

  // board is dartmonkey
  cros_config_.SetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                         kFpBoardDartmonkey);

  // expect both boot control functions to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // RW to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success (but reset is needed) with an
  // RW version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceededNeedPowerReset);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchRWVersion);
}

TEST_F(CrosFpUpdaterTest, RWMismatch_UpdateRW_ResetNotNeeded) {
  // Given an environment where
  SetupEnvironment(true, false,
                   // RW needs to be updated,
                   true);

  // hardware write protect is disabled,
  EXPECT_CALL(system_, HardwareWriteProtectIsEnabled())
      .WillRepeatedly(Return(false));

  // board is bloonchipper
  cros_config_.SetString(kCrosConfigFPPath, kCrosConfigFPBoard,
                         kFpBoardBloonchipper);

  // expect both boot control functions to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // RW to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success with an
  // RW version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchRWVersion);
}

TEST_F(CrosFpUpdaterTest, FPDisabled_ROMismatch_UpdateRO) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is disabled
      false,
      // and RO needs to be updated,
      true, false);

  // expect both boot control functions to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash());
  EXPECT_CALL(boot_ctrl_, ScheduleReboot());
  // RO to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RO));
  // and the updater to report a success with an
  // RO version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchROVersion);
}

TEST_F(CrosFpUpdaterTest, FPDisabled_RORWMismatch_UpdateRORW) {
  // Given an environment where
  SetupEnvironment(
      // flash-protect is disabled,
      false,
      // RO needs to be updated,
      true,
      // RW needs to be updated,
      true);

  // expect both boot control functions to be triggered,
  EXPECT_CALL(boot_ctrl_, TriggerBootUpdateSplash()).Times(AtLeast(1));
  EXPECT_CALL(boot_ctrl_, ScheduleReboot()).Times(AtLeast(1));
  // both firmware images to be flashed,
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RO));
  EXPECT_CALL(dev_update_, Flash(Ref(fw_), EC_IMAGE_RW));
  // and the updater to report a success with an
  // RW and RO version mismatch update reason.
  auto result = RunUpdater();
  EXPECT_EQ(result.status, UpdateStatus::kUpdateSucceeded);
  EXPECT_EQ(result.reason, UpdateReason::kMismatchROVersion |
                               UpdateReason::kMismatchRWVersion);
}

TEST(GetAppOutputAndErrorWithTimeout, SleepFunctionStatusNotOk) {
  base::CommandLine cmd_sleep{base::FilePath("sleep")};
  cmd_sleep.AppendArg("2s");
  std::string cmd_output;
  base::TimeDelta delta = base::Milliseconds(100);
  bool status = GetAppOutputAndErrorWithTimeout(cmd_sleep, delta, &cmd_output);
  std::string expected_cmd_output = "timeout: sending signal QUIT to command";
  EXPECT_EQ(
      cmd_output.compare(0, expected_cmd_output.size(), expected_cmd_output),
      0);
  EXPECT_FALSE(status);
  EXPECT_EQ(cmd_sleep.GetProgram().BaseName().value(), "sleep");
}

TEST(GetAppOutputAndErrorWithTimeout, SleepFunctionStatusOk) {
  base::CommandLine cmd_sleep{base::FilePath("sleep")};
  cmd_sleep.AppendArg("0.1s");
  std::string cmd_output;
  base::TimeDelta delta = base::Seconds(2);
  bool status = GetAppOutputAndErrorWithTimeout(cmd_sleep, delta, &cmd_output);
  EXPECT_TRUE(status);
  EXPECT_TRUE(cmd_output.empty());
  EXPECT_EQ(cmd_sleep.GetProgram().BaseName().value(), "sleep");
}

}  // namespace updater
}  // namespace biod
