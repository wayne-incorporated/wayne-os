// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The calling structure of HammerUpdater:
//   Run() => RunLoop() => RunOnce() => PostRWProcess().
// Since RunLoop only iterately call the Run() method, so we don't test it
// directly. Therefore, we have 3-layer unittests:
//
// - HammerUpdaterFlowTest:
//  - Test the logic of Run(), the interaction with RunOnce().
//  - Mock RunOnce() and data members.
//
// - HammerUpdaterRWTest:
//  - Test the logic of RunOnce(), the interaction with PostRWProcess() and
//    external interfaces (fw_updater, pair_manager, ...etc).
//  - One exception: Test a special sequence that needs to reset 3 times called
//    by Run().
//  - Mock PostRWProcess() and data members.
//
// - HammerUpdaterPostRWTest:
//  - Test the individual methods called from within PostRWProcess(),
//    like Pair, UpdateRO, RunTouchpadUpdater().
//  - Test logic for RunTouchpadUpdater():
//    - Verify the return value if we can't get touchpad infomation.
//    - Verify the IC size matches with local firmware binary blob.
//    - Verify the entire firmware blob hash matches one accepted in RW EC.
//    - Verify the return value if update is failed during process.
//  - Mock all external data members only.

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/files/file_path.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library.h>
#include <metrics/metrics_library_mock.h>

#include "hammerd/hammer_updater.h"
#include "hammerd/mock_dbus_wrapper.h"
#include "hammerd/mock_pair_utils.h"
#include "hammerd/mock_update_fw.h"
#include "hammerd/uma_metric_names.h"
#include "hammerd/update_fw.h"

using testing::_;
using testing::AnyNumber;
using testing::Assign;
using testing::AtLeast;
using testing::DoAll;
using testing::Exactly;
using testing::InSequence;
using testing::Return;
using testing::ReturnPointee;

namespace hammerd {

ACTION_P(Increment, n) {
  ++(*n);
}
ACTION_P(Decrement, n) {
  --(*n);
}

class MockRunOnceHammerUpdater : public HammerUpdater {
 public:
  using HammerUpdater::HammerUpdater;
  ~MockRunOnceHammerUpdater() override = default;

  MOCK_METHOD(RunStatus, RunOnce, (), (override));
};

class MockRWProcessHammerUpdater : public HammerUpdater {
 public:
  using HammerUpdater::HammerUpdater;
  ~MockRWProcessHammerUpdater() override = default;

  MOCK_METHOD(RunStatus, PostRWProcess, (), (override));
};

class MockNothing : public HammerUpdater {
 public:
  using HammerUpdater::HammerUpdater;
  ~MockNothing() override = default;
};

template <typename HammerUpdaterType>
class HammerUpdaterTest : public testing::Test {
 public:
  void SetUp() override {
    // Mock out data members.
    hammer_updater_.reset(new HammerUpdaterType{
        ec_image_, touchpad_image_, touchpad_product_id_, touchpad_fw_ver_, "",
        false, HammerUpdater::ToUpdateCondition("mismatch"),
        std::make_unique<MockFirmwareUpdater>(),
        std::make_unique<MockPairManagerInterface>(),
        std::make_unique<MockDBusWrapper>(),
        std::make_unique<MetricsLibraryMock>()});
    fw_updater_ =
        static_cast<MockFirmwareUpdater*>(hammer_updater_->fw_updater_.get());
    pair_manager_ = static_cast<MockPairManagerInterface*>(
        hammer_updater_->pair_manager_.get());
    dbus_wrapper_ =
        static_cast<MockDBusWrapper*>(hammer_updater_->dbus_wrapper_.get());
    metrics_ =
        static_cast<MetricsLibraryMock*>(hammer_updater_->metrics_.get());
    task_ = &(hammer_updater_->task_);
    update_condition_ = const_cast<HammerUpdater::UpdateCondition*>(
        &(hammer_updater_->update_condition_));
    at_boot_ = const_cast<bool*>(&(hammer_updater_->at_boot_));
    // By default, expect no USB connections to be made. This can
    // be overridden by a call to ExpectUsbConnections.
    usb_connection_count_ = 0;
    EXPECT_CALL(*fw_updater_, TryConnectUsb()).Times(0);
    EXPECT_CALL(*fw_updater_, CloseUsb()).Times(0);

    // These two methods are called at the beginning of each round but not
    // related to most of testing logic. Set the default action here.
    ON_CALL(*fw_updater_, SendFirstPdu()).WillByDefault(Return(true));
    ON_CALL(*fw_updater_, SendDone()).WillByDefault(Return());

    // Do not verify these non-state-changing methods are called.
    ON_CALL(*fw_updater_, LoadEcImage(_)).WillByDefault(Return(true));
    ON_CALL(*fw_updater_, LoadTouchpadImage(_)).WillByDefault(Return(true));
    ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(false));
    ON_CALL(*fw_updater_, IsSectionLocked(_)).WillByDefault(Return(false));
    ON_CALL(*fw_updater_, ValidKey()).WillByDefault(Return(true));
    ON_CALL(*fw_updater_, CurrentSection())
        .WillByDefault(ReturnPointee(&current_section_));
    ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(0));
  }

  void TearDown() override { ASSERT_EQ(usb_connection_count_, 0); }

  void ExpectUsbConnections(const testing::Cardinality count) {
    // Checked in TearDown.
    EXPECT_CALL(*fw_updater_, TryConnectUsb())
        .Times(count)
        .WillRepeatedly(DoAll(Increment(&usb_connection_count_),
                              Return(UsbConnectStatus::kSuccess)));
    EXPECT_CALL(*fw_updater_, CloseUsb())
        .Times(count)
        .WillRepeatedly(DoAll(Decrement(&usb_connection_count_), Return()));
  }

 protected:
  std::unique_ptr<HammerUpdaterType> hammer_updater_;
  MockFirmwareUpdater* fw_updater_;
  MockPairManagerInterface* pair_manager_;
  MockDBusWrapper* dbus_wrapper_;
  MetricsLibraryMock* metrics_;
  std::string ec_image_ = "MOCK EC IMAGE";
  std::string touchpad_image_ = "MOCK TOUCHPAD IMAGE";
  std::string touchpad_product_id_ = "1.0";
  std::string touchpad_fw_ver_ = "2.0";
  int usb_connection_count_;
  HammerUpdater::TaskState* task_;
  HammerUpdater::UpdateCondition* update_condition_;
  bool* at_boot_;
  SectionName current_section_ = SectionName::RO;
};

// We mock RunOnce function here to verify the interaction between Run() and
// RunOnce().
class HammerUpdaterFlowTest
    : public HammerUpdaterTest<MockRunOnceHammerUpdater> {};
// We mock PostRWProcess function here to verify the flow of RW section
// updating.
class HammerUpdaterRWTest
    : public HammerUpdaterTest<MockRWProcessHammerUpdater> {};
// Mock nothing to test the individual methods called from within PostRWProcess.
class HammerUpdaterPostRWTest : public HammerUpdaterTest<MockNothing> {
 public:
  void SetUp() override {
    HammerUpdaterTest::SetUp();
    // Create a nice response of kTouchpadInfo for important fields.
    response_.status = 0x00;
    response_.vendor = ELAN_VENDOR_ID;
    response_.elan.id = 0x01;
    response_.elan.fw_version = 0x02;
    response_.fw_size = touchpad_image_.size();
    std::memcpy(
        response_.allowed_fw_hash,
        SHA256(reinterpret_cast<const uint8_t*>(touchpad_image_.data()),
               response_.fw_size, reinterpret_cast<unsigned char*>(&digest_)),
        SHA256_DIGEST_LENGTH);
  }

 protected:
  TouchpadInfo response_;
  uint8_t digest_[SHA256_DIGEST_LENGTH];
};

// Failed to load EC image.
TEST_F(HammerUpdaterFlowTest, Run_LoadEcImageFailed) {
  ON_CALL(*fw_updater_, LoadEcImage(_)).WillByDefault(Return(false));
  EXPECT_CALL(*fw_updater_, TryConnectUsb()).Times(0);
  EXPECT_CALL(*hammer_updater_, RunOnce()).Times(0);

  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kInvalidFirmware);
}

// Sends reset command if RunOnce returns kNeedReset.
TEST_F(HammerUpdaterFlowTest, Run_AlwaysReset) {
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(HammerUpdater::RunStatus::kNeedReset));
  EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kImmediateReset))
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(),
            HammerUpdater::RunStatus::kNeedReset);  // FAILURE
}

// A fatal error occurred during update.
TEST_F(HammerUpdaterFlowTest, Run_FatalError) {
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .WillOnce(Return(HammerUpdater::RunStatus::kFatalError));
  EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kImmediateReset))
      .WillOnce(Return(true));

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(),
            HammerUpdater::RunStatus::kNeedReset);  // FAILURE
}

// After three attempts, Run reports no update needed.
TEST_F(HammerUpdaterFlowTest, Run_Reset3Times) {
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .WillOnce(Return(HammerUpdater::RunStatus::kNeedReset))
      .WillOnce(Return(HammerUpdater::RunStatus::kNeedReset))
      .WillOnce(Return(HammerUpdater::RunStatus::kNeedReset))
      .WillRepeatedly(Return(HammerUpdater::RunStatus::kNoUpdate));
  EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kImmediateReset))
      .Times(3)
      .WillRepeatedly(Return(true));

  ExpectUsbConnections(Exactly(4));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Fails if the base connected is invalid.
// kInvalidBaseConnectedSignal DBus signal should be raised.
TEST_F(HammerUpdaterFlowTest, RunOnce_InvalidDevice) {
  EXPECT_CALL(*fw_updater_, TryConnectUsb())
      .WillRepeatedly(Return(UsbConnectStatus::kInvalidDevice));
  EXPECT_CALL(*fw_updater_, CloseUsb()).WillRepeatedly(Return());

  EXPECT_CALL(*dbus_wrapper_, SendSignal(kInvalidBaseConnectedSignal));

  // Do not call ExpectUsbConnections since it conflicts with our EXPECT_CALLs.
  ASSERT_EQ(hammer_updater_->Run(),
            HammerUpdater::RunStatus::kNeedJump);  // FAILURE
}

// Check PendingRWUpdate metric:
// CommunicationError
TEST_F(HammerUpdaterFlowTest, RunOnce_PendingRWUpdate_CommunicationError) {
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  EXPECT_CALL(*fw_updater_, TryConnectUsb())
      .WillRepeatedly(Return(UsbConnectStatus::kInvalidDevice));
  EXPECT_CALL(*fw_updater_, CloseUsb()).WillRepeatedly(Return());
  EXPECT_CALL(
      *metrics_,
      SendEnumToUMA(kMetricPendingRWUpdate,
                    static_cast<int>(PendingRWUpdate::kCommunicationError),
                    static_cast<int>(PendingRWUpdate::kCount)));

  ASSERT_EQ(hammer_updater_->Run(),
            HammerUpdater::RunStatus::kNeedJump);  // FAILURE
}

// Check PendingRWUpdate metric:
// NoUpdate
TEST_F(HammerUpdaterFlowTest, RunOnce_PendingRWUpdate_NoUpdate) {
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .WillRepeatedly(Return(HammerUpdater::RunStatus::kNoUpdate));
  ON_CALL(*fw_updater_, IsCritical()).WillByDefault(Return(false));
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(false));
  EXPECT_CALL(*metrics_,
              SendEnumToUMA(kMetricPendingRWUpdate,
                            static_cast<int>(PendingRWUpdate::kNoUpdate),
                            static_cast<int>(PendingRWUpdate::kCount)));

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Check PendingRWUpdate metric:
// CriticalUpdate
TEST_F(HammerUpdaterFlowTest, RunOnce_PendingRWUpdate_CriticalUpdate) {
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .WillRepeatedly(Return(HammerUpdater::RunStatus::kNoUpdate));
  ON_CALL(*fw_updater_, IsCritical()).WillByDefault(Return(true));
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(true));
  EXPECT_CALL(*metrics_,
              SendEnumToUMA(kMetricPendingRWUpdate,
                            static_cast<int>(PendingRWUpdate::kCriticalUpdate),
                            static_cast<int>(PendingRWUpdate::kCount)));

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Check PendingRWUpdatemetric:
// NonCriticalUpdate
TEST_F(HammerUpdaterFlowTest, RunOnce_PendingRWUpdate_NonCriticalUpdate) {
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  EXPECT_CALL(*hammer_updater_, RunOnce())
      .WillRepeatedly(Return(HammerUpdater::RunStatus::kNoUpdate));
  ON_CALL(*fw_updater_, IsCritical()).WillByDefault(Return(false));
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(true));
  EXPECT_CALL(
      *metrics_,
      SendEnumToUMA(kMetricPendingRWUpdate,
                    static_cast<int>(PendingRWUpdate::kNonCriticalUpdate),
                    static_cast<int>(PendingRWUpdate::kCount)));

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// In "never" update condition, send DBus signal only if a critical update
// is available.
// Condition:
//   1. Update condition is "never".
//   2. In RW section.
//   3. RW needs a critical update.
TEST_F(HammerUpdaterRWTest, Run_NeverUpdateCriticalUpdate) {
  current_section_ = SectionName::RW;
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(true));
  ON_CALL(*fw_updater_, IsCritical()).WillByDefault(Return(true));

  {
    InSequence dummy;

    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareNeedUpdateSignal));
    EXPECT_CALL(*hammer_updater_, PostRWProcess())
        .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));
  }
  EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW)).Times(0);

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// In "mismatch" update condition, no update is performed.
// Condition:
//   1. Update condition is "mismatch".
//   2. In RW section.
//   3. RW needs update.
TEST_F(HammerUpdaterRWTest, Run_MismatchUpdateRWMismatch) {
  current_section_ = SectionName::RW;
  *update_condition_ = HammerUpdater::UpdateCondition::kMismatch;
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(false));
  EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW)).Times(0);

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// In "never" update condition, send DBus signal only if RW is broken.
// Condition:
//   1. Update condition is "never".
//   2. In RO section.
//   3. RW is broken.
TEST_F(HammerUpdaterRWTest, Run_NeverUpdateRWBroken) {
  current_section_ = SectionName::RO;
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;

  EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW)).Times(0);
  {
    InSequence dummy;

    // Try to jump to RW, but still in RO.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(Return(true));
    // Send DBus signal, and reset the device again.
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareNeedUpdateSignal));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(Return(true));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(),
            HammerUpdater::RunStatus::kNeedReset);  // FAILURE
}

// In "never" update condition, do nothing if there is only normal update.
// Condition:
//   1. Update condition is "never".
//   2. In RO section.
//   3. RW is broken.
TEST_F(HammerUpdaterRWTest, Run_NeverUpdateNothing) {
  current_section_ = SectionName::RW;
  *update_condition_ = HammerUpdater::UpdateCondition::kNever;
  ON_CALL(*fw_updater_, VersionMismatch(_)).WillByDefault(Return(true));

  EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW)).Times(0);
  EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareNeedUpdateSignal))
      .Times(0);

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Return kInvalidFirmware if the layout of the firmware is changed.
// Condition:
//   1. The current section is Invalid.
TEST_F(HammerUpdaterRWTest, RunOnce_InvalidSection) {
  current_section_ = SectionName::Invalid;

  ASSERT_EQ(hammer_updater_->RunOnce(),
            HammerUpdater::RunStatus::kInvalidFirmware);
}

// Update the RW after JUMP_TO_RW failed.
// Condition:
//   1. In RO section.
//   2. RW does not need update.
//   3. Fails to jump to RW due to invalid signature.
TEST_F(HammerUpdaterRWTest, Run_UpdateRWAfterJumpToRWFailed) {
  current_section_ = SectionName::RO;

  {
    InSequence dummy;

    // First round: RW does not need update.  Attempt to jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(Return(true));

    // Second round: Jump to RW fails, so update RW. After update, again attempt
    // to jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(Return(true));

    // Third round: Again attempt to jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));

    // Fourth round: Check that jumping to RW was successful, and that
    // PostRWProcessing is called.
    EXPECT_CALL(*hammer_updater_, PostRWProcess())
        .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Inject Entropy.
// Condition:
//   1. In RO section at the begining.
//   2. RW does not need update.
//   3. RW is not locked.
//   4. Pairing failed at the first time.
//   5. After injecting entropy successfully, pairing is successful
TEST_F(HammerUpdaterRWTest, Run_InjectEntropy) {
  current_section_ = SectionName::RO;

  {
    InSequence dummy;

    // First round: RW does not need update.  Attempt to jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));

    // Second round: Entering RW section, and need to inject entropy.
    EXPECT_CALL(*hammer_updater_, PostRWProcess())
        .WillOnce(DoAll(Assign(&(task_->inject_entropy), true),
                        Return(HammerUpdater::RunStatus::kNeedReset)));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RO), Return(true)));

    // Third round: Inject entropy and reset again.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, InjectEntropy()).WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(Return(true));

    // Fourth round: Send JumpToRW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));

    // Fifth round: Post-RW processing is successful.
    EXPECT_CALL(*hammer_updater_, PostRWProcess())
        .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Update the RW and continue.
// Condition:
//   1. In RO section.
//   2. RW needs update.
//   3. RW is not locked.
TEST_F(HammerUpdaterRWTest, RunOnce_UpdateRW) {
  current_section_ = SectionName::RO;
  ON_CALL(*fw_updater_, VersionMismatch(SectionName::RW))
      .WillByDefault(Return(true));

  {
    InSequence dummy;
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW))
        .WillOnce(Return(true));
  }

  task_->update_rw = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNeedReset);
}

// Unlock the RW and reset.
// Condition:
//   1. In RO section.
//   2. RW needs update.
//   3. RW is locked.
TEST_F(HammerUpdaterRWTest, RunOnce_UnlockRW) {
  current_section_ = SectionName::RO;
  ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(1));
  ON_CALL(*fw_updater_, IsSectionLocked(SectionName::RW))
      .WillByDefault(Return(true));

  {
    InSequence dummy;
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, UnlockRW()).WillRepeatedly(Return(true));
  }

  task_->update_rw = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNeedReset);
}

// Jump to RW.
// Condition:
//   1. In RO section.
//   2. RW does not need update.
TEST_F(HammerUpdaterRWTest, RunOnce_JumpToRW) {
  current_section_ = SectionName::RO;

  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNeedJump);
}

// Complete RW jump.
// Condition:
//   1. In RW section.
//   2. RW jump flag is set.
TEST_F(HammerUpdaterRWTest, RunOnce_CompleteRWJump) {
  current_section_ = SectionName::RW;
  EXPECT_CALL(*hammer_updater_, PostRWProcess())
      .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));

  task_->post_rw_jump = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNoUpdate);
}

// Keep in RW.
// Condition:
//   1. In RW section.
//   2. RW does not need update.
TEST_F(HammerUpdaterRWTest, RunOnce_KeepInRW) {
  current_section_ = SectionName::RW;
  EXPECT_CALL(*hammer_updater_, PostRWProcess())
      .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));

  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNoUpdate);
}

// Reset to RO.
// Condition:
//   1. In RW section.
//   2. RW needs update.
TEST_F(HammerUpdaterRWTest, RunOnce_ResetToRO) {
  current_section_ = SectionName::RW;
  ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(1));
  ON_CALL(*fw_updater_, VersionMismatch(SectionName::RW))
      .WillByDefault(Return(true));

  task_->update_rw = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNeedReset);
}

// Update working RW with incompatible key firmware.
// Under the situation RO (key1, v1) RW (key1, v1),
// invoke hammerd with (key2, v2).
// Should print: "RW section needs update, but local image is
// incompatible. Continuing to post-RW process; maybe RO can
// be updated."
// Condition:
//   1. In RW section.
//   2. RW needs update.
//   3. Local image key_version is incompatible.
TEST_F(HammerUpdaterRWTest, RunOnce_UpdateWorkingRWIncompatibleKey) {
  current_section_ = SectionName::RW;
  ON_CALL(*fw_updater_, ValidKey()).WillByDefault(Return(false));
  ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(1));
  ON_CALL(*fw_updater_, VersionMismatch(SectionName::RW))
      .WillByDefault(Return(true));

  EXPECT_CALL(*hammer_updater_, PostRWProcess())
      .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));

  task_->update_rw = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kNoUpdate);
}

// Update corrupt RW with incompatible key firmware.
// Under the situation RO (key1, v1) RW (corrupt),
// invoke hammerd with (key2, v2).
// Should print: "RW section is unusable, but local image is
// incompatible. Giving up."
// Condition:
//   1. In RO section right after a failed JumpToRW.
//   2. RW needs update.
//   3. Local image key_version is incompatible.
TEST_F(HammerUpdaterRWTest, RunOnce_UpdateCorruptRWIncompatibleKey) {
  current_section_ = SectionName::RO;
  ON_CALL(*fw_updater_, ValidKey()).WillByDefault(Return(false));
  ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(1));
  ON_CALL(*fw_updater_, VersionMismatch(SectionName::RW))
      .WillByDefault(Return(true));

  task_->post_rw_jump = true;
  ASSERT_EQ(hammer_updater_->RunOnce(), HammerUpdater::RunStatus::kFatalError);
}

// Update locked RW section.
// Condition:
//   1. In RO section first.
//   2. A valid update is available for RW.
//   3. RW is locked.
TEST_F(HammerUpdaterRWTest, Run_UpdateLockedRW) {
  current_section_ = SectionName::RO;
  bool is_rw_locked = true;

  ON_CALL(*fw_updater_, IsSectionLocked(SectionName::RW))
      .WillByDefault(ReturnPointee(&is_rw_locked));

  {
    InSequence dummy;
    // First round: Find RW is locked, send UnlockRW command and reset.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, UnlockRW()).WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(DoAll(Assign(&is_rw_locked, false), Return(true)));
    // Second round: Update RW section, and reset again.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(Return(true));
    // Third round: Jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));
    // Fourth round: Run PostRWProcess.
    EXPECT_CALL(*hammer_updater_, PostRWProcess())
        .WillOnce(Return(HammerUpdater::RunStatus::kNoUpdate));
  }

  task_->update_rw = true;
  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Successfully Pair with Hammer.
TEST_F(HammerUpdaterPostRWTest, Pairing_Passed) {
  EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
      .WillOnce(Return(ChallengeStatus::kChallengePassed));
  EXPECT_EQ(hammer_updater_->Pair(), HammerUpdater::RunStatus::kNoUpdate);
}

// Hammer needs to inject entropy, and rollback is locked.
TEST_F(HammerUpdaterPostRWTest, Pairing_NeedEntropyRollbackLocked) {
  {
    InSequence dummy;
    EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
        .WillOnce(Return(ChallengeStatus::kNeedInjectEntropy));
    EXPECT_CALL(*fw_updater_, IsRollbackLocked()).WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, UnlockRollback()).WillOnce(Return(true));
  }
  EXPECT_EQ(hammer_updater_->Pair(), HammerUpdater::RunStatus::kNeedReset);
}

// Hammer needs to inject entropy, and rollback is not locked.
TEST_F(HammerUpdaterPostRWTest, Pairing_NeedEntropyRollbackUnlocked) {
  {
    InSequence dummy;
    EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
        .WillOnce(Return(ChallengeStatus::kNeedInjectEntropy));
    EXPECT_CALL(*fw_updater_, IsRollbackLocked()).WillOnce(Return(false));
  }
  EXPECT_EQ(hammer_updater_->Pair(), HammerUpdater::RunStatus::kNeedReset);
}

// Failed to pair with Hammer.
TEST_F(HammerUpdaterPostRWTest, Pairing_Failed) {
  EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
      .WillOnce(Return(ChallengeStatus::kChallengeFailed));
  EXPECT_EQ(hammer_updater_->Pair(), HammerUpdater::RunStatus::kFatalError);
}

// RO update is required and successful.
TEST_F(HammerUpdaterPostRWTest, ROUpdate_Passed) {
  {
    InSequence dummy;
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateStartedSignal));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RO))
        .WillOnce(Return(true));
  }

  task_->update_ro = true;
  EXPECT_EQ(hammer_updater_->UpdateRO(), HammerUpdater::RunStatus::kNeedReset);
}

// RO update is required and fails.
TEST_F(HammerUpdaterPostRWTest, ROUpdate_Failed) {
  {
    InSequence dummy;
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateStartedSignal));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RO))
        .WillOnce(Return(false));
  }

  task_->update_ro = true;
  EXPECT_EQ(hammer_updater_->UpdateRO(), HammerUpdater::RunStatus::kNeedReset);
}

// RO update is not possible.
TEST_F(HammerUpdaterPostRWTest, ROUpdate_NotPossible) {
  ON_CALL(*fw_updater_, IsSectionLocked(SectionName::RO))
      .WillByDefault(Return(true));
  EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RO)).Times(0);

  task_->update_ro = true;
  EXPECT_EQ(hammer_updater_->UpdateRO(), HammerUpdater::RunStatus::kNoUpdate);
}

// Skip updating to new key version on a normal device.
// Condition:
//   1. Rollback number is increased.
//   2. Key is changed.
//   3. RO is locked.
TEST_F(HammerUpdaterPostRWTest, Run_SkipUpdateWhenKeyChanged) {
  current_section_ = SectionName::RO;

  ON_CALL(*fw_updater_, IsSectionLocked(SectionName::RO))
      .WillByDefault(Return(true));
  ON_CALL(*fw_updater_, ValidKey()).WillByDefault(Return(false));
  ON_CALL(*fw_updater_, CompareRollback()).WillByDefault(Return(1));

  {
    InSequence dummy;

    // RW cannot be updated, since the key version is incorrect. Attempt to
    // jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));
    // Check that RO was not updated and jumping to RW was successful.
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RO)).Times(0);
    EXPECT_CALL(*fw_updater_, SendSubcommandReceiveResponse(
                                  UpdateExtraCommand::kTouchpadInfo, "", _,
                                  sizeof(TouchpadInfo), false))
        .WillOnce(WriteResponse(static_cast<void*>(&response_)));
    EXPECT_CALL(*fw_updater_, TransferTouchpadFirmware(_, _))
        .Times(0);  // Version matched, skip updating.
    EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
        .WillOnce(Return(ChallengeStatus::kChallengePassed));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Test updating to new key version on a dogfood device.
// Condition:
//   1. Rollback number is increased.
//   2. Key is changed.
//   3. RO is not locked.
TEST_F(HammerUpdaterPostRWTest, Run_KeyVersionUpdate) {
  current_section_ = SectionName::RO;
  bool valid_key = false;
  int rollback_cmp = 1;

  ON_CALL(*fw_updater_, ValidKey()).WillByDefault(ReturnPointee(&valid_key));
  ON_CALL(*fw_updater_, CompareRollback())
      .WillByDefault(ReturnPointee(&rollback_cmp));

  {
    InSequence dummy;

    // RW cannot be updated, since the key version is incorrect. Attempt to
    // jump to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));

    // After jumping to RW, RO will be updated. Reset afterwards.
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateStartedSignal));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(DoAll(Assign(&current_section_, SectionName::RO),
                        Assign(&valid_key, true), Return(true)));

    // Hammer resets back into RO. Now the key version is correct, and
    // RW will be updated. Reset afterwards.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kStayInRO))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_, TransferImage(SectionName::RW))
        .WillOnce(Return(true));
    EXPECT_CALL(*fw_updater_,
                SendSubcommand(UpdateExtraCommand::kImmediateReset))
        .WillOnce(DoAll(Assign(&rollback_cmp, 0), Return(true)));

    // Now both sections are updated. Jump from RO to RW.
    EXPECT_CALL(*fw_updater_, SendSubcommand(UpdateExtraCommand::kJumpToRW))
        .WillOnce(
            DoAll(Assign(&current_section_, SectionName::RW), Return(true)));

    // Check that jumping to RW was successful.
    EXPECT_CALL(*fw_updater_, SendSubcommandReceiveResponse(
                                  UpdateExtraCommand::kTouchpadInfo, "", _,
                                  sizeof(TouchpadInfo), false))
        .WillOnce(WriteResponse(static_cast<void*>(&response_)));
    EXPECT_CALL(*fw_updater_, TransferTouchpadFirmware(_, _))
        .Times(0);  // Version matched, skip updating.
    EXPECT_CALL(*pair_manager_, PairChallenge(fw_updater_, dbus_wrapper_))
        .WillOnce(Return(ChallengeStatus::kChallengePassed));
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateSucceededSignal));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}

// Test the return value if we can't get touchpad infomation.
TEST_F(HammerUpdaterPostRWTest, Run_FailToGetTouchpadInfo) {
  EXPECT_CALL(*fw_updater_,
              SendSubcommandReceiveResponse(UpdateExtraCommand::kTouchpadInfo,
                                            "", _, sizeof(TouchpadInfo), false))
      .WillOnce(Return(false));

  ASSERT_EQ(hammer_updater_->RunTouchpadUpdater(),
            HammerUpdater::RunStatus::kNeedReset);
}

// Test logic of IC size matches with local firmware binary blob.
TEST_F(HammerUpdaterPostRWTest, Run_ICSizeMismatchAndStop) {
  // Make a mismatch response by setting a different firmware size.
  response_.fw_size += 9487;
  EXPECT_CALL(*fw_updater_,
              SendSubcommandReceiveResponse(UpdateExtraCommand::kTouchpadInfo,
                                            "", _, sizeof(TouchpadInfo), false))
      .WillOnce(WriteResponse(reinterpret_cast<void*>(&response_)));

  ASSERT_EQ(hammer_updater_->RunTouchpadUpdater(),
            HammerUpdater::RunStatus::kTouchpadMismatched);
}

// Test logic of entire firmware blob hash matches one accepted in RW EC.
TEST_F(HammerUpdaterPostRWTest, Run_HashMismatchAndStop) {
  // Make a mismatch response by setting a different allowed_fw_hash.
  memset(response_.allowed_fw_hash, response_.allowed_fw_hash[0] + 0x5F,
         SHA256_DIGEST_LENGTH);
  EXPECT_CALL(*fw_updater_,
              SendSubcommandReceiveResponse(UpdateExtraCommand::kTouchpadInfo,
                                            "", _, sizeof(TouchpadInfo), false))
      .WillOnce(WriteResponse(static_cast<void*>(&response_)));

  ASSERT_EQ(hammer_updater_->RunTouchpadUpdater(),
            HammerUpdater::RunStatus::kTouchpadMismatched);
}

// Test the return value if TransferTouchpadFirmware is failed.
TEST_F(HammerUpdaterPostRWTest, Run_FailToTransferFirmware) {
  response_.elan.fw_version -= 1;  // Make local fw_ver is newer than base.
  EXPECT_CALL(*fw_updater_,
              SendSubcommandReceiveResponse(UpdateExtraCommand::kTouchpadInfo,
                                            "", _, sizeof(TouchpadInfo), false))
      .WillOnce(WriteResponse(static_cast<void*>(&response_)));
  EXPECT_CALL(*fw_updater_, TransferTouchpadFirmware(_, _))
      .WillOnce(Return(false));

  ASSERT_EQ(hammer_updater_->RunTouchpadUpdater(),
            HammerUpdater::RunStatus::kNeedReset);
}

// Update touchpad firmware on boot if the firmware is broken.
// Condition:
//   1. at_boot_ is True.
//   2. In RW section.
//   2. touchpad firmware is broken.
TEST_F(HammerUpdaterPostRWTest, Run_UpdateTouchpadOnBoot) {
  *at_boot_ = true;
  current_section_ = SectionName::RW;
  response_.elan.fw_version = kElanBrokenFwVersion;

  {
    InSequence dummy;
    // Check that RO was not updated and jumping to RW was successful.
    EXPECT_CALL(*fw_updater_, SendSubcommandReceiveResponse(
                                  UpdateExtraCommand::kTouchpadInfo, "", _,
                                  sizeof(TouchpadInfo), false))
        .WillOnce(WriteResponse(static_cast<void*>(&response_)));
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateStartedSignal));
    EXPECT_CALL(*fw_updater_, TransferTouchpadFirmware(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*dbus_wrapper_, SendSignal(kBaseFirmwareUpdateSucceededSignal));
  }

  ExpectUsbConnections(AtLeast(1));
  ASSERT_EQ(hammer_updater_->Run(), HammerUpdater::RunStatus::kNoUpdate);
}
}  // namespace hammerd
