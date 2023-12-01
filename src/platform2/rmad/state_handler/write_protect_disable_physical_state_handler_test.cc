// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/state_handler/state_handler_test_common.h"
#include "rmad/state_handler/write_protect_disable_physical_state_handler.h"
#include "rmad/utils/mock_cr50_utils.h"
#include "rmad/utils/mock_crossystem_utils.h"
#include "rmad/utils/mock_write_protect_utils.h"

using testing::_;
using testing::Assign;
using testing::DoAll;
using testing::Eq;
using testing::InSequence;
using testing::IsFalse;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace {

struct StateHandlerArgs {
  std::vector<bool> wp_status_list = {};
  bool factory_mode_enabled = false;
  bool enable_factory_mode_succeeded = true;
  bool is_cros_debug = false;
  bool* factory_mode_toggled = nullptr;
  bool* powerwash_requested = nullptr;
  bool* reboot_toggled = nullptr;
};

}  // namespace

namespace rmad {

class WriteProtectDisablePhysicalStateHandlerTest : public StateHandlerTest {
 public:
  // Helper class to mock the callback function to send signal.
  class SignalSender {
   public:
    MOCK_METHOD(void, SendHardwareWriteProtectSignal, (bool), (const));
  };

  scoped_refptr<WriteProtectDisablePhysicalStateHandler> CreateStateHandler(
      const StateHandlerArgs& args = {}) {
    // Mock |CrosSystemUtils|.
    auto mock_crossystem_utils =
        std::make_unique<NiceMock<MockCrosSystemUtils>>();
    ON_CALL(*mock_crossystem_utils,
            GetInt(Eq(CrosSystemUtils::kCrosDebugProperty), _))
        .WillByDefault(
            DoAll(SetArgPointee<1>(args.is_cros_debug ? 1 : 0), Return(true)));

    // Mock |WriteProtectUtils|.
    auto mock_write_protect_utils =
        std::make_unique<StrictMock<MockWriteProtectUtils>>();
    {
      InSequence seq;
      for (bool enabled : args.wp_status_list) {
        EXPECT_CALL(*mock_write_protect_utils,
                    GetHardwareWriteProtectionStatus(_))
            .WillOnce(DoAll(SetArgPointee<0, bool>(enabled), Return(true)));
      }
    }

    // Mock |Cr50Utils|.
    auto mock_cr50_utils = std::make_unique<NiceMock<MockCr50Utils>>();
    ON_CALL(*mock_cr50_utils, IsFactoryModeEnabled())
        .WillByDefault(Return(args.factory_mode_enabled));
    if (args.factory_mode_toggled) {
      ON_CALL(*mock_cr50_utils, EnableFactoryMode())
          .WillByDefault(DoAll(Assign(args.factory_mode_toggled, true),
                               Return(args.enable_factory_mode_succeeded)));
    }

    // Register signal callback.
    daemon_callback_->SetWriteProtectSignalCallback(
        base::BindRepeating(&SignalSender::SendHardwareWriteProtectSignal,
                            base::Unretained(&signal_sender_)));
    // Register request powerwash callback.
    daemon_callback_->SetExecuteRequestRmaPowerwashCallback(base::BindRepeating(
        &WriteProtectDisablePhysicalStateHandlerTest::RequestRmaPowerwash,
        base::Unretained(this), args.powerwash_requested));
    // Register reboot EC callback.
    daemon_callback_->SetExecuteRebootEcCallback(base::BindRepeating(
        &WriteProtectDisablePhysicalStateHandlerTest::RebootEc,
        base::Unretained(this), args.reboot_toggled));

    return base::MakeRefCounted<WriteProtectDisablePhysicalStateHandler>(
        json_store_, daemon_callback_, GetTempDirPath(),
        std::move(mock_cr50_utils), std::move(mock_crossystem_utils),
        std::move(mock_write_protect_utils));
  }

  void RequestRmaPowerwash(bool* powerwash_requested,
                           base::OnceCallback<void(bool)> callback) {
    if (powerwash_requested) {
      *powerwash_requested = true;
    }
    std::move(callback).Run(true);
  }

  void RebootEc(bool* reboot_toggled, base::OnceCallback<void(bool)> callback) {
    if (reboot_toggled) {
      *reboot_toggled = true;
    }
    std::move(callback).Run(true);
  }

 protected:
  StrictMock<SignalSender> signal_sender_;
  bool factory_mode_enabled_;

  // Variables for TaskRunner.
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(WriteProtectDisablePhysicalStateHandlerTest, InitializeState_Success) {
  // Set up environment to wipe device.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_FALSE(handler->GetState().wp_disable_physical().keep_device_open());
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest, InitializeState_Failed) {
  // No kWipeDevice set in |json_store_|.
  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(),
            RMAD_ERROR_STATE_HANDLER_INITIALIZATION_FAILED);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       TryGetNextStateCaseAtBoot_Succeeded_FactoryModeEnabled) {
  // Set up environment for wiping the device and rebooted the device.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));
  EXPECT_TRUE(json_store_->SetValue(kEcRebooted, true));

  auto handler = CreateStateHandler(
      {.wp_status_list = {false}, .factory_mode_enabled = true});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableComplete);

  // Check |json_store_|.
  std::string wp_disable_method_name;
  WpDisableMethod wp_disable_method;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method, RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE);

  // Check if the metrics value set correctly.
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method, RMAD_WP_DISABLE_METHOD_PHYSICAL_ASSEMBLE_DEVICE);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       TryGetNextStateCaseAtBoot_Succeeded_KeepDeviceOpen) {
  // Set up environment for not wiping the device and rebooted the device.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  EXPECT_TRUE(json_store_->SetValue(kEcRebooted, true));

  auto handler = CreateStateHandler(
      {.wp_status_list = {false}, .factory_mode_enabled = false});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisableComplete);

  // Check |json_store_|.
  std::string wp_disable_method_name;
  WpDisableMethod wp_disable_method;
  EXPECT_TRUE(json_store_->GetValue(kWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method,
            RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN);

  // Check if the metrics value set correctly.
  EXPECT_TRUE(MetricsUtils::GetMetricsValue(
      json_store_, kMetricsWpDisableMethod, &wp_disable_method_name));
  EXPECT_TRUE(
      WpDisableMethod_Parse(wp_disable_method_name, &wp_disable_method));
  EXPECT_EQ(wp_disable_method,
            RMAD_WP_DISABLE_METHOD_PHYSICAL_KEEP_DEVICE_OPEN);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       TryGetNextStateCaseAtBoot_Failed) {
  // Set up environment for not wiping the device and rebooted the device.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));
  EXPECT_TRUE(json_store_->SetValue(kEcRebooted, true));

  // WP is still enabled.
  auto handler = CreateStateHandler(
      {.wp_status_list = {true}, .factory_mode_enabled = true});
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  auto [error, state_case] = handler->TryGetNextStateCaseAtBoot();
  EXPECT_EQ(error, RMAD_ERROR_OK);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_Success_AdditionalEcReboot) {
  // Set up environment for not wiping the device and the device has not
  // rebooted yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));

  // Factory mode is enabled but we still need to do EC reboot.
  bool factory_mode_toggled = false, powerwash_requested = false,
       reboot_toggled = false;
  auto handler =
      CreateStateHandler({.wp_status_list = {false},
                          .factory_mode_enabled = true,
                          .factory_mode_toggled = &factory_mode_toggled,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});

  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_TRUE(handler->GetState().wp_disable_physical().keep_device_open());

  RmadState state;
  state.set_allocated_wp_disable_physical(new WriteProtectDisablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsFalse()))
      .WillOnce(Assign(&signal_sent, true));

  // Call to |mock_crossystem_utils_| during polling, get 0.
  // Doesn't need to enable factory mode and still send the signal.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_TRUE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Doesn't request powerwash and reboot after a delay.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kRebootDelay);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);

  bool ec_rebooted;
  EXPECT_TRUE(json_store_->GetValue(kEcRebooted, &ec_rebooted));
  EXPECT_TRUE(ec_rebooted);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_EnableFactoryModeSuccess) {
  // Set up environment for wiping the device and the device has not rebooted
  // yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  // Factory mode is disabled so we should enable it and do EC reboot.
  bool factory_mode_toggled = false, powerwash_requested = false,
       reboot_toggled = false;
  auto handler =
      CreateStateHandler({.wp_status_list = {true, true, false},
                          .factory_mode_enabled = false,
                          .factory_mode_toggled = &factory_mode_toggled,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});

  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_FALSE(handler->GetState().wp_disable_physical().keep_device_open());

  RmadState state;
  state.set_allocated_wp_disable_physical(new WriteProtectDisablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsFalse()))
      .WillOnce(Assign(&signal_sent, true));

  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // First call to |mock_crossystem_utils_| during polling, get 1.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Second call to |mock_crossystem_utils_| during polling, get 1.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Third call to |mock_crossystem_utils_| during polling, get 0.
  // Try to enable factory mode and send the signal.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_TRUE(factory_mode_toggled);
  EXPECT_TRUE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Request powerwash and reboot after a delay.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kRebootDelay);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);

  bool ec_rebooted;
  EXPECT_TRUE(json_store_->GetValue(kEcRebooted, &ec_rebooted));
  EXPECT_TRUE(ec_rebooted);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_FactoryModeSuccess_PowerwashDisabled_CrosDebug) {
  // Set up environment for wiping the device and the device has not rebooted
  // yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  // Powerwash is disabled manually.
  brillo::TouchFile(GetTempDirPath().AppendASCII(kDisablePowerwashFilePath));

  // Factory mode is disabled so we should enable it and do EC reboot.
  bool factory_mode_toggled = false, powerwash_requested = false,
       reboot_toggled = false;
  auto handler =
      CreateStateHandler({.wp_status_list = {false},
                          .factory_mode_enabled = false,
                          .is_cros_debug = true,
                          .factory_mode_toggled = &factory_mode_toggled,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});

  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_FALSE(handler->GetState().wp_disable_physical().keep_device_open());

  RmadState state;
  state.set_allocated_wp_disable_physical(new WriteProtectDisablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsFalse()))
      .WillOnce(Assign(&signal_sent, true));

  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Call to |mock_crossystem_utils_| during polling, get 0.
  // Try to enable factory mode and send the signal.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_TRUE(factory_mode_toggled);
  EXPECT_TRUE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Reboot after a delay.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kRebootDelay);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);

  bool ec_rebooted;
  EXPECT_TRUE(json_store_->GetValue(kEcRebooted, &ec_rebooted));
  EXPECT_TRUE(ec_rebooted);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_FactoryModeSuccess_PowerwashDisabled_NonCrosDebug) {
  // Set up environment for wiping the device and the device has not rebooted
  // yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  // Powerwash is disabled manually.
  brillo::TouchFile(GetTempDirPath().AppendASCII(kDisablePowerwashFilePath));

  // Factory mode is disabled so we should enable it an do EC reboot. cros_debug
  // is not turned on so we still do a powerwash.
  bool factory_mode_toggled = false, powerwash_requested = false,
       reboot_toggled = false;
  auto handler =
      CreateStateHandler({.wp_status_list = {false},
                          .factory_mode_enabled = false,
                          .is_cros_debug = false,
                          .factory_mode_toggled = &factory_mode_toggled,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});

  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_FALSE(handler->GetState().wp_disable_physical().keep_device_open());

  RmadState state;
  state.set_allocated_wp_disable_physical(new WriteProtectDisablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsFalse()))
      .WillOnce(Assign(&signal_sent, true));

  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Call to |mock_crossystem_utils_| during polling, get 0.
  // Try to enable factory mode and send the signal.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_TRUE(factory_mode_toggled);
  EXPECT_TRUE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Request powerwash and reboot after a delay.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kRebootDelay);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);

  bool ec_rebooted;
  EXPECT_TRUE(json_store_->GetValue(kEcRebooted, &ec_rebooted));
  EXPECT_TRUE(ec_rebooted);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_FactoryModeFailed) {
  // Set up environment for wiping the device and the device has not rebooted
  // yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, true));

  // Factory mode is disabled so we should enable it, but it fails.
  bool factory_mode_toggled = false, powerwash_requested = false,
       reboot_toggled = false;
  auto handler =
      CreateStateHandler({.wp_status_list = {false},
                          .factory_mode_enabled = false,
                          .enable_factory_mode_succeeded = false,
                          .factory_mode_toggled = &factory_mode_toggled,
                          .powerwash_requested = &powerwash_requested,
                          .reboot_toggled = &reboot_toggled});

  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);
  handler->RunState();
  EXPECT_FALSE(handler->GetState().wp_disable_physical().keep_device_open());

  RmadState state;
  state.set_allocated_wp_disable_physical(new WriteProtectDisablePhysicalState);

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_WAIT);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);

  bool signal_sent = false;
  EXPECT_CALL(signal_sender_, SendHardwareWriteProtectSignal(IsFalse()))
      .WillOnce(Assign(&signal_sent, true));

  EXPECT_FALSE(factory_mode_toggled);
  EXPECT_FALSE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Call to |mock_crossystem_utils_| during polling, get 0.
  // Try to enable factory mode and send the signal.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kPollInterval);
  EXPECT_TRUE(factory_mode_toggled);
  EXPECT_TRUE(signal_sent);
  EXPECT_FALSE(powerwash_requested);
  EXPECT_FALSE(reboot_toggled);
  // Request powerwash and reboot after a delay.
  task_environment_.FastForwardBy(
      WriteProtectDisablePhysicalStateHandler::kRebootDelay);
  EXPECT_TRUE(powerwash_requested);
  EXPECT_TRUE(reboot_toggled);

  bool ec_rebooted;
  EXPECT_TRUE(json_store_->GetValue(kEcRebooted, &ec_rebooted));
  EXPECT_TRUE(ec_rebooted);
}

TEST_F(WriteProtectDisablePhysicalStateHandlerTest,
       GetNextStateCase_MissingState) {
  // Set up environment for not wiping the device and the device has not
  // rebooted yet.
  EXPECT_TRUE(json_store_->SetValue(kWipeDevice, false));

  auto handler = CreateStateHandler();
  EXPECT_EQ(handler->InitializeState(), RMAD_ERROR_OK);

  // No WriteProtectDisablePhysicalState.
  RmadState state;

  auto [error, state_case] = handler->GetNextStateCase(state);
  EXPECT_EQ(error, RMAD_ERROR_REQUEST_INVALID);
  EXPECT_EQ(state_case, RmadState::StateCase::kWpDisablePhysical);
}

}  // namespace rmad
