// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/daemon/dbus_service.h"

#include <sysexits.h>

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/dbus/dbus_object_test_helpers.h>
#include <brillo/file_utils.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_exported_object.h>
#include <dbus/rmad/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/interface/mock_rmad_interface.h"
#include "rmad/system/mock_tpm_manager_client.h"
#include "rmad/utils/mock_cros_config_utils.h"
#include "rmad/utils/mock_crossystem_utils.h"

using brillo::dbus_utils::AsyncEventSequencer;
using brillo::dbus_utils::PopValueFromReader;
using testing::_;
using testing::A;
using testing::DoAll;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace rmad {

class DBusServiceTest : public testing::Test {
 public:
  DBusServiceTest() {
    dbus::Bus::Options options;
    mock_bus_ = base::MakeRefCounted<NiceMock<dbus::MockBus>>(options);
    dbus::ObjectPath path(kRmadServicePath);
    mock_exported_object_ =
        base::MakeRefCounted<StrictMock<dbus::MockExportedObject>>(
            mock_bus_.get(), path);
    ON_CALL(*mock_bus_, GetExportedObject(path))
        .WillByDefault(Return(mock_exported_object_.get()));
    EXPECT_CALL(*mock_exported_object_, ExportMethod(_, _, _, _))
        .WillRepeatedly(Return());
    EXPECT_CALL(*mock_exported_object_, Unregister()).WillRepeatedly(Return());
  }
  ~DBusServiceTest() override = default;

  base::FilePath GetStateFilePath() const {
    return temp_dir_.GetPath().AppendASCII("state");
  }

  void SetUpDBusService(bool state_file_exist,
                        RoVerificationStatus ro_verification_status,
                        bool setup_success) {
    base::FilePath state_file_path = GetStateFilePath();
    if (state_file_exist) {
      brillo::TouchFile(state_file_path);
    }
    auto mock_tpm_manager_client =
        std::make_unique<NiceMock<MockTpmManagerClient>>();
    ON_CALL(*mock_tpm_manager_client, GetRoVerificationStatus(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(ro_verification_status), Return(true)));
    auto mock_cros_config_utils =
        std::make_unique<NiceMock<MockCrosConfigUtils>>();
    ON_CALL(*mock_cros_config_utils, GetRmadConfig(_))
        .WillByDefault(DoAll(SetArgPointee<0>(RmadConfig({.enabled = true})),
                             Return(true)));
    auto mock_crossystem_utils =
        std::make_unique<NiceMock<MockCrosSystemUtils>>();
    ON_CALL(*mock_crossystem_utils,
            GetString(Eq(CrosSystemUtils::kMainFwTypeProperty), _))
        .WillByDefault(DoAll(SetArgPointee<1>("normal"), Return(true)));
    dbus_service_ = std::make_unique<DBusService>(
        mock_bus_, &mock_rmad_service_, state_file_path,
        std::move(mock_tpm_manager_client), std::move(mock_cros_config_utils),
        std::move(mock_crossystem_utils));
    ASSERT_EQ(dbus_service_->OnEventLoopStarted(), EX_OK);

    auto sequencer = base::MakeRefCounted<AsyncEventSequencer>();
    dbus_service_->RegisterDBusObjectsAsync(sequencer.get());

    if (state_file_exist ||
        ro_verification_status == RMAD_RO_VERIFICATION_PASS ||
        ro_verification_status == RMAD_RO_VERIFICATION_UNSUPPORTED_TRIGGERED) {
      EXPECT_CALL(mock_rmad_service_, SetUp(_))
          .WillRepeatedly(Return(setup_success));
      EXPECT_CALL(mock_rmad_service_, TryTransitionNextStateFromCurrentState())
          .WillRepeatedly(Return());
    }
  }

  template <typename RequestProtobufType, typename ReplyProtobufType>
  void ExecuteMethod(const std::string& method_name,
                     const RequestProtobufType& request,
                     ReplyProtobufType* reply) {
    std::unique_ptr<dbus::MethodCall> call = CreateMethodCall(method_name);
    dbus::MessageWriter writer(call.get());
    writer.AppendProtoAsArrayOfBytes(request);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    if (response.get()) {
      dbus::MessageReader reader(response.get());
      EXPECT_TRUE(reader.PopArrayOfBytesAsProto(reply));
    }
  }

  template <typename ReplyProtobufType>
  void ExecuteMethod(const std::string& method_name,
                     const std::string request,
                     ReplyProtobufType* reply) {
    std::unique_ptr<dbus::MethodCall> call = CreateMethodCall(method_name);
    dbus::MessageWriter writer(call.get());
    writer.AppendString(request);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    if (response.get()) {
      dbus::MessageReader reader(response.get());
      EXPECT_TRUE(reader.PopArrayOfBytesAsProto(reply));
    }
  }

  template <typename ReplyProtobufType>
  void ExecuteMethod(const std::string& method_name, ReplyProtobufType* reply) {
    std::unique_ptr<dbus::MethodCall> call = CreateMethodCall(method_name);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    if (response.get()) {
      dbus::MessageReader reader(response.get());
      EXPECT_TRUE(reader.PopArrayOfBytesAsProto(reply));
    }
  }

  void ExecuteMethod(const std::string& method_name, std::string* reply) {
    std::unique_ptr<dbus::MethodCall> call = CreateMethodCall(method_name);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    if (response.get()) {
      dbus::MessageReader reader(response.get());
      EXPECT_TRUE(reader.PopString(reply));
    }
  }

  void ExecuteMethod(const std::string& method_name, bool* reply) {
    std::unique_ptr<dbus::MethodCall> call = CreateMethodCall(method_name);
    auto response = brillo::dbus_utils::testing::CallMethod(
        *dbus_service_->dbus_object_, call.get());
    if (response.get()) {
      dbus::MessageReader reader(response.get());
      EXPECT_TRUE(reader.PopBool(reply));
    }
  }

  void SignalError(RmadErrorCode error) {
    dbus_service_->SendErrorSignal(error);
  }

  void SignalHardwareVerification(const HardwareVerificationResult& result) {
    dbus_service_->SendHardwareVerificationResultSignal(result);
  }

  void SignalUpdateRoFirmwareStatus(const UpdateRoFirmwareStatus status) {
    dbus_service_->SendUpdateRoFirmwareStatusSignal(status);
  }

  void SignalCalibrationOverall(CalibrationOverallStatus overall_status) {
    dbus_service_->SendCalibrationOverallSignal(overall_status);
  }

  void SignalCalibrationComponent(CalibrationComponentStatus component_status) {
    dbus_service_->SendCalibrationProgressSignal(component_status);
  }

  void SignalProvision(const ProvisionStatus& status) {
    dbus_service_->SendProvisionProgressSignal(status);
  }

  void SignalFinalize(const FinalizeStatus& status) {
    dbus_service_->SendFinalizeProgressSignal(status);
  }

  void SignalHardwareWriteProtection(bool enabled) {
    dbus_service_->SendHardwareWriteProtectionStateSignal(enabled);
  }

  void SignalPowerCableState(bool plugged_in) {
    dbus_service_->SendPowerCableStateSignal(plugged_in);
  }

  void SignalExternalDisk(bool detected) {
    dbus_service_->SendExternalDiskSignal(detected);
  }

  dbus::MockExportedObject* GetMockExportedObject() {
    return mock_exported_object_.get();
  }

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  std::unique_ptr<dbus::MethodCall> CreateMethodCall(
      const std::string& method_name) {
    auto call =
        std::make_unique<dbus::MethodCall>(kRmadInterfaceName, method_name);
    call->SetSerial(1);
    return call;
  }

  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockExportedObject> mock_exported_object_;
  base::ScopedTempDir temp_dir_;
  StrictMock<MockRmadInterface> mock_rmad_service_;
  std::unique_ptr<DBusService> dbus_service_;
};

TEST_F(DBusServiceTest, IsRmaRequired_NotRequired) {
  SetUpDBusService(false, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  bool is_rma_required;
  ExecuteMethod(kIsRmaRequiredMethod, &is_rma_required);
  EXPECT_EQ(is_rma_required, false);
  EXPECT_FALSE(base::PathExists(GetStateFilePath()));
}

TEST_F(DBusServiceTest, IsRmaRequired_RoVerificationPass) {
  SetUpDBusService(false, RMAD_RO_VERIFICATION_PASS, true);
  bool is_rma_required;
  ExecuteMethod(kIsRmaRequiredMethod, &is_rma_required);
  EXPECT_EQ(is_rma_required, true);
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(DBusServiceTest, IsRmaRequired_RoVerificationUnsupportedTriggered) {
  SetUpDBusService(false, RMAD_RO_VERIFICATION_UNSUPPORTED_TRIGGERED, true);
  bool is_rma_required;
  ExecuteMethod(kIsRmaRequiredMethod, &is_rma_required);
  EXPECT_EQ(is_rma_required, true);
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(DBusServiceTest, IsRmaRequired_StateFileExists) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  bool is_rma_required;
  ExecuteMethod(kIsRmaRequiredMethod, &is_rma_required);
  EXPECT_EQ(is_rma_required, true);
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(DBusServiceTest, IsRmaRequired_InterfaceSetUpFailed) {
  // The method call doesn't set up the interface so it works normally.
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, false);
  bool is_rma_required;
  ExecuteMethod(kIsRmaRequiredMethod, &is_rma_required);
  EXPECT_EQ(is_rma_required, true);
  EXPECT_TRUE(base::PathExists(GetStateFilePath()));
}

TEST_F(DBusServiceTest, GetCurrentState_Success) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, GetCurrentState(_))
      .WillOnce(Invoke([](RmadInterface::GetStateCallback callback) {
        GetStateReply reply;
        reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
        std::move(callback).Run(reply, false);
      }));

  GetStateReply reply;
  ExecuteMethod(kGetCurrentStateMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, reply.error());
  EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state().state_case());
}

TEST_F(DBusServiceTest, GetCurrentState_RmaNotRequired) {
  SetUpDBusService(false, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);

  GetStateReply reply;
  ExecuteMethod(kGetCurrentStateMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, reply.error());
  EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state().state_case());
}

TEST_F(DBusServiceTest, GetCurrentState_InterfaceSetUpFailed) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, false);

  GetStateReply reply;
  ExecuteMethod(kGetCurrentStateMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_DAEMON_INITIALIZATION_FAILED, reply.error());
  EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state().state_case());
}

TEST_F(DBusServiceTest, TransitionNextState) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, TransitionNextState(_, _))
      .WillOnce(Invoke([](const TransitionNextStateRequest& request,
                          RmadInterface::GetStateCallback callback) {
        GetStateReply reply;
        reply.set_error(RMAD_ERROR_OK);
        RmadState* state = new RmadState();
        state->set_allocated_welcome(new WelcomeState());
        reply.set_allocated_state(state);
        std::move(callback).Run(reply, false);
      }));

  TransitionNextStateRequest request;
  GetStateReply reply;
  ExecuteMethod(kTransitionNextStateMethod, request, &reply);
  EXPECT_EQ(RMAD_ERROR_OK, reply.error());
  EXPECT_EQ(RmadState::kWelcome, reply.state().state_case());
}

TEST_F(DBusServiceTest, TransitionPreviousState) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, TransitionPreviousState(_))
      .WillOnce(Invoke([](RmadInterface::GetStateCallback callback) {
        GetStateReply reply;
        reply.set_error(RMAD_ERROR_TRANSITION_FAILED);
        std::move(callback).Run(reply, false);
      }));

  GetStateReply reply;
  ExecuteMethod(kTransitionPreviousStateMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_TRANSITION_FAILED, reply.error());
  EXPECT_EQ(RmadState::STATE_NOT_SET, reply.state().state_case());
}

TEST_F(DBusServiceTest, AbortRma) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, AbortRma(_))
      .WillOnce(Invoke([](RmadInterface::AbortRmaCallback callback) {
        AbortRmaReply reply;
        reply.set_error(RMAD_ERROR_ABORT_FAILED);
        std::move(callback).Run(reply, false);
      }));

  AbortRmaReply reply;
  ExecuteMethod(kAbortRmaMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_ABORT_FAILED, reply.error());
}

TEST_F(DBusServiceTest, GetLog) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, GetLog(_))
      .WillOnce(Invoke([](RmadInterface::GetLogCallback callback) {
        GetLogReply reply;
        reply.set_error(RMAD_ERROR_OK);
        reply.set_log("RMA log");
        std::move(callback).Run(reply, false);
      }));

  GetLogReply reply;
  ExecuteMethod(kGetLogMethod, &reply);
  EXPECT_EQ(RMAD_ERROR_OK, reply.error());
  EXPECT_EQ("RMA log", reply.log());
}

TEST_F(DBusServiceTest, SaveLog) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(mock_rmad_service_, SaveLog(_, _))
      .WillOnce(Invoke([](const std::string& diagnostics_log_text,
                          RmadInterface::SaveLogCallback callback) {
        SaveLogReply reply;
        reply.set_error(RMAD_ERROR_OK);
        reply.set_save_path("/save/path");
        std::move(callback).Run(reply, false);
      }));

  const std::string text = "A sample diagnostics log.";
  SaveLogReply reply;
  ExecuteMethod(kSaveLogMethod, text, &reply);
  EXPECT_EQ(RMAD_ERROR_OK, reply.error());
  EXPECT_EQ("/save/path", reply.save_path());
}

TEST_F(DBusServiceTest, SignalError) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "Error");
        EXPECT_EQ("i", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](RmadErrorCode error) {
          EXPECT_EQ(RMAD_ERROR_RMA_NOT_REQUIRED, error);
          called = true;
        };
        EXPECT_TRUE(
            (brillo::dbus_utils::DBusParamReader<false, RmadErrorCode>::Invoke(
                callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalError(RMAD_ERROR_RMA_NOT_REQUIRED);
}

TEST_F(DBusServiceTest, SignalHardwareVerification) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "HardwareVerificationResult");
        EXPECT_EQ("(bs)", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](HardwareVerificationResult result) {
          EXPECT_TRUE(result.is_compliant());
          EXPECT_EQ("test_error_string", result.error_str());
          called = true;
        };
        EXPECT_TRUE(
            (brillo::dbus_utils::DBusParamReader<
                false, HardwareVerificationResult>::Invoke(callback, &reader,
                                                           nullptr)));
        EXPECT_TRUE(called);
      }));
  HardwareVerificationResult result;
  result.set_is_compliant(true);
  result.set_error_str("test_error_string");
  SignalHardwareVerification(result);
}

TEST_F(DBusServiceTest, SignalUpdateRoFirmwareStatus) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "UpdateRoFirmwareStatus");
        EXPECT_EQ("i", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](UpdateRoFirmwareStatus status) {
          EXPECT_EQ(RMAD_UPDATE_RO_FIRMWARE_WAIT_USB, status);
          called = true;
        };
        EXPECT_TRUE((brillo::dbus_utils::DBusParamReader<
                     false, UpdateRoFirmwareStatus>::Invoke(callback, &reader,
                                                            nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalUpdateRoFirmwareStatus(RMAD_UPDATE_RO_FIRMWARE_WAIT_USB);
}

TEST_F(DBusServiceTest, SignalCalibrationOverall) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "CalibrationOverall");
        EXPECT_EQ("i", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](CalibrationOverallStatus status) {
          EXPECT_EQ(RMAD_CALIBRATION_OVERALL_CURRENT_ROUND_COMPLETE, status);
          called = true;
        };
        EXPECT_TRUE((brillo::dbus_utils::DBusParamReader<
                     false, CalibrationOverallStatus>::Invoke(callback, &reader,
                                                              nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalCalibrationOverall(RMAD_CALIBRATION_OVERALL_CURRENT_ROUND_COMPLETE);
}

TEST_F(DBusServiceTest, SignalCalibrationComponent) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "CalibrationProgress");
        EXPECT_EQ("(iid)", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](CalibrationComponentStatus status) {
          EXPECT_EQ(RmadComponent::RMAD_COMPONENT_BASE_ACCELEROMETER,
                    status.component());
          EXPECT_EQ(CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS,
                    status.status());
          EXPECT_DOUBLE_EQ(0.3, status.progress());
          called = true;
        };
        EXPECT_TRUE(
            (brillo::dbus_utils::DBusParamReader<
                false, CalibrationComponentStatus>::Invoke(callback, &reader,
                                                           nullptr)));
        EXPECT_TRUE(called);
      }));
  CalibrationComponentStatus component_status;
  component_status.set_component(
      RmadComponent::RMAD_COMPONENT_BASE_ACCELEROMETER);
  component_status.set_status(
      CalibrationComponentStatus::RMAD_CALIBRATION_IN_PROGRESS);
  component_status.set_progress(0.3);
  SignalCalibrationComponent(component_status);
}

TEST_F(DBusServiceTest, SignalProvision) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "ProvisioningProgress");
        EXPECT_EQ("(idi)", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](ProvisionStatus status) {
          EXPECT_EQ(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS,
                    status.status());
          EXPECT_DOUBLE_EQ(0.5, status.progress());
          EXPECT_EQ(ProvisionStatus::RMAD_PROVISION_ERROR_INTERNAL,
                    status.error());
          called = true;
        };
        EXPECT_TRUE((
            brillo::dbus_utils::DBusParamReader<false, ProvisionStatus>::Invoke(
                callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  ProvisionStatus status;
  status.set_status(ProvisionStatus::RMAD_PROVISION_STATUS_IN_PROGRESS);
  status.set_progress(0.5);
  status.set_error(ProvisionStatus::RMAD_PROVISION_ERROR_INTERNAL);
  SignalProvision(status);
}

TEST_F(DBusServiceTest, SignalFinalize) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "FinalizeProgress");
        EXPECT_EQ("(idi)", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](FinalizeStatus status) {
          EXPECT_EQ(FinalizeStatus::RMAD_FINALIZE_STATUS_IN_PROGRESS,
                    status.status());
          EXPECT_DOUBLE_EQ(0.5, status.progress());
          EXPECT_EQ(FinalizeStatus::RMAD_FINALIZE_ERROR_INTERNAL,
                    status.error());
          called = true;
        };
        EXPECT_TRUE(
            (brillo::dbus_utils::DBusParamReader<false, FinalizeStatus>::Invoke(
                callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  FinalizeStatus status;
  status.set_status(FinalizeStatus::RMAD_FINALIZE_STATUS_IN_PROGRESS);
  status.set_progress(0.5);
  status.set_error(FinalizeStatus::RMAD_FINALIZE_ERROR_INTERNAL);
  SignalFinalize(status);
}

TEST_F(DBusServiceTest, SignalHardwareWriteProtection) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "HardwareWriteProtectionState");
        EXPECT_EQ("b", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](bool wp_status) {
          EXPECT_TRUE(wp_status);
          called = true;
        };
        EXPECT_TRUE((brillo::dbus_utils::DBusParamReader<false, bool>::Invoke(
            callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalHardwareWriteProtection(true);
}

TEST_F(DBusServiceTest, SignalPowerCableState) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "PowerCableState");
        EXPECT_EQ("b", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](bool power_cable_status) {
          EXPECT_TRUE(power_cable_status);
          called = true;
        };
        EXPECT_TRUE((brillo::dbus_utils::DBusParamReader<false, bool>::Invoke(
            callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalPowerCableState(true);
}

TEST_F(DBusServiceTest, SignalExternalDisk) {
  SetUpDBusService(true, RMAD_RO_VERIFICATION_NOT_TRIGGERED, true);
  EXPECT_CALL(*GetMockExportedObject(), SendSignal(_))
      .WillOnce(Invoke([](dbus::Signal* signal) {
        EXPECT_EQ(signal->GetInterface(), "org.chromium.Rmad");
        EXPECT_EQ(signal->GetMember(), "ExternalDiskDetected");
        EXPECT_EQ("b", signal->GetSignature());
        dbus::MessageReader reader(signal);
        bool called = false;
        auto callback = [&called](bool external_disk_status) {
          EXPECT_TRUE(external_disk_status);
          called = true;
        };
        EXPECT_TRUE((brillo::dbus_utils::DBusParamReader<false, bool>::Invoke(
            callback, &reader, nullptr)));
        EXPECT_TRUE(called);
      }));
  SignalExternalDisk(true);
}

}  // namespace rmad
