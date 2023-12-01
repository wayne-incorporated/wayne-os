// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/json/json_reader.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_discovery.h"
#include "diagnostics/cros_healthd/routines/routine_test_utils.h"
#include "diagnostics/cros_healthd/system/mock_bluetooth_info_manager.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/dbus_bindings/bluetooth/dbus-proxy-mocks.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::WithArg;

class BluetoothDiscoveryRoutineTest : public testing::Test {
 protected:
  BluetoothDiscoveryRoutineTest() = default;
  BluetoothDiscoveryRoutineTest(const BluetoothDiscoveryRoutineTest&) = delete;
  BluetoothDiscoveryRoutineTest& operator=(
      const BluetoothDiscoveryRoutineTest&) = delete;

  void SetUp() override {
    EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
        .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
            &mock_adapter_proxy_}));
    routine_ = std::make_unique<BluetoothDiscoveryRoutine>(&mock_context_);
  }

  MockExecutor* mock_executor() { return mock_context_.mock_executor(); }

  MockBluetoothInfoManager* mock_bluetooth_info_manager() {
    return mock_context_.mock_bluetooth_info_manager();
  }

  FakeBluetoothEventHub* fake_bluetooth_event_hub() {
    return mock_context_.fake_bluetooth_event_hub();
  }

  void SetUpNullAdapter() {
    EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
        .WillOnce(
            Return(std::vector<org::bluez::Adapter1ProxyInterface*>{nullptr}));
    routine_ = std::make_unique<BluetoothDiscoveryRoutine>(&mock_context_);
  }

  // Ensure the adapter powered is on when the powered is |current_powered| at
  // first.
  void SetEnsurePoweredOnCall(bool current_powered, bool is_success = true) {
    EXPECT_CALL(mock_adapter_proxy_, powered())
        .WillOnce(Return(current_powered));
    if (!current_powered) {
      EXPECT_CALL(mock_adapter_proxy_, set_powered(_, _))
          .WillOnce(Invoke(
              [=](bool powered, base::OnceCallback<void(bool)> on_finish) {
                EXPECT_TRUE(powered);
                std::move(on_finish).Run(is_success);
              }));
    }
  }

  // Setup the discovering status after changing in HCI level and D-Bus level.
  void SetVerifyDiscoveringCall(bool hci_result_discovering,
                                bool dbus_result_discovering) {
    EXPECT_CALL(mock_adapter_proxy_, discovering())
        .WillOnce(Return(dbus_result_discovering));
    EXPECT_CALL(*mock_executor(), GetHciDeviceConfig(_))
        .WillOnce(WithArg<0>(
            Invoke([=](mojom::Executor::GetHciDeviceConfigCallback callback) {
              mojom::ExecutedProcessResult result;
              result.return_code = EXIT_SUCCESS;
              if (hci_result_discovering)
                result.out = "\tUP RUNNING PSCAN ISCAN INQUIRY \n";
              else
                result.out = "\tUP RUNNING PSCAN ISCAN \n";
              std::move(callback).Run(result.Clone());
            })));
  }

  void CheckRoutineUpdate(uint32_t progress_percent,
                          mojom::DiagnosticRoutineStatusEnum status,
                          std::string status_message,
                          base::Value::Dict output_dict = base::Value::Dict()) {
    routine_->PopulateStatusUpdate(&update_, true);
    EXPECT_EQ(update_.progress_percent, progress_percent);
    VerifyNonInteractiveUpdate(update_.routine_update_union, status,
                               status_message);
    EXPECT_EQ(output_dict, base::JSONReader::Read(
                               GetStringFromValidReadOnlySharedMemoryMapping(
                                   std::move(update_.output))));
  }

  base::Value::Dict ConstructResult(bool hci_discovering,
                                    bool dbus_discovering) {
    base::Value::Dict out_result;
    out_result.Set("hci_discovering", hci_discovering);
    out_result.Set("dbus_discovering", dbus_discovering);
    return out_result;
  }

  base::Value::Dict ConstructRoutineOutput(
      base::Value::Dict start_discovery_result,
      std::optional<base::Value::Dict> stop_discovery_result = std::nullopt) {
    base::Value::Dict output_dict;
    output_dict.Set("start_discovery_result",
                    std::move(start_discovery_result));
    if (stop_discovery_result.has_value()) {
      output_dict.Set("stop_discovery_result",
                      std::move(stop_discovery_result.value()));
    }
    return output_dict;
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<DiagnosticRoutine> routine_;
  StrictMock<org::bluez::Adapter1ProxyMock> mock_adapter_proxy_;

 private:
  MockContext mock_context_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that the BluetoothDiscoveryRoutine can be run successfully when the
// powered is off at first.
TEST_F(BluetoothDiscoveryRoutineTest, RoutineSuccessWhenPoweredOff) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/true,
                           /*dbus_result_discovering=*/true);
  // Stop Discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/false,
                           /*dbus_result_discovering=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage,
                     ConstructRoutineOutput(ConstructResult(true, true),
                                            ConstructResult(false, false)));
}

// Test that the BluetoothDiscoveryRoutine can be run successfully when the
// powered is on at first.
TEST_F(BluetoothDiscoveryRoutineTest, RoutineSuccessWhenPoweredOn) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/true);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/true,
                           /*dbus_result_discovering=*/true);
  // Stop Discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/false,
                           /*dbus_result_discovering=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage,
                     ConstructRoutineOutput(ConstructResult(true, true),
                                            ConstructResult(false, false)));
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when it
// fails to power on the adapter.
TEST_F(BluetoothDiscoveryRoutineTest, FailedPowerOnAdapter) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Failed to power on.
  SetEnsurePoweredOnCall(/*current_powered=*/false, /*is_success=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
}

// Test that the BluetoothDiscoveryRoutine can handle unexpected discovering
// status in HCI level and return a kFailed status.
TEST_F(BluetoothDiscoveryRoutineTest, FailedVerifyDiscoveringHci) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery, but get unexpected discovering status in HCI level.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/false,
                           /*dbus_result_discovering=*/true);
  // Stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedVerifyDiscovering,
                     ConstructRoutineOutput(ConstructResult(false, true)));
}

// Test that the BluetoothDiscoveryRoutine can handle unexpected discovering
// status in D-Bus level and return a kFailed status.
TEST_F(BluetoothDiscoveryRoutineTest, FailedVerifyDiscoveringDbus) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/true,
                           /*dbus_result_discovering=*/true);
  // Stop Discovery, but get unexpected discovering status in D-Bus level.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/false,
                           /*dbus_result_discovering=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedVerifyDiscovering,
                     ConstructRoutineOutput(ConstructResult(true, true),
                                            ConstructResult(false, true)));
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when it
// fails to start discovery.
TEST_F(BluetoothDiscoveryRoutineTest, FailedStartDiscovery) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Failed to start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<1>(
          Invoke([](base::OnceCallback<void(brillo::Error*)> on_error) {
            std::move(on_error).Run(nullptr);
          })));
  // Stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery);
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when it
// fails to stop discovery.
TEST_F(BluetoothDiscoveryRoutineTest, FailedStopDiscovery) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  SetVerifyDiscoveringCall(/*hci_result_discovering=*/true,
                           /*dbus_result_discovering=*/true);
  // Failed to stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<1>(
          Invoke([](base::OnceCallback<void(brillo::Error*)> on_error) {
            std::move(on_error).Run(nullptr);
          })));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery,
                     ConstructRoutineOutput(ConstructResult(true, true)));
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when it fails
// to get adapter.
TEST_F(BluetoothDiscoveryRoutineTest, GetAdapterError) {
  SetUpNullAdapter();
  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedGetAdapter);
}

// Test that the BluetoothDiscoveryRoutine returns a kFailed status when the
// adapter is in discovery mode.
TEST_F(BluetoothDiscoveryRoutineTest, PreCheckFailed) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  // The adapter is in discovery mode.
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedDiscoveryMode);
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when it gets
// error by calling GetHciDeviceConfig from executor.
TEST_F(BluetoothDiscoveryRoutineTest, GetHciDeviceConfigError) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));
  // Set error return code.
  EXPECT_CALL(*mock_executor(), GetHciDeviceConfig(_))
      .WillOnce(WithArg<0>(
          Invoke([=](mojom::Executor::GetHciDeviceConfigCallback callback) {
            mojom::ExecutedProcessResult result;
            result.return_code = EXIT_FAILURE;
            result.err = "Failed to run hciconfig";
            std::move(callback).Run(result.Clone());
          })));
  // Stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     "GetHciConfig failed with return code: 1 and error: "
                     "Failed to run hciconfig");
}

// Test that the BluetoothPowerRoutine returns a kError status when it failed to
// ensure powered status is on from the output of calling GetHciDeviceConfig.
TEST_F(BluetoothDiscoveryRoutineTest, UnexpectedHciDeviceConfigError) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
        fake_bluetooth_event_hub()->SendAdapterPropertyChanged(
            &mock_adapter_proxy_, mock_adapter_proxy_.DiscoveringName());
      })));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));
  // Set error return code.
  EXPECT_CALL(*mock_executor(), GetHciDeviceConfig(_))
      .WillOnce(WithArg<0>(
          Invoke([=](mojom::Executor::GetHciDeviceConfigCallback callback) {
            mojom::ExecutedProcessResult result;
            result.return_code = EXIT_SUCCESS;
            result.out = "DOWN";
            std::move(callback).Run(result.Clone());
          })));
  // Stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _));

  routine_->Start();
  CheckRoutineUpdate(
      100, mojom::DiagnosticRoutineStatusEnum::kError,
      "Failed to ensure powered status is on from HCI device config.");
}

// Test that the BluetoothDiscoveryRoutine returns a kError status when timeout
// occurred.
TEST_F(BluetoothDiscoveryRoutineTest, RoutineTimeoutOccurred) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _));
  // Stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _));

  routine_->Start();
  // Trigger timeout.
  task_environment_.FastForwardBy(kRoutineDiscoveryTimeout);
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     "Bluetooth routine failed to complete before timeout.");
}

}  // namespace
}  // namespace diagnostics
