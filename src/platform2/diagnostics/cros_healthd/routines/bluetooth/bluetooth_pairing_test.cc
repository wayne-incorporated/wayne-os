// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/hash/hash.h>
#include <base/json/json_reader.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_constants.h"
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_pairing.h"
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
using ::testing::ReturnRef;
using ::testing::StrictMock;
using ::testing::WithArg;
using ::testing::WithArgs;

class BluetoothPairingRoutineTest : public testing::Test {
 protected:
  BluetoothPairingRoutineTest() = default;
  BluetoothPairingRoutineTest(const BluetoothPairingRoutineTest&) = delete;
  BluetoothPairingRoutineTest& operator=(const BluetoothPairingRoutineTest&) =
      delete;

  void SetUp() override {
    EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
        .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
            &mock_adapter_proxy_}));
    routine_ = std::make_unique<BluetoothPairingRoutine>(
        &mock_context_, base::NumberToString(base::FastHash(target_address_)));
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
    routine_ = std::make_unique<BluetoothPairingRoutine>(
        &mock_context_, base::NumberToString(base::FastHash(target_address_)));
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

  // The adapter starts discovery and send device added events for each device
  // in |added_devices|.
  void SetStartDiscoveryCall(
      bool is_success,
      const std::vector<org::bluez::Device1ProxyInterface*>& added_devices) {
    EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
        .WillOnce(WithArgs<0, 1>(
            Invoke([=](base::OnceCallback<void()> on_success,
                       base::OnceCallback<void(brillo::Error*)> on_error) {
              if (is_success) {
                std::move(on_success).Run();
                // Send out peripheral in |added_devices|.
                for (const auto& device : added_devices)
                  fake_bluetooth_event_hub()->SendDeviceAdded(device);
              } else {
                std::move(on_error).Run(nullptr);
              }
            })));
  }

  // The adapter stops discovery.
  void SetStopDiscoveryCall(bool is_success) {
    EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
        .WillOnce(WithArgs<0, 1>(
            Invoke([=](base::OnceCallback<void()> on_success,
                       base::OnceCallback<void(brillo::Error*)> on_error) {
              if (is_success) {
                std::move(on_success).Run();
              } else {
                std::move(on_error).Run(nullptr);
              }
            })));
  }

  void SetChangeAliasCall(bool is_success, const std::string& expected_alias) {
    EXPECT_CALL(mock_target_device_, set_alias(_, _))
        .WillOnce(Invoke([=](const std::string& alias,
                             base::OnceCallback<void(bool)> callback) {
          EXPECT_EQ(alias, expected_alias);
          std::move(callback).Run(is_success);
        }));
  }

  // The |mock_target_device_| with the address |target_address_| is expected to
  // be added.
  void SetDeviceAddedCall() {
    // Function call in BluetoothEventHub::OnDeviceAdded.
    EXPECT_CALL(mock_target_device_, SetPropertyChangedCallback(_));

    // Function call in device added callback.
    EXPECT_CALL(mock_target_device_, address())
        .WillOnce(ReturnRef(target_address_));
    // Bluetooth class of device (CoD).
    if (target_bluetooth_class_.has_value()) {
      EXPECT_CALL(mock_target_device_, is_bluetooth_class_valid())
          .WillOnce(Return(true));
      EXPECT_CALL(mock_target_device_, bluetooth_class())
          .WillOnce(Return(target_bluetooth_class_.value()));
    } else {
      EXPECT_CALL(mock_target_device_, is_bluetooth_class_valid())
          .WillOnce(Return(false));
    }
    // UUIDs.
    if (!target_uuids_.empty()) {
      EXPECT_CALL(mock_target_device_, is_uuids_valid()).WillOnce(Return(true));
      EXPECT_CALL(mock_target_device_, uuids())
          .WillOnce(ReturnRef(target_uuids_));
    } else {
      EXPECT_CALL(mock_target_device_, is_uuids_valid())
          .WillOnce(Return(false));
    }
  }

  // Successfully connect the |mock_target_device_| and report the connection
  // result.
  void SetConnectDeviceCall(bool connected_result = true) {
    EXPECT_CALL(mock_target_device_, ConnectAsync(_, _, _))
        .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
          std::move(on_success).Run();
          // Send out connected status changed event.
          fake_bluetooth_event_hub()->SendDevicePropertyChanged(
              &mock_target_device_, mock_target_device_.ConnectedName());
        })));
    EXPECT_CALL(mock_target_device_, connected())
        .WillOnce(Return(connected_result));
  }

  // Successfully pair the |mock_target_device_|.
  void SetPairDeviceCall(bool paired_result = true) {
    // Return false to call Pair function.
    EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(false));
    EXPECT_CALL(mock_target_device_, PairAsync(_, _, _))
        .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
          std::move(on_success).Run();
          // Send out paired status changed event.
          fake_bluetooth_event_hub()->SendDevicePropertyChanged(
              &mock_target_device_, mock_target_device_.PairedName());
        })));
    // Return false to monitor paired changed event.
    EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(false));
    EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(paired_result));
  }

  // The adapter removes the |mock_target_device_|.
  void SetRemoveDeviceCall() {
    EXPECT_CALL(mock_target_device_, GetObjectPath())
        .WillOnce(ReturnRef(target_device_path_));
    EXPECT_CALL(mock_adapter_proxy_, RemoveDeviceAsync(_, _, _, _))
        .WillOnce(
            WithArgs<0, 1>(Invoke([&](const dbus::ObjectPath& in_device,
                                      base::OnceCallback<void()> on_success) {
              EXPECT_EQ(in_device, target_device_path_);
              std::move(on_success).Run();
            })));
  }

  base::Value::Dict GetErrorDict(const brillo::Error& error) {
    base::Value::Dict out_error;
    out_error.Set("code", error.GetCode());
    out_error.Set("message", error.GetMessage());
    return out_error;
  }

  base::Value::Dict ConstructOutputDict(
      const brillo::Error* connect_error = nullptr,
      const brillo::Error* pair_error = nullptr) {
    base::Value::Dict output_dict;
    if (target_bluetooth_class_.has_value()) {
      output_dict.Set("bluetooth_class",
                      base::NumberToString(target_bluetooth_class_.value()));
    }
    if (!target_uuids_.empty()) {
      base::Value::List out_uuids;
      for (const auto& uuid : target_uuids_)
        out_uuids.Append(uuid);
      output_dict.Set("uuids", std::move(out_uuids));
    }

    if (connect_error)
      output_dict.Set("connect_error", GetErrorDict(*connect_error));
    if (pair_error)
      output_dict.Set("pair_error", GetErrorDict(*pair_error));

    return output_dict;
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

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<DiagnosticRoutine> routine_;
  StrictMock<org::bluez::Adapter1ProxyMock> mock_adapter_proxy_;
  StrictMock<org::bluez::Device1ProxyMock> mock_target_device_;

  const std::string target_address_ = "70:88:6B:92:34:70";
  const dbus::ObjectPath target_device_path_ =
      dbus::ObjectPath("/org/bluez/dev_70_88_6B_92_34_70");

 private:
  MockContext mock_context_;
  const std::optional<uint32_t> target_bluetooth_class_ = 2360344;
  const std::vector<std::string> target_uuids_ = {
      "0000110b-0000-1000-8000-00805f9b34fb",
      "0000110c-0000-1000-8000-00805f9b34fb",
      "0000110e-0000-1000-8000-00805f9b34fb",
      "0000111e-0000-1000-8000-00805f9b34fb",
      "00001200-0000-1000-8000-00805f9b34fb"};
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that the BluetoothPairingRoutine can be run successfully.
TEST_F(BluetoothPairingRoutineTest, RoutineSuccess) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  // Check if the target peripheral is cached. If so, remove it.
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          &mock_target_device_, nullptr}));
  EXPECT_CALL(mock_target_device_, address())
      .WillOnce(ReturnRef(target_address_));
  EXPECT_CALL(mock_target_device_, alias()).WillOnce(ReturnRef(""));
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(false));
  SetRemoveDeviceCall();

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();
  SetPairDeviceCall();
  SetChangeAliasCall(/*is_success=*/true, /*expected_alias=*/"");
  SetRemoveDeviceCall();
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage, ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine can be run successfully when the device
// is paired automatically during connecting.
TEST_F(BluetoothPairingRoutineTest, RoutineSuccessOnlyConnect) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  // Check existed devices when the target peripheral is cached.
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();
  // The device is paired automatically after connecting.
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(true));
  // Return true to avoid monitoring paired status changed event.
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(true));

  SetChangeAliasCall(/*is_success=*/true, /*expected_alias=*/"");
  SetRemoveDeviceCall();
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage, ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kError status when it fails
// to power on the adapter.
TEST_F(BluetoothPairingRoutineTest, FailedPowerOnAdapter) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Failed to power on.
  SetEnsurePoweredOnCall(/*current_powered=*/false, /*is_success=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to remove cached peripheral.
TEST_F(BluetoothPairingRoutineTest, FailedRemoveCachedPeripheral) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  // Check cached devices.
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          &mock_target_device_}));
  EXPECT_CALL(mock_target_device_, address())
      .WillOnce(ReturnRef(target_address_));
  EXPECT_CALL(mock_target_device_, alias()).WillOnce(ReturnRef(""));
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(false));

  // Failed to remove device.
  EXPECT_CALL(mock_target_device_, GetObjectPath())
      .WillOnce(ReturnRef(target_device_path_));
  EXPECT_CALL(mock_adapter_proxy_, RemoveDeviceAsync(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(
          Invoke([&](const dbus::ObjectPath& in_device,
                     base::OnceCallback<void(brillo::Error*)> on_error) {
            EXPECT_EQ(in_device, target_device_path_);
            std::move(on_error).Run(nullptr);
          })));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     "Bluetooth routine failed to remove target peripheral.");
}

// Test that the BluetoothPairingRoutine returns a kFailed status when the
// target peripheral is already paired.
TEST_F(BluetoothPairingRoutineTest, FailedPeripheralAlreadyPaired) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Failed to power on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  // Check cached devices.
  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{
          &mock_target_device_}));
  EXPECT_CALL(mock_target_device_, address())
      .WillOnce(ReturnRef(target_address_));
  EXPECT_CALL(mock_target_device_, alias()).WillOnce(ReturnRef(""));
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(true));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     "The target peripheral is already paired.");
}

// Test that the BluetoothPairingRoutine returns a kError status when it fails
// to start discovery.
TEST_F(BluetoothPairingRoutineTest, FailedStartDiscovery) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Failed to start and stop discovery.
  SetStartDiscoveryCall(/*is_success=*/false, /*added_devices=*/{});
  SetStopDiscoveryCall(/*is_success=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery);
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to find target peripheral.
TEST_F(BluetoothPairingRoutineTest, FailedFindTargetPeripheral) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery but not sending target peripheral.
  SetStartDiscoveryCall(/*is_success=*/true, /*added_devices=*/{});
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(27, mojom::DiagnosticRoutineStatusEnum::kRunning,
                     kBluetoothRoutineRunningMessage);
  // Failed to find target peripheral before timeout.
  task_environment_.FastForwardBy(kRoutinePairingTimeout);
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedFindTargetPeripheral);
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to set alias of target peripheral.
TEST_F(BluetoothPairingRoutineTest, FailedTagTargetPeripheral) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/false,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     "Bluetooth routine failed to set target device's alias.",
                     ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to create baseband connection.
TEST_F(BluetoothPairingRoutineTest, FailedCreateBasebandConnection) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);

  // Failed to connect.
  auto error = brillo::Error::Create(
      FROM_HERE, /*domain=*/"", /*code=*/"org.bluez.Error.Failed",
      /*message=*/"br-connection-profile-unavailable");
  EXPECT_CALL(mock_target_device_, ConnectAsync(_, _, _))
      .WillOnce(WithArg<1>(
          Invoke([&](base::OnceCallback<void(brillo::Error*)> on_error) {
            std::move(on_error).Run(error.get());
          })));

  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedCreateBasebandConnection,
                     ConstructOutputDict(/*connect_error=*/error.get()));
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to verify connected status after connection.
TEST_F(BluetoothPairingRoutineTest, FailedVerifyConnected) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  // Failed to verify connected status.
  SetConnectDeviceCall(/*connected_result=*/false);
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedCreateBasebandConnection,
                     ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to pair.
TEST_F(BluetoothPairingRoutineTest, FailedToPair) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();

  // Failed to pair.
  EXPECT_CALL(mock_target_device_, paired()).WillOnce(Return(false));
  auto error = brillo::Error::Create(
      FROM_HERE, /*domain=*/"", /*code=*/"org.bluez.Error.AuthenticationFailed",
      /*message=*/"Authentication Failed");
  EXPECT_CALL(mock_target_device_, PairAsync(_, _, _))
      .WillOnce(WithArg<1>(
          Invoke([&](base::OnceCallback<void(brillo::Error*)> on_error) {
            std::move(on_error).Run(error.get());
          })));

  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedFinishPairing,
                     ConstructOutputDict(/*connect_error=*/nullptr,
                                         /*pair_error=*/error.get()));
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to verify paired status.
TEST_F(BluetoothPairingRoutineTest, FailedVerifyPaired) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();
  SetPairDeviceCall(/*paired_result=*/false);
  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedFinishPairing,
                     ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kFailed status when it fails
// to remove paired peripheral after pairing.
TEST_F(BluetoothPairingRoutineTest, FailedRemovePairedPeripheral) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();
  SetPairDeviceCall();
  SetChangeAliasCall(/*is_success=*/true, /*expected_alias=*/"");

  // Failed to remove device.
  EXPECT_CALL(mock_target_device_, GetObjectPath())
      .WillOnce(ReturnRef(target_device_path_));
  EXPECT_CALL(mock_adapter_proxy_, RemoveDeviceAsync(_, _, _, _))
      .WillOnce(WithArgs<0, 2>(
          Invoke([&](const dbus::ObjectPath& in_device,
                     base::OnceCallback<void(brillo::Error*)> on_error) {
            EXPECT_EQ(in_device, target_device_path_);
            std::move(on_error).Run(nullptr);
          })));

  // Stop Discovery.
  SetStopDiscoveryCall(/*is_success=*/true);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     "Bluetooth routine failed to remove target peripheral.",
                     ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kError status when it fails
// to stop discovery.
TEST_F(BluetoothPairingRoutineTest, FailedStopDiscovery) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);

  EXPECT_CALL(*mock_bluetooth_info_manager(), GetDevices())
      .WillOnce(Return(std::vector<org::bluez::Device1ProxyInterface*>{}));

  // Start discovery.
  SetStartDiscoveryCall(/*is_success=*/true,
                        /*added_devices=*/{&mock_target_device_});
  SetDeviceAddedCall();
  SetChangeAliasCall(/*is_success=*/true,
                     /*expected_alias=*/kHealthdBluetoothDiagnosticsTag);
  SetConnectDeviceCall();
  SetPairDeviceCall();
  SetChangeAliasCall(/*is_success=*/true, /*expected_alias=*/"");
  SetRemoveDeviceCall();

  // Failed to stop discovery.
  SetStopDiscoveryCall(/*is_success=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery,
                     ConstructOutputDict());
}

// Test that the BluetoothPairingRoutine returns a kError status when it fails
// to get adapter.
TEST_F(BluetoothPairingRoutineTest, GetAdapterError) {
  SetUpNullAdapter();
  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedGetAdapter);
}

// Test that the BluetoothPairingRoutine returns a kFailed status when the
// adapter is in discovery mode.
TEST_F(BluetoothPairingRoutineTest, PreCheckFailed) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  // The adapter is in discovery mode.
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedDiscoveryMode);
}

}  // namespace
}  // namespace diagnostics
