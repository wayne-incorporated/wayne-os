// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
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
#include "diagnostics/cros_healthd/routines/bluetooth/bluetooth_scanning.h"
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

class BluetoothScanningRoutineTest : public testing::Test {
 protected:
  BluetoothScanningRoutineTest() = default;
  BluetoothScanningRoutineTest(const BluetoothScanningRoutineTest&) = delete;
  BluetoothScanningRoutineTest& operator=(const BluetoothScanningRoutineTest&) =
      delete;

  void SetUp() override { SetUpRoutine(std::nullopt); }

  MockBluetoothInfoManager* mock_bluetooth_info_manager() {
    return mock_context_.mock_bluetooth_info_manager();
  }

  FakeBluetoothEventHub* fake_bluetooth_event_hub() {
    return mock_context_.fake_bluetooth_event_hub();
  }

  void SetUpRoutine(const std::optional<base::TimeDelta>& exec_duration) {
    EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
        .WillOnce(Return(std::vector<org::bluez::Adapter1ProxyInterface*>{
            &mock_adapter_proxy_}));
    routine_ = std::make_unique<BluetoothScanningRoutine>(&mock_context_,
                                                          exec_duration);
  }

  void SetUpNullAdapter() {
    EXPECT_CALL(*mock_bluetooth_info_manager(), GetAdapters())
        .WillOnce(
            Return(std::vector<org::bluez::Adapter1ProxyInterface*>{nullptr}));
    routine_ = std::make_unique<BluetoothScanningRoutine>(&mock_context_,
                                                          std::nullopt);
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

  void SetSwitchDiscoveryCall() {
    EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
        .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
          std::move(on_success).Run();
          for (const auto& device : fake_devices_) {
            auto mock_device = mock_device_proxies_[device.first].get();
            fake_bluetooth_event_hub()->SendDeviceAdded(mock_device);
            // Send out the rest RSSIs.
            for (int i = 1; i < device.second.rssi_history.size(); i++) {
              fake_bluetooth_event_hub()->SendDevicePropertyChanged(
                  mock_device, mock_device->RSSIName());
            }
          }
        })));
    for (const auto& device : fake_devices_) {
      SetDeviceAddedCall(/*device_path=*/device.first,
                         /*device=*/device.second);
      for (int i = 1; i < device.second.rssi_history.size(); i++) {
        SetDeviceRssiChangedCall(/*device_path=*/device.first,
                                 /*rssi=*/device.second.rssi_history[i]);
      }
    }
    EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
        .WillOnce(WithArg<0>(Invoke([](base::OnceCallback<void()> on_success) {
          std::move(on_success).Run();
        })));
  }

  void SetDeviceAddedCall(const dbus::ObjectPath& device_path,
                          const ScannedPeripheralDevice& device) {
    auto mock_device = mock_device_proxies_[device_path].get();

    // Function call in BluetoothEventHub::OnDeviceAdded.
    EXPECT_CALL(*mock_device, SetPropertyChangedCallback(_));

    EXPECT_CALL(*mock_device, GetObjectPath()).WillOnce(ReturnRef(device_path));
    // Address.
    EXPECT_CALL(*mock_device, address())
        .WillOnce(ReturnRef(device_addresses_[device_path]));
    // Name.
    if (device.name.has_value()) {
      EXPECT_CALL(*mock_device, is_name_valid()).WillOnce(Return(true));
      EXPECT_CALL(*mock_device, name())
          .WillOnce(ReturnRef(device.name.value()));
    } else {
      EXPECT_CALL(*mock_device, is_name_valid()).WillOnce(Return(false));
    }
    // RSSI history.
    if (!device.rssi_history.empty()) {
      EXPECT_CALL(*mock_device, is_rssi_valid()).WillOnce(Return(true));
      EXPECT_CALL(*mock_device, rssi())
          .WillOnce(Return(device.rssi_history[0]));
    } else {
      EXPECT_CALL(*mock_device, is_rssi_valid()).WillOnce(Return(false));
    }
    // Bluetooth class of device (CoD).
    if (device.bluetooth_class.has_value()) {
      EXPECT_CALL(*mock_device, is_bluetooth_class_valid())
          .WillOnce(Return(true));
      EXPECT_CALL(*mock_device, bluetooth_class())
          .WillOnce(Return(device.bluetooth_class.value()));
    } else {
      EXPECT_CALL(*mock_device, is_bluetooth_class_valid())
          .WillOnce(Return(false));
    }
    // UUIDs.
    if (!device.uuids.empty()) {
      EXPECT_CALL(*mock_device, is_uuids_valid()).WillOnce(Return(true));
      EXPECT_CALL(*mock_device, uuids()).WillOnce(ReturnRef(device.uuids));
    } else {
      EXPECT_CALL(*mock_device, is_uuids_valid()).WillOnce(Return(false));
    }
  }

  void SetDeviceRssiChangedCall(const dbus::ObjectPath& device_path,
                                const int16_t& rssi) {
    auto mock_device = mock_device_proxies_[device_path].get();
    EXPECT_CALL(*mock_device, GetObjectPath()).WillOnce(ReturnRef(device_path));
    EXPECT_CALL(*mock_device, is_rssi_valid()).WillOnce(Return(true));
    EXPECT_CALL(*mock_device, rssi()).WillOnce(Return(rssi));
  }

  void SetScannedDeviceData(dbus::ObjectPath device_path,
                            std::string address,
                            std::optional<std::string> name,
                            std::vector<int16_t> rssi_history,
                            std::optional<uint32_t> bluetooth_class,
                            std::vector<std::string> uuids) {
    fake_devices_[device_path] = ScannedPeripheralDevice{
        .peripheral_id = base::NumberToString(base::FastHash(address)),
        .name = name,
        .rssi_history = rssi_history,
        .bluetooth_class = bluetooth_class,
        .uuids = uuids};
    device_addresses_[device_path] = address;
    mock_device_proxies_[device_path] =
        std::make_unique<StrictMock<org::bluez::Device1ProxyMock>>();
  }

  base::Value::Dict ConstructOutputDict() {
    base::Value::List peripherals;
    for (const auto& device : fake_devices_) {
      base::Value::Dict peripheral;
      peripheral.Set("peripheral_id", device.second.peripheral_id);
      if (device.second.name.has_value())
        peripheral.Set("name", device.second.name.value());
      base::Value::List out_rssi_history;
      for (const auto& rssi : device.second.rssi_history)
        out_rssi_history.Append(rssi);
      peripheral.Set("rssi_history", std::move(out_rssi_history));
      if (device.second.bluetooth_class.has_value()) {
        peripheral.Set(
            "bluetooth_class",
            base::NumberToString(device.second.bluetooth_class.value()));
      }
      base::Value::List out_uuids;
      for (const auto& uuid : device.second.uuids)
        out_uuids.Append(uuid);
      peripheral.Set("uuids", std::move(out_uuids));
      peripherals.Append(std::move(peripheral));
    }
    base::Value::Dict output_dict;
    output_dict.Set("peripherals", std::move(peripherals));
    return output_dict;
  }

  void CheckRoutineUpdate(uint32_t progress_percent,
                          mojom::DiagnosticRoutineStatusEnum status,
                          std::string status_message) {
    routine_->PopulateStatusUpdate(&update_, true);
    EXPECT_EQ(update_.progress_percent, progress_percent);
    VerifyNonInteractiveUpdate(update_.routine_update_union, status,
                               status_message);
    EXPECT_EQ(
        ConstructOutputDict(),
        base::JSONReader::Read(GetStringFromValidReadOnlySharedMemoryMapping(
            std::move(update_.output))));
  }

  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  std::unique_ptr<DiagnosticRoutine> routine_;
  StrictMock<org::bluez::Adapter1ProxyMock> mock_adapter_proxy_;

 private:
  MockContext mock_context_;
  std::map<dbus::ObjectPath, ScannedPeripheralDevice> fake_devices_;
  std::map<dbus::ObjectPath, std::string> device_addresses_;
  std::map<dbus::ObjectPath, std::unique_ptr<org::bluez::Device1ProxyMock>>
      mock_device_proxies_;
  mojom::RoutineUpdate update_{0, mojo::ScopedHandle(),
                               mojom::RoutineUpdateUnionPtr()};
};

// Test that the BluetoothScanningRoutine can be run successfully.
TEST_F(BluetoothScanningRoutineTest, RoutineSuccess) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Set up fake data.
  SetScannedDeviceData(dbus::ObjectPath("/org/bluez/dev_70_88_6B_92_34_70"),
                       "70:88:6B:92:34:70", "GID6B", {-54, -66, -62}, 2360344,
                       {"0000110c-0000-1000-8000-00805f9b34fb",
                        "0000110e-0000-1000-8000-00805f9b34fb",
                        "0000111e-0000-1000-8000-00805f9b34fb"});
  SetScannedDeviceData(dbus::ObjectPath("/org/bluez/dev_70_D6_9F_0B_4F_D8"),
                       "70:D6:9F:0B:4F:D8", std::nullopt, {-64}, std::nullopt,
                       {});
  // Start scanning.
  SetSwitchDiscoveryCall();

  routine_->Start();
  CheckRoutineUpdate(60, mojom::DiagnosticRoutineStatusEnum::kRunning,
                     kBluetoothRoutineRunningMessage);
  task_environment_.FastForwardBy(kDefaultBluetoothScanningRuntime);
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage);
}

// Test that the BluetoothScanningRoutine can be run successfully without
// scanned devices.
TEST_F(BluetoothScanningRoutineTest, RoutineSuccessNoDevices) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start scanning.
  SetSwitchDiscoveryCall();

  routine_->Start();
  CheckRoutineUpdate(60, mojom::DiagnosticRoutineStatusEnum::kRunning,
                     kBluetoothRoutineRunningMessage);
  task_environment_.FastForwardBy(kDefaultBluetoothScanningRuntime);
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kPassed,
                     kBluetoothRoutinePassedMessage);
}

// Test that the BluetoothScanningRoutine returns a kError status when it
// fails to power on the adapter.
TEST_F(BluetoothScanningRoutineTest, FailedPowerOnAdapter) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Failed to power on.
  SetEnsurePoweredOnCall(/*current_powered=*/false, /*is_success=*/false);

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedChangePowered);
}

// Test that the BluetoothScanningRoutine returns a kError status when it
// fails to start discovery.
TEST_F(BluetoothScanningRoutineTest, FailedStartDiscovery) {
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

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery);
}

// Test that the BluetoothScanningRoutine returns a kFailed status when it
// fails to stop discovery.
TEST_F(BluetoothScanningRoutineTest, FailedStopDiscovery) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(false));
  // Ensure adapter is powered on.
  SetEnsurePoweredOnCall(/*current_powered=*/false);
  // Start discovery.
  EXPECT_CALL(mock_adapter_proxy_, StartDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<0>(Invoke([&](base::OnceCallback<void()> on_success) {
        std::move(on_success).Run();
      })));
  // Failed to stop discovery.
  EXPECT_CALL(mock_adapter_proxy_, StopDiscoveryAsync(_, _, _))
      .WillOnce(WithArg<1>(
          Invoke([](base::OnceCallback<void(brillo::Error*)> on_error) {
            std::move(on_error).Run(nullptr);
          })));

  routine_->Start();
  CheckRoutineUpdate(60, mojom::DiagnosticRoutineStatusEnum::kRunning,
                     kBluetoothRoutineRunningMessage);
  task_environment_.FastForwardBy(kDefaultBluetoothScanningRuntime);
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedSwitchDiscovery);
}

// Test that the BluetoothScanningRoutine returns a kError status when it fails
// to get adapter.
TEST_F(BluetoothScanningRoutineTest, GetAdapterError) {
  SetUpNullAdapter();
  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kError,
                     kBluetoothRoutineFailedGetAdapter);
}

// Test that the BluetoothScanningRoutine returns a kFailed status when the
// adapter is in discovery mode.
TEST_F(BluetoothScanningRoutineTest, PreCheckFailed) {
  InSequence s;
  // Pre-check.
  EXPECT_CALL(mock_adapter_proxy_, powered()).WillOnce(Return(true));
  // The adapter is in discovery mode.
  EXPECT_CALL(mock_adapter_proxy_, discovering()).WillOnce(Return(true));

  routine_->Start();
  CheckRoutineUpdate(100, mojom::DiagnosticRoutineStatusEnum::kFailed,
                     kBluetoothRoutineFailedDiscoveryMode);
}

// Test that the BluetoothScanningRoutine returns a kError status when the
// routine execution time is zero.
TEST_F(BluetoothScanningRoutineTest, ZeroExecutionTimeError) {
  SetUpRoutine(base::Seconds(0));
  routine_->Start();
  CheckRoutineUpdate(
      100, mojom::DiagnosticRoutineStatusEnum::kError,
      "Routine execution time should be strictly greater than zero.");
}

}  // namespace
}  // namespace diagnostics
