// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/fake_libusb_wrapper.h"
#include "permission_broker/usb_control.h"

#include <gtest/gtest.h>

#include <string>
#include <utility>

#include <brillo/message_loops/fake_message_loop.h>
#include <brillo/message_loops/message_loop.h>

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace permission_broker {

class UsbControlTest : public testing::Test {
 public:
  UsbControlTest() : loop_(nullptr) { loop_.SetAsCurrent(); }
  UsbControlTest(const UsbControlTest&) = delete;
  UsbControlTest& operator=(const UsbControlTest&) = delete;

  ~UsbControlTest() override = default;

 protected:
  brillo::FakeMessageLoop loop_;
};

TEST_F(UsbControlTest, DeviceNotAllowed) {
  auto manager = std::make_unique<FakeUsbDeviceManager>(
      std::vector<std::unique_ptr<UsbDeviceInterface>>());
  UsbControl usb_control(std::move(manager));

  EXPECT_FALSE(usb_control.IsDeviceAllowed(0x0, 0x0011));
  EXPECT_FALSE(usb_control.IsDeviceAllowed(0x2bd9, 0x0));
}

TEST_F(UsbControlTest, DeviceAllowed) {
  auto manager = std::make_unique<FakeUsbDeviceManager>(
      std::vector<std::unique_ptr<UsbDeviceInterface>>());
  UsbControl usb_control(std::move(manager));

  EXPECT_TRUE(usb_control.IsDeviceAllowed(0x2bd9, 0x0011));
}

void TestResultCallback(std::shared_ptr<bool> result_out, bool result) {
  *result_out = result;
}

TEST_F(UsbControlTest, PowerCycleSingleDeviceSucceeds) {
  // Create the fake valid device that will be used together with the associated
  // device parent.
  // - Target device.
  FakeUsbDevice::State state(false, false);
  UsbDeviceInfo info(0x2bd9, 0x0011);
  UsbDeviceInfo parent_info(0x1111, 0x2222, LIBUSB_CLASS_HUB);
  auto valid_device =
      std::make_unique<FakeUsbDevice>(info, parent_info, &state);
  // Add the device into the vector of extracted devices and create a manager
  // that is capable of returing such a vector.
  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  devices.push_back(std::move(valid_device));
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control is correctly able to power-cycle the device.
  UsbControl usb_control(std::move(manager));
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x2bd9, 0x0011, base::Milliseconds(1));

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 0);

  loop_.RunOnce(true);

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 1);
  EXPECT_TRUE(*result);
}

TEST_F(UsbControlTest, PowerCycleMultipleDevicesSucceed) {
  // Create two fake valid devices that will be used together with the
  // associated device parent.
  // - First target device.
  UsbDeviceInfo info(0x2bd9, 0x0011);
  UsbDeviceInfo parent_info(0x1111, 0x2222, LIBUSB_CLASS_HUB);
  FakeUsbDevice::State state1(false, false);
  auto valid_device1 =
      std::make_unique<FakeUsbDevice>(info, parent_info, &state1);
  // - Second target device.
  FakeUsbDevice::State state2(false, false);
  auto valid_device2 =
      std::make_unique<FakeUsbDevice>(info, parent_info, &state2);
  // Add the device into the vector of extracted devices and create a manager
  // that is capable of returing such a vector.
  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  devices.push_back(std::move(valid_device1));
  devices.push_back(std::move(valid_device2));
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control is correctly able to power-cycle the device.
  UsbControl usb_control(std::move(manager));
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x2bd9, 0x0011, base::Milliseconds(1));

  EXPECT_EQ(state1.power_off_counter, 1);
  EXPECT_EQ(state1.power_on_counter, 0);
  EXPECT_EQ(state2.power_off_counter, 1);
  EXPECT_EQ(state2.power_on_counter, 0);

  loop_.RunOnce(true);

  EXPECT_EQ(state1.power_off_counter, 1);
  EXPECT_EQ(state1.power_on_counter, 1);
  EXPECT_EQ(state2.power_off_counter, 1);
  EXPECT_EQ(state2.power_on_counter, 1);
  EXPECT_TRUE(*result);
}

TEST_F(UsbControlTest, DeviceNotFound) {
  // Create a fake manager that returns an empty vector when querying the
  // available USB devices.
  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control is not able to apply the requested operation because
  // the device is not available.
  UsbControl usb_control(std::move(manager));
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x2bd9, 0x0011, base::Milliseconds(1));

  EXPECT_FALSE(*result);
}

TEST_F(UsbControlTest, PowerCycleNotAllowedDevice) {
  // Set up a target device that was not allowed.
  FakeUsbDevice::State state(false, false);
  UsbDeviceInfo info(0x1234, 0x5678);
  UsbDeviceInfo parent_info;
  auto invalid_device =
      std::make_unique<FakeUsbDevice>(info, parent_info, &state);

  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  devices.push_back(std::move(invalid_device));
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control unable to powercycle the device that is not
  // allowed.
  UsbControl usb_control(std::move(manager));
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x1234, 0x5678, base::Milliseconds(1));

  EXPECT_EQ(state.power_off_counter, 0);
  EXPECT_EQ(state.power_on_counter, 0);
  EXPECT_FALSE(*result);
}

TEST_F(UsbControlTest, PowerOffFails) {
  // Create the fake valid device that will be used together with the associated
  // device parent.
  // - Target device.
  FakeUsbDevice::State state(true, false);
  UsbDeviceInfo info(0x2bd9, 0x0011);
  UsbDeviceInfo parent_info(0x1111, 0x2222, LIBUSB_CLASS_HUB);
  auto device = std::make_unique<FakeUsbDevice>(info, parent_info, &state);

  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  devices.push_back(std::move(device));
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control will return false when the device to be powercycled
  // failes to turn off.
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  UsbControl usb_control(std::move(manager));
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x2bd9, 0x0011, base::Milliseconds(1));

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 0);

  loop_.RunOnce(true);

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 1);
  EXPECT_FALSE(*result);
}

TEST_F(UsbControlTest, PowerOnFails) {
  // Create the fake valid device that will be used together with the associated
  // device parent.
  // - Target device.
  FakeUsbDevice::State state(false, true);
  UsbDeviceInfo info(0x2bd9, 0x0011);
  UsbDeviceInfo parent_info(0x1111, 0x2222, LIBUSB_CLASS_HUB);
  auto device = std::make_unique<FakeUsbDevice>(info, parent_info, &state);

  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;
  devices.push_back(std::move(device));
  auto manager = std::make_unique<FakeUsbDeviceManager>(std::move(devices));

  // Test that usb_control will return false when the device to be powercycled
  // failes to turn on.
  std::shared_ptr<bool> result = std::make_shared<bool>(false);
  UsbControl usb_control(std::move(manager));
  usb_control.PowerCycleUsbPorts(base::BindOnce(&TestResultCallback, result),
                                 0x2bd9, 0x0011, base::Milliseconds(1));

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 0);

  loop_.RunOnce(true);

  EXPECT_EQ(state.power_off_counter, 1);
  EXPECT_EQ(state.power_on_counter, 1);
  EXPECT_FALSE(*result);
}

}  // namespace permission_broker
