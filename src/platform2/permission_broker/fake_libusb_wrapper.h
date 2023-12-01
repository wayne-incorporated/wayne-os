// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_FAKE_LIBUSB_WRAPPER_H_
#define PERMISSION_BROKER_FAKE_LIBUSB_WRAPPER_H_

#include "permission_broker/libusb_wrapper.h"

#include <memory>
#include <vector>

#include <gmock/gmock.h>

namespace permission_broker {

// Fake implementation of the UsbDeviceInterface used for testing. This class
// implements all the required APIs but returns variables and state that is
// decided through the constructor.
class FakeUsbDevice : public UsbDeviceInterface {
 public:
  // Container struct used to pass state information to the FakeUsbDevice.
  // Mostly used to configure whether to fail or succeed SetPowerState() and to
  // return recorded internal state to be later checked.
  struct State {
    const bool fail_power_off;
    const bool fail_power_on;
    // |power_off_counter| is used in tests to track whether the
    // SetPowerState function was called to turn off a device.
    int power_off_counter;
    // |power_on_counter| is used in tests to track whether the
    // SetPowerState function was called to turn on a device.
    int power_on_counter;

    State(bool fail_power_off, bool fail_power_on)
        : fail_power_off(fail_power_off),
          fail_power_on(fail_power_on),
          power_off_counter(0),
          power_on_counter(0) {}
  };

  // This class considers an UsbDeviceInfo to be valid only when both VID and
  // PID are non-zero. This means that when |parent_info| is invalid, the device
  // is lacking the parent. Ownership of |state| remains with the caller.
  FakeUsbDevice(const UsbDeviceInfo& info,
                const UsbDeviceInfo& parent_info,
                State* state);
  FakeUsbDevice(const FakeUsbDevice&) = delete;
  FakeUsbDevice& operator=(const FakeUsbDevice&) = delete;

  ~FakeUsbDevice() override;

  UsbDeviceInfo GetInfo() const override;
  uint8_t GetPort() const override;
  // This function returns a nullptr the parent's UsbDeviceInfo is invalid.
  // Otherwise, the function returns a new FakeUsbDevice parent.
  std::unique_ptr<UsbDeviceInterface> GetParent() const override;

  bool SetPowerState(bool enabled, uint16_t port) const override;

 private:
  const UsbDeviceInfo info_;
  // |parent_info| is considered 'invalid' when both VID and PID are set to 0.
  const UsbDeviceInfo parent_info_;
  // |state_| is a pointer which is owned by the caller of the constructor of
  // this class. |state_| is meant as a way to communicate back the collected
  // state of a UsbDeviceInterface object in tests.
  State* state_;
};

// Fake implementation of the UsbDeviceManagerInterface used for testing. This
// class implements all the required APIs but returns variables and state that
// is decided through the constructor.
class FakeUsbDeviceManager : public UsbDeviceManagerInterface {
 public:
  FakeUsbDeviceManager(
      std::vector<std::unique_ptr<UsbDeviceInterface>> devices);
  FakeUsbDeviceManager(const FakeUsbDeviceManager&) = delete;
  FakeUsbDeviceManager& operator=(const FakeUsbDeviceManager&) = delete;

  ~FakeUsbDeviceManager() override;

  std::vector<std::unique_ptr<UsbDeviceInterface>> GetDevicesByVidPid(
      uint16_t vid, uint16_t pid) override;

 private:
  std::vector<std::unique_ptr<UsbDeviceInterface>> devices_;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_FAKE_LIBUSB_WRAPPER_H_
