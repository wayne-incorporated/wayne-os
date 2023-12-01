// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/fake_libusb_wrapper.h"

#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>

namespace permission_broker {

FakeUsbDevice::FakeUsbDevice(const UsbDeviceInfo& info,
                             const UsbDeviceInfo& parent_info,
                             State* state)
    : info_(info), parent_info_(parent_info), state_(state) {
  DCHECK(state);
}

FakeUsbDevice::~FakeUsbDevice() = default;

UsbDeviceInfo FakeUsbDevice::GetInfo() const {
  return info_;
}

uint8_t FakeUsbDevice::GetPort() const {
  return 0;
}

std::unique_ptr<UsbDeviceInterface> FakeUsbDevice::GetParent() const {
  if (parent_info_.vid == 0 && parent_info_.pid == 0) {
    return nullptr;
  }

  return std::make_unique<FakeUsbDevice>(
      parent_info_,
      UsbDeviceInfo(), /* we do not need a valid parent for this node. */
      state_);
}

bool FakeUsbDevice::SetPowerState(bool enabled, uint16_t port) const {
  if (enabled) {
    state_->power_on_counter += 1;
    return !state_->fail_power_on;
  }

  state_->power_off_counter += 1;
  return !state_->fail_power_off;
}

FakeUsbDeviceManager::FakeUsbDeviceManager(
    std::vector<std::unique_ptr<UsbDeviceInterface>> devices)
    : devices_(std::move(devices)) {}

FakeUsbDeviceManager::~FakeUsbDeviceManager() = default;

std::vector<std::unique_ptr<UsbDeviceInterface>>
FakeUsbDeviceManager::GetDevicesByVidPid(uint16_t vid, uint16_t pid) {
  return std::move(devices_);
}

}  // namespace permission_broker
