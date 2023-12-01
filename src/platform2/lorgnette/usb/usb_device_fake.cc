// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/usb/usb_device_fake.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

namespace lorgnette {

UsbDeviceFake::UsbDeviceFake() = default;

UsbDeviceFake::~UsbDeviceFake() = default;

std::unique_ptr<UsbDeviceFake> UsbDeviceFake::Clone(UsbDevice& source) {
  auto device = std::make_unique<UsbDeviceFake>();

  auto device_desc = source.GetDeviceDescriptor();
  if (!device_desc) {
    return device;
  }
  device->SetDeviceDescriptor(*device_desc);

  std::vector<libusb_config_descriptor> configs;
  for (uint8_t i = 0; i < device_desc->bNumConfigurations; i++) {
    auto one_config = source.GetConfigDescriptor(i);
    configs.emplace_back(*one_config.get());
  }
  device->SetConfigDescriptors(std::move(configs));

  // String descriptors start at 1.  Index 0 is a placeholder.
  std::vector<std::string> strings{""};
  uint8_t i = 1;
  while (auto s = source.GetStringDescriptor(i)) {
    strings.emplace_back(*s);
    ++i;
  }
  device->SetStringDescriptors(strings);

  device->Init();
  return device;
}

std::optional<libusb_device_descriptor> UsbDeviceFake::GetDeviceDescriptor()
    const {
  return device_descriptor_;
}

UsbDevice::ScopedConfigDescriptor UsbDeviceFake::GetConfigDescriptor(
    uint8_t config) const {
  if (config >= config_descriptors_.size()) {
    return ScopedConfigDescriptor(nullptr, nullptr);
  }

  // The caller will expect to have a non-const copy, so return a copy of the
  // struct instead of a pointer.  Don't deep copy any of the inner pointers
  // because the free function doesn't clean them up.
  const libusb_config_descriptor& in = config_descriptors_[config];
  CHECK(in.wTotalLength >= sizeof(libusb_config_descriptor));
  libusb_config_descriptor* out =
      reinterpret_cast<libusb_config_descriptor*>(malloc(in.wTotalLength));
  memcpy(out, &in, in.wTotalLength);
  return ScopedConfigDescriptor(out,
                                [](libusb_config_descriptor* d) { free(d); });
}

std::optional<std::string> UsbDeviceFake::GetStringDescriptor(uint8_t index) {
  if (index >= string_descriptors_.size()) {
    return std::nullopt;
  }
  return string_descriptors_[index];
}

void UsbDeviceFake::SetDeviceDescriptor(
    const libusb_device_descriptor& descriptor) {
  device_descriptor_ = descriptor;
}

libusb_device_descriptor& UsbDeviceFake::MutableDeviceDescriptor() {
  return *device_descriptor_;
}

void UsbDeviceFake::SetConfigDescriptors(
    std::vector<libusb_config_descriptor> descriptors) {
  config_descriptors_ = std::move(descriptors);
}

libusb_config_descriptor& UsbDeviceFake::MutableConfigDescriptor(
    uint8_t index) {
  return config_descriptors_[index];
}

void UsbDeviceFake::SetStringDescriptors(std::vector<std::string> strings) {
  CHECK(strings[0].empty()) << "String descriptor at index 0 must be empty";
  string_descriptors_ = std::move(strings);
}

}  // namespace lorgnette
