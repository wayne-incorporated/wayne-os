// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_MOCK_USB_DEVICE_EVENT_OBSERVER_H_
#define LIBBRILLO_BRILLO_USB_MOCK_USB_DEVICE_EVENT_OBSERVER_H_

#include <string>

#include <gmock/gmock.h>

#include "brillo/usb/usb_device_event_observer.h"

namespace brillo {

class MockUsbDeviceEventObserver : public UsbDeviceEventObserver {
 public:
  MockUsbDeviceEventObserver() = default;
  MockUsbDeviceEventObserver(const MockUsbDeviceEventObserver&) = delete;
  MockUsbDeviceEventObserver& operator=(const MockUsbDeviceEventObserver&) =
      delete;

  ~MockUsbDeviceEventObserver() override = default;

  MOCK_METHOD(void,
              OnUsbDeviceAdded,
              (const std::string&, uint8_t, uint8_t, uint16_t, uint16_t),
              (override));
  MOCK_METHOD(void, OnUsbDeviceRemoved, (const std::string&), (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_MOCK_USB_DEVICE_EVENT_OBSERVER_H_
