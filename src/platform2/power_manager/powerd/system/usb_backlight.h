// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_USB_BACKLIGHT_H_
#define POWER_MANAGER_POWERD_SYSTEM_USB_BACKLIGHT_H_

#include <memory>
#include <string>

#include <base/observer_list.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <libec/ec_command.h>
#include <libec/ec_usb_endpoint.h>
#include <libec/pwm_command.h>

#include "power_manager/powerd/system/internal_backlight.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"

namespace power_manager::system {

class UsbBacklight : public InternalBacklight, public UdevTaggedDeviceObserver {
 public:
  UsbBacklight();
  explicit UsbBacklight(UdevInterface* udev);
  UsbBacklight(const UsbBacklight&) = delete;
  UsbBacklight& operator=(const UsbBacklight&) = delete;

  ~UsbBacklight() override = default;

  void AddObserver(BacklightObserver* observer) override;
  void RemoveObserver(BacklightObserver* observer) override;
  bool SetBrightnessLevel(int64_t level, base::TimeDelta interval) override;
  bool DeviceExists() const override;

  // Implementation of TaggedDeviceObserver.
  void OnTaggedDeviceChanged(const system::TaggedDevice& device) override;
  void OnTaggedDeviceRemoved(const system::TaggedDevice& device) override;

 private:
  bool UpdateDevice();
  void ReleaseDevice();
  bool WriteBrightness(int64_t new_level) override;
  std::unique_ptr<ec::EcUsbEndpointInterface> usb_endpoint_;
  UdevInterface* udev_ = nullptr;
  base::ObserverList<BacklightObserver> observers_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_USB_BACKLIGHT_H_
