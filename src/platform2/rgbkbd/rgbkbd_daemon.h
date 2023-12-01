// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RGBKBD_RGBKBD_DAEMON_H_
#define RGBKBD_RGBKBD_DAEMON_H_

#include <cstdint>
#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/udev/udev.h>
#include <brillo/usb/usb_device_event_notifier.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>
#include <dbus/rgbkbd/dbus-constants.h>
#include <libcrossystem/crossystem.h>
#include <libec/ec_usb_device_monitor.h>

#include "rgbkbd/dbus_adaptors/org.chromium.Rgbkbd.h"
#include "rgbkbd/internal_rgb_keyboard.h"
#include "rgbkbd/keyboard_backlight_logger.h"
#include "rgbkbd/rgb_keyboard_controller_impl.h"

namespace rgbkbd {

class RgbkbdDaemon;

class DBusAdaptor : public org::chromium::RgbkbdInterface,
                    public org::chromium::RgbkbdAdaptor {
 public:
  DBusAdaptor(scoped_refptr<dbus::Bus> bus,
              brillo::CrosConfigInterface* cros_config,
              crossystem::Crossystem* crossystem,
              RgbkbdDaemon* daemon);
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;
  ~DBusAdaptor() override;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  void GetRgbKeyboardCapabilities(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>>
          response) override;
  void SetCapsLockState(bool enabled) override;
  void SetStaticBackgroundColor(uint8_t r, uint8_t g, uint8_t b) override;
  void SetRainbowMode() override;
  void SetZoneColor(int zone_idx, uint8_t r, uint8_t g, uint8_t b) override;
  void SetTestingMode(bool enable_testing, uint32_t capability) override;
  void SetAnimationMode(uint32_t mode) override;

  // Queries CrosConfig to check if device has prism keyboard and initializes
  // USB device observing if it does.
  void InitializeForPrismUsbKeyboard();

 private:
  brillo::dbus_utils::DBusObject dbus_object_;
  std::unique_ptr<brillo::UsbDeviceEventNotifier> usb_device_event_notifier_;
  std::unique_ptr<brillo::Udev> udev_;
  std::unique_ptr<InternalRgbKeyboard> internal_keyboard_;
  std::unique_ptr<KeyboardBacklightLogger> logger_keyboard_;
  RgbKeyboardControllerImpl rgb_keyboard_controller_;

  // Non-owning
  raw_ptr<brillo::CrosConfigInterface> cros_config_;
  raw_ptr<crossystem::Crossystem> crossystem_;
  raw_ptr<RgbkbdDaemon> daemon_;
};

class RgbkbdDaemon : public brillo::DBusServiceDaemon {
 public:
  RgbkbdDaemon();
  RgbkbdDaemon(const RgbkbdDaemon&) = delete;
  RgbkbdDaemon& operator=(const RgbkbdDaemon&) = delete;
  ~RgbkbdDaemon() override = default;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  std::unique_ptr<DBusAdaptor> adaptor_;
  brillo::CrosConfig cros_config_;
  crossystem::Crossystem crossystem_;
};

}  // namespace rgbkbd

#endif  // RGBKBD_RGBKBD_DAEMON_H_
