// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rgbkbd/rgbkbd_daemon.h"

#include <memory>
#include <string>
#include <utility>

#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>
#include <dbus/bus.h>
#include <dbus/rgbkbd/dbus-constants.h>
#include <libcrossystem/crossystem.h>

#include "base/check.h"
#include "base/files/file_path.h"
#include "rgbkbd/internal_rgb_keyboard.h"
#include "rgbkbd/keyboard_backlight_logger.h"

namespace {

constexpr char kLogFilePathForTesting[] = "/run/rgbkbd/log";

bool IsDevMode(crossystem::Crossystem* crossystem) {
  std::optional<int> value = crossystem->VbGetSystemPropertyInt("cros_debug");
  return value && *value == 1;
}

}  // namespace

namespace rgbkbd {
DBusAdaptor::DBusAdaptor(scoped_refptr<dbus::Bus> bus,
                         brillo::CrosConfigInterface* cros_config,
                         crossystem::Crossystem* crossystem,
                         RgbkbdDaemon* daemon)
    : org::chromium::RgbkbdAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kRgbkbdServicePath)),
      internal_keyboard_(std::make_unique<InternalRgbKeyboard>()),
      rgb_keyboard_controller_(internal_keyboard_.get()),
      cros_config_(cros_config),
      crossystem_(crossystem),
      daemon_(daemon) {}

DBusAdaptor::~DBusAdaptor() {
  if (usb_device_event_notifier_) {
    usb_device_event_notifier_->RemoveObserver(&rgb_keyboard_controller_);
  }
}

void DBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void DBusAdaptor::InitializeForPrismUsbKeyboard() {
  DCHECK(!udev_);
  DCHECK(!usb_device_event_notifier_);

  // A null cros_config is valid for testing.
  if (!cros_config_) {
    return;
  }

  std::string value;
  const bool has_prism_usb_controller =
      cros_config_->GetString("/keyboard", "mcutype", &value) &&
      value == "prism_rgb_controller";

  if (has_prism_usb_controller) {
    LOG(INFO) << "Detected we are running with a prism kbmcu. Starting USB "
                 "event observing...";
    udev_ = brillo::Udev::Create();
    if (!udev_) {
      LOG(ERROR) << "Could not create udev library context.";
      return;
    }

    usb_device_event_notifier_ =
        std::make_unique<brillo::UsbDeviceEventNotifier>(udev_.get());
    if (!usb_device_event_notifier_->Initialize()) {
      LOG(ERROR) << "Could not initialize USB device event notification.";
      udev_.reset();
      usb_device_event_notifier_.reset();
      return;
    }

    rgb_keyboard_controller_.SetKeyboardCapabilityAsIndividualKey();

    // Add the rgb controller as an observer and scan all connected devices to
    // the system to properly initialize it.
    usb_device_event_notifier_->AddObserver(&rgb_keyboard_controller_);
    usb_device_event_notifier_->ScanExistingDevices();
  }
}

void DBusAdaptor::GetRgbKeyboardCapabilities(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>>
        response) {
  const uint32_t capabilities =
      rgb_keyboard_controller_.GetRgbKeyboardCapabilities();
  response->Return(capabilities);

  // After we return capabilities we want to schedule the Daemon to quit.
  // DBusServiceDaemon runs tasks based on a sequential message loop so it is
  // guaranteed RgbkbdDaemon will exit only after all tasks are completed.
  // Note that a nullptr `daemon_` is valid for tests, tests will own lifetime
  // of the daemon.
  if (daemon_ &&
      capabilities == static_cast<uint32_t>(RgbKeyboardCapabilities::kNone)) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&RgbkbdDaemon::Quit, base::Unretained(daemon_)));
  }
}

void DBusAdaptor::SetCapsLockState(bool enabled) {
  rgb_keyboard_controller_.SetCapsLockState(enabled);
}

void DBusAdaptor::SetStaticBackgroundColor(uint8_t r, uint8_t g, uint8_t b) {
  rgb_keyboard_controller_.SetStaticBackgroundColor(r, g, b);
}

void DBusAdaptor::SetRainbowMode() {
  rgb_keyboard_controller_.SetRainbowMode();
}

void DBusAdaptor::SetZoneColor(int zone_idx, uint8_t r, uint8_t g, uint8_t b) {
  rgb_keyboard_controller_.SetStaticZoneColor(zone_idx, r, g, b);
}

void DBusAdaptor::SetTestingMode(bool enable_testing, uint32_t capability) {
  // Null crossystem is valid for testing.
  if (crossystem_ && !IsDevMode(crossystem_)) {
    return;
  }

  if (enable_testing) {
    if (capability >
        static_cast<uint32_t>(RgbKeyboardCapabilities::kMaxValue)) {
      LOG(ERROR)
          << "Attempted to set unsupported capability. Defaulting to kNone.";
      capability = static_cast<uint32_t>(RgbKeyboardCapabilities::kNone);
    }

    const auto keyboard_capability =
        static_cast<RgbKeyboardCapabilities>(capability);
    if (!logger_keyboard_) {
      logger_keyboard_ = std::make_unique<KeyboardBacklightLogger>(
          base::FilePath(kLogFilePathForTesting), keyboard_capability);
    }
    rgb_keyboard_controller_.SetKeyboardClient(logger_keyboard_.get());
    rgb_keyboard_controller_.SetKeyboardCapabilityForTesting(
        keyboard_capability);
    SendCapabilityUpdatedForTestingSignal(capability);
  } else {
    DCHECK(internal_keyboard_);
    rgb_keyboard_controller_.SetKeyboardClient(internal_keyboard_.get());
  }
}

// TODO(jimmyxgong): Implement switch case for different modes.
void DBusAdaptor::SetAnimationMode(uint32_t mode) {
  rgb_keyboard_controller_.SetAnimationMode(
      RgbAnimationMode::kBasicTestPattern);
}

RgbkbdDaemon::RgbkbdDaemon() : DBusServiceDaemon(kRgbkbdServiceName) {}

void RgbkbdDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  adaptor_.reset(new DBusAdaptor(bus_, &cros_config_, &crossystem_, this));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));

  adaptor_->InitializeForPrismUsbKeyboard();
}
}  // namespace rgbkbd
