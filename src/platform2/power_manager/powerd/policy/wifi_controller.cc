// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/wifi_controller.h"

#include "power_manager/common/prefs.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace power_manager::policy {

const char WifiController::kUdevSubsystem[] = "net";
const char WifiController::kUdevDevtype[] = "wlan";

WifiController::WifiController() = default;

WifiController::~WifiController() {
  if (udev_)
    udev_->RemoveSubsystemObserver(kUdevSubsystem, this);
}

void WifiController::Init(Delegate* delegate,
                          PrefsInterface* prefs,
                          system::UdevInterface* udev,
                          TabletMode tablet_mode) {
  DCHECK(delegate);
  DCHECK(prefs);
  DCHECK(udev);

  delegate_ = delegate;
  udev_ = udev;
  tablet_mode_ = tablet_mode;

  prefs->GetBool(kSetWifiTransmitPowerForTabletModePref,
                 &set_transmit_power_for_tablet_mode_);
  prefs->GetBool(kSetWifiTransmitPowerForProximityPref,
                 &set_transmit_power_for_proximity_);
  prefs->GetString(kWifiTransmitPowerModeForStaticDevicePref,
                   &transmit_power_mode_for_static_device_);
  LOG(INFO) << "WifiController::Init: "
            << base::StringPrintf(
                   "%s=%d, %s=%d, %s=%s",
                   kSetWifiTransmitPowerForTabletModePref,
                   set_transmit_power_for_tablet_mode_,
                   kSetWifiTransmitPowerForProximityPref,
                   set_transmit_power_for_proximity_,
                   kWifiTransmitPowerModeForStaticDevicePref,
                   transmit_power_mode_for_static_device_.c_str());

  if (set_transmit_power_for_tablet_mode_ &&
      !transmit_power_mode_for_static_device_.empty()) {
    LOG(FATAL) << "Invalid configuration: both "
               << kSetWifiTransmitPowerForTabletModePref << " and "
               << kWifiTransmitPowerModeForStaticDevicePref << " pref set";
  }

  if (!set_transmit_power_for_tablet_mode_ &&
      !set_transmit_power_for_proximity_ &&
      !transmit_power_mode_for_static_device_.empty()) {
    static_mode_ = StaticModeFromString(transmit_power_mode_for_static_device_);
    if (static_mode_ == StaticMode::UNSUPPORTED) {
      LOG(WARNING) << "Invalid configuration: "
                   << kWifiTransmitPowerModeForStaticDevicePref << '='
                   << transmit_power_mode_for_static_device_;
    }
  }

  udev_->AddSubsystemObserver(kUdevSubsystem, this);
  UpdateTransmitPower(TriggerSource::INIT);
}

void WifiController::HandleTabletModeChange(TabletMode mode) {
  if (!set_transmit_power_for_tablet_mode_)
    return;

  if (tablet_mode_ == mode)
    return;

  tablet_mode_ = mode;
  UpdateTransmitPower(TriggerSource::TABLET_MODE);
}

void WifiController::HandleRegDomainChange(WifiRegDomain domain) {
  if (wifi_reg_domain_ == domain)
    return;

  wifi_reg_domain_ = domain;
  UpdateTransmitPower(TriggerSource::REG_DOMAIN);
}

void WifiController::ProximitySensorDetected(UserProximity value) {
  if (!set_transmit_power_for_proximity_)
    return;

  if (set_transmit_power_for_tablet_mode_) {
    LOG(INFO) << "WiFi power will be handled by proximity sensor and "
                 "tablet mode";
  } else {
    LOG(INFO) << "WiFi power will be handled by proximity sensor";
  }
  HandleProximityChange(value);
}

void WifiController::HandleProximityChange(UserProximity proximity) {
  if (proximity_ == proximity)
    return;

  proximity_ = proximity;
  UpdateTransmitPower(TriggerSource::PROXIMITY);
}

void WifiController::OnUdevEvent(const system::UdevEvent& event) {
  DCHECK_EQ(event.device_info.subsystem, kUdevSubsystem);
  if (event.action == system::UdevEvent::Action::ADD &&
      event.device_info.devtype == kUdevDevtype)
    UpdateTransmitPower(TriggerSource::UDEV_EVENT);
}

/*
 * The algorithm chosen is - as always - a conservative one where all inputs
 * need to be in "HIGH-allowed" mode (FAR for proximity, OFF for tablet mode)
 * in order to allow HIGH power to be selected.
 *
 * When no input states are known, return |UNSPECIFIED| power level.
 */
RadioTransmitPower WifiController::DetermineTransmitPower() const {
  RadioTransmitPower proximity_power = RadioTransmitPower::UNSPECIFIED;
  RadioTransmitPower tablet_mode_power = RadioTransmitPower::UNSPECIFIED;

  if (set_transmit_power_for_proximity_) {
    switch (proximity_) {
      case UserProximity::UNKNOWN:
        break;
      case UserProximity::NEAR:
        proximity_power = RadioTransmitPower::LOW;
        break;
      case UserProximity::FAR:
        proximity_power = RadioTransmitPower::HIGH;
        break;
    }
  }

  if (set_transmit_power_for_tablet_mode_) {
    switch (tablet_mode_) {
      case TabletMode::UNSUPPORTED:
        break;
      case TabletMode::ON:
        tablet_mode_power = RadioTransmitPower::LOW;
        break;
      case TabletMode::OFF:
        tablet_mode_power = RadioTransmitPower::HIGH;
        break;
    }
  }

  if (proximity_power == RadioTransmitPower::UNSPECIFIED &&
      tablet_mode_power == RadioTransmitPower::UNSPECIFIED &&
      static_mode_ == StaticMode::UNSUPPORTED)
    return RadioTransmitPower::UNSPECIFIED;

  if (proximity_power == RadioTransmitPower::LOW ||
      tablet_mode_power == RadioTransmitPower::LOW ||
      static_mode_ == StaticMode::LOW_TRANSMIT_POWER)
    return RadioTransmitPower::LOW;

  return RadioTransmitPower::HIGH;
}

void WifiController::UpdateTransmitPower(TriggerSource tr_source) {
  RadioTransmitPower wanted_power = DetermineTransmitPower();

  if (wanted_power != RadioTransmitPower::UNSPECIFIED)
    delegate_->SetWifiTransmitPower(wanted_power, wifi_reg_domain_, tr_source);
}

}  // namespace power_manager::policy
