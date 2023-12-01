// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_WIFI_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_WIFI_CONTROLLER_H_

#include <string>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/policy/user_proximity_handler.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/udev_subsystem_observer.h"

namespace power_manager {

class PrefsInterface;

namespace policy {

// WifiController initiates power-related changes to the wifi chipset.
class WifiController : public system::UdevSubsystemObserver,
                       public UserProximityHandler::Delegate {
 public:
  // Performs work on behalf of WifiController.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Updates the wifi transmit power to |power|.
    virtual void SetWifiTransmitPower(RadioTransmitPower power,
                                      WifiRegDomain domain,
                                      TriggerSource source) = 0;
  };

  // Net subsystem and wlan devtype for udev events.
  static const char kUdevSubsystem[];
  static const char kUdevDevtype[];

  WifiController();
  WifiController(const WifiController&) = delete;
  WifiController& operator=(const WifiController&) = delete;

  ~WifiController() override;

  // Ownership of raw pointers remains with the caller.
  void Init(Delegate* delegate,
            PrefsInterface* prefs,
            system::UdevInterface* udev,
            TabletMode tablet_mode);

  // Called when the tablet mode changes.
  void HandleTabletModeChange(TabletMode mode);

  void HandleRegDomainChange(WifiRegDomain domain);

  // UserProximityHandler::Delegate overrides:
  void ProximitySensorDetected(UserProximity proximity) override;
  void HandleProximityChange(UserProximity proximity) override;

  // system::UdevSubsystemObserver:
  void OnUdevEvent(const system::UdevEvent& event) override;

 private:
  enum class UpdatePowerInputSource {
    NONE,
    TABLET_MODE,
    PROXIMITY,
    STATIC_MODE,
  };
  enum class StaticMode {
    UNSUPPORTED,
    HIGH_TRANSMIT_POWER,
    LOW_TRANSMIT_POWER,
  };
  static StaticMode StaticModeFromString(const std::string& v) {
    if (v == "non-tablet") {
      return StaticMode::HIGH_TRANSMIT_POWER;
    } else if (v == "tablet") {
      return StaticMode::LOW_TRANSMIT_POWER;
    } else {
      return StaticMode::UNSUPPORTED;
    }
  }

  // Updates transmit power via |delegate_|.
  // Decide which power setting to use based on current input source(s) state.
  void UpdateTransmitPower(TriggerSource source);

  RadioTransmitPower DetermineTransmitPower() const;

  Delegate* delegate_ = nullptr;           // Not owned.
  system::UdevInterface* udev_ = nullptr;  // Not owned.

  StaticMode static_mode_ = StaticMode::UNSUPPORTED;
  TabletMode tablet_mode_ = TabletMode::UNSUPPORTED;
  WifiRegDomain wifi_reg_domain_ = WifiRegDomain::NONE;
  UserProximity proximity_ = UserProximity::UNKNOWN;

  // True if powerd has been configured to set wifi transmit power in response
  // to tablet mode changes.
  bool set_transmit_power_for_tablet_mode_ = false;

  // True if powerd has been configured to set wifi transmit power in response
  // to proximity changes.
  bool set_transmit_power_for_proximity_ = false;

  // Not empty if powerd has been configured to set wifi transmit power for
  // "static" devices.
  std::string transmit_power_mode_for_static_device_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_WIFI_CONTROLLER_H_
