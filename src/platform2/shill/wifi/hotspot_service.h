// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_HOTSPOT_SERVICE_H_
#define SHILL_WIFI_HOTSPOT_SERVICE_H_

#include <string>

#include "shill/refptr_types.h"
#include "shill/wifi/local_service.h"
#include "shill/wifi/wifi_security.h"

namespace shill {

class KeyValueStore;
class LocalDevice;
class Manager;

// A HotspotService inherits from the base class LocalService and represent a
// wpa_supplicant network in mode AP. This class saves the AP network related
// parameters and have a helper function to convert these parameters to
// wpa_supplicant recognizable dictionary.
class HotspotService : public LocalService {
 public:
  HotspotService(LocalDeviceConstRefPtr device,
                 const std::string& ssid,
                 const std::string& passphrase,
                 WiFiSecurity security,
                 int frequency);
  HotspotService(const HotspotService&) = delete;
  HotspotService& operator=(const HotspotService&) = delete;

  // Generate a wpa_supplicant recognizable dictionary.
  KeyValueStore GetSupplicantConfigurationParameters() const override;

 private:
  friend class HotspotServiceTest;
  // The hex-encoded tethering SSID name to be used in WiFi downstream.
  std::string hex_ssid_;
  // The passphrase to be used in WiFi downstream.
  std::string passphrase_;
  // The security mode to be used in WiFi downstream.
  WiFiSecurity security_;
  // The WiFi frequency to be used for the hotspot.
  int frequency_;
};

}  // namespace shill

#endif  // SHILL_WIFI_HOTSPOT_SERVICE_H_
