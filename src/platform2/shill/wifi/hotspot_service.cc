// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/hotspot_service.h"

#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/store/property_accessor.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/wifi/local_device.h"

namespace shill {

HotspotService::HotspotService(LocalDeviceConstRefPtr device,
                               const std::string& ssid,
                               const std::string& passphrase,
                               WiFiSecurity security,
                               int frequency)
    : LocalService(device),
      hex_ssid_(ssid),
      passphrase_(passphrase),
      security_(security),
      frequency_(frequency) {}

KeyValueStore HotspotService::GetSupplicantConfigurationParameters() const {
  KeyValueStore params;

  if (!security_.IsValid()) {
    LOG(ERROR) << "Security is not valid";
    return params;
  }

  if (security_ != WiFiSecurity::kNone && security_ != WiFiSecurity::kWpa2 &&
      security_ != WiFiSecurity::kWpa2Wpa3 &&
      security_ != WiFiSecurity::kWpa3) {
    LOG(ERROR) << "Hotspot service do not support security " << security_;
    return params;
  }

  params.Set<uint32_t>(WPASupplicant::kNetworkPropertyMode,
                       WPASupplicant::kNetworkModeAccessPointInt);

  if (security_.SecurityClass() == kSecurityClassNone) {
    params.Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyManagement,
                            WPASupplicant::kKeyManagementNone);
  } else {  // kSecurityClassPsk
    // WPA2 and WPA3 use RSN.
    params.Set<std::string>(WPASupplicant::kPropertySecurityProtocol,
                            WPASupplicant::kSecurityModeRSN);

    std::string key_mgmt;
    bool sae_enabled = false;
    if (security_ == WiFiSecurity::kWpa3) {
      key_mgmt = base::StringPrintf("%s", WPASupplicant::kKeyManagementSAE);
      sae_enabled = true;
    } else if (security_ == WiFiSecurity::kWpa2Wpa3) {
      key_mgmt =
          base::StringPrintf("%s %s", WPASupplicant::kKeyManagementWPAPSK,
                             WPASupplicant::kKeyManagementSAE);
      sae_enabled = true;
    } else {
      key_mgmt = base::StringPrintf("%s", WPASupplicant::kKeyManagementWPAPSK);
    }
    params.Set<std::string>(WPASupplicant::kNetworkPropertyEapKeyManagement,
                            key_mgmt);

    // Require 802.11w if SAE is used.
    if (sae_enabled) {
      params.Set<uint32_t>(WPASupplicant::kNetworkPropertyIeee80211w,
                           WPASupplicant::kNetworkIeee80211wRequired);
    } else {
      params.Set<uint32_t>(WPASupplicant::kNetworkPropertyIeee80211w,
                           WPASupplicant::kNetworkIeee80211wEnabled);
    }

    // Explicitly specify the cipher suites to avoid using TKIP for pairwise and
    // group cipher in WPA2 and WPA3.
    params.Set<std::string>(WPASupplicant::kNetworkCipherPairwise,
                            WPASupplicant::kNetworkCipherSuiteCCMP);
    params.Set<std::string>(WPASupplicant::kNetworkCipherGroup,
                            WPASupplicant::kNetworkCipherSuiteCCMP);

    params.Set<std::string>(WPASupplicant::kPropertyPreSharedKey, passphrase_);
  }

  std::vector<uint8_t> ssid_bytes;
  base::HexStringToBytes(hex_ssid_, &ssid_bytes);
  params.Set<std::vector<uint8_t>>(WPASupplicant::kNetworkPropertySSID,
                                   ssid_bytes);

  params.Set<int>(WPASupplicant::kNetworkPropertyFrequency, frequency_);

  return params;
}

}  // namespace shill
