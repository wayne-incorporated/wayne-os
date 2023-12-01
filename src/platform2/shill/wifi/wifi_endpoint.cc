// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_endpoint.h"

#include <algorithm>

#include <base/containers/contains.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/control_interface.h"
#include "shill/logging.h"
#include "shill/metrics.h"
#include "shill/net/ieee80211.h"
#include "shill/supplicant/supplicant_bss_proxy_interface.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/tethering.h"
#include "shill/wifi/wifi.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

namespace {

void PackSecurity(const WiFiEndpoint::SecurityFlags& flags,
                  KeyValueStore* args) {
  Strings wpa, rsn;

  if (flags.rsn_8021x_wpa3)
    rsn.push_back(std::string(WPASupplicant::kKeyManagementMethodPrefixEAP) +
                  std::string(WPASupplicant::kKeyManagementMethodSuiteB));
  if (flags.rsn_sae)
    rsn.push_back(WPASupplicant::kKeyManagementMethodSAE);
  if (flags.rsn_8021x) {
    rsn.push_back(std::string("wpa2") +
                  WPASupplicant::kKeyManagementMethodSuffixEAP);
  }
  if (flags.rsn_psk) {
    rsn.push_back(std::string("wpa2") +
                  WPASupplicant::kKeyManagementMethodSuffixPSK);
  }
  if (flags.wpa_8021x)
    wpa.push_back(std::string("wpa") +
                  WPASupplicant::kKeyManagementMethodSuffixEAP);
  if (flags.wpa_psk)
    wpa.push_back(std::string("wpa") +
                  WPASupplicant::kKeyManagementMethodSuffixPSK);

  if (flags.privacy)
    args->Set<bool>(WPASupplicant::kPropertyPrivacy, true);

  if (!rsn.empty()) {
    KeyValueStore rsn_args;
    rsn_args.Set<Strings>(WPASupplicant::kSecurityMethodPropertyKeyManagement,
                          rsn);
    args->Set<KeyValueStore>(WPASupplicant::kPropertyRSN, rsn_args);
  }
  if (!wpa.empty()) {
    KeyValueStore wpa_args;
    wpa_args.Set<Strings>(WPASupplicant::kSecurityMethodPropertyKeyManagement,
                          wpa);
    args->Set<KeyValueStore>(WPASupplicant::kPropertyWPA, wpa_args);
  }
}

}  // namespace

WiFiEndpoint::WiFiEndpoint(ControlInterface* control_interface,
                           const WiFiRefPtr& device,
                           const RpcIdentifier& rpc_id,
                           const KeyValueStore& properties,
                           Metrics* metrics)
    : ssid_(properties.Get<std::vector<uint8_t>>(
          WPASupplicant::kBSSPropertySSID)),
      bssid_(properties.Get<std::vector<uint8_t>>(
          WPASupplicant::kBSSPropertyBSSID)),
      ssid_hex_(base::HexEncode(ssid_.data(), ssid_.size())),
      bssid_string_(Device::MakeStringFromHardwareAddress(bssid_)),
      bssid_hex_(base::HexEncode(bssid_.data(), bssid_.size())),
      frequency_(0),
      physical_mode_(Metrics::kWiFiNetworkPhyModeUndef),
      metrics_(metrics),
      control_interface_(control_interface),
      device_(device),
      rpc_id_(rpc_id) {
  signal_strength_ = properties.Get<int16_t>(WPASupplicant::kBSSPropertySignal);
  if (properties.Contains<uint32_t>(WPASupplicant::kBSSPropertyAge)) {
    last_seen_ =
        base::Time::Now() -
        base::Seconds(properties.Get<uint32_t>(WPASupplicant::kBSSPropertyAge));
  } else {
    last_seen_ = base::Time();
  }
  if (properties.Contains<uint16_t>(WPASupplicant::kBSSPropertyFrequency)) {
    frequency_ = properties.Get<uint16_t>(WPASupplicant::kBSSPropertyFrequency);
  }

  Metrics::WiFiNetworkPhyMode phy_mode = Metrics::kWiFiNetworkPhyModeUndef;
  if (!ParseIEs(properties, &phy_mode, &vendor_information_, &country_code_,
                &supported_features_)) {
    phy_mode = DeterminePhyModeFromFrequency(properties, frequency_);
  }
  physical_mode_ = phy_mode;

  network_mode_ =
      ParseMode(properties.Get<std::string>(WPASupplicant::kBSSPropertyMode));
  security_mode_ = ParseSecurity(properties, &security_flags_);
  has_rsn_property_ =
      properties.Contains<KeyValueStore>(WPASupplicant::kPropertyRSN);
  has_wpa_property_ =
      properties.Contains<KeyValueStore>(WPASupplicant::kPropertyWPA);

  ssid_string_ = std::string(ssid_.begin(), ssid_.end());
  WiFi::SanitizeSSID(&ssid_string_);

  CheckForTetheringSignature();
}

WiFiEndpoint::~WiFiEndpoint() = default;

void WiFiEndpoint::Start() {
  supplicant_bss_proxy_ =
      control_interface_->CreateSupplicantBSSProxy(this, rpc_id_);
}

void WiFiEndpoint::PropertiesChanged(const KeyValueStore& properties) {
  SLOG(2) << __func__;
  bool should_notify = false;
  if (properties.Contains<int16_t>(WPASupplicant::kBSSPropertySignal)) {
    signal_strength_ =
        properties.Get<int16_t>(WPASupplicant::kBSSPropertySignal);
    should_notify = true;
  }

  if (properties.Contains<uint32_t>(WPASupplicant::kBSSPropertyAge)) {
    last_seen_ =
        base::Time::Now() -
        base::Seconds(properties.Get<uint32_t>(WPASupplicant::kBSSPropertyAge));
    should_notify = true;
  }

  if (properties.Contains<std::string>(WPASupplicant::kBSSPropertyMode)) {
    auto new_mode =
        ParseMode(properties.Get<std::string>(WPASupplicant::kBSSPropertyMode));
    if (!new_mode.empty() && new_mode != network_mode_) {
      network_mode_ = new_mode;
      SLOG(2) << "WiFiEndpoint " << bssid_string_ << " mode is now "
              << network_mode_;
      should_notify = true;
    }
  }

  if (properties.Contains<uint16_t>(WPASupplicant::kBSSPropertyFrequency)) {
    uint16_t new_frequency =
        properties.Get<uint16_t>(WPASupplicant::kBSSPropertyFrequency);
    if (new_frequency != frequency_) {
      if (metrics_) {
        metrics_->NotifyApChannelSwitch(frequency_, new_frequency);
      }
      if (device_->GetCurrentEndpoint().get() == this) {
        SLOG(2) << "Current WiFiEndpoint " << bssid_string_ << " frequency "
                << frequency_ << " -> " << new_frequency;
      }
      frequency_ = new_frequency;
      should_notify = true;
    }
  }

  WiFiSecurity::Mode new_security_mode =
      ParseSecurity(properties, &security_flags_);
  if (new_security_mode != security_mode()) {
    security_mode_ = new_security_mode;
    SLOG(2) << "WiFiEndpoint " << bssid_string_ << " security is now "
            << security_mode();
    should_notify = true;
  }

  if (should_notify) {
    device_->NotifyEndpointChanged(this);
  }
}

void WiFiEndpoint::UpdateSignalStrength(int16_t strength) {
  if (signal_strength_ == strength) {
    return;
  }

  SLOG(2) << __func__ << ": signal strength " << signal_strength_ << " -> "
          << strength;
  signal_strength_ = strength;
  device_->NotifyEndpointChanged(this);
}

std::map<std::string, std::string> WiFiEndpoint::GetVendorInformation() const {
  std::map<std::string, std::string> vendor_information;
  if (!vendor_information_.wps_manufacturer.empty()) {
    vendor_information[kVendorWPSManufacturerProperty] =
        vendor_information_.wps_manufacturer;
  }
  if (!vendor_information_.wps_model_name.empty()) {
    vendor_information[kVendorWPSModelNameProperty] =
        vendor_information_.wps_model_name;
  }
  if (!vendor_information_.wps_model_number.empty()) {
    vendor_information[kVendorWPSModelNumberProperty] =
        vendor_information_.wps_model_number;
  }
  if (!vendor_information_.wps_device_name.empty()) {
    vendor_information[kVendorWPSDeviceNameProperty] =
        vendor_information_.wps_device_name;
  }
  if (!vendor_information_.oui_set.empty()) {
    std::vector<std::string> oui_vector;
    for (auto oui : vendor_information_.oui_set) {
      oui_vector.push_back(base::StringPrintf("%02x-%02x-%02x", oui >> 16,
                                              (oui >> 8) & 0xff, oui & 0xff));
    }
    vendor_information[kVendorOUIListProperty] =
        base::JoinString(oui_vector, " ");
  }
  return vendor_information;
}

// static
uint32_t WiFiEndpoint::ModeStringToUint(const std::string& mode_string) {
  if (mode_string == kModeManaged)
    return WPASupplicant::kNetworkModeInfrastructureInt;
  else
    NOTIMPLEMENTED() << "Shill does not support " << mode_string
                     << " mode at this time.";
  return 0;
}

const std::vector<uint8_t>& WiFiEndpoint::ssid() const {
  return ssid_;
}

const std::string& WiFiEndpoint::ssid_string() const {
  return ssid_string_;
}

const std::string& WiFiEndpoint::ssid_hex() const {
  return ssid_hex_;
}

const std::vector<uint8_t>& WiFiEndpoint::bssid() const {
  return bssid_;
}

const std::string& WiFiEndpoint::bssid_string() const {
  return bssid_string_;
}

const std::string& WiFiEndpoint::bssid_hex() const {
  return bssid_hex_;
}

const std::string& WiFiEndpoint::country_code() const {
  return country_code_;
}

const WiFiRefPtr& WiFiEndpoint::device() const {
  return device_;
}

int16_t WiFiEndpoint::signal_strength() const {
  return signal_strength_;
}

base::Time WiFiEndpoint::last_seen() const {
  return last_seen_;
}

uint16_t WiFiEndpoint::frequency() const {
  return frequency_;
}

uint16_t WiFiEndpoint::physical_mode() const {
  return physical_mode_;
}

const std::string& WiFiEndpoint::network_mode() const {
  return network_mode_;
}

WiFiSecurity::Mode WiFiEndpoint::security_mode() const {
  return security_mode_;
}

bool WiFiEndpoint::has_rsn_property() const {
  return has_rsn_property_;
}

bool WiFiEndpoint::has_wpa_property() const {
  return has_wpa_property_;
}

// "PSK", as in WPA-PSK or WPA2-PSK.
bool WiFiEndpoint::has_psk_property() const {
  return security_flags_.rsn_psk || security_flags_.wpa_psk;
}

bool WiFiEndpoint::has_tethering_signature() const {
  return has_tethering_signature_;
}

const WiFiEndpoint::Ap80211krvSupport& WiFiEndpoint::krv_support() const {
  return supported_features_.krv_support;
}

const WiFiEndpoint::HS20Information& WiFiEndpoint::hs20_information() const {
  return supported_features_.hs20_information;
}

bool WiFiEndpoint::mbo_support() const {
  return supported_features_.mbo_support;
}

const WiFiEndpoint::QosSupport& WiFiEndpoint::qos_support() const {
  return supported_features_.qos_support;
}

// static
WiFiEndpointRefPtr WiFiEndpoint::MakeOpenEndpoint(
    ControlInterface* control_interface,
    const WiFiRefPtr& wifi,
    const std::string& ssid,
    const std::string& bssid,
    const std::string& network_mode,
    uint16_t frequency,
    int16_t signal_dbm) {
  return MakeEndpoint(control_interface, wifi, ssid, bssid, network_mode,
                      frequency, signal_dbm, SecurityFlags());
}

// static
WiFiEndpointRefPtr WiFiEndpoint::MakeEndpoint(
    ControlInterface* control_interface,
    const WiFiRefPtr& wifi,
    const std::string& ssid,
    const std::string& bssid,
    const std::string& network_mode,
    uint16_t frequency,
    int16_t signal_dbm,
    const SecurityFlags& security_flags) {
  KeyValueStore args;

  args.Set<std::vector<uint8_t>>(
      WPASupplicant::kBSSPropertySSID,
      std::vector<uint8_t>(ssid.begin(), ssid.end()));

  auto bssid_bytes = Device::MakeHardwareAddressFromString(bssid);
  args.Set<std::vector<uint8_t>>(WPASupplicant::kBSSPropertyBSSID, bssid_bytes);

  args.Set<int16_t>(WPASupplicant::kBSSPropertySignal, signal_dbm);
  args.Set<uint16_t>(WPASupplicant::kBSSPropertyFrequency, frequency);
  args.Set<std::string>(WPASupplicant::kBSSPropertyMode, network_mode);

  PackSecurity(security_flags, &args);

  return new WiFiEndpoint(control_interface, wifi,
                          RpcIdentifier(bssid),  // |bssid| fakes an RPC ID
                          args,
                          nullptr);  // MakeEndpoint is only used for unit
                                     // tests, where Metrics are not needed.
}

// static
std::string WiFiEndpoint::ParseMode(const std::string& mode_string) {
  if (mode_string == WPASupplicant::kNetworkModeInfrastructure) {
    return kModeManaged;
  } else if (mode_string == WPASupplicant::kNetworkModeAdHoc ||
             mode_string == WPASupplicant::kNetworkModeAccessPoint ||
             mode_string == WPASupplicant::kNetworkModeP2P ||
             mode_string == WPASupplicant::kNetworkModeMesh) {
    SLOG(2) << "Shill does not support mode: " << mode_string;
    return "";
  } else {
    LOG(ERROR) << "Unknown WiFi endpoint mode: " << mode_string;
    return "";
  }
}

// static
WiFiSecurity::Mode WiFiEndpoint::ParseSecurity(const KeyValueStore& properties,
                                               SecurityFlags* flags) {
  if (properties.Contains<KeyValueStore>(WPASupplicant::kPropertyRSN)) {
    KeyValueStore rsn_properties =
        properties.Get<KeyValueStore>(WPASupplicant::kPropertyRSN);
    std::set<KeyManagement> key_management;
    ParseKeyManagementMethods(rsn_properties, &key_management);
    flags->rsn_8021x_wpa3 =
        base::Contains(key_management, kKeyManagement802_1x_Wpa3);
    flags->rsn_8021x = base::Contains(key_management, kKeyManagement802_1x);
    flags->rsn_psk = base::Contains(key_management, kKeyManagementPSK);
    flags->rsn_sae = base::Contains(key_management, kKeyManagementSAE);
  }

  if (properties.Contains<KeyValueStore>(WPASupplicant::kPropertyWPA)) {
    KeyValueStore rsn_properties =
        properties.Get<KeyValueStore>(WPASupplicant::kPropertyWPA);
    std::set<KeyManagement> key_management;
    ParseKeyManagementMethods(rsn_properties, &key_management);
    flags->wpa_8021x = base::Contains(key_management, kKeyManagement802_1x);
    flags->wpa_psk = base::Contains(key_management, kKeyManagementPSK);
  }

  if (properties.Contains<bool>(WPASupplicant::kPropertyPrivacy)) {
    flags->privacy = properties.Get<bool>(WPASupplicant::kPropertyPrivacy);
  }

  if (flags->rsn_8021x_wpa3) {
    return flags->rsn_8021x ? WiFiSecurity::kWpa2Wpa3Enterprise
                            : WiFiSecurity::kWpa3Enterprise;
  } else if (flags->rsn_8021x) {
    return flags->wpa_8021x ? WiFiSecurity::kWpaWpa2Enterprise
                            : WiFiSecurity::kWpa2Enterprise;
  } else if (flags->wpa_8021x) {
    return WiFiSecurity::kWpaEnterprise;
  } else if (flags->rsn_sae) {
    return flags->rsn_psk ? WiFiSecurity::kWpa2Wpa3 : WiFiSecurity::kWpa3;
  } else if (flags->rsn_psk) {
    return flags->wpa_psk ? WiFiSecurity::kWpaWpa2 : WiFiSecurity::kWpa2;
  } else if (flags->wpa_psk) {
    return WiFiSecurity::kWpa;
  } else if (flags->privacy) {
    return WiFiSecurity::kWep;
  } else {
    return WiFiSecurity::kNone;
  }
}

// static
void WiFiEndpoint::ParseKeyManagementMethods(
    const KeyValueStore& security_method_properties,
    std::set<KeyManagement>* key_management_methods) {
  if (!security_method_properties.Contains<Strings>(
          WPASupplicant::kSecurityMethodPropertyKeyManagement)) {
    return;
  }

  const std::vector<std::string> key_management_vec =
      security_method_properties.Get<Strings>(
          WPASupplicant::kSecurityMethodPropertyKeyManagement);

  for (const auto& method : key_management_vec) {
    if (method == WPASupplicant::kKeyManagementMethodSAE) {
      key_management_methods->insert(kKeyManagementSAE);
    } else if (base::StartsWith(method,
                                WPASupplicant::kKeyManagementMethodPrefixEAP) &&
               (base::Contains(method,
                               WPASupplicant::kKeyManagementMethodSuiteB) ||
                base::EndsWith(
                    method, WPASupplicant::kKeyManagementMethodSuffixEAPSHA256,
                    base::CompareCase::SENSITIVE))) {
      key_management_methods->insert(kKeyManagement802_1x_Wpa3);
    } else if (base::StartsWith(method,
                                WPASupplicant::kKeyManagementMethodPrefixEAP) ||
               base::EndsWith(method,
                              WPASupplicant::kKeyManagementMethodSuffixEAP,
                              base::CompareCase::SENSITIVE)) {
      key_management_methods->insert(kKeyManagement802_1x);
    } else if (base::EndsWith(method,
                              WPASupplicant::kKeyManagementMethodSuffixPSK,
                              base::CompareCase::SENSITIVE) ||
               base::EndsWith(
                   method, WPASupplicant::kKeyManagementMethodSuffixPSKSHA256,
                   base::CompareCase::SENSITIVE)) {
      key_management_methods->insert(kKeyManagementPSK);
    }
  }
}

// static
Metrics::WiFiNetworkPhyMode WiFiEndpoint::DeterminePhyModeFromFrequency(
    const KeyValueStore& properties, uint16_t frequency) {
  uint32_t max_rate = 0;
  if (properties.Contains<std::vector<uint32_t>>(
          WPASupplicant::kBSSPropertyRates)) {
    auto rates =
        properties.Get<std::vector<uint32_t>>(WPASupplicant::kBSSPropertyRates);
    if (!rates.empty()) {
      max_rate = rates[0];  // Rates are sorted in descending order
    }
  }

  Metrics::WiFiNetworkPhyMode phy_mode = Metrics::kWiFiNetworkPhyModeUndef;
  if (frequency < 3000) {
    // 2.4GHz legacy, check for tx rate for 11b-only
    // (note 22M is valid)
    if (max_rate < 24000000)
      phy_mode = Metrics::kWiFiNetworkPhyMode11b;
    else
      phy_mode = Metrics::kWiFiNetworkPhyMode11g;
  } else {
    phy_mode = Metrics::kWiFiNetworkPhyMode11a;
  }

  return phy_mode;
}

// static
bool WiFiEndpoint::ParseIEs(const KeyValueStore& properties,
                            Metrics::WiFiNetworkPhyMode* phy_mode,
                            VendorInformation* vendor_information,
                            std::string* country_code,
                            SupportedFeatures* supported_features) {
  if (!properties.Contains<std::vector<uint8_t>>(
          WPASupplicant::kBSSPropertyIEs)) {
    SLOG(2) << __func__ << ": No IE property in BSS.";
    return false;
  }
  auto ies =
      properties.Get<std::vector<uint8_t>>(WPASupplicant::kBSSPropertyIEs);

  // Format of an information element not of type 255:
  //    1       1          1 - 252
  // +------+--------+----------------+
  // | Type | Length | Data           |
  // +------+--------+----------------+
  //
  // Format of an information element of type 255:
  //    1       1          1         variable
  // +------+--------+----------+----------------+
  // | Type | Length | Ext Type | Data           |
  // +------+--------+----------+----------------+
  *phy_mode = Metrics::kWiFiNetworkPhyModeUndef;
  bool found_ht = false;
  bool found_vht = false;
  bool found_he = false;
  bool found_erp = false;
  bool found_country = false;
  bool found_power_constraint = false;
  bool found_rm_enabled_cap = false;
  bool found_mde = false;
  bool found_ft_cipher = false;
  int ie_len = 0;
  std::vector<uint8_t>::iterator it;
  for (it = ies.begin();
       std::distance(it, ies.end()) > 1;  // Ensure Length field is within PDU.
       it += ie_len) {
    ie_len = 2 + *(it + 1);
    if (std::distance(it, ies.end()) < ie_len) {
      LOG(ERROR) << __func__ << ": IE extends past containing PDU.";
      break;
    }
    switch (*it) {
      case IEEE_80211::kElemIdBSSMaxIdlePeriod:
        supported_features->krv_support.bss_max_idle_period_supported = true;
        break;
      case IEEE_80211::kElemIdCountry:
        // Retrieve 2-character country code from the beginning of the element.
        if (ie_len >= 4) {
          std::string country(it + 2, it + 4);
          // ISO 3166 alpha-2 codes must be ASCII. There are probably other
          // restrictions we should honor too, but this is at least a minimum
          // coherence check.
          if (base::IsStringASCII(country)) {
            found_country = true;
            *country_code = country;
          }
        }
        break;
      case IEEE_80211::kElemIdErp:
        found_erp = true;
        break;
      case IEEE_80211::kElemIdExtendedCap:
        ParseExtendedCapabilities(it + 2, it + ie_len, supported_features);
        break;
      case IEEE_80211::kElemIdHTCap:
      case IEEE_80211::kElemIdHTInfo:
        found_ht = true;
        break;
      case IEEE_80211::kElemIdMDE:
        found_mde = true;
        ParseMobilityDomainElement(it + 2, it + ie_len,
                                   &supported_features->krv_support);
        break;
      case IEEE_80211::kElemIdPowerConstraint:
        found_power_constraint = true;
        break;
      case IEEE_80211::kElemIdRmEnabledCap:
        found_rm_enabled_cap = true;
        break;
      case IEEE_80211::kElemIdRSN:
        ParseWPACapabilities(it + 2, it + ie_len, &found_ft_cipher);
        break;
      case IEEE_80211::kElemIdVendor:
        ParseVendorIE(it + 2, it + ie_len, vendor_information,
                      supported_features);
        break;
      case IEEE_80211::kElemIdVHTCap:
      case IEEE_80211::kElemIdVHTOperation:
        found_vht = true;
        break;
      case IEEE_80211::kElemIdExt:
        if (std::distance(it, ies.end()) > 2) {
          switch (*(it + 2)) {
            case IEEE_80211::kElemIdExtHECap:
            case IEEE_80211::kElemIdExtHEOperation:
              found_he = true;
              break;
            default:
              SLOG(5) << __func__ << ": Element ID Extension " << *(it + 2)
                      << " not supported.";
              break;
          }
        }

        break;
      default:
        SLOG(5) << __func__ << ": parsing of " << *it
                << " type IE not supported.";
    }
  }
  supported_features->krv_support.neighbor_list_supported =
      found_country && found_power_constraint && found_rm_enabled_cap;
  supported_features->krv_support.ota_ft_supported =
      found_mde && found_ft_cipher;
  supported_features->krv_support.otds_ft_supported =
      supported_features->krv_support.otds_ft_supported &&
      supported_features->krv_support.ota_ft_supported;
  if (found_he) {
    *phy_mode = Metrics::kWiFiNetworkPhyMode11ax;
  } else if (found_vht) {
    *phy_mode = Metrics::kWiFiNetworkPhyMode11ac;
  } else if (found_ht) {
    *phy_mode = Metrics::kWiFiNetworkPhyMode11n;
  } else if (found_erp) {
    *phy_mode = Metrics::kWiFiNetworkPhyMode11g;
  } else {
    return false;
  }
  return true;
}

// static
void WiFiEndpoint::ParseMobilityDomainElement(
    std::vector<uint8_t>::const_iterator ie,
    std::vector<uint8_t>::const_iterator end,
    Ap80211krvSupport* krv_support) {
  // Format of a Mobility Domain Element:
  //    2                1
  // +------+--------------------------+
  // | MDID | FT Capability and Policy |
  // +------+--------------------------+
  if (std::distance(ie, end) < IEEE_80211::kMDEFTCapabilitiesLen) {
    return;
  }

  // Advance past the MDID field and check the first bit of the capability
  // field, the Over-the-DS FT bit.
  ie += IEEE_80211::kMDEIDLen;
  krv_support->otds_ft_supported = (*ie & IEEE_80211::kMDEOTDSCapability) > 0;
}

// static
void WiFiEndpoint::ParseExtendedCapabilities(
    std::vector<uint8_t>::const_iterator ie,
    std::vector<uint8_t>::const_iterator end,
    SupportedFeatures* supported_features) {
  // Format of an Extended Capabilities Element:
  //        n
  // +--------------+
  // | Capabilities |
  // +--------------+
  // The Capabilities field is a bit field indicating the capabilities being
  // advertised by the STA transmitting the element. See section 8.4.2.29 of
  // the IEEE 802.11-2012 for a list of capabilities and their corresponding
  // bit positions.
  supported_features->krv_support.bss_transition_supported =
      GetExtendedCapability(ie, end, IEEE_80211::kExtendedCapOctet2,
                            IEEE_80211::kExtendedCapBit3);
  supported_features->krv_support.dms_supported = GetExtendedCapability(
      ie, end, IEEE_80211::kExtendedCapOctet3, IEEE_80211::kExtendedCapBit2);
  supported_features->qos_support.scs_supported = GetExtendedCapability(
      ie, end, IEEE_80211::kExtendedCapOctet6, IEEE_80211::kExtendedCapBit6);
  supported_features->qos_support.alternate_edca_supported =
      GetExtendedCapability(ie, end, IEEE_80211::kExtendedCapOctet7,
                            IEEE_80211::kExtendedCapBit0);
  supported_features->qos_support.mscs_supported = GetExtendedCapability(
      ie, end, IEEE_80211::kExtendedCapOctet10, IEEE_80211::kExtendedCapBit5);
}

// static
bool WiFiEndpoint::GetExtendedCapability(
    std::vector<uint8_t>::const_iterator ie,
    std::vector<uint8_t>::const_iterator end,
    IEEE_80211::ExtendedCapOctet octet,
    uint8_t bit) {
  // According to IEEE802.11-2020 (section 9.4.2.26) if fewer bits are received
  // in an Extended Capabilities field, the rest of the Extended Capabilities
  // field bits are assumed to be zero.
  if (std::distance(ie, end) < octet + 1) {
    return false;
  }
  return (*(ie + octet) & bit) != 0;
}

// static
void WiFiEndpoint::ParseWPACapabilities(
    std::vector<uint8_t>::const_iterator ie,
    std::vector<uint8_t>::const_iterator end,
    bool* found_ft_cipher) {
  // Format of an RSN Information Element:
  //    2             4
  // +------+--------------------+
  // | Type | Group Cipher Suite |
  // +------+--------------------+
  //             2             4 * pairwise count
  // +-----------------------+---------------------+
  // | Pairwise Cipher Count | Pairwise Ciphers... |
  // +-----------------------+---------------------+
  //             2             4 * authkey count
  // +-----------------------+---------------------+
  // | AuthKey Suite Count   | AuthKey Suites...   |
  // +-----------------------+---------------------+
  //          2
  // +------------------+
  // | RSN Capabilities |
  // +------------------+
  //          2            16 * pmkid count
  // +------------------+-------------------+
  // |   PMKID Count    |      PMKIDs...    |
  // +------------------+-------------------+
  //          4
  // +-------------------------------+
  // | Group Management Cipher Suite |
  // +-------------------------------+
  if (std::distance(ie, end) < IEEE_80211::kRSNIECipherCountOffset) {
    return;
  }
  ie += IEEE_80211::kRSNIECipherCountOffset;

  // Advance past the pairwise and authkey ciphers.  Each is a little-endian
  // cipher count followed by n * cipher_selector.
  for (int i = 0; i < IEEE_80211::kRSNIENumCiphers; ++i) {
    // Retrieve a little-endian cipher count.
    if (std::distance(ie, end) < IEEE_80211::kRSNIECipherCountLen) {
      return;
    }
    uint16_t cipher_count = *ie | (*(ie + 1) << 8);

    int skip_length = IEEE_80211::kRSNIECipherCountLen +
                      cipher_count * IEEE_80211::kRSNIESelectorLen;
    if (std::distance(ie, end) < skip_length) {
      return;
    }

    if (i == IEEE_80211::kRSNIEAuthKeyCiphers && cipher_count > 0 &&
        found_ft_cipher) {
      // Find the AuthKey Suite List and check for matches to Fast Transition
      // ciphers.
      std::vector<uint32_t> akm_suite_list(cipher_count, 0);
      std::memcpy(&akm_suite_list[0], &*(ie + IEEE_80211::kRSNIECipherCountLen),
                  cipher_count * IEEE_80211::kRSNIESelectorLen);
      for (uint16_t i = 0; i < cipher_count; i++) {
        uint32_t suite = akm_suite_list[i];
        if (suite == IEEE_80211::kRSNAuthType8021XFT ||
            suite == IEEE_80211::kRSNAuthTypePSKFT ||
            suite == IEEE_80211::kRSNAuthTypeSAEFT) {
          *found_ft_cipher = true;
          break;
        }
      }
    }

    // Skip over the cipher selectors.
    ie += skip_length;
  }
}

// static
void WiFiEndpoint::ParseVendorIE(std::vector<uint8_t>::const_iterator ie,
                                 std::vector<uint8_t>::const_iterator end,
                                 VendorInformation* vendor_information,
                                 SupportedFeatures* supported_features) {
  // Format of an vendor-specific information element (with type
  // and length field for the IE removed by the caller):
  //        3           1       1 - 248
  // +------------+----------+----------------+
  // | OUI        | OUI Type | Data           |
  // +------------+----------+----------------+
  if (std::distance(ie, end) < 4) {
    LOG(WARNING) << __func__ << ": no room in IE for OUI and type field.";
    return;
  }
  uint32_t oui = (*ie << 16) | (*(ie + 1) << 8) | *(ie + 2);
  uint8_t oui_type = *(ie + 3);
  ie += 4;

  if (oui != IEEE_80211::kOUIVendorEpigram &&
      oui != IEEE_80211::kOUIVendorMicrosoft) {
    vendor_information->oui_set.insert(oui);
  }

  if (oui == IEEE_80211::kOUIVendorMicrosoft &&
      oui_type == IEEE_80211::kOUIMicrosoftWPS) {
    // Format of a WPS data element:
    //    2       2
    // +------+--------+----------------+
    // | Type | Length | Data           |
    // +------+--------+----------------+
    while (std::distance(ie, end) >= 4) {
      int element_type = (*ie << 8) | *(ie + 1);
      int element_length = (*(ie + 2) << 8) | *(ie + 3);
      ie += 4;
      if (std::distance(ie, end) < element_length) {
        LOG(WARNING) << __func__
                     << ": WPS element extends past containing PDU.";
        break;
      }
      std::string s(ie, ie + element_length);
      if (base::IsStringASCII(s)) {
        switch (element_type) {
          case IEEE_80211::kWPSElementManufacturer:
            vendor_information->wps_manufacturer = s;
            break;
          case IEEE_80211::kWPSElementModelName:
            vendor_information->wps_model_name = s;
            break;
          case IEEE_80211::kWPSElementModelNumber:
            vendor_information->wps_model_number = s;
            break;
          case IEEE_80211::kWPSElementDeviceName:
            vendor_information->wps_device_name = s;
            break;
        }
      }
      ie += element_length;
    }
  } else if (oui == IEEE_80211::kOUIVendorWiFiAlliance &&
             oui_type == IEEE_80211::kOUITypeWiFiAllianceHS20Indicator) {
    // Format of a Hotspot 2.0 Indication data element:
    //            1                  2             2
    // +-----------------------+-----------+----------------+
    // | Hotspot Configuration | PPS MO ID | ANQP Domain ID |
    // +-----------------------+-----------+----------------+
    //                          (optional)     (optional)
    //
    // Format of Hotspot Configuration Field (bits):
    //         4              1               1
    // +----------------+----------+------------------------+
    // | Version Number | Reserved | ANQP Domain ID present |
    // +----------------+----------+------------------------+
    //          1                 1
    // +-------------------+---------------+
    // | PPS MO ID Present | DGAF Disabled |
    // +-------------------+---------------+
    if (std::distance(ie, end) < 1) {
      LOG(WARNING) << __func__ << ": no room in Hotspot 2.0 indication element"
                   << " for Hotspot Configuration field.";
      return;
    }
    supported_features->hs20_information.supported = true;
    // Parse out the version number from the Hotspot Configuration field.
    supported_features->hs20_information.version = (*ie & 0xf0) >> 4;
  } else if (oui == IEEE_80211::kOUIVendorWiFiAlliance &&
             oui_type == IEEE_80211::kOUITypeWiFiAllianceMBO) {
    supported_features->mbo_support = true;
  } else if (oui == IEEE_80211::kOUIVendorCiscoAironet &&
             oui_type == IEEE_80211::kOUITypeCiscoExtendedCapabilitiesIE) {
    if (std::distance(ie, end) < 1) {
      LOG(WARNING) << __func__ << ": Cisco Extended Capabilities IE too short";
      return;
    }
    supported_features->krv_support.adaptive_ft_supported =
        *ie & IEEE_80211::kCiscoExtendedCapabilitiesAdaptiveFT;
  }
}

void WiFiEndpoint::CheckForTetheringSignature() {
  has_tethering_signature_ =
      Tethering::IsAndroidBSSID(bssid_) ||
      (Tethering::IsLocallyAdministeredBSSID(bssid_) &&
       Tethering::HasIosOui(vendor_information_.oui_set));
}

}  // namespace shill
