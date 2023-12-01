// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_PHY_H_
#define SHILL_WIFI_WIFI_PHY_H_

#include <map>
#include <set>
#include <vector>

#include "shill/mockable.h"
#include "shill/net/nl80211_message.h"
#include "shill/wifi/wifi.h"
#include "shill/wifi/wifi_provider.h"

namespace shill {

struct IfaceLimit {
  std::vector<nl80211_iftype> iftypes;
  uint32_t max;
};

struct ConcurrencyCombination {
  std::vector<IfaceLimit> limits;
  uint32_t max_num;
  uint32_t num_channels;
};

// A WiFiPhy object represents a wireless physical layer device. Objects of this
// class map 1:1 with an NL80211 "wiphy". WiFiPhy objects are created and owned
// by the WiFiProvider singleton. The lifecycle of a WiFiPhy object begins with
// the netlink command NL80211_CMD_NEW_WIPHY and ends with
// NL80211_CMD_DEL_WIPHY.

// TODO(b/244630773): Update WiFiPhy to store phy cabilities, and update the
// documentation accordingly.

class WiFiPhy {
 public:
  explicit WiFiPhy(uint32_t phy_index);

  virtual ~WiFiPhy();

  // Return the phy index.
  uint32_t GetPhyIndex() const { return phy_index_; }

  // Remove a WiFi device instance from wifi_devices_.
  void DeleteWiFiDevice(WiFiConstRefPtr device);

  // Add a WiFi device instance to wifi_devices_.
  void AddWiFiDevice(WiFiConstRefPtr device);

  // Remove a WiFi local device instance from wifi_local_devices_.
  void DeleteWiFiLocalDevice(LocalDeviceConstRefPtr device);

  // Add a WiFi local device instance to wifi_local_devices_.
  void AddWiFiLocalDevice(LocalDeviceConstRefPtr device);

  // Signals the end of the sequence of the PHY dump messages - all the
  // frequencies cached during parsing of NewWiphy messages are accepted as
  // a new value.
  void PhyDumpComplete();

  // Parse an NL80211_CMD_NEW_WIPHY netlink message.
  // TODO(b/248103586): Move NL80211_CMD_NEW_WIPHY parsing out of WiFiPhy and
  // into WiFiProvider.
  mockable void OnNewWiphy(const Nl80211Message& nl80211_message);

  // Return true if the phy supports iftype, false otherwise.
  bool SupportsIftype(nl80211_iftype iftype) const;

  // Returns true if the PHY handles 802.11d country notifications (for
  // automatic changes of regulatory domains).
  bool reg_self_managed() const { return reg_self_managed_; }

  std::vector<ConcurrencyCombination> ConcurrencyCombinations() {
    return concurrency_combs_;
  }

  // Helper functions to retrieve WiFiPhy capabilities.
  // Return true if the phy supports AP interface type, false otherwise.
  mockable bool SupportAPMode() const;

  // Return true if the phy supports |iface_type1|/|iface_type2| concurrency,
  // false otherwise.
  bool SupportConcurrency(nl80211_iftype iface_type1,
                          nl80211_iftype iface_type2) const;

  // Return true if the phy supports AP/STA concurrency, false otherwise.
  mockable bool SupportAPSTAConcurrency() const;

  // This structure keeps information about frequency reported in PHY dump.
  // |flags| is a bitmap with bits corresponding to NL80211_FREQUENCY_ATTR_*
  // flags reported, |value| is the actual frequency in MHz and |attributes|
  // keeps map of reported attributes that has value (e.g.
  // NL80211_FREQUENCY_ATTR_MAX_TX_POWER)
  struct Frequency {
    uint64_t flags = 0;
    uint32_t value = 0;
    std::map<int, uint32_t> attributes;
  };

  // Frequencies available are returned as a map:
  //   "band" -> "list of frequencies".
  // The key (band) is the NL band attribute (NL80211_BAND_2GHZ etc.) and the
  // value is just vector of Frequency structs (see above).
  using Frequencies = std::map<int, std::vector<Frequency>>;
  // Returns map of available frequencies.
  mockable const Frequencies& frequencies() const { return frequencies_; }

 private:
  friend class WiFiPhyTest;
  friend class MockWiFiPhy;

  // Helper functions used to parse NL80211_CMD_NEW_WIPHY message.  They take
  // relevant portion (attribute), parse it and store the information in member
  // variables.  Respectively these are:
  // - NL80211_ATTR_SUPPORTED_IFTYPES -> supported_ifaces_
  // - NL80211_ATTR_INTERFACE_COMBINATIONS -> concurrency_combs_
  // - NL80211_ATTR_WIPHY_BANDS/NL80211_BAND_ATTR_FREQS -> frequencies_
  void ParseInterfaceTypes(const Nl80211Message& nl80211_message);
  void ParseConcurrency(const Nl80211Message& nl80211_message);
  void ParseFrequencies(const Nl80211Message& nl80211_message);

  uint32_t phy_index_;
  bool reg_self_managed_;
  std::set<WiFiConstRefPtr> wifi_devices_;
  std::set<LocalDeviceConstRefPtr> wifi_local_devices_;
  std::set<nl80211_iftype> supported_ifaces_;
  std::vector<ConcurrencyCombination> concurrency_combs_;
  Frequencies frequencies_;
  // This is temporarily used during parsing of WiFi PHY dumps.  At the end of
  // PHY dump this is transferred into |frequencies_| - see also
  // PhyDumpComplete().
  Frequencies temp_freqs_;
};

inline bool operator==(const WiFiPhy::Frequency& f1,
                       const WiFiPhy::Frequency& f2) {
  return f1.value == f2.value && f1.flags == f2.flags &&
         f1.attributes == f2.attributes;
}

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_PHY_H_
