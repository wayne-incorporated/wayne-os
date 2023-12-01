// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "shill/logging.h"
#include "shill/net/netlink_attribute.h"
#include "shill/wifi/wifi_phy.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

WiFiPhy::WiFiPhy(uint32_t phy_index)
    : phy_index_(phy_index), reg_self_managed_(false) {}

WiFiPhy::~WiFiPhy() = default;

void WiFiPhy::AddWiFiDevice(WiFiConstRefPtr device) {
  wifi_devices_.insert(device);
}

void WiFiPhy::DeleteWiFiDevice(WiFiConstRefPtr device) {
  wifi_devices_.erase(device);
}

void WiFiPhy::AddWiFiLocalDevice(LocalDeviceConstRefPtr device) {
  wifi_local_devices_.insert(device);
}

void WiFiPhy::DeleteWiFiLocalDevice(LocalDeviceConstRefPtr device) {
  wifi_local_devices_.erase(device);
}

// TODO(b/248103586): Move NL80211_CMD_NEW_WIPHY parsing out of WiFiPhy and into
// WiFiProvider.
void WiFiPhy::OnNewWiphy(const Nl80211Message& nl80211_message) {
  if (nl80211_message.const_attributes()->IsFlagAttributeTrue(
          NL80211_ATTR_WIPHY_SELF_MANAGED_REG)) {
    reg_self_managed_ = true;
  }
  ParseInterfaceTypes(nl80211_message);
  // TODO(b/244630773): Parse out the message and store phy information.
  ParseConcurrency(nl80211_message);
  ParseFrequencies(nl80211_message);
}

bool WiFiPhy::SupportsIftype(nl80211_iftype iftype) const {
  return base::Contains(supported_ifaces_, iftype);
}

void WiFiPhy::ParseInterfaceTypes(const Nl80211Message& nl80211_message) {
  AttributeListConstRefPtr ifaces;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SUPPORTED_IFTYPES, &ifaces)) {
    AttributeIdIterator ifaces_iter(*ifaces);
    for (; !ifaces_iter.AtEnd(); ifaces_iter.Advance()) {
      uint32_t iface;
      if (!ifaces->GetU32AttributeValue(ifaces_iter.GetId(), &iface)) {
        LOG(ERROR) << "Failed to get supported iface type "
                   << ifaces_iter.GetId();
        continue;
      }
      if (iface < 0 || iface >= NL80211_IFTYPE_MAX) {
        LOG(ERROR) << "Invalid iface type: " << iface;
        continue;
      }
      supported_ifaces_.insert(nl80211_iftype(iface));
    }
  }
}

void WiFiPhy::ParseConcurrency(const Nl80211Message& nl80211_message) {
  // Check that the message contains concurrency combinations.
  AttributeListConstRefPtr interface_combinations_attr;
  if (!nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_INTERFACE_COMBINATIONS, &interface_combinations_attr)) {
    return;
  }
  // Iterate over the combinations in the message.
  concurrency_combs_.clear();
  AttributeIdIterator comb_iter(*interface_combinations_attr);
  for (; !comb_iter.AtEnd(); comb_iter.Advance()) {
    struct ConcurrencyCombination comb;
    AttributeListConstRefPtr iface_comb_attr;
    if (!interface_combinations_attr->ConstGetNestedAttributeList(
            comb_iter.GetId(), &iface_comb_attr)) {
      continue;  // Next combination.
    }

    // Check that the combination has limits.
    AttributeListConstRefPtr iface_limits_attr;
    if (!iface_comb_attr->ConstGetNestedAttributeList(NL80211_IFACE_COMB_LIMITS,
                                                      &iface_limits_attr)) {
      continue;  // Next combination.
    }

    iface_comb_attr->GetU32AttributeValue(NL80211_IFACE_COMB_MAXNUM,
                                          &comb.max_num);
    iface_comb_attr->GetU32AttributeValue(NL80211_IFACE_COMB_NUM_CHANNELS,
                                          &comb.num_channels);

    AttributeIdIterator limit_iter(*iface_limits_attr);
    for (; !limit_iter.AtEnd(); limit_iter.Advance()) {
      struct IfaceLimit limit;
      AttributeListConstRefPtr limit_attr;
      if (!iface_limits_attr->ConstGetNestedAttributeList(limit_iter.GetId(),
                                                          &limit_attr)) {
        LOG(WARNING) << "Interface combination limit " << limit_iter.GetId()
                     << " not found";
        // If we reach this line then the message is malformed and we should
        // stop parsing it.
        return;
      }
      limit_attr->GetU32AttributeValue(NL80211_IFACE_LIMIT_MAX, &limit.max);

      // Check that the limit contains interface types.
      AttributeListConstRefPtr iface_types_attr;
      if (!limit_attr->ConstGetNestedAttributeList(NL80211_IFACE_LIMIT_TYPES,
                                                   &iface_types_attr)) {
        continue;
      }
      for (uint32_t iftype = NL80211_IFTYPE_UNSPECIFIED;
           iftype < NUM_NL80211_IFTYPES; iftype++) {
        if (iface_types_attr->GetFlagAttributeValue(iftype, nullptr)) {
          limit.iftypes.push_back(nl80211_iftype(iftype));
        }
      }
      comb.limits.push_back(limit);
    }
    concurrency_combs_.push_back(comb);
  }
}

void WiFiPhy::PhyDumpComplete() {
  std::swap(frequencies_, temp_freqs_);
  temp_freqs_.clear();
}

void WiFiPhy::ParseFrequencies(const Nl80211Message& nl80211_message) {
  // Code below depends on being able to pack all flags into bits.
  static_assert(
      sizeof(WiFiPhy::Frequency::flags) * CHAR_BIT > NL80211_FREQUENCY_ATTR_MAX,
      "Not enough bits to hold all possible flags");

  SLOG(3) << __func__;
  if (!(nl80211_message.flags() & NLM_F_MULTI)) {
    return;
  }

  AttributeListConstRefPtr bands_list;
  if (nl80211_message.const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WIPHY_BANDS, &bands_list)) {
    AttributeIdIterator bands_iter(*bands_list);
    for (; !bands_iter.AtEnd(); bands_iter.Advance()) {
      // Each band has nested attributes and ...
      AttributeListConstRefPtr band_attrs;
      if (bands_list->ConstGetNestedAttributeList(bands_iter.GetId(),
                                                  &band_attrs)) {
        int current_band = bands_iter.GetId();
        // ... we are interested in freqs (which itself is a nested attribute).
        AttributeListConstRefPtr freqs_list;
        if (!band_attrs->ConstGetNestedAttributeList(NL80211_BAND_ATTR_FREQS,
                                                     &freqs_list)) {
          continue;
        }
        AttributeIdIterator freqs_iter(*freqs_list);
        for (; !freqs_iter.AtEnd(); freqs_iter.Advance()) {
          AttributeListConstRefPtr freq_attrs;
          if (freqs_list->ConstGetNestedAttributeList(freqs_iter.GetId(),
                                                      &freq_attrs)) {
            Frequency freq;
            for (auto attr = AttributeIdIterator(*freq_attrs); !attr.AtEnd();
                 attr.Advance()) {
              if (attr.GetType() == NetlinkAttribute::kTypeFlag) {
                freq.flags |= 1 << attr.GetId();
              } else {
                if (attr.GetId() == NL80211_FREQUENCY_ATTR_FREQ) {
                  freq_attrs->GetU32AttributeValue(attr.GetId(), &freq.value);
                } else {
                  if (!freq_attrs->GetU32AttributeValue(
                          attr.GetId(), &freq.attributes[attr.GetId()])) {
                    LOG(WARNING) << "Failed to read frequency attribute: "
                                 << attr.GetId();
                  }
                }
              }
            }
            if (freq.value == 0) {
              continue;
            }
            SLOG(3) << "Found frequency: " << freq.value;
            auto& fvec = temp_freqs_[current_band];
            auto it =
                std::find_if(std::begin(fvec), std::end(fvec),
                             [&](auto& f) { return f.value == freq.value; });
            if (it == fvec.end()) {
              temp_freqs_[current_band].emplace_back(std::move(freq));
            } else {
              LOG(WARNING) << "Repeated frequency in WIPHY dump: "
                           << freq.value;
              *it = std::move(freq);
            }
          }
        }
      }
    }
  }
}

bool WiFiPhy::SupportAPMode() const {
  return SupportsIftype(NL80211_IFTYPE_AP);
}

bool WiFiPhy::SupportConcurrency(nl80211_iftype iface_type1,
                                 nl80211_iftype iface_type2) const {
  for (auto comb : concurrency_combs_) {
    if (comb.max_num < 2) {
      // Support less than 2 interfaces combination, skip this combination.
      continue;
    }

    bool support_type1 = false;
    bool support_type2 = false;

    for (auto limit : comb.limits) {
      std::set<nl80211_iftype> iftypes(limit.iftypes.begin(),
                                       limit.iftypes.end());

      if (limit.max == 1 && base::Contains(iftypes, iface_type1) &&
          base::Contains(iftypes, iface_type2)) {
        // Case #{ iface_type1, iface_type2 } <= 1 does not meet concurrency
        // requirement, skip and check next combination.
        break;
      }
      if (base::Contains(iftypes, iface_type1)) {
        support_type1 = true;
      } else if (base::Contains(iftypes, iface_type2)) {
        support_type2 = true;
      }
    }

    if (support_type1 && support_type2) {
      // This combination already satisfies concurrency, skip checking the rest
      // combinations.
      return true;
    }
  }
  return false;
}

bool WiFiPhy::SupportAPSTAConcurrency() const {
  return SupportConcurrency(NL80211_IFTYPE_AP, NL80211_IFTYPE_STATION);
}

}  // namespace shill
