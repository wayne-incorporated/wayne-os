// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_NETWORK_PROXY_INTERFACE_H_
#define SHILL_SUPPLICANT_SUPPLICANT_NETWORK_PROXY_INTERFACE_H_

#include "shill/store/key_value_store.h"

namespace shill {

// SupplicantNetworkProxyInterface declares only the subset of
// fi::w1::wpa_supplicant1::Network_proxy that is actually used by WiFi.
class SupplicantNetworkProxyInterface {
 public:
  virtual ~SupplicantNetworkProxyInterface() = default;

  virtual bool SetEnabled(bool enabled) = 0;
  virtual bool SetProperties(const KeyValueStore& props) = 0;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_NETWORK_PROXY_INTERFACE_H_
