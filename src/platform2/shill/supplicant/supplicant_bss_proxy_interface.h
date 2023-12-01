// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_BSS_PROXY_INTERFACE_H_
#define SHILL_SUPPLICANT_SUPPLICANT_BSS_PROXY_INTERFACE_H_

namespace shill {

// SupplicantBSSProxyInterface declares only the subset of
// fi::w1::wpa_supplicant1::BSS_proxy that is actually used by WiFi.
class SupplicantBSSProxyInterface {
 public:
  virtual ~SupplicantBSSProxyInterface() = default;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_BSS_PROXY_INTERFACE_H_
