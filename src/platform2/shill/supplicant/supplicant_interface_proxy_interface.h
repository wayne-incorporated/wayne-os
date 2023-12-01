// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_INTERFACE_PROXY_INTERFACE_H_
#define SHILL_SUPPLICANT_SUPPLICANT_INTERFACE_PROXY_INTERFACE_H_

#include <string>
#include <vector>

#include "shill/store/key_value_store.h"

namespace shill {

// SupplicantInterfaceProxyInterface declares only the subset of
// fi::w1::wpa_supplicant1::Interface_proxy that is actually used by WiFi.
class SupplicantInterfaceProxyInterface {
 public:
  virtual ~SupplicantInterfaceProxyInterface() = default;

  virtual bool AddNetwork(const KeyValueStore& args,
                          RpcIdentifier* network) = 0;
  virtual bool EAPLogoff() = 0;
  virtual bool EAPLogon() = 0;
  virtual bool Disconnect() = 0;
  virtual bool FlushBSS(const uint32_t& age) = 0;
  virtual bool NetworkReply(const RpcIdentifier& network,
                            const std::string& field,
                            const std::string& value) = 0;
  virtual bool Reassociate() = 0;
  virtual bool Reattach() = 0;
  virtual bool RemoveAllNetworks() = 0;
  virtual bool RemoveNetwork(const RpcIdentifier& network) = 0;
  virtual bool Roam(const std::string& addr) = 0;
  virtual bool Scan(const KeyValueStore& args) = 0;
  virtual bool SelectNetwork(const RpcIdentifier& network) = 0;
  virtual bool SetFastReauth(bool enabled) = 0;
  virtual bool SetScanInterval(int seconds) = 0;
  virtual bool SetScan(bool enable) = 0;
  virtual bool EnableMacAddressRandomization(
      const std::vector<unsigned char>& mask, bool sched_scan) = 0;
  virtual bool DisableMacAddressRandomization() = 0;
  virtual bool GetCapabilities(KeyValueStore* capabilities) = 0;
  virtual bool AddCred(const KeyValueStore& args, RpcIdentifier* cred) = 0;
  virtual bool RemoveCred(const RpcIdentifier& cred) = 0;
  virtual bool RemoveAllCreds() = 0;
  virtual bool InterworkingSelect() = 0;
  virtual bool SignalPoll(KeyValueStore* signalInfo) = 0;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_INTERFACE_PROXY_INTERFACE_H_
