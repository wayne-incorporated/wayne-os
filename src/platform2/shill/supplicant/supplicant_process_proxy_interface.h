// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_PROCESS_PROXY_INTERFACE_H_
#define SHILL_SUPPLICANT_SUPPLICANT_PROCESS_PROXY_INTERFACE_H_

#include <string>

#include "shill/store/key_value_store.h"

namespace shill {

// SupplicantProcessProxyInterface declares only the subset of
// fi::w1::wpa_supplicant1_proxy that is actually used by WiFi.
class SupplicantProcessProxyInterface {
 public:
  virtual ~SupplicantProcessProxyInterface() = default;
  virtual bool CreateInterface(const KeyValueStore& args,
                               RpcIdentifier* rpc_identifier) = 0;
  virtual bool GetInterface(const std::string& ifname,
                            RpcIdentifier* rpc_identifier) = 0;
  virtual bool RemoveInterface(const RpcIdentifier& rpc_identifier) = 0;
  virtual bool SetDebugLevel(const std::string& level) = 0;
  virtual bool GetDebugLevel(std::string* level) = 0;
  virtual bool ExpectDisconnect() = 0;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_PROCESS_PROXY_INTERFACE_H_
