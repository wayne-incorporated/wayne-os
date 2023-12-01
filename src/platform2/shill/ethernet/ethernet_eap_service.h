// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_ETHERNET_EAP_SERVICE_H_
#define SHILL_ETHERNET_ETHERNET_EAP_SERVICE_H_

#include <string>

#include "shill/service.h"

namespace shill {

// The EthernetEapService contains configuraton for any Ethernet interface
// while authenticating or authenticated to a wired 802.1x endpoint.  This
// includes EAP credentials and Static IP configuration.  This service in
// itself is not connectable, but can be used by any Ethernet device during
// authentication.
class EthernetEapService : public Service {
 public:
  explicit EthernetEapService(Manager* manager);
  ~EthernetEapService() override;

  // Inherited from Service.
  RpcIdentifier GetDeviceRpcId(Error* error) const override;
  std::string GetStorageIdentifier() const override;
  bool Is8021x() const override { return true; }
  bool IsVisible() const override { return false; }
  void OnEapCredentialsChanged(
      Service::UpdateCredentialsReason reason) override;
  bool Unload() override;

 protected:
  // Inherited from Service.
  void OnConnect(Error* /*error*/) override {}
  void OnDisconnect(Error* /*error*/, const char* /*reason*/) override {}
};

}  // namespace shill

#endif  // SHILL_ETHERNET_ETHERNET_EAP_SERVICE_H_
