// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_ETHERNET_TEMPORARY_SERVICE_H_
#define SHILL_ETHERNET_ETHERNET_TEMPORARY_SERVICE_H_

#include <string>

#include "shill/service.h"

namespace shill {

class Manager;

// This is only use for loading non-active Ethernet service entries from the
// profile.
class EthernetTemporaryService : public Service {
 public:
  EthernetTemporaryService(Manager* manager,
                           const std::string& storage_identifier);
  EthernetTemporaryService(const EthernetTemporaryService&) = delete;
  EthernetTemporaryService& operator=(const EthernetTemporaryService&) = delete;

  ~EthernetTemporaryService() override;

  // Inherited from Service.
  RpcIdentifier GetDeviceRpcId(Error* error) const override;
  std::string GetStorageIdentifier() const override;
  bool IsVisible() const override;

 protected:
  // Inherited from Service.
  void OnConnect(Error* /*error*/) override {}
  void OnDisconnect(Error* /*error*/, const char* /*reason*/) override {}

 private:
  std::string storage_identifier_;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_ETHERNET_TEMPORARY_SERVICE_H_
