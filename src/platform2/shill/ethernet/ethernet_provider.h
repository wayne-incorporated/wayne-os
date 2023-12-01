// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_ETHERNET_PROVIDER_H_
#define SHILL_ETHERNET_ETHERNET_PROVIDER_H_

#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>

#include "shill/ethernet/ethernet_service.h"
#include "shill/provider_interface.h"
#include "shill/refptr_types.h"

namespace shill {

class Error;
class Ethernet;
class KeyValueStore;
class Manager;

class EthernetProvider : public ProviderInterface {
 public:
  explicit EthernetProvider(Manager* manager);
  EthernetProvider(const EthernetProvider&) = delete;
  EthernetProvider& operator=(const EthernetProvider&) = delete;

  ~EthernetProvider() override;

  // Called by Manager as a part of the Provider interface.
  void CreateServicesFromProfile(const ProfileRefPtr& profile) override;
  ServiceRefPtr GetService(const KeyValueStore& args, Error* error) override;
  ServiceRefPtr FindSimilarService(const KeyValueStore& args,
                                   Error* error) const override;
  ServiceRefPtr CreateTemporaryService(const KeyValueStore& args,
                                       Error* error) override;
  ServiceRefPtr CreateTemporaryServiceFromProfile(const ProfileRefPtr& profile,
                                                  const std::string& entry_name,
                                                  Error* error) override;
  void Start() override;
  void Stop() override;

  virtual EthernetServiceRefPtr CreateService(base::WeakPtr<Ethernet> ethernet);
  bool LoadGenericEthernetService();
  virtual void RefreshGenericEthernetService();
  // |service| should be non-null in both Register- and DeregisterService.
  virtual void RegisterService(EthernetServiceRefPtr service);
  virtual void DeregisterService(EthernetServiceRefPtr service);

  virtual const EthernetServiceRefPtr& service() const { return service_; }

 private:
  friend class EthernetProviderTest;
  friend class ManagerTest;

  FRIEND_TEST(EthernetProviderTest, MultipleServices);

  EthernetServiceRefPtr FindEthernetServiceForService(
      ServiceRefPtr service) const;

  // Representative service
  EthernetServiceRefPtr service_;

  Manager* manager_;
  std::vector<EthernetServiceRefPtr> services_;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_ETHERNET_PROVIDER_H_
