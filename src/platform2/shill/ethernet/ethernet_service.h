// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_ETHERNET_SERVICE_H_
#define SHILL_ETHERNET_ETHERNET_SERVICE_H_

#include <string>
#include <utility>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/service.h"

namespace shill {

class Ethernet;
class Manager;

class EthernetService : public Service {
 public:
  static constexpr char kDefaultEthernetDeviceIdentifier[] = "ethernet_any";

  struct Properties {
   public:
    explicit Properties(const std::string& storage_id)
        : storage_id_(storage_id) {}
    explicit Properties(base::WeakPtr<Ethernet> ethernet)
        : ethernet_(ethernet) {}
    std::string storage_id_;
    base::WeakPtr<Ethernet> ethernet_;
  };

  EthernetService(Manager* manager, const Properties& props);
  ~EthernetService() override;

  // ethernet_<MAC>
  std::string GetStorageIdentifier() const override;
  bool IsAutoConnectByDefault() const override;
  bool SetAutoConnectFull(const bool& connect, Error* error) override;

  void Remove(Error* error) override;
  bool IsVisible() const override;
  TetheringState GetTethering() const override;
  bool IsAutoConnectable(const char** reason) const override;

  // Called by the Ethernet device when link state has caused the service
  // visibility to change.
  virtual void OnVisibilityChanged();

  bool HasEthernet() { return props_.ethernet_.get(); }
  void SetEthernet(base::WeakPtr<Ethernet> ethernet) {
    props_.ethernet_ = ethernet;
  }
  void ResetEthernet() { SetEthernet(nullptr); }
  bool HasStorageIdentifier() const { return !props_.storage_id_.empty(); }
  void SetStorageIdentifier(std::string storage_id) {
    props_.storage_id_ = std::move(storage_id);
  }
  void ResetStorageIdentifier() { props_.storage_id_ = std::string(); }

 protected:
  // This constructor performs none of the initialization that the normal
  // constructor does and sets the reported technology to |technology|.  It is
  // intended for use by subclasses which want to override specific aspects of
  // EthernetService behavior, while still retaining their own technology
  // identifier.
  EthernetService(Manager* manager,
                  Technology technology,
                  const Properties& props);
  EthernetService(const EthernetService&) = delete;
  EthernetService& operator=(const EthernetService&) = delete;

  // Inherited from Service.
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* error, const char* reason) override;

  void SetUp();

  Ethernet* ethernet() const { return props_.ethernet_.get(); }

 private:
  RpcIdentifier GetDeviceRpcId(Error* error) const override;

  Properties props_;
};

}  // namespace shill

#endif  // SHILL_ETHERNET_ETHERNET_SERVICE_H_
