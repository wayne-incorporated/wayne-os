// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_VPN_SERVICE_H_
#define SHILL_VPN_VPN_SERVICE_H_

#include <memory>
#include <string>

#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/callbacks.h"
#include "shill/default_service_observer.h"
#include "shill/service.h"
#include "shill/vpn/vpn_driver.h"

namespace shill {

class KeyValueStore;
class VPNService : public Service,
                   public DefaultServiceObserver,
                   public VPNDriver::EventHandler {
 public:
  VPNService(Manager* manager, std::unique_ptr<VPNDriver> driver);
  VPNService(const VPNService&) = delete;
  VPNService& operator=(const VPNService&) = delete;

  ~VPNService() override;

  // Inherited from Service.
  std::string GetStorageIdentifier() const override;
  bool Load(const StoreInterface* storage) override;
  void MigrateDeprecatedStorage(StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;
  bool Unload() override;
  void EnableAndRetainAutoConnect() override;
  TetheringState GetTethering() const override;
  bool SetNameProperty(const std::string& name, Error* error) override;
  VirtualDeviceRefPtr GetVirtualDevice() const override;

  // Power management events.
  void OnBeforeSuspend(ResultCallback callback) override;
  void OnAfterResume() override;

  // Inherited from DefaultServiceObserver.
  void OnDefaultLogicalServiceChanged(
      const ServiceRefPtr& logical_service) override;
  void OnDefaultPhysicalServiceChanged(
      const ServiceRefPtr& physical_service) override;

  virtual void InitDriverPropertyStore();

  VPNDriver* driver() const { return driver_.get(); }

  static std::string CreateStorageIdentifier(const KeyValueStore& args,
                                             Error* error);
  void set_storage_id(const std::string& id) { storage_id_ = id; }

  // Returns the type name of the underlying physical service.
  std::string GetPhysicalTechnologyProperty(Error* error);

  // Returns true if the service supports always-on VPN.
  bool SupportsAlwaysOnVpn();

  // Inherited from VPNDriver::EventHandler. Callbacks from VPNDriver.
  void OnDriverConnected(const std::string& if_name, int if_index) override;
  void OnDriverFailure(ConnectFailure failure,
                       base::StringPiece error_details) override;
  void OnDriverReconnecting(base::TimeDelta timeout) override;

  const NetworkConfig& static_network_config_for_testing() {
    return mutable_static_ip_parameters()->config();
  }

 protected:
  // Inherited from Service.
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* error, const char* reason) override;
  bool IsAutoConnectable(const char** reason) const override;

 private:
  friend class VPNServiceTest;
  FRIEND_TEST(ManagerTest, FindDeviceFromService);
  FRIEND_TEST(VPNServiceTest, GetDeviceRpcId);
  FRIEND_TEST(VPNServiceTest, GetPhysicalTechnologyPropertyFailsIfNoCarrier);
  FRIEND_TEST(VPNServiceTest, GetPhysicalTechnologyPropertyOverWifi);
  FRIEND_TEST(VPNServiceTest, ConfigureDeviceAndCleanupDevice);
  FRIEND_TEST(VPNServiceTest, ReportIPTypeMetrics);
  FRIEND_TEST(VPNServiceTest, ConnectFlow);

  static const char kAutoConnNeverConnected[];
  static const char kAutoConnVPNAlreadyActive[];

  RpcIdentifier GetDeviceRpcId(Error* error) const override;

  // Create a VPN VirtualDevice as device_.
  bool CreateDevice(const std::string& if_name, int if_index);
  void ConfigureDevice(std::unique_ptr<IPConfig::Properties> ipv4_props,
                       std::unique_ptr<IPConfig::Properties> ipv6_props);
  void CleanupDevice();

  // Initializes a callback that will invoke OnDriverConnectTimeout() after
  // |timeout|. The timeout will be restarted if it's already scheduled. If
  // kTimeoutNone is passed in, only cancels the current timeout, if any.
  void StartDriverConnectTimeout(base::TimeDelta timeout);
  // Cancels the connect timeout callback, if any, previously scheduled through
  // StartConnectTimeout.
  void StopDriverConnectTimeout();
  // Called if a connect timeout scheduled through StartConnectTimeout
  // fires. Cancels the timeout callback.
  void OnDriverConnectTimeout();

  std::string storage_id_;
  std::unique_ptr<VPNDriver> driver_;
  VirtualDeviceRefPtr device_;

  // Indicates whether the default physical service state, which is known from
  // Manager, is online. Helps distinguish between a network->network transition
  // (where the client simply reconnects), and a network->link_down->network
  // transition (where the client should disconnect, wait for link up, then
  // reconnect). Uses true as the default value before we get the first
  // notification from Manager, this is safe because the default physical
  // service must be online before we connect to any VPN service.
  bool last_default_physical_service_online_;
  // The current default physical service known from Manager.
  std::string last_default_physical_service_path_;

  base::CancelableOnceClosure driver_connect_timeout_callback_;

  base::WeakPtrFactory<VPNService> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_VPN_SERVICE_H_
