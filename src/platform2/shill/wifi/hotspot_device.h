// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_HOTSPOT_DEVICE_H_
#define SHILL_WIFI_HOTSPOT_DEVICE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>

#include "shill/mockable.h"
#include "shill/store/key_value_store.h"
#include "shill/supplicant/supplicant_event_delegate_interface.h"
#include "shill/wifi/hotspot_service.h"
#include "shill/wifi/local_device.h"

namespace shill {

class SupplicantInterfaceProxyInterface;

class HotspotDevice : public LocalDevice,
                      public SupplicantEventDelegateInterface {
 public:
  // Constructor function
  HotspotDevice(Manager* manager,
                const std::string& primary_link_name,
                const std::string& link_name,
                const std::string& mac_address,
                uint32_t phy_index,
                LocalDevice::EventCallback callback);

  HotspotDevice(const HotspotDevice&) = delete;
  HotspotDevice& operator=(const HotspotDevice&) = delete;

  ~HotspotDevice() override;

  // HotspotDevice start routine. Like connect to wpa_supplicant, register
  // netlink events, clean up any wpa_supplicant networks, etc. Return true if
  // interface is started successfully. Return false if error happens.
  bool Start() override;

  // HotspotDevice stop routine. Like clean up wpa_supplicant networks,
  // disconnect to wpa_supplicant, deregister netlink events, etc. Return true
  // if interface is stopped. Return false if fail to remove the wlan interface
  // but other resources have been cleaned up.
  bool Stop() override;

  // Return the configured service on this device.
  LocalService* GetService() const override { return service_.get(); }

  // Configure and select HotspotService |service|.
  mockable bool ConfigureService(std::unique_ptr<HotspotService> service);

  // Disconnect from and remove HotspotService.
  mockable bool DeconfigureService();

  // Get the MAC addresses of the connected stations to this hotspot device.
  mockable std::vector<std::vector<uint8_t>> GetStations();

  // Implementation of SupplicantEventDelegateInterface.  These methods
  // are called by SupplicantInterfaceProxy, in response to events from
  // wpa_supplicant.
  void PropertiesChanged(const KeyValueStore& properties) override;
  void BSSAdded(const RpcIdentifier& BSS,
                const KeyValueStore& properties) override{};
  void BSSRemoved(const RpcIdentifier& BSS) override{};
  void Certification(const KeyValueStore& properties) override{};
  void EAPEvent(const std::string& status,
                const std::string& parameter) override{};
  void InterworkingAPAdded(const RpcIdentifier& BSS,
                           const RpcIdentifier& cred,
                           const KeyValueStore& properties) override{};
  void InterworkingSelectDone() override{};
  void ScanDone(const bool& success) override{};
  void StationAdded(const RpcIdentifier& Station,
                    const KeyValueStore& properties) override;
  void StationRemoved(const RpcIdentifier& Station) override;
  void PskMismatch() override{};

 private:
  friend class HotspotDeviceTest;
  FRIEND_TEST(HotspotDeviceTest, InterfaceDisabledEvent);
  FRIEND_TEST(HotspotDeviceTest, ServiceEvent);

  // Create an AP interface and connect to the wpa_supplicant interface proxy.
  bool CreateInterface();
  // Remove the AP interface and disconnect from the wpa_supplicant interface
  // proxy.
  bool RemoveInterface();
  void PropertiesChangedTask(const KeyValueStore& properties);
  void StateChanged(const std::string& new_state);

  // Primary interface link name.
  std::string primary_link_name_;
  // wpa_supplicant's RPC path for the primary interface.
  RpcIdentifier supplicant_primary_interface_path_;
  // If the primary interface was controlled by wpa_supplicant before starting a
  // virtual interface.
  bool prev_primary_iface_control_state_;

  std::unique_ptr<SupplicantInterfaceProxyInterface>
      supplicant_interface_proxy_;
  // wpa_supplicant's RPC path for this device/interface.
  RpcIdentifier supplicant_interface_path_;
  // wpa_supplicant's RPC path for the supplicant network. It is associated with
  // this local device subclass.
  RpcIdentifier supplicant_network_path_;
  // Hotspot service configured on this device.
  std::unique_ptr<HotspotService> service_;
  // wpa_supplicant's RPC paths and properties for the connected stations.
  std::map<RpcIdentifier, KeyValueStore> stations_;
  std::string supplicant_state_;
  base::WeakPtrFactory<HotspotDevice> weak_ptr_factory_{this};
};

}  // namespace shill

#endif  // SHILL_WIFI_HOTSPOT_DEVICE_H_
