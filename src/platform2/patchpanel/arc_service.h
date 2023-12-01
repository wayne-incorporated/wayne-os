// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_ARC_SERVICE_H_
#define PATCHPANEL_ARC_SERVICE_H_

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <metrics/metrics_library.h>

#include "patchpanel/address_manager.h"
#include "patchpanel/datapath.h"
#include "patchpanel/device.h"
#include "patchpanel/shill_client.h"

namespace patchpanel {

constexpr char kArcbr0Ifname[] = "arcbr0";
constexpr char kArc0Ifname[] = "arc0";

class ArcService {
 public:
  enum class ArcType {
    kContainer,
    kVM,
  };

  using ArcDeviceChangeHandler = base::RepeatingCallback<void(
      const ShillClient::Device&, const Device&, Device::ChangeEvent)>;

  // All pointers are required, cannot be null, and are owned by the caller.
  ArcService(Datapath* datapath,
             AddressManager* addr_mgr,
             ArcType arc_type,
             MetricsLibraryInterface* metrics,
             ArcDeviceChangeHandler arc_device_change_handler);
  ArcService(const ArcService&) = delete;
  ArcService& operator=(const ArcService&) = delete;

  ~ArcService();

  bool Start(uint32_t id);
  void Stop(uint32_t id);

  // Returns a list of ARC Device configurations. This method only really is
  // useful when ARCVM is running as it enables the caller to discover which
  // configurations, if any, are currently associated to TAP devices.
  std::vector<const Device::Config*> GetDeviceConfigs() const;

  // Returns a list of all patchpanel Devices currently managed by this service
  // and attached to a shill Device.
  std::vector<const Device*> GetDevices() const;

  // Returns true if the service has been started for ARC container or ARCVM.
  bool IsStarted() const;

  // Build and configure the ARC datapath for the upstream network interface
  // |ifname| managed by Shill.
  void AddDevice(const ShillClient::Device& shill_device);

  // Teardown the ARC datapath associated with the upstream network interface
  // |ifname|.
  void RemoveDevice(const ShillClient::Device& shill_device);

  // Notifies ArcService that the IP configuration of the physical shill Device
  // |shill_device| changed.
  void UpdateDeviceIPConfig(const ShillClient::Device& shill_device);

 private:
  // Creates ARC interface configurations for all available IPv4 subnets which
  // will be assigned to ARC Devices as they are added.
  void AllocateAddressConfigs();

  void RefreshMacAddressesInConfigs();

  // Reserve a configuration for an interface.
  std::unique_ptr<Device::Config> AcquireConfig(ShillClient::Device::Type type);

  // Returns a configuration to the pool.
  void ReleaseConfig(ShillClient::Device::Type type,
                     std::unique_ptr<Device::Config> config);

  FRIEND_TEST(ArcServiceTest, NotStarted_AddDevice);
  FRIEND_TEST(ArcServiceTest, NotStarted_AddRemoveDevice);
  FRIEND_TEST(ArcServiceTest, VmImpl_ArcvmInterfaceMapping);

  // Routing and iptables controller service, owned by Manager.
  Datapath* datapath_;
  // IPv4 prefix and address manager, owned by Manager.
  AddressManager* addr_mgr_;
  // Type of ARC environment.
  ArcType arc_type_;
  // UMA metrics client, owned by Manager.
  MetricsLibraryInterface* metrics_;
  // Manager callback used for notifying about ARC virtual device creation and
  // removal events.
  ArcDeviceChangeHandler arc_device_change_handler_;
  // A set of preallocated ARC interface configurations keyed by technology type
  // and used for setting up ARCVM TAP devices at VM booting time.
  std::map<ShillClient::Device::Type,
           std::deque<std::unique_ptr<Device::Config>>>
      available_configs_;
  // The list of all ARC interface configurations. Also includes the ARC
  // management interface arc0 for ARCVM.
  std::vector<Device::Config*> all_configs_;
  // The ARC Devices corresponding to the host upstream network interfaces,
  // keyed by upstream interface name.
  std::map<std::string, std::unique_ptr<Device>> devices_;
  // ARCVM hardcodes its interface name as eth%d (starting from 0). This is a
  // mapping of its TAP interface name to the interface name inside ARCVM.
  std::map<std::string, std::string> arcvm_guest_ifnames_;
  // The ARC management Device associated with the ARC management interface arc0
  // used for legacy adb-over-tcp support and VPN forwarding.
  std::unique_ptr<Device> arc_device_;
  // The PID of the ARC container instance or the CID of ARCVM instance.
  uint32_t id_;
  // All shill Devices currently managed by shill, keyed by host interface name.
  std::map<std::string, ShillClient::Device> shill_devices_;

  base::WeakPtrFactory<ArcService> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_ARC_SERVICE_H_
