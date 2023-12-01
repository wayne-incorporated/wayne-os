// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/crostini_service.h"

#include <memory>
#include <optional>
#include <ostream>
#include <utility>

#include "base/task/single_thread_task_runner.h"
#include <base/check.h>
#include <base/logging.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
// Ignore Wconversion warnings in dbus headers.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#pragma GCC diagnostic pop

#include "patchpanel/adb_proxy.h"
#include "patchpanel/address_manager.h"
#include "patchpanel/device.h"
#include "patchpanel/ipc.h"
#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {
constexpr int32_t kInvalidID = 0;
constexpr int kDbusTimeoutMs = 200;
// The maximum number of ADB sideloading query failures before stopping.
constexpr int kAdbSideloadMaxTry = 5;
constexpr base::TimeDelta kAdbSideloadUpdateDelay = base::Milliseconds(5000);

std::ostream& operator<<(
    std::ostream& stream,
    const std::pair<uint64_t, CrostiniService::VMType>& vm_info) {
  return stream << "{id: " << vm_info.first << ", vm_type: " << vm_info.second
                << "}";
}

std::optional<AutoDNATTarget> GetAutoDNATTarget(Device::Type guest_type) {
  switch (guest_type) {
    case Device::Type::kTerminaVM:
      return AutoDNATTarget::kCrostini;
    case Device::Type::kParallelsVM:
      return AutoDNATTarget::kParallels;
    default:
      return std::nullopt;
  }
}
}  // namespace

CrostiniService::CrostiniService(
    AddressManager* addr_mgr,
    Datapath* datapath,
    Device::ChangeEventHandler device_changed_handler)
    : addr_mgr_(addr_mgr),
      datapath_(datapath),
      device_changed_handler_(device_changed_handler),
      adb_sideloading_enabled_(false) {
  DCHECK(addr_mgr_);
  DCHECK(datapath_);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  bus_ = new dbus::Bus(options);
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
  } else {
    CheckAdbSideloadingStatus();
  }
}

CrostiniService::~CrostiniService() {
  if (bus_)
    bus_->ShutdownAndBlock();
}

const Device* CrostiniService::Start(uint64_t vm_id,
                                     CrostiniService::VMType vm_type,
                                     uint32_t subnet_index) {
  const auto vm_info = std::make_pair(vm_id, vm_type);
  if (vm_id == kInvalidID) {
    LOG(ERROR) << __func__ << " " << vm_info << ": Invalid VM id";
    return nullptr;
  }

  if (taps_.find(vm_id) != taps_.end()) {
    LOG(WARNING) << __func__ << " " << vm_info << ": Datapath already started";
    return nullptr;
  }

  auto tap = AddTAP(vm_type, subnet_index);
  if (!tap) {
    LOG(ERROR) << __func__ << " " << vm_info << ": Failed to create TAP device";
    return nullptr;
  }

  datapath_->StartRoutingDeviceAsUser(tap->host_ifname(),
                                      tap->config().host_ipv4_addr(),
                                      TrafficSourceFromVMType(vm_type));
  if (adb_sideloading_enabled_) {
    StartAdbPortForwarding(tap->host_ifname());
  }
  if (vm_type == VMType::kParallels) {
    StartAutoDNAT(tap.get());
  }

  LOG(INFO) << __func__ << " " << vm_info
            << ": Crostini network service started on " << tap->host_ifname();
  device_changed_handler_.Run(*tap, Device::ChangeEvent::kAdded);
  auto [it, _] = taps_.emplace(vm_id, std::move(tap));
  return it->second.get();
}

void CrostiniService::Stop(uint64_t vm_id) {
  const auto it = taps_.find(vm_id);
  if (it == taps_.end()) {
    LOG(WARNING) << __func__ << " {id: " << vm_id << "}: Unknown VM";
    return;
  }

  auto vm_type = VMTypeFromDeviceType(it->second->type());
  if (!vm_type) {
    LOG(ERROR) << "Unexpected Device type " << it->second->type()
               << " for TAP Device of VM " << vm_id;
    return;
  }
  const auto vm_info = std::make_pair(vm_id, *vm_type);

  device_changed_handler_.Run(*it->second, Device::ChangeEvent::kRemoved);
  const std::string tap_ifname = it->second->host_ifname();
  datapath_->StopRoutingDevice(tap_ifname);
  if (adb_sideloading_enabled_) {
    StopAdbPortForwarding(tap_ifname);
  }
  if (vm_type == VMType::kParallels) {
    StopAutoDNAT(it->second.get());
  }
  datapath_->RemoveInterface(tap_ifname);
  taps_.erase(vm_id);

  LOG(INFO) << __func__ << " " << vm_info
            << ": Crostini network service stopped on " << tap_ifname;
}

const Device* const CrostiniService::GetDevice(uint64_t vm_id) const {
  const auto it = taps_.find(vm_id);
  if (it == taps_.end()) {
    return nullptr;
  }
  return it->second.get();
}

std::vector<const Device*> CrostiniService::GetDevices() const {
  std::vector<const Device*> devices;
  for (const auto& [_, dev] : taps_) {
    devices.push_back(dev.get());
  }
  return devices;
}

std::unique_ptr<Device> CrostiniService::AddTAP(CrostiniService::VMType vm_type,
                                                uint32_t subnet_index) {
  auto guest_type = GuestTypeFromVMType(vm_type);
  auto ipv4_subnet = addr_mgr_->AllocateIPv4Subnet(guest_type, subnet_index);
  if (!ipv4_subnet) {
    LOG(ERROR) << "Subnet already in use or unavailable.";
    return nullptr;
  }
  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  if (!host_ipv4_addr) {
    LOG(ERROR) << "Host address already in use or unavailable.";
    return nullptr;
  }
  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  if (!guest_ipv4_addr) {
    LOG(ERROR) << "VM address already in use or unavailable.";
    return nullptr;
  }
  std::unique_ptr<Subnet> lxd_subnet;
  if (vm_type == VMType::kTermina) {
    lxd_subnet =
        addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kLXDContainer);
    if (!lxd_subnet) {
      LOG(ERROR) << "lxd subnet already in use or unavailable.";
      return nullptr;
    }
  }

  const auto mac_addr = addr_mgr_->GenerateMacAddress(subnet_index);
  // Name is autogenerated.
  const std::string tap = datapath_->AddTAP(
      /*name=*/"", &mac_addr, &(host_ipv4_addr->cidr()), vm_tools::kCrosVmUser);
  if (tap.empty()) {
    LOG(ERROR) << "Failed to create TAP device.";
    return nullptr;
  }

  if (lxd_subnet) {
    // Setup lxd route for the container using the VM as a gateway.
    const auto gateway_cidr = ipv4_subnet->CIDRAtOffset(2);
    const auto lxd_subnet_cidr = lxd_subnet->CIDRAtOffset(1);
    if (!gateway_cidr || !lxd_subnet_cidr) {
      LOG(ERROR) << "Failed to get CIDR from Subnet, ipv4_subnet="
                 << ipv4_subnet->base_cidr()
                 << ", lxd_subnet=" << lxd_subnet->base_cidr();
      return nullptr;
    }
    if (!datapath_->AddIPv4Route(gateway_cidr->address(), *lxd_subnet_cidr)) {
      LOG(ERROR) << "Failed to setup lxd route";
      return nullptr;
    }
  }

  auto config = std::make_unique<Device::Config>(
      mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
      std::move(guest_ipv4_addr), std::move(lxd_subnet));

  // The crosvm virtual devices used for non ARC guests are isolated TAP
  // devices without any bridge setup. They are not associated to any specific
  // physical network and instead follows the current default logical network,
  // therefore |phys_ifname| is undefined. |guest_ifname| is
  // not used inside the crosvm guest and is left empty.
  return std::make_unique<Device>(VirtualDeviceTypeFromVMType(vm_type),
                                  /*shill_device=*/std::nullopt, tap,
                                  /*guest_ifname=*/"", std::move(config));
}

void CrostiniService::StartAdbPortForwarding(const std::string& ifname) {
  if (!datapath_->AddAdbPortForwardRule(ifname)) {
    LOG(ERROR) << __func__ << ": Error adding ADB port forwarding rule for "
               << ifname;
    return;
  }

  if (!datapath_->AddAdbPortAccessRule(ifname)) {
    datapath_->DeleteAdbPortForwardRule(ifname);
    LOG(ERROR) << __func__ << ": Error adding ADB port access rule for "
               << ifname;
    return;
  }

  if (!datapath_->SetRouteLocalnet(ifname, true)) {
    LOG(ERROR) << __func__ << ": Failed to set up route localnet for "
               << ifname;
    return;
  }
}

void CrostiniService::StopAdbPortForwarding(const std::string& ifname) {
  datapath_->DeleteAdbPortForwardRule(ifname);
  datapath_->DeleteAdbPortAccessRule(ifname);
  datapath_->SetRouteLocalnet(ifname, false);
}

void CrostiniService::CheckAdbSideloadingStatus() {
  static int num_try = 0;
  if (num_try >= kAdbSideloadMaxTry) {
    LOG(WARNING) << __func__
                 << ": Failed getting feature enablement status after "
                 << num_try << " tries.";
    return;
  }

  dbus::ObjectProxy* proxy = bus_->GetObjectProxy(
      login_manager::kSessionManagerServiceName,
      dbus::ObjectPath(login_manager::kSessionManagerServicePath));
  dbus::MethodCall method_call(login_manager::kSessionManagerInterface,
                               login_manager::kSessionManagerQueryAdbSideload);
  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDbusTimeoutMs);

  if (!dbus_response) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&CrostiniService::CheckAdbSideloadingStatus,
                       weak_factory_.GetWeakPtr()),
        kAdbSideloadUpdateDelay);
    num_try++;
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  reader.PopBool(&adb_sideloading_enabled_);
  if (!adb_sideloading_enabled_)
    return;

  // If ADB sideloading is enabled, start ADB forwarding on all configured
  // Crostini's TAP interfaces.
  for (const auto& tap : taps_) {
    StartAdbPortForwarding(tap.second->host_ifname());
  }
}

void CrostiniService::OnShillDefaultLogicalDeviceChanged(
    const ShillClient::Device& new_device,
    const ShillClient::Device& prev_device) {
  // b/197930417: Update Auto DNAT rules if a Parallels VM is running.
  const Device* parallels_device = nullptr;
  for (const auto& [_, dev] : taps_) {
    if (dev->type() == Device::Type::kParallelsVM) {
      parallels_device = dev.get();
      break;
    }
  }

  if (parallels_device) {
    StopAutoDNAT(parallels_device);
  }
  if (new_device.ifname.empty()) {
    default_logical_device_ = std::nullopt;
  } else {
    default_logical_device_ = new_device;
  }
  if (parallels_device) {
    StartAutoDNAT(parallels_device);
  }
}

void CrostiniService::StartAutoDNAT(const Device* virtual_device) {
  if (!default_logical_device_) {
    return;
  }
  const auto target = GetAutoDNATTarget(virtual_device->type());
  if (!target) {
    LOG(ERROR) << __func__ << ": unexpected Device " << *virtual_device;
    return;
  }
  datapath_->AddInboundIPv4DNAT(*target, *default_logical_device_,
                                virtual_device->config().guest_ipv4_addr());
}

void CrostiniService::StopAutoDNAT(const Device* virtual_device) {
  if (!default_logical_device_) {
    return;
  }
  const auto target = GetAutoDNATTarget(virtual_device->type());
  if (!target) {
    LOG(ERROR) << __func__ << ": unexpected Device " << *virtual_device;
    return;
  }
  datapath_->RemoveInboundIPv4DNAT(*target, *default_logical_device_,
                                   virtual_device->config().guest_ipv4_addr());
}

// static
std::optional<CrostiniService::VMType> CrostiniService::VMTypeFromDeviceType(
    Device::Type device_type) {
  switch (device_type) {
    case Device::Type::kTerminaVM:
      return VMType::kTermina;
    case Device::Type::kParallelsVM:
      return VMType::kParallels;
    default:
      return std::nullopt;
  }
}

// static
std::optional<CrostiniService::VMType>
CrostiniService::VMTypeFromProtoGuestType(NetworkDevice::GuestType guest_type) {
  switch (guest_type) {
    case NetworkDevice::TERMINA_VM:
      return VMType::kTermina;
    case NetworkDevice::PARALLELS_VM:
      return VMType::kParallels;
    default:
      return std::nullopt;
  }
}

// static
TrafficSource CrostiniService::TrafficSourceFromVMType(
    CrostiniService::VMType vm_type) {
  switch (vm_type) {
    case VMType::kTermina:
      return TrafficSource::kCrosVM;
    case VMType::kParallels:
      return TrafficSource::kParallelsVM;
  }
}

// static
GuestMessage::GuestType CrostiniService::GuestMessageTypeFromVMType(
    CrostiniService::VMType vm_type) {
  switch (vm_type) {
    case VMType::kTermina:
      return GuestMessage::TERMINA_VM;
    case VMType::kParallels:
      return GuestMessage::PARALLELS_VM;
  }
}

// static
AddressManager::GuestType CrostiniService::GuestTypeFromVMType(
    CrostiniService::VMType vm_type) {
  switch (vm_type) {
    case VMType::kTermina:
      return AddressManager::GuestType::kTerminaVM;
    case VMType::kParallels:
      return AddressManager::GuestType::kParallelsVM;
  }
}

// static
Device::Type CrostiniService::VirtualDeviceTypeFromVMType(
    CrostiniService::VMType vm_type) {
  switch (vm_type) {
    case VMType::kTermina:
      return Device::Type::kTerminaVM;
    case VMType::kParallels:
      return Device::Type::kParallelsVM;
  }
}

std::ostream& operator<<(std::ostream& stream,
                         const CrostiniService::VMType vm_type) {
  switch (vm_type) {
    case CrostiniService::VMType::kTermina:
      return stream << "Termina";
    case CrostiniService::VMType::kParallels:
      return stream << "Parallels";
  }
}

}  // namespace patchpanel
