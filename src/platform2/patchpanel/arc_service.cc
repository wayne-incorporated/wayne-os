// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/arc_service.h"

#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/system/sys_info.h>
#include <brillo/key_value_store.h>
#include <chromeos/constants/vm_tools.h>
#include <net-base/ipv4_address.h>

#include "patchpanel/adb_proxy.h"
#include "patchpanel/address_manager.h"
#include "patchpanel/datapath.h"
#include "patchpanel/mac_address_generator.h"
#include "patchpanel/metrics.h"
#include "patchpanel/minijailed_process_runner.h"
#include "patchpanel/net_util.h"
#include "patchpanel/patchpanel_daemon.h"
#include "patchpanel/scoped_ns.h"

namespace patchpanel {
namespace {
// UID of Android root, relative to the host pid namespace.
const int32_t kAndroidRootUid = 655360;
constexpr uint32_t kInvalidId = 0;
constexpr char kArcNetnsName[] = "arc_netns";
constexpr char kArcVmIfnamePrefix[] = "eth";

void RecordEvent(MetricsLibraryInterface* metrics, ArcServiceUmaEvent event) {
  metrics->SendEnumToUMA(kArcServiceUmaEventMetrics, event);
}

bool IsAdbAllowed(ShillClient::Device::Type type) {
  static const std::set<ShillClient::Device::Type> adb_allowed_types{
      ShillClient::Device::Type::kEthernet,
      ShillClient::Device::Type::kEthernetEap,
      ShillClient::Device::Type::kWifi,
  };
  return adb_allowed_types.find(type) != adb_allowed_types.end();
}

bool KernelVersion(int* major, int* minor) {
  struct utsname u;
  if (uname(&u) != 0) {
    PLOG(ERROR) << "uname failed";
    *major = *minor = 0;
    return false;
  }
  int unused;
  if (sscanf(u.release, "%d.%d.%d", major, minor, &unused) != 3) {
    LOG(ERROR) << "unexpected release string: " << u.release;
    *major = *minor = 0;
    return false;
  }
  return true;
}

// Makes Android root the owner of /sys/class/ + |path|. |pid| is the ARC
// container pid.
bool SetSysfsOwnerToAndroidRoot(pid_t pid, const std::string& path) {
  auto ns = ScopedNS::EnterMountNS(pid);
  if (!ns) {
    LOG(ERROR) << "Cannot enter mnt namespace for pid " << pid;
    return false;
  }

  const std::string sysfs_path = "/sys/class/" + path;
  if (chown(sysfs_path.c_str(), kAndroidRootUid, kAndroidRootUid) == -1) {
    PLOG(ERROR) << "Failed to change ownership of " + sysfs_path;
    return false;
  }

  return true;
}

bool OneTimeContainerSetup(Datapath& datapath, pid_t pid) {
  static bool done = false;
  if (done)
    return true;

  bool success = true;

  // Load networking modules needed by Android that are not compiled in the
  // kernel. Android does not allow auto-loading of kernel modules.
  // Expected for all kernels.
  if (!datapath.ModprobeAll({
          // The netfilter modules needed by netd for iptables commands.
          "ip6table_filter",
          "ip6t_ipv6header",
          "ip6t_REJECT",
          // The ipsec modules for AH and ESP encryption for ipv6.
          "ah6",
          "esp6",
      })) {
    LOG(ERROR) << "One or more required kernel modules failed to load."
               << " Some Android functionality may be broken.";
    success = false;
  }
  // The xfrm modules needed for Android's ipsec APIs on kernels < 5.4.
  int major, minor;
  if (KernelVersion(&major, &minor) &&
      (major < 5 || (major == 5 && minor < 4)) &&
      !datapath.ModprobeAll({
          "xfrm4_mode_transport",
          "xfrm4_mode_tunnel",
          "xfrm6_mode_transport",
          "xfrm6_mode_tunnel",
      })) {
    LOG(ERROR) << "One or more required kernel modules failed to load."
               << " Some Android functionality may be broken.";
    success = false;
  }

  // Additional modules optional for CTS compliance but required for some
  // Android features.
  if (!datapath.ModprobeAll({
          // This module is not available in kernels < 3.18
          "nf_reject_ipv6",
          // These modules are needed for supporting Chrome traffic on Android
          // VPN which uses Android's NAT feature. Android NAT sets up
          // iptables
          // rules that use these conntrack modules for FTP/TFTP.
          "nf_nat_ftp",
          "nf_nat_tftp",
          // The tun module is needed by the Android 464xlat clatd process.
          "tun",
      })) {
    LOG(WARNING) << "One or more optional kernel modules failed to load.";
    success = false;
  }

  // This is only needed for CTS (b/27932574).
  if (!SetSysfsOwnerToAndroidRoot(pid, "xt_idletimer")) {
    success = false;
  }

  done = true;
  return success;
}

// Creates the ARC management Device used for VPN forwarding, ADB-over-TCP.
std::unique_ptr<Device> MakeArc0Device(AddressManager* addr_mgr,
                                       ArcService::ArcType arc_type) {
  auto ipv4_subnet =
      addr_mgr->AllocateIPv4Subnet(AddressManager::GuestType::kArc0);
  if (!ipv4_subnet) {
    LOG(ERROR) << "Subnet already in use or unavailable";
    return nullptr;
  }

  auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
  if (!host_ipv4_addr) {
    LOG(ERROR) << "Bridge address already in use or unavailable";
    return nullptr;
  }

  auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
  if (!guest_ipv4_addr) {
    LOG(ERROR) << "ARC address already in use or unavailable";
    return nullptr;
  }

  uint32_t subnet_index =
      (arc_type == ArcService::ArcType::kVM) ? 1 : kAnySubnetIndex;
  auto config = std::make_unique<Device::Config>(
      addr_mgr->GenerateMacAddress(subnet_index), std::move(ipv4_subnet),
      std::move(host_ipv4_addr), std::move(guest_ipv4_addr));

  // The "arc0" virtual device is either attached on demand to host VPNs or is
  // used to forward host traffic into an Android VPN. Therefore, |shill_device|
  // is not meaningful for the "arc0" virtual device and is undefined.
  return std::make_unique<Device>(Device::Type::kARC0,
                                  /*shill_device=*/std::nullopt, kArcbr0Ifname,
                                  kArc0Ifname, std::move(config));
}
}  // namespace

ArcService::ArcService(Datapath* datapath,
                       AddressManager* addr_mgr,
                       ArcType arc_type,
                       MetricsLibraryInterface* metrics,
                       ArcDeviceChangeHandler arc_device_change_handler)
    : datapath_(datapath),
      addr_mgr_(addr_mgr),
      arc_type_(arc_type),
      metrics_(metrics),
      arc_device_change_handler_(arc_device_change_handler),
      id_(kInvalidId) {
  arc_device_ = MakeArc0Device(addr_mgr, arc_type_);
  AllocateAddressConfigs();
}

ArcService::~ArcService() {
  if (IsStarted()) {
    Stop(id_);
  }
}

bool ArcService::IsStarted() const {
  return id_ != kInvalidId;
}

void ArcService::AllocateAddressConfigs() {
  // The first usable subnet is the "other" ARC Device subnet.
  // As a temporary workaround, for ARCVM, allocate fixed MAC addresses.
  uint32_t mac_addr_index = 2;
  // Allocate 2 subnets each for Ethernet and WiFi and 1 for LTE WAN interfaces.
  for (const auto type :
       {ShillClient::Device::Type::kEthernet,
        ShillClient::Device::Type::kEthernet, ShillClient::Device::Type::kWifi,
        ShillClient::Device::Type::kWifi,
        ShillClient::Device::Type::kCellular}) {
    auto ipv4_subnet =
        addr_mgr_->AllocateIPv4Subnet(AddressManager::GuestType::kArcNet);
    if (!ipv4_subnet) {
      LOG(ERROR) << "Subnet already in use or unavailable";
      continue;
    }
    // For here out, use the same slices.
    auto host_ipv4_addr = ipv4_subnet->AllocateAtOffset(1);
    if (!host_ipv4_addr) {
      LOG(ERROR) << "Bridge address already in use or unavailable";
      continue;
    }
    auto guest_ipv4_addr = ipv4_subnet->AllocateAtOffset(2);
    if (!guest_ipv4_addr) {
      LOG(ERROR) << "ARC address already in use or unavailable";
      continue;
    }

    MacAddress mac_addr = (arc_type_ == ArcType::kVM)
                              ? addr_mgr_->GenerateMacAddress(mac_addr_index++)
                              : addr_mgr_->GenerateMacAddress();
    available_configs_[type].emplace_back(std::make_unique<Device::Config>(
        mac_addr, std::move(ipv4_subnet), std::move(host_ipv4_addr),
        std::move(guest_ipv4_addr)));
  }

  all_configs_.push_back(&arc_device_->config());
  // Iterate over |available_configs_| with a fixed explicit order and do not
  // rely on the implicit ordering derived from key values.
  for (const auto type :
       {ShillClient::Device::Type::kEthernet, ShillClient::Device::Type::kWifi,
        ShillClient::Device::Type::kCellular}) {
    for (const auto& c : available_configs_[type]) {
      all_configs_.push_back(c.get());
    }
  }
}

void ArcService::RefreshMacAddressesInConfigs() {
  arc_device_->config().set_mac_addr(addr_mgr_->GenerateMacAddress());
  for (const auto type :
       {ShillClient::Device::Type::kEthernet, ShillClient::Device::Type::kWifi,
        ShillClient::Device::Type::kCellular}) {
    for (auto& c : available_configs_[type]) {
      c->set_mac_addr(addr_mgr_->GenerateMacAddress());
    }
  }
}

std::unique_ptr<Device::Config> ArcService::AcquireConfig(
    ShillClient::Device::Type type) {
  // Normalize shill Device types for different ethernet flavors.
  if (type == ShillClient::Device::Type::kEthernetEap)
    type = ShillClient::Device::Type::kEthernet;

  auto it = available_configs_.find(type);
  if (it == available_configs_.end()) {
    LOG(ERROR) << "Unsupported shill Device type " << type;
    return nullptr;
  }

  if (it->second.empty()) {
    LOG(ERROR)
        << "Cannot make virtual Device: No more addresses available for type "
        << type;
    return nullptr;
  }

  std::unique_ptr<Device::Config> config;
  config = std::move(it->second.front());
  it->second.pop_front();
  return config;
}

void ArcService::ReleaseConfig(ShillClient::Device::Type type,
                               std::unique_ptr<Device::Config> config) {
  available_configs_[type].push_front(std::move(config));
}

bool ArcService::Start(uint32_t id) {
  RecordEvent(metrics_, ArcServiceUmaEvent::kStart);

  if (IsStarted()) {
    RecordEvent(metrics_, ArcServiceUmaEvent::kStartWithoutStop);
    LOG(WARNING) << "Already running - did something crash?"
                 << " Stopping and restarting...";
    Stop(id_);
  }

  std::string arc_device_ifname;
  if (arc_type_ == ArcType::kVM) {
    // Allocate TAP devices for all configs.
    int arcvm_ifname_id = 0;
    for (auto* config : all_configs_) {
      auto mac = config->mac_addr();
      // Tap device name is autogenerated. IPv4 is configured on the bridge.
      auto tap =
          datapath_->AddTAP(/*name=*/"", &mac,
                            /*ipv4_addr=*/nullptr, vm_tools::kCrosVmUser);
      if (tap.empty()) {
        LOG(ERROR) << "Failed to create TAP device";
        continue;
      }

      config->set_tap_ifname(tap);

      // Inside ARCVM, interface names follow the pattern eth%d (starting from
      // 0) following the order of the TAP interface.
      arcvm_guest_ifnames_[tap] =
          kArcVmIfnamePrefix + std::to_string(arcvm_ifname_id);
      arcvm_ifname_id++;
    }
    arc_device_ifname = arc_device_->config().tap_ifname();
  } else {
    pid_t pid = static_cast<int>(id);
    if (pid < 0) {
      LOG(ERROR) << "Invalid ARC container pid " << pid;
      return false;
    }
    if (!OneTimeContainerSetup(*datapath_, pid)) {
      RecordEvent(metrics_, ArcServiceUmaEvent::kOneTimeContainerSetupError);
      LOG(ERROR) << "One time container setup failed";
    }
    if (!datapath_->NetnsAttachName(kArcNetnsName, pid)) {
      LOG(ERROR) << "Failed to attach name " << kArcNetnsName << " to pid "
                 << pid;
      return false;
    }
    // b/208240700: Refresh MAC address in AddressConfigs every time ARC starts
    // to ensure ARC container has different MAC after optout and reopt-in.
    // TODO(b/185881882): this should be safe to remove after b/185881882.
    RefreshMacAddressesInConfigs();

    arc_device_ifname = ArcVethHostName(arc_device_->guest_ifname());
    const auto guest_cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
        arc_device_->config().guest_ipv4_addr(), 30);
    if (!datapath_->ConnectVethPair(
            pid, kArcNetnsName, arc_device_ifname, arc_device_->guest_ifname(),
            arc_device_->config().mac_addr(), guest_cidr,
            /*remote_multicast_flag=*/false)) {
      LOG(ERROR) << "Cannot create virtual link for " << kArc0Ifname;
      return false;
    }
    // Allow netd to write to /sys/class/net/arc0/mtu (b/175571457).
    if (!SetSysfsOwnerToAndroidRoot(
            pid, "net/" + arc_device_->guest_ifname() + "/mtu")) {
      RecordEvent(metrics_, ArcServiceUmaEvent::kSetVethMtuError);
    }
  }
  id_ = id;

  // CreateFromAddressAndPrefix() is valid because 30 is a valid prefix.
  const auto cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
      arc_device_->config().host_ipv4_addr(), 30);
  // Create the bridge for the management device arc0.
  if (!datapath_->AddBridge(kArcbr0Ifname, cidr)) {
    LOG(ERROR) << "Failed to setup bridge " << kArcbr0Ifname;
    return false;
  }

  if (!datapath_->AddToBridge(kArcbr0Ifname, arc_device_ifname)) {
    LOG(ERROR) << "Failed to bridge ARC Device " << arc_device_ifname << " to "
               << kArcbr0Ifname;
    return false;
  }
  LOG(INFO) << "Started ARC management Device " << *arc_device_.get();

  // Start already known shill <-> ARC mapped devices.
  for (const auto& [_, shill_device] : shill_devices_)
    AddDevice(shill_device);

  // Enable conntrack helpers needed for processing through SNAT the IPv4 GRE
  // packets sent by Android PPTP client (b/172214190).
  // TODO(b/252749921) Find alternative for chromeos-6.1+ kernels.
  if (!datapath_->SetConntrackHelpers(true)) {
    // Do not consider this error fatal for ARC datapath setup (b/252749921).
    LOG(ERROR) << "Failed to enable conntrack helpers";
  }

  RecordEvent(metrics_, ArcServiceUmaEvent::kStartSuccess);
  return true;
}

void ArcService::Stop(uint32_t id) {
  RecordEvent(metrics_, ArcServiceUmaEvent::kStop);
  if (!IsStarted()) {
    RecordEvent(metrics_, ArcServiceUmaEvent::kStopBeforeStart);
    LOG(ERROR) << "ArcService was not running";
    return;
  }

  // After the ARC container has stopped, the pid is not known anymore.
  // The stop message for ARCVM may be sent after a new VM is started. Only
  // stop if the CID matched the latest started ARCVM CID.
  if (arc_type_ == ArcType::kVM && id_ != id) {
    LOG(WARNING) << "Mismatched ARCVM CIDs " << id_ << " != " << id;
    return;
  }

  if (!datapath_->SetConntrackHelpers(false))
    LOG(ERROR) << "Failed to disable conntrack helpers";

  // Remove all ARC Devices associated with a shill Device.
  // Make a copy of |shill_devices_| to avoid invalidating any iterator over
  // |shill_devices_| while removing device from it and resetting it afterwards.
  auto shill_devices = shill_devices_;
  for (const auto& [_, shill_device] : shill_devices) {
    RemoveDevice(shill_device);
  }
  shill_devices_ = shill_devices;

  // Stop the bridge for the management interface arc0.
  if (arc_type_ == ArcType::kContainer) {
    datapath_->RemoveInterface(ArcVethHostName(kArc0Ifname));
    if (!datapath_->NetnsDeleteName(kArcNetnsName)) {
      LOG(WARNING) << "Failed to delete netns name " << kArcNetnsName;
    }
  }

  // Destroy allocated TAP devices if any, including the ARC management Device.
  for (auto* config : all_configs_) {
    if (config->tap_ifname().empty())
      continue;

    datapath_->RemoveInterface(config->tap_ifname());
    config->set_tap_ifname("");
  }
  arcvm_guest_ifnames_.clear();

  datapath_->RemoveBridge(kArcbr0Ifname);
  LOG(INFO) << "Stopped ARC management Device " << *arc_device_.get();
  id_ = kInvalidId;
  RecordEvent(metrics_, ArcServiceUmaEvent::kStopSuccess);
}

void ArcService::AddDevice(const ShillClient::Device& shill_device) {
  shill_devices_[shill_device.ifname] = shill_device;
  if (!IsStarted())
    return;

  if (shill_device.ifname.empty())
    return;

  RecordEvent(metrics_, ArcServiceUmaEvent::kAddDevice);

  if (devices_.find(shill_device.ifname) != devices_.end()) {
    LOG(DFATAL) << "Attemping to add already tracked shill Device "
                << shill_device;
    return;
  }

  auto config = AcquireConfig(shill_device.type);
  if (!config) {
    LOG(ERROR) << "Cannot acquire an ARC IPv4 config for shill Device "
               << shill_device;
    return;
  }

  // The interface name visible inside ARC depends on the type of ARC
  // environment:
  //  - ARC container: the veth interface created inside ARC has the same name
  //  as the physical interface that this ARC virtual device is attached to.
  //  - ARCVM: the interfaces created by virtio-net follow the pattern eth%d.
  auto guest_ifname = shill_device.ifname;
  if (arc_type_ == ArcType::kVM) {
    const auto it = arcvm_guest_ifnames_.find(config->tap_ifname());
    if (it == arcvm_guest_ifnames_.end()) {
      LOG(ERROR) << "Cannot acquire a ARCVM guest ifname for shill Device "
                 << shill_device;
    } else {
      guest_ifname = it->second;
    }
  }

  auto device_type = arc_type_ == ArcType::kVM ? Device::Type::kARCVM
                                               : Device::Type::kARCContainer;
  auto device = std::make_unique<Device>(device_type, shill_device,
                                         ArcBridgeName(shill_device.ifname),
                                         guest_ifname, std::move(config));
  LOG(INFO) << "Starting ARC Device " << *device;

  // CreateFromAddressAndPrefix() is valid because 30 is a valid prefix.
  const auto cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
      device->config().host_ipv4_addr(), 30);
  // Create the bridge.
  if (!datapath_->AddBridge(device->host_ifname(), cidr)) {
    LOG(ERROR) << "Failed to setup bridge " << device->host_ifname();
    return;
  }

  datapath_->StartRoutingDevice(shill_device, device->host_ifname(),
                                TrafficSource::kArc);
  datapath_->AddInboundIPv4DNAT(AutoDNATTarget::kArc, shill_device,
                                device->config().guest_ipv4_addr());

  std::string virtual_device_ifname;
  if (arc_type_ == ArcType::kVM) {
    virtual_device_ifname = device->config().tap_ifname();
    if (virtual_device_ifname.empty()) {
      LOG(ERROR) << "No TAP device for " << *device;
      return;
    }
  } else {
    pid_t pid = static_cast<int>(id_);
    if (pid < 0) {
      LOG(ERROR) << "Invalid ARC container pid " << pid;
      return;
    }
    virtual_device_ifname = ArcVethHostName(device->guest_ifname());

    const auto guest_cidr = *net_base::IPv4CIDR::CreateFromAddressAndPrefix(
        device->config().guest_ipv4_addr(), 30);
    if (!datapath_->ConnectVethPair(
            pid, kArcNetnsName, virtual_device_ifname, device->guest_ifname(),
            device->config().mac_addr(), guest_cidr,
            IsMulticastInterface(shill_device.ifname))) {
      LOG(ERROR) << "Cannot create veth link for device " << *device;
      return;
    }
    // Allow netd to write to /sys/class/net/<guest_ifname>/mtu (b/169936104).
    SetSysfsOwnerToAndroidRoot(pid, "net/" + device->guest_ifname() + "/mtu");
  }

  if (!datapath_->AddToBridge(device->host_ifname(), virtual_device_ifname)) {
    if (arc_type_ == ArcType::kContainer) {
      datapath_->RemoveInterface(virtual_device_ifname);
    }
    LOG(ERROR) << "Failed to bridge interface " << virtual_device_ifname;
    return;
  }

  if (IsAdbAllowed(shill_device.type) &&
      !datapath_->AddAdbPortAccessRule(shill_device.ifname)) {
    LOG(ERROR) << "Failed to add ADB port access rule";
  }

  arc_device_change_handler_.Run(shill_device, *device,
                                 Device::ChangeEvent::kAdded);
  devices_.emplace(shill_device.ifname, std::move(device));
  RecordEvent(metrics_, ArcServiceUmaEvent::kAddDeviceSuccess);
}

void ArcService::RemoveDevice(const ShillClient::Device& shill_device) {
  shill_devices_.erase(shill_device.ifname);
  if (!IsStarted())
    return;

  const auto it = devices_.find(shill_device.ifname);
  if (it == devices_.end()) {
    LOG(WARNING) << "Unknown shill Device " << shill_device;
    return;
  }

  const auto* device = it->second.get();
  LOG(INFO) << "Removing ARC Device " << *device;

  arc_device_change_handler_.Run(shill_device, *device,
                                 Device::ChangeEvent::kRemoved);

  // ARCVM TAP devices are removed in VmImpl::Stop() when the service stops
  if (arc_type_ == ArcType::kContainer)
    datapath_->RemoveInterface(ArcVethHostName(shill_device.ifname));

  datapath_->StopRoutingDevice(device->host_ifname());
  datapath_->RemoveInboundIPv4DNAT(AutoDNATTarget::kArc, shill_device,
                                   device->config().guest_ipv4_addr());
  datapath_->RemoveBridge(device->host_ifname());

  if (IsAdbAllowed(shill_device.type))
    datapath_->DeleteAdbPortAccessRule(shill_device.ifname);

  // Once the upstream shill Device is gone it may not be possible to retrieve
  // the Device type from shill DBus interface by interface name.
  ReleaseConfig(shill_device.type, it->second->release_config());
  devices_.erase(it);
}

void ArcService::UpdateDeviceIPConfig(const ShillClient::Device& shill_device) {
  auto shill_device_it = shill_devices_.find(shill_device.ifname);
  if (shill_device_it == shill_devices_.end()) {
    LOG(WARNING) << "Unknown shill Device " << shill_device;
    return;
  }
  shill_device_it->second = shill_device;

  auto arc_dev_it = devices_.find(shill_device.ifname);
  if (arc_dev_it == devices_.end()) {
    // If ARC is not running, ARC devices are not created.
    return;
  }

  auto new_device = std::make_unique<Device>(
      arc_dev_it->second->type(), shill_device,
      arc_dev_it->second->host_ifname(), arc_dev_it->second->guest_ifname(),
      arc_dev_it->second->release_config());
  arc_dev_it->second = std::move(new_device);
}

std::vector<const Device::Config*> ArcService::GetDeviceConfigs() const {
  std::vector<const Device::Config*> configs;
  for (auto* c : all_configs_)
    configs.emplace_back(c);

  return configs;
}

std::vector<const Device*> ArcService::GetDevices() const {
  std::vector<const Device*> devices;
  for (const auto& [_, dev] : devices_) {
    devices.push_back(dev.get());
  }
  return devices;
}

}  // namespace patchpanel
