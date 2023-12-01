// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device_info.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/userdb_utils.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <re2/re2.h>

#include "shill/cellular/modem_info.h"
#include "shill/device.h"
#include "shill/ethernet/ethernet.h"
#include "shill/ethernet/virtio_ethernet.h"
#include "shill/logging.h"
#include "shill/manager.h"
#include "shill/metrics.h"
#include "shill/net/netlink_manager.h"
#include "shill/net/nl80211_message.h"
#include "shill/net/rtnl_handler.h"
#include "shill/net/rtnl_link_stats.h"
#include "shill/net/rtnl_listener.h"
#include "shill/net/rtnl_message.h"
#include "shill/net/shill_time.h"
#include "shill/network/network.h"
#include "shill/power_manager.h"
#include "shill/routing_table.h"
#include "shill/vpn/vpn_provider.h"
#include "shill/wifi/wake_on_wifi.h"
#include "shill/wifi/wifi.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDevice;
}  // namespace Logging

namespace {

// Device name prefix for modem pseudo devices used in testing.
constexpr char kModemPseudoDeviceNamePrefix[] = "pseudomodem";

// Device name prefix for virtual ethernet devices used in testing.
constexpr char kEthernetPseudoDeviceNamePrefix[] = "pseudoethernet";

// Root of the kernel sysfs directory holding network device info.
constexpr char kDeviceInfoRoot[] = "/sys/class/net";

// Name of the "cdc_ether" driver.  This driver is not included in the
// kModemDrivers list because we need to do additional checking.
constexpr char kDriverCdcEther[] = "cdc_ether";

// Name of the "cdc_ncm" driver.  This driver is not included in the
// kModemDrivers list because we need to do additional checking.
constexpr char kDriverCdcNcm[] = "cdc_ncm";

// Name of the virtio network driver.
constexpr char kDriverVirtioNet[] = "virtio_net";

// Sysfs path to a device uevent file.
constexpr char kInterfaceUevent[] = "uevent";

// Content of a device uevent file that indicates it is a bridge device.
constexpr char kInterfaceUeventBridgeSignature[] = "DEVTYPE=bridge\n";

// Content of a device uevent file that indicates it is a WiFi device.
constexpr char kInterfaceUeventWifiSignature[] = "DEVTYPE=wlan\n";

// Content of a device uevent file that indicates it is a VLAN device.
constexpr char kInterfaceUeventVlanSignature[] = "DEVTYPE=vlan\n";

// Sysfs path to a device via its interface name.
constexpr char kInterfaceDevice[] = "device";

// Sysfs path to the driver of a device via its interface name.
constexpr char kInterfaceDriver[] = "device/driver";

// Sysfs path to the driver of an FM350 device via its interface name. This is
// a temporary fix until the mtkt7xx driver exposes the driver symlink at the
// same "device/driver" endpoint as expected (b/225373673)
constexpr char kInterfaceDriverMtkt7xx[] = "device/device/driver";

// Sysfs path prefix to the lower device of a virtual VLAN device. E.g. for a
// multiplexed "mbimmux1.1" device the lower device reference may be a link
// named "lower_wwan0" pointing to the sysfs path of the "wwan0" device.
constexpr char kInterfaceLowerPrefix[] = "lower_";

// Sysfs path to the vendor ID file via its interface name.
constexpr char kInterfaceVendorId[] = "device/vendor";

// Sysfs path to the device ID file via its interface name.
constexpr char kInterfaceDeviceId[] = "device/device";

// Sysfs path to the subsystem ID file via its interface name.
constexpr char kInterfaceSubsystemId[] = "device/subsystem_device";

// Sysfs path to the device uevent file that contains the characteristics of
// integrated WiFi adapters.
constexpr char kInterfaceIntegratedId[] = "device/uevent";

// Sysfs path to the file that is used to determine the owner of the interface.
constexpr char kInterfaceOwner[] = "owner";

// Sysfs path to the file that is used to determine if this is tun device.
constexpr char kInterfaceTunFlags[] = "tun_flags";

// Sysfs path to the file that is used to determine if a wifi device is
// operating in monitor mode.
constexpr char kInterfaceType[] = "type";

// Device name prefixes for virtual devices that should be ignored.
// TODO(chromium:899004): Using network device name is a bit fragile. Find
// other signals to identify these network devices.
const char* const kIgnoredDeviceNamePrefixes[] = {
    // TODO(garrick): Workaround for (chromium:917923): 'arc_' is the prefix
    // used for all ARC++ multinet bridge interface. These should be ignored
    // for now.
    "arc_",
    "veth",
};

// As of Linux v5.4, these "kinds" are not part of a UAPI header definition, so
// we open-code them here, with some reference to where and when we found them
// in the Linux kernel tree (version numbers are just a snapshot in time, not
// necessarily when they were first supported). These strings are also usually
// annotated in the kernel source tree via MODULE_ALIAS_RTNL_LINK() macros.
const char* const kIgnoredDeviceKinds[] = {
    "ifb",  // v5.4, drivers/net/ifb.c:289
};
// v5.4, drivers/net/veth.c:1393
constexpr char kKindVeth[] = "veth";
// v5.4, drivers/net/ethernet/qualcomm/rmnet/rmnet_config.c:369
constexpr char kKindRmnet[] = "rmnet";
// v5.10, drivers/net/wireguard/device.c:254, |device_type.name| is set to
// KBUILD_MODNAME, which is "wireguard".
constexpr char kKindWireGuard[] = "wireguard";
// v4.19+, net/xfrm/xfrm_interface.c
constexpr char kKindXfrm[] = "xfrm";

// Modem drivers that we support.
const char* const kModemDrivers[] = {
    // For modems which expose MBIM to userspace (Fibocom L850-GL, NL668-AM,
    // FM101, etc.)
    "cdc_mbim",
    // For modems which expose QMI to userspace. This may not be usable if
    // USE=qmi is not set.
    "qmi_wwan",
    // For Mediatek-based PCIe modems (Fibocom FM350, etc.)
    "mtk_t7xx",
};

// Path to the tun device.
constexpr char kTunDeviceName[] = "/dev/net/tun";

// Time to wait before registering devices which need extra time to detect.
constexpr base::TimeDelta kDelayedDeviceCreation = base::Seconds(5);

// Time interval for polling for link statistics.
constexpr base::TimeDelta kRequestLinkStatisticsInterval = base::Seconds(20);

// IFLA_XFRM_LINK and IFLA_XFRM_IF_ID are defined in
// /usr/include/linux/if_link.h on 4.19+ kernels.
constexpr int kIflaXfrmLink = 1;
constexpr int kIflaXfrmIfId = 2;

// Non-functional Device subclass used for non-operable or blocked devices
class DeviceStub : public Device {
 public:
  DeviceStub(Manager* manager,
             const std::string& link_name,
             const std::string& address,
             int interface_index,
             Technology technology)
      : Device(manager, link_name, address, interface_index, technology) {}
  DeviceStub(const DeviceStub&) = delete;
  DeviceStub& operator=(const DeviceStub&) = delete;

  void Start(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(Error(Error::kNotSupported));
  }
  void Stop(EnabledStateChangedCallback callback) override {
    std::move(callback).Run(Error(Error::kNotSupported));
  }
  void Initialize() override {}
};

}  // namespace

DeviceInfo::DeviceInfo(Manager* manager)
    : manager_(manager),
      device_info_root_(kDeviceInfoRoot),
      routing_table_(RoutingTable::GetInstance()),
      rtnl_handler_(RTNLHandler::GetInstance()),
      netlink_manager_(NetlinkManager::GetInstance()),
      sockets_(new Sockets()),
      time_(Time::GetInstance()) {
  if (manager) {
    // |manager| may be null in tests.
    dispatcher_ = manager->dispatcher();
    metrics_ = manager->metrics();
  }
}

DeviceInfo::~DeviceInfo() = default;

void DeviceInfo::BlockDevice(const std::string& device_name) {
  blocked_list_.insert(device_name);
  // Remove the current device info if it exist, since it will be out-dated.
  DeregisterDevice(GetIndex(device_name));
  // Request link info update to allow device info to be recreated.
  if (manager_->running()) {
    rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  }
}

void DeviceInfo::AllowDevice(const std::string& device_name) {
  blocked_list_.erase(device_name);
  // Remove the current device info if it exist, since it will be out-dated.
  DeregisterDevice(GetIndex(device_name));
  // Request link info update to allow device info to be recreated.
  if (manager_->running()) {
    rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  }
}

bool DeviceInfo::IsDeviceBlocked(const std::string& device_name) {
  return base::Contains(blocked_list_, device_name);
}

void DeviceInfo::Start() {
  link_listener_.reset(
      new RTNLListener(RTNLHandler::kRequestLink,
                       base::BindRepeating(&DeviceInfo::LinkMsgHandler,
                                           base::Unretained(this))));
  rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  request_link_statistics_callback_.Reset(base::BindOnce(
      &DeviceInfo::RequestLinkStatistics, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               request_link_statistics_callback_.callback(),
                               kRequestLinkStatisticsInterval);
}

void DeviceInfo::Stop() {
  link_listener_.reset();
  infos_.clear();
  request_link_statistics_callback_.Cancel();
  delayed_devices_callback_.Cancel();
  delayed_devices_.clear();
}

std::vector<std::string> DeviceInfo::GetUninitializedTechnologies() const {
  std::set<std::string> unique_technologies;
  std::set<Technology> initialized_technologies;
  for (const auto& info : infos_) {
    Technology technology = info.second.technology;
    if (info.second.device) {
      // If there is more than one device for a technology and at least
      // one of them has been initialized, make sure that it doesn't get
      // listed as uninitialized.
      initialized_technologies.insert(technology);
      unique_technologies.erase(TechnologyName(technology));
      continue;
    }
    if (IsPrimaryConnectivityTechnology(technology) &&
        !base::Contains(initialized_technologies, technology))
      unique_technologies.insert(TechnologyName(technology));
  }
  return std::vector<std::string>(unique_technologies.begin(),
                                  unique_technologies.end());
}

void DeviceInfo::RegisterDevice(const DeviceRefPtr& device) {
  SLOG(1) << __func__ << "(" << device->link_name() << ", "
          << device->interface_index() << ")";
  device->Initialize();
  delayed_devices_.erase(device->interface_index());
  CHECK(!GetDevice(device->interface_index()).get());
  infos_[device->interface_index()].device = device;
  if (metrics_->IsDeviceRegistered(device->interface_index(),
                                   device->technology())) {
    metrics_->NotifyDeviceInitialized(device->interface_index());
  } else {
    metrics_->RegisterDevice(device->interface_index(), device->technology());
  }
  if (device->technology() != Technology::kBlocked &&
      device->technology() != Technology::kUnknown) {
    routing_table_->RegisterDevice(device->interface_index(),
                                   device->link_name());
  }
  if (IsPrimaryConnectivityTechnology(device->technology())) {
    manager_->RegisterDevice(device);
  }
}

base::FilePath DeviceInfo::GetDeviceInfoPath(
    const std::string& iface_name, const std::string& path_name) const {
  return device_info_root_.Append(iface_name).Append(path_name);
}

bool DeviceInfo::GetDeviceInfoContents(const std::string& iface_name,
                                       const std::string& path_name,
                                       std::string* contents_out) const {
  return base::ReadFileToString(GetDeviceInfoPath(iface_name, path_name),
                                contents_out);
}

bool DeviceInfo::GetDeviceInfoSymbolicLink(const std::string& iface_name,
                                           const std::string& path_name,
                                           base::FilePath* path_out) const {
  return base::ReadSymbolicLink(GetDeviceInfoPath(iface_name, path_name),
                                path_out);
}

bool DeviceInfo::GetLowerDeviceInfoPath(const std::string& iface_name,
                                        base::FilePath* path_out) const {
  const auto type = static_cast<base::FileEnumerator::FileType>(
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS);
  base::FileEnumerator dir_enum(GetDeviceInfoPath(iface_name, ""), false, type);
  for (auto curr_dir = dir_enum.Next(); !curr_dir.empty();
       curr_dir = dir_enum.Next()) {
    if (base::StartsWith(curr_dir.BaseName().value(), kInterfaceLowerPrefix)) {
      return base::ReadSymbolicLink(curr_dir, path_out);
    }
  }
  return false;
}

int DeviceInfo::GetDeviceArpType(const std::string& iface_name) const {
  std::string type_string;
  int arp_type;

  if (!GetDeviceInfoContents(iface_name, kInterfaceType, &type_string) ||
      !base::TrimString(type_string, "\n", &type_string) ||
      !base::StringToInt(type_string, &arp_type)) {
    return ARPHRD_VOID;
  }
  return arp_type;
}

Technology DeviceInfo::GetDeviceTechnology(
    const std::string& iface_name,
    const std::optional<std::string>& kind) const {
  int arp_type = GetDeviceArpType(iface_name);

  if (kind.has_value()) {
    SLOG(2) << iface_name << ": device is kind '" << kind.value() << "'";
  }

  if (IsGuestDevice(iface_name)) {
    SLOG(2) << iface_name << ": device is a guest device";
    return Technology::kGuestInterface;
  }

  if (kind.has_value()) {
    // Ignore certain KINDs of devices.
    for (const char* ignoreKind : kIgnoredDeviceKinds) {
      if (ignoreKind == kind.value()) {
        SLOG(2) << __func__ << ": device " << iface_name << " ignored, kind \""
                << ignoreKind << "\"";
        return Technology::kUnknown;
      }
    }
  }

  // Special case for devices which should be ignored.
  for (const char* prefix : kIgnoredDeviceNamePrefixes) {
    if (iface_name.find(prefix) == 0) {
      SLOG(2) << __func__ << ": device " << iface_name << " should be ignored";
      return Technology::kUnknown;
    }
  }

  if (kind.has_value() && kind.value() == kKindWireGuard) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " is a wireguard device. Treat it as a tunnel.";
    return Technology::kTunnel;
  }

  if (kind.has_value() && kind.value() == kKindXfrm) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " is a xfrm device. Treat it as a tunnel.";
    return Technology::kTunnel;
  }

  // Special case for pseudo modem veth pairs which are used for testing.
  if (iface_name.find(kModemPseudoDeviceNamePrefix) == 0) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " is a pseudo modem for testing";
    return Technology::kCellular;
  }

  // Special case for pseudo ethernet devices which are used for testing.
  if (iface_name.find(kEthernetPseudoDeviceNamePrefix) == 0) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " is a virtual ethernet device for testing";
    return Technology::kEthernet;
  }

  // No point delaying veth devices just because they don't have a device
  // symlink. Treat it as Ethernet directly.
  if (kind.has_value() && kind.value() == kKindVeth) {
    SLOG(2) << __func__ << ": device " << iface_name << " is kind veth";
    return Technology::kEthernet;
  }

  // 'rmnet' is Qualcomm's data-path cellular netdevice.
  if (kind.has_value() && kind.value() == kKindRmnet) {
    SLOG(2) << __func__ << ": device " << iface_name << " is kind rmnet";
    return Technology::kCellular;
  }

  if (arp_type == ARPHRD_IEEE80211_RADIOTAP) {
    SLOG(2) << __func__ << ": wifi device " << iface_name
            << " is in monitor mode";
    return Technology::kWiFiMonitor;
  }

  std::string contents;
  if (!GetDeviceInfoContents(iface_name, kInterfaceUevent, &contents)) {
    LOG(INFO) << __func__ << ": device " << iface_name << " has no uevent file";
    return Technology::kUnknown;
  }

  // If the "uevent" file contains the string "DEVTYPE=wlan\n" at the
  // start of the file or after a newline, we can safely assume this
  // is a wifi device.
  if (contents.find(kInterfaceUeventWifiSignature) != std::string::npos) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " has wifi signature in uevent file";
    return Technology::kWiFi;
  }

  // Similarly, if the uevent file contains "DEVTYPE=bridge\n" then we can
  // safely assume this is a bridge device and can be treated as ethernet.
  if (contents.find(kInterfaceUeventBridgeSignature) != std::string::npos) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " has bridge signature in uevent file";
    return Technology::kEthernet;
  }

  // VLANs are virtual interfaces that have a lower real network interface;
  // the technology of the VLAN will be the technology of the lower device.
  if (contents.find(kInterfaceUeventVlanSignature) != std::string::npos) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " has vlan signature in uevent file";
    base::FilePath lower_device_path;
    if (GetLowerDeviceInfoPath(iface_name, &lower_device_path)) {
      std::string lower_device_name(lower_device_path.BaseName().value());
      SLOG(2) << __func__ << ": device " << iface_name
              << " has same technology as lower device " << lower_device_name;
      return GetDeviceTechnology(lower_device_name, std::nullopt);
    }
  }

  base::FilePath driver_path;
  if (!GetDeviceInfoSymbolicLink(iface_name, kInterfaceDriver, &driver_path) &&
      !GetDeviceInfoSymbolicLink(iface_name, kInterfaceDriverMtkt7xx,
                                 &driver_path)) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " has no device symlink";
    if (arp_type == ARPHRD_LOOPBACK) {
      SLOG(2) << __func__ << ": device " << iface_name
              << " is a loopback device";
      return Technology::kLoopback;
    }
    if (arp_type == ARPHRD_PPP) {
      SLOG(2) << __func__ << ": device " << iface_name << " is a ppp device";
      return Technology::kPPP;
    }
    // Devices like Qualcomm's IPA (IP Accelerator) should not be managed by
    // Shill.
    if (arp_type == ARPHRD_RAWIP) {
      SLOG(2) << __func__ << ": device " << iface_name << " is a raw IP device";
      return Technology::kUnknown;
    }
    std::string tun_flags_str;
    int tun_flags = 0;
    if (GetDeviceInfoContents(iface_name, kInterfaceTunFlags, &tun_flags_str) &&
        base::TrimString(tun_flags_str, "\n", &tun_flags_str) &&
        base::HexStringToInt(tun_flags_str, &tun_flags) &&
        (tun_flags & IFF_TUN)) {
      SLOG(2) << __func__ << ": device " << iface_name << " is tun device";
      return Technology::kTunnel;
    }

    // We don't know what sort of device it is.
    return Technology::kNoDeviceSymlink;
  }

  std::string driver_name(driver_path.BaseName().value());
  // See if driver for this interface is in a list of known modem driver names.
  for (auto modem_driver : kModemDrivers) {
    if (driver_name == modem_driver) {
      SLOG(2) << __func__ << ": device " << iface_name
              << " is matched with modem driver " << driver_name;
      return Technology::kCellular;
    }
  }

  // For cdc_ether / cdc_ncm devices, make sure it's a modem because this driver
  // can be used for other ethernet devices.
  if (driver_name == kDriverCdcEther || driver_name == kDriverCdcNcm) {
    if (IsCdcEthernetModemDevice(iface_name)) {
      LOG(INFO) << __func__ << ": device " << iface_name << " is a "
                << driver_name << " modem device";
      return Technology::kCellular;
    }
    SLOG(2) << __func__ << ": device " << iface_name << " is a " << driver_name
            << " device";
    return Technology::kCDCEthernet;
  }

  // Special case for the virtio driver, used when run under KVM. See also
  // the comment in VirtioEthernet::Start.
  if (driver_name == kDriverVirtioNet) {
    SLOG(2) << __func__ << ": device " << iface_name << " is virtio ethernet";
    return Technology::kVirtioEthernet;
  }

  SLOG(2) << __func__ << ": device " << iface_name << ", with driver "
          << driver_name << ", is defaulted to type ethernet";
  return Technology::kEthernet;
}

bool DeviceInfo::IsCdcEthernetModemDevice(const std::string& iface_name) const {
  // A cdc_ether / cdc_ncm device is a modem device if it also exposes tty
  // interfaces. To determine this, we look for the existence of the tty
  // interface in the USB device sysfs tree.
  //
  // A typical sysfs dir hierarchy for a cdc_ether / cdc_ncm modem USB device is
  // as follows:
  //
  //   /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2
  //     1-2:1.0
  //       tty
  //         ttyACM0
  //     1-2:1.1
  //       net
  //         usb0
  //     1-2:1.2
  //       tty
  //         ttyACM1
  //       ...
  //
  // /sys/class/net/usb0/device symlinks to
  // /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2/1-2:1.1
  //
  // Note that some modem devices have the tty directory one level deeper
  // (eg. E362), so the device tree for the tty interface is:
  // /sys/devices/pci0000:00/0000:00:1d.7/usb/1-2/1-2:1.0/ttyUSB0/tty/ttyUSB0

  base::FilePath device_file = GetDeviceInfoPath(iface_name, kInterfaceDevice);
  base::FilePath device_path;
  if (!base::ReadSymbolicLink(device_file, &device_path)) {
    SLOG(2) << __func__ << ": device " << iface_name
            << " has no device symlink";
    return false;
  }
  if (!device_path.IsAbsolute()) {
    device_path =
        base::MakeAbsoluteFilePath(device_file.DirName().Append(device_path));
  }

  // Look for tty interface by enumerating all directories under the parent
  // USB device and see if there's a subdirectory "tty" inside.  In other
  // words, using the example dir hierarchy above, find
  // /sys/devices/pci0000:00/0000:00:1d.7/usb1/1-2/.../tty.
  // If this exists, then this is a modem device.
  return HasSubdir(device_path.DirName(), base::FilePath("tty"));
}

// static
bool DeviceInfo::HasSubdir(const base::FilePath& base_dir,
                           const base::FilePath& subdir) {
  const auto type = static_cast<base::FileEnumerator::FileType>(
      base::FileEnumerator::DIRECTORIES | base::FileEnumerator::SHOW_SYM_LINKS);
  base::FileEnumerator dir_enum(base_dir, true, type);
  for (auto curr_dir = dir_enum.Next(); !curr_dir.empty();
       curr_dir = dir_enum.Next()) {
    if (curr_dir.BaseName() == subdir)
      return true;
  }
  return false;
}

DeviceRefPtr DeviceInfo::CreateDevice(const std::string& link_name,
                                      const std::string& address,
                                      int interface_index,
                                      Technology technology) {
  SLOG(1) << __func__ << ": " << link_name << " Address: " << address
          << " Index: " << interface_index;
  DeviceRefPtr device;
  delayed_devices_.erase(interface_index);
  infos_[interface_index].technology = technology;
  bool flush = true;

  switch (technology) {
    case Technology::kCellular:
      // Cellular devices are managed by ModemInfo.
      SLOG(2) << "Cellular link " << link_name << " at index "
              << interface_index << " -- notifying ModemInfo.";
      // The MAC address provided by RTNL is not reliable for Gobi 2K modems.
      // Clear it here, and it will be fetched from the kernel in
      // GetMacAddress().
      infos_[interface_index].mac_address.Clear();
      manager_->modem_info()->OnDeviceInfoAvailable(link_name);
      break;
    case Technology::kEthernet:
      device = new Ethernet(manager_, link_name, address, interface_index);
      break;
    case Technology::kVirtioEthernet:
      device =
          new VirtioEthernet(manager_, link_name, address, interface_index);
      break;
    case Technology::kWiFi:
      // Defer creating this device until we get information about the
      // type of WiFi interface.
      GetWiFiInterfaceInfo(interface_index);
      break;
    case Technology::kArcBridge:
      // Shill doesn't touch the IP configuration for the ARC bridge.
      flush = false;
      break;
    case Technology::kPPP:
    case Technology::kTunnel:
      // Tunnel and PPP devices are managed by the VPN code (PPP for
      // l2tpipsec). Notify the corresponding VPNService of the interface's
      // presence through the pre-registered callback.
      // Since CreateDevice is only called once in the lifetime of an
      // interface index, this notification will only occur the first
      // time the device is seen.
      if (pending_links_.find(link_name) != pending_links_.end()) {
        SLOG(2) << "Tunnel / PPP link " << link_name << " at index "
                << interface_index << " -- triggering callback.";
        std::move(pending_links_[link_name]).Run(link_name, interface_index);
        pending_links_.erase(link_name);
      } else if (technology == Technology::kTunnel) {
        // If no one claims this tunnel, it is probably
        // left over from a previous instance and should not exist.
        SLOG(2) << "Tunnel link " << link_name << " at index "
                << interface_index << " is unused. Deleting.";
        DeleteInterface(interface_index);
      }
      break;
    case Technology::kLoopback:
      // Loopback devices are largely ignored, but we should make sure the
      // link is enabled.
      SLOG(2) << "Bringing up loopback device " << link_name << " at index "
              << interface_index;
      rtnl_handler_->SetInterfaceFlags(interface_index, IFF_UP, IFF_UP);
      return nullptr;
    case Technology::kCDCEthernet:
      // CDCEthernet devices are of indeterminate type when they are
      // initially created.  Some time later, tty devices may or may
      // not appear under the same USB device root, which will identify
      // it as a modem.  Alternatively, ModemManager may discover the
      // device and create and register a Cellular device.  In either
      // case, we should delay creating a Device until we can make a
      // better determination of what type this Device should be.
    case Technology::kNoDeviceSymlink:  // FALLTHROUGH
      // The same is true for devices that do not report a device
      // symlink.  It has been observed that tunnel devices may not
      // immediately contain a tun_flags component in their
      // /sys/class/net entry.
      LOG(INFO) << "Delaying creation of device for " << link_name
                << " at index " << interface_index;
      DelayDeviceCreation(interface_index);
      return nullptr;
    case Technology::kGuestInterface:
      return nullptr;
    default:
      // We will not manage this device in shill.  Do not create a device
      // object or do anything to change its state.  We create a stub object
      // which is useful for testing.
      return new DeviceStub(manager_, link_name, address, interface_index,
                            technology);
  }

  if (flush) {
    // Reset the routing table and addresses.
    routing_table_->FlushRoutes(interface_index);
  }

  manager_->UpdateUninitializedTechnologies();

  return device;
}

// static
bool DeviceInfo::GetLinkNameFromMessage(const RTNLMessage& msg,
                                        std::string* link_name) {
  if (!msg.HasAttribute(IFLA_IFNAME))
    return false;

  ByteString link_name_bytes(msg.GetAttribute(IFLA_IFNAME));
  link_name->assign(
      reinterpret_cast<const char*>(link_name_bytes.GetConstData()));

  return true;
}

bool DeviceInfo::IsRenamedBlockedDevice(const RTNLMessage& msg) {
  int interface_index = msg.interface_index();
  const Info* info = GetInfo(interface_index);
  if (!info)
    return false;

  if (!info->device || info->device->technology() != Technology::kBlocked)
    return false;

  std::string interface_name;
  if (!GetLinkNameFromMessage(msg, &interface_name))
    return false;

  if (interface_name == info->name)
    return false;

  LOG(INFO) << __func__ << ": interface index " << interface_index
            << " renamed from " << info->name << " to " << interface_name;
  return true;
}

void DeviceInfo::AddLinkMsgHandler(const RTNLMessage& msg) {
  SLOG(2) << __func__ << " index: " << msg.interface_index();

  DCHECK(msg.type() == RTNLMessage::kTypeLink &&
         msg.mode() == RTNLMessage::kModeAdd);
  int dev_index = msg.interface_index();
  Technology technology = Technology::kUnknown;
  unsigned int flags = msg.link_status().flags;
  unsigned int change = msg.link_status().change;

  if (IsRenamedBlockedDevice(msg)) {
    // Treat renamed blocked devices as new devices.
    DeregisterDevice(dev_index);
  }

  bool new_device = !infos_[dev_index].received_add_link;
  SLOG(2) << __func__
          << base::StringPrintf(
                 "(index=%d, flags=0x%x, change=0x%x), new_device=%d",
                 dev_index, flags, change, new_device);
  infos_[dev_index].received_add_link = true;
  infos_[dev_index].flags = flags;

  RetrieveLinkStatistics(dev_index, msg);

  DeviceRefPtr device = GetDevice(dev_index);
  if (new_device) {
    CHECK(!device);
    std::string link_name;
    if (!GetLinkNameFromMessage(msg, &link_name) || link_name.empty()) {
      LOG(ERROR) << "Add Link message does not contain a link name!";
      return;
    }
    SLOG(2) << "add link index " << dev_index << " name " << link_name;
    infos_[dev_index].name = link_name;
    indices_[link_name] = dev_index;

    if (link_name == VPNProvider::kArcBridgeIfName) {
      technology = Technology::kArcBridge;
    } else if (IsDeviceBlocked(link_name)) {
      technology = Technology::kBlocked;
    } else if (!manager_->DeviceManagementAllowed(link_name)) {
      technology = Technology::kBlocked;
      BlockDevice(link_name);
    } else {
      technology = GetDeviceTechnology(link_name, msg.link_status().kind);
    }

    std::string address;
    if (msg.HasAttribute(IFLA_ADDRESS)) {
      infos_[dev_index].mac_address = msg.GetAttribute(IFLA_ADDRESS);
      address = infos_[dev_index].mac_address.HexEncode();
      SLOG(2) << "link index " << dev_index << " address " << address;
    } else if (technology == Technology::kWiFi ||
               technology == Technology::kEthernet) {
      LOG(ERROR) << "Add link message does not have IFLA_ADDRESS, link: "
                 << link_name << ", Technology: " << technology;
      return;
    }
    metrics_->RegisterDevice(dev_index, technology);
    device = CreateDevice(link_name, address, dev_index, technology);
    if (device) {
      RegisterDevice(device);
    }
  }
  if (device) {
    device->LinkEvent(flags, change);
  }
}

void DeviceInfo::DelLinkMsgHandler(const RTNLMessage& msg) {
  SLOG(2) << __func__ << "(index=" << msg.interface_index() << ")";

  DCHECK(msg.type() == RTNLMessage::kTypeLink &&
         msg.mode() == RTNLMessage::kModeDelete);
  SLOG(2) << __func__
          << base::StringPrintf("(index=%d, flags=0x%x, change=0x%x)",
                                msg.interface_index(), msg.link_status().flags,
                                msg.link_status().change);

  std::string link_name;
  if (!GetLinkNameFromMessage(msg, &link_name)) {
    LOG(ERROR) << "Del Link message does not contain a link name!";
    return;
  }

  DeregisterDevice(msg.interface_index());
}

DeviceRefPtr DeviceInfo::GetDevice(int interface_index) const {
  const Info* info = GetInfo(interface_index);
  return info ? info->device : nullptr;
}

int DeviceInfo::GetIndex(const std::string& interface_name) const {
  std::map<std::string, int>::const_iterator it = indices_.find(interface_name);
  return it == indices_.end() ? -1 : it->second;
}

bool DeviceInfo::GetMacAddress(int interface_index, ByteString* address) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  // |mac_address| from RTNL is not used for some devices, in which case it will
  // be empty here.
  if (!info->mac_address.IsEmpty()) {
    *address = info->mac_address;
    return true;
  }

  // Ask the kernel for the MAC address.
  *address = GetMacAddressFromKernel(interface_index);
  return !address->IsEmpty();
}

ByteString DeviceInfo::GetMacAddressFromKernel(int interface_index) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return ByteString();
  }

  const int fd = sockets_->Socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    PLOG(ERROR) << __func__ << ": Unable to open socket";
    return ByteString();
  }

  ScopedSocketCloser socket_closer(sockets_.get(), fd);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_ifindex = interface_index;
  strcpy(ifr.ifr_ifrn.ifrn_name, info->name.c_str());  // NOLINT(runtime/printf)
  int err = sockets_->Ioctl(fd, SIOCGIFHWADDR, &ifr);
  if (err < 0) {
    PLOG(ERROR) << __func__ << ": Unable to read MAC address";
    return ByteString();
  }

  return ByteString(ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
}

bool DeviceInfo::GetIntegratedWiFiHardwareIds(const std::string& iface_name,
                                              int* vendor_id,
                                              int* product_id,
                                              int* subsystem_id) const {
  std::string content;
  if (!GetDeviceInfoContents(iface_name, kInterfaceIntegratedId, &content)) {
    LOG(WARNING) << iface_name << " no uevent file found";
    return false;
  }
  const auto lines = base::SplitString(content, "\n", base::TRIM_WHITESPACE,
                                       base::SPLIT_WANT_NONEMPTY);
  static constexpr LazyRE2 qcom_adapter_matcher = {
      "OF_COMPATIBLE_(\\d+)=qcom,wcn(\\d+)-wifi"};
  for (const auto& line : lines) {
    int i;
    int wcn_id;
    if (RE2::FullMatch(line, *qcom_adapter_matcher, &i, &wcn_id)) {
      *vendor_id = Metrics::kWiFiIntegratedAdapterVendorId;
      *product_id = wcn_id;
      *subsystem_id = 0;
      return true;
    }
  }
  return false;
}

bool DeviceInfo::GetWiFiHardwareIds(int interface_index,
                                    int* vendor_id,
                                    int* product_id,
                                    int* subsystem_id) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    LOG(ERROR) << "No DeviceInfo for interface index " << interface_index;
    return false;
  }
  if (info->technology != Technology::kWiFi) {
    LOG(ERROR) << info->name << " adapter reports for technology "
               << info->technology << " not supported.";
    return false;
  }
  SLOG(2) << info->name << " detecting adapter information";

  if (!base::PathIsReadable(
          GetDeviceInfoPath(info->name, kInterfaceVendorId))) {
    // No "vendor" file, check if the adapter is an integrated chipset.
    if (GetIntegratedWiFiHardwareIds(info->name, vendor_id, product_id,
                                     subsystem_id)) {
      return true;
    }
    LOG(WARNING) << info->name << " no vendor ID found";
    return false;
  }
  bool ret = true;
  std::string content;
  int content_int;
  if (!GetDeviceInfoContents(info->name, kInterfaceVendorId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *vendor_id = content_int;
  }
  if (!GetDeviceInfoContents(info->name, kInterfaceDeviceId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *product_id = content_int;
  }
  // Devices with SDIO WiFi chipsets may not have a |subsystem_device| file.
  // Use 0 in that case.
  if (!base::PathIsReadable(
          GetDeviceInfoPath(info->name, kInterfaceSubsystemId))) {
    *subsystem_id = 0;
    return ret;
  }
  if (!GetDeviceInfoContents(info->name, kInterfaceSubsystemId, &content) ||
      !base::TrimString(content, "\n", &content) ||
      !base::HexStringToInt(content, &content_int)) {
    ret = false;
  } else {
    *subsystem_id = content_int;
  }
  return ret;
}

bool DeviceInfo::GetFlags(int interface_index, unsigned int* flags) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  *flags = info->flags;
  return true;
}

bool DeviceInfo::GetByteCounts(int interface_index,
                               uint64_t* rx_bytes,
                               uint64_t* tx_bytes) const {
  const Info* info = GetInfo(interface_index);
  if (!info) {
    return false;
  }
  *rx_bytes = info->rx_bytes;
  *tx_bytes = info->tx_bytes;
  return true;
}

void DeviceInfo::AddVirtualInterfaceReadyCallback(
    const std::string& interface_name, LinkReadyCallback callback) {
  if (pending_links_.erase(interface_name) > 0) {
    PLOG(WARNING) << "Callback for RTNL link ready event of " << interface_name
                  << " already existed, overwritten";
  }
  pending_links_.emplace(interface_name, std::move(callback));
}

bool DeviceInfo::CreateTunnelInterface(LinkReadyCallback callback) {
  int fd = HANDLE_EINTR(open(kTunDeviceName, O_RDWR | O_CLOEXEC));
  if (fd < 0) {
    PLOG(ERROR) << "failed to open " << kTunDeviceName;
    return false;
  }
  base::ScopedFD scoped_fd(fd);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (HANDLE_EINTR(ioctl(fd, TUNSETIFF, &ifr))) {
    PLOG(ERROR) << "failed to create tunnel interface";
    return false;
  }

  if (HANDLE_EINTR(ioctl(fd, TUNSETPERSIST, 1))) {
    PLOG(ERROR) << "failed to set tunnel interface to be persistent";
    return false;
  }

  if (callback) {
    std::string ifname(ifr.ifr_name);
    AddVirtualInterfaceReadyCallback(ifname, std::move(callback));
  }
  return true;
}

int DeviceInfo::OpenTunnelInterface(const std::string& interface_name) const {
  int fd = HANDLE_EINTR(open(kTunDeviceName, O_RDWR | O_CLOEXEC));
  if (fd < 0) {
    PLOG(ERROR) << "failed to open " << kTunDeviceName;
    return -1;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface_name.c_str(), sizeof(ifr.ifr_name));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  if (HANDLE_EINTR(ioctl(fd, TUNSETIFF, &ifr))) {
    PLOG(ERROR) << "failed to set tunnel interface name";
    return -1;
  }

  return fd;
}

bool DeviceInfo::CreateWireGuardInterface(const std::string& interface_name,
                                          LinkReadyCallback link_ready_callback,
                                          base::OnceClosure failure_callback) {
  if (!rtnl_handler_->AddInterface(
          interface_name, kKindWireGuard, {},
          base::BindOnce(&DeviceInfo::OnCreateInterfaceResponse,
                         weak_factory_.GetWeakPtr(), interface_name,
                         std::move(failure_callback)))) {
    return false;
  }
  AddVirtualInterfaceReadyCallback(interface_name,
                                   std::move(link_ready_callback));
  return true;
}

bool DeviceInfo::CreateXFRMInterface(const std::string& interface_name,
                                     int underlying_if_index,
                                     int xfrm_if_id,
                                     LinkReadyCallback link_ready_callback,
                                     base::OnceClosure failure_callback) {
  RTNLAttrMap attrs;
  attrs[kIflaXfrmLink] = ByteString::CreateFromCPUUInt32(underlying_if_index);
  attrs[kIflaXfrmIfId] = ByteString::CreateFromCPUUInt32(xfrm_if_id);
  const ByteString link_info_data = RTNLMessage::PackAttrs(attrs);
  if (!rtnl_handler_->AddInterface(
          interface_name, kKindXfrm, link_info_data,
          base::BindOnce(&DeviceInfo::OnCreateInterfaceResponse,
                         weak_factory_.GetWeakPtr(), interface_name,
                         std::move(failure_callback)))) {
    return false;
  }
  AddVirtualInterfaceReadyCallback(interface_name,
                                   std::move(link_ready_callback));
  return true;
}

VirtualDevice* DeviceInfo::CreatePPPDevice(Manager* manager,
                                           const std::string& ifname,
                                           int ifindex) {
  return new VirtualDevice(manager, ifname, ifindex, Technology::kPPP);
}

void DeviceInfo::OnCreateInterfaceResponse(const std::string& interface_name,
                                           base::OnceClosure failure_callback,
                                           int32_t error) {
  if (error == 0) {
    // |error| == 0 means ACK. Needs to do nothing here. We expect getting the
    // new interface message latter.
    return;
  }

  LOG(ERROR) << "Failed to create wireguard interface " << interface_name
             << ", error code=" << error;
  if (pending_links_.erase(interface_name) != 1) {
    LOG(WARNING)
        << "Failed to remove link ready callback from |pending_links_| for "
        << interface_name;
  }
  std::move(failure_callback).Run();
}

bool DeviceInfo::DeleteInterface(int interface_index) const {
  return rtnl_handler_->RemoveInterface(interface_index);
}

const DeviceInfo::Info* DeviceInfo::GetInfo(int interface_index) const {
  std::map<int, Info>::const_iterator iter = infos_.find(interface_index);
  if (iter == infos_.end()) {
    return nullptr;
  }
  return &iter->second;
}

void DeviceInfo::DeregisterDevice(int interface_index) {
  auto iter = infos_.find(interface_index);
  if (iter == infos_.end()) {
    LOG(WARNING) << __func__ << ": Unknown device index: " << interface_index;
    return;
  }

  LOG(INFO) << __func__ << " index: " << interface_index;
  // Deregister the device if not deregistered yet.
  if (iter->second.device.get()) {
    manager_->DeregisterDevice(iter->second.device);
    metrics_->DeregisterDevice(interface_index);
    routing_table_->DeregisterDevice(iter->second.device->interface_index(),
                                     iter->second.device->link_name());
  }
  indices_.erase(iter->second.name);
  infos_.erase(iter);
  delayed_devices_.erase(interface_index);
}

void DeviceInfo::LinkMsgHandler(const RTNLMessage& msg) {
  DCHECK(msg.type() == RTNLMessage::kTypeLink);
  if (msg.mode() == RTNLMessage::kModeAdd) {
    AddLinkMsgHandler(msg);
  } else if (msg.mode() == RTNLMessage::kModeDelete) {
    DelLinkMsgHandler(msg);
  } else {
    NOTREACHED();
  }
}

void DeviceInfo::DelayDeviceCreation(int interface_index) {
  delayed_devices_.insert(interface_index);
  delayed_devices_callback_.Reset(base::BindOnce(
      &DeviceInfo::DelayedDeviceCreationTask, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE, delayed_devices_callback_.callback(),
                               kDelayedDeviceCreation);
}

// Re-evaluate the technology type for each delayed device.
void DeviceInfo::DelayedDeviceCreationTask() {
  while (!delayed_devices_.empty()) {
    const auto it = delayed_devices_.begin();
    int dev_index = *it;
    delayed_devices_.erase(it);

    DCHECK(base::Contains(infos_, dev_index));
    DCHECK(!GetDevice(dev_index));

    const std::string& link_name = infos_[dev_index].name;
    Technology technology = GetDeviceTechnology(link_name, std::nullopt);

    if (technology == Technology::kCDCEthernet) {
      LOG(INFO) << "In " << __func__ << ": device " << link_name
                << " is now assumed to be regular Ethernet.";
      technology = Technology::kEthernet;
    } else if (technology == Technology::kNoDeviceSymlink) {
      if (manager_->ignore_unknown_ethernet()) {
        SLOG(2) << __func__ << ": device " << link_name
                << ", without driver name will be ignored";
        technology = Technology::kUnknown;
      } else {
        // Act the same as if there was a driver symlink, but we did not
        // recognize the driver name.
        SLOG(2) << __func__ << ": device " << link_name
                << ", without driver name is defaulted to type ethernet";
        technology = Technology::kEthernet;
      }
    } else if (technology != Technology::kCellular &&
               technology != Technology::kTunnel &&
               technology != Technology::kGuestInterface) {
      LOG(WARNING) << "In " << __func__ << ": device " << link_name
                   << " is unexpected technology " << technology;
    }

    std::string address = infos_[dev_index].mac_address.HexEncode();
    int arp_type = GetDeviceArpType(link_name);

    // NB: ARHRD_RAWIP was introduced in kernel 4.14.
    if (technology != Technology::kTunnel &&
        technology != Technology::kUnknown && arp_type != ARPHRD_RAWIP) {
      DCHECK(!address.empty());
    }

    DeviceRefPtr device =
        CreateDevice(link_name, address, dev_index, technology);
    if (device) {
      RegisterDevice(device);
    }
  }
}

void DeviceInfo::RetrieveLinkStatistics(int interface_index,
                                        const RTNLMessage& msg) {
  if (!msg.HasAttribute(IFLA_STATS64)) {
    return;
  }
  ByteString stats_bytes(msg.GetAttribute(IFLA_STATS64));
  struct old_rtnl_link_stats64 stats;
  if (stats_bytes.GetLength() < sizeof(stats)) {
    LOG(WARNING) << "Link statistics size is too small: "
                 << stats_bytes.GetLength() << " < " << sizeof(stats);
    return;
  }

  memcpy(&stats, stats_bytes.GetConstData(), sizeof(stats));
  SLOG(2) << "Link statistics for "
          << " interface index " << interface_index << ": "
          << "receive: " << stats.rx_bytes << "; "
          << "transmit: " << stats.tx_bytes << ".";
  infos_[interface_index].rx_bytes = stats.rx_bytes;
  infos_[interface_index].tx_bytes = stats.tx_bytes;

  DeviceRefPtr device = GetDevice(interface_index);
  if (device && device->technology() == Technology::kWiFi) {
    (reinterpret_cast<WiFi*>(device.get()))
        ->OnReceivedRtnlLinkStatistics(stats);
  }
}

void DeviceInfo::RequestLinkStatistics() {
  rtnl_handler_->RequestDump(RTNLHandler::kRequestLink);
  request_link_statistics_callback_.Reset(base::BindOnce(
      &DeviceInfo::RequestLinkStatistics, weak_factory_.GetWeakPtr()));
  dispatcher_->PostDelayedTask(FROM_HERE,
                               request_link_statistics_callback_.callback(),
                               kRequestLinkStatisticsInterval);
}

void DeviceInfo::GetWiFiInterfaceInfo(int interface_index) {
  GetInterfaceMessage msg;
  if (!msg.attributes()->SetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                              interface_index)) {
    LOG(ERROR) << "Unable to set interface index attribute for "
                  "GetInterface message.  Interface type cannot be "
                  "determined!";
    return;
  }
  netlink_manager_->SendNl80211Message(
      &msg,
      base::BindRepeating(&DeviceInfo::OnWiFiInterfaceInfoReceived,
                          weak_factory_.GetWeakPtr()),
      base::BindRepeating(&NetlinkManager::OnAckDoNothing),
      base::BindRepeating(&NetlinkManager::OnNetlinkMessageError));
}

void DeviceInfo::OnWiFiInterfaceInfoReceived(const Nl80211Message& msg) {
  if (msg.command() != NL80211_CMD_NEW_INTERFACE) {
    LOG(ERROR) << "Message is not a new interface response";
    return;
  }

  uint32_t interface_index;
  if (!msg.const_attributes()->GetU32AttributeValue(NL80211_ATTR_IFINDEX,
                                                    &interface_index)) {
    LOG(ERROR) << "Message contains no interface index";
    return;
  }
  uint32_t interface_type;
  if (!msg.const_attributes()->GetU32AttributeValue(NL80211_ATTR_IFTYPE,
                                                    &interface_type)) {
    LOG(ERROR) << "Message contains no interface type";
    return;
  }

  uint32_t phy_index;
  if (!msg.const_attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY,
                                                    &phy_index)) {
    LOG(ERROR) << "Message contains no phy index";
    return;
  }
  const Info* info = GetInfo(interface_index);
  if (!info) {
    LOG(ERROR) << "Could not find device info for interface index "
               << interface_index;
    return;
  }
  if (info->device) {
    LOG(ERROR) << "Device already created for interface index "
               << interface_index;
    return;
  }
  if (interface_type != NL80211_IFTYPE_STATION) {
    LOG(INFO) << "Ignoring WiFi device " << info->name << " at interface index "
              << interface_index << " since it is not in station mode.";
    return;
  }
  LOG(INFO) << "Creating WiFi device for station mode interface " << info->name
            << " at interface index " << interface_index;
  std::string address = info->mac_address.HexEncode();

#if !defined(DISABLE_WAKE_ON_WIFI)
  auto wake_on_wifi = std::make_unique<WakeOnWiFi>(
      netlink_manager_, dispatcher_, metrics_,
      base::BindRepeating(&DeviceInfo::RecordDarkResumeWakeReason,
                          weak_factory_.GetWeakPtr()));
#else
  auto wake_on_wifi = std::unique_ptr<WakeOnWiFi>(nullptr);
#endif  // DISABLE_WAKE_ON_WIFI
  DeviceRefPtr device = new WiFi(manager_, info->name, address, interface_index,
                                 phy_index, std::move(wake_on_wifi));
  RegisterDevice(device);
}

void DeviceInfo::RecordDarkResumeWakeReason(const std::string& wake_reason) {
  manager_->power_manager()->RecordDarkResumeWakeReason(wake_reason);
}

// Verifies if a device is guest by checking if the owner of the device
// identified by |interface_name| has the same UID as the user that runs the
// Crostini VMs.
bool DeviceInfo::IsGuestDevice(const std::string& interface_name) const {
  std::string owner;
  if (!GetDeviceInfoContents(interface_name, kInterfaceOwner, &owner)) {
    return false;
  }
  uint32_t owner_id;
  base::TrimWhitespaceASCII(owner, base::TRIM_ALL, &owner);
  if (!base::StringToUint(owner, &owner_id)) {
    return false;
  }

  uid_t crosvm_user_uid;
  if (!GetUserId(vm_tools::kCrosVmUser, &crosvm_user_uid)) {
    LOG(WARNING) << "unable to get uid for " << vm_tools::kCrosVmUser;
    return false;
  }

  return owner_id == crosvm_user_uid;
}

void DeviceInfo::OnPatchpanelClientReady() {
  manager_->patchpanel_client()->RegisterNeighborReachabilityEventHandler(
      base::BindRepeating(&DeviceInfo::OnNeighborReachabilityEvent,
                          weak_factory_.GetWeakPtr()));
}

void DeviceInfo::OnNeighborReachabilityEvent(
    const patchpanel::Client::NeighborReachabilityEvent& event) {
  SLOG(2) << __func__ << ": " << event;
  auto device = GetDevice(event.ifindex);
  if (!device) {
    LOG(ERROR) << __func__ << " " << event << ": device not found";
    return;
  }

  // Neighbor reachability events never expected in Cellular, so the primary
  // network will always exist.
  CHECK(device->GetPrimaryNetwork());
  device->GetPrimaryNetwork()->OnNeighborReachabilityEvent(event);
}

bool DeviceInfo::GetUserId(const std::string& user_name, uid_t* uid) const {
  return brillo::userdb::GetUserInfo(user_name, uid, nullptr);
}

DeviceInfo::Info::Info()
    : flags(0),
      rx_bytes(0),
      tx_bytes(0),
      received_add_link(false),
      technology(Technology::kUnknown) {}

}  // namespace shill
