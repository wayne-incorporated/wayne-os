// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pciguard/sysfs_utils.h"

#include <base/command_line.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>

#include <set>
#include <string>
#include <sysexits.h>

namespace pciguard {

namespace {

// Actual driver allowlist.
const char* kAllowlist[] = {
    // TODO(b/163121310): Finalize allowlist
    "pcieport",  // PCI Core services - AER, Hotplug etc.
    "xhci_hcd",  // XHCI host controller driver.
    "nvme",      // PCI Express NVME host controller driver.
    "ahci",      // AHCI driver
    "igb",       // Intel Gigabit Ethernet driver
    "igc",       // Intel I225-LM/I225-V Ethernet controller driver
    "atlantic",  // Aquantia 10gbps Ethernet NIC driver
};

}  // namespace

SysfsUtils::SysfsUtils() : SysfsUtils(FilePath("/")) {}

SysfsUtils::SysfsUtils(FilePath root)
    : allowlist_path_(root.Append("sys/bus/pci/drivers_allowlist")),
      pci_lockdown_path_(root.Append("sys/bus/pci/drivers_allowlist_lockdown")),
      pci_rescan_path_(root.Append("sys/bus/pci/rescan")),
      tbt_devices_path_(root.Append("sys/bus/thunderbolt/devices")),
      pci_devices_path_(root.Append("sys/bus/pci/devices")) {}

int SysfsUtils::SetAuthorizedAttribute(base::FilePath devpath, bool enable) {
  if (!PathExists(devpath)) {
    PLOG(ERROR) << "Path doesn't exist : " << devpath;
    return EXIT_FAILURE;
  }

  base::FilePath symlink;
  // Check it is a thunderbolt path
  if (!base::ReadSymbolicLink(devpath.Append("subsystem"), &symlink) ||
      !base::EndsWith(symlink.value(), "/bus/thunderbolt",
                      base::CompareCase::SENSITIVE)) {
    LOG(ERROR) << "Not a thunderbolt devpath: " << devpath;
    return EXIT_FAILURE;
  }

  base::FilePath authorized_path = devpath.Append("authorized");
  std::string authorized;

  // Proceed only if authorized file exists
  if (!base::ReadFileToString(authorized_path, &authorized))
    return EXIT_SUCCESS;

  // Nevermind if no need to change the state.
  if (!authorized.empty() &&
      ((enable && authorized[0] != '0') || (!enable && authorized[0] == '0')))
    return EXIT_SUCCESS;

  auto val = "0";
  if (enable) {
    LOG(INFO) << "Authorizing:" << devpath;
    val = "1";
  } else {
    LOG(INFO) << "Deauthorizing:" << devpath;
  }

  if (base::WriteFile(authorized_path, val, 1) != 1) {
    PLOG(ERROR) << "Couldn't write " << val << " to " << authorized_path;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int SysfsUtils::DeauthorizeThunderboltDev(base::FilePath devpath) {
  return SetAuthorizedAttribute(devpath, false);
}

int SysfsUtils::OnInit(void) {
  if (!base::PathIsWritable(allowlist_path_) ||
      !base::PathIsWritable(pci_lockdown_path_)) {
    PLOG(ERROR) << "Kernel is missing needed support for external PCI security";
    return EX_OSFILE;
  }

  if (base::WriteFile(pci_lockdown_path_, "1", 1) != 1) {
    PLOG(ERROR) << "Couldn't write 1 to " << pci_lockdown_path_;
    return EX_IOERR;
  }

  for (const char* drvr_name : kAllowlist) {
    auto len = strlen(drvr_name);
    if (base::WriteFile(allowlist_path_, drvr_name, len) == len)
      LOG(INFO) << "Allowed " << drvr_name;
    else
      PLOG(ERROR) << "Couldn't allow " << drvr_name;
  }
  return EX_OK;
}

int SysfsUtils::AuthorizeThunderboltDev(base::FilePath devpath) {
  return SetAuthorizedAttribute(devpath, true);
}

int SysfsUtils::AuthorizeAllDevices(void) {
  LOG(INFO) << "Authorizing all external PCI devices";

  // Allow drivers to bind to PCI devices. This also binds any PCI devices
  // that may have been hotplugged "into" external peripherals, while the
  // screen was locked.
  if (base::WriteFile(pci_lockdown_path_, "0", 1) != 1) {
    PLOG(ERROR) << "Couldn't write 0 to " << pci_lockdown_path_;
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;

  // Add any PCI devices that we removed when the user had logged off.
  if (base::WriteFile(pci_rescan_path_, "1", 1) != 1) {
    PLOG(ERROR) << "Couldn't write 1 to " << pci_rescan_path_;
    ret = EXIT_FAILURE;
  }

  // Create an BFS ordered set of thunderbolt devices.
  auto cmp = [](const base::FilePath& dev1, const base::FilePath& dev2) {
    base::FilePath symlink1, symlink2;
    (void)base::ReadSymbolicLink(dev1, &symlink1);
    (void)base::ReadSymbolicLink(dev2, &symlink2);
    return symlink1 < symlink2;
  };
  std::set<base::FilePath, decltype(cmp)> thunderbolt_devs(cmp);
  base::FileEnumerator iter(tbt_devices_path_, false,
                            base::FileEnumerator::DIRECTORIES);
  for (auto devpath = iter.Next(); !devpath.empty(); devpath = iter.Next())
    thunderbolt_devs.insert(devpath);

  // Authorize the thunderbolt devices in BFS order (sorting using the
  // symlinks to which the devices point, gives us BFS). This is
  // required because if a parent is deauthorized, the children are
  // automatically deauthorized, but vice versa is not true.
  for (auto dev : thunderbolt_devs) {
    if (AuthorizeThunderboltDev(dev))
      ret = EXIT_FAILURE;
  }

  return ret;
}

int SysfsUtils::DenyNewDevices(void) {
  LOG(INFO) << "Will deny all new external PCI devices";

  // Deny drivers to bind to any *new* external PCI devices.
  if (base::WriteFile(pci_lockdown_path_, "1", 1) != 1) {
    PLOG(ERROR) << "Couldn't write 1 to " << pci_lockdown_path_;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int SysfsUtils::DeauthorizeAllDevices(void) {
  int ret = EXIT_SUCCESS;
  if (DenyNewDevices())
    return EXIT_FAILURE;

  LOG(INFO) << "Deauthorizing all external PCI devices";

  // Remove all untrusted (external) PCI devices.
  base::FileEnumerator iter(pci_devices_path_, false,
                            base::FileEnumerator::DIRECTORIES);
  for (auto devpath = iter.Next(); !devpath.empty(); devpath = iter.Next()) {
    std::string removable;

    // It is possible this device may already been have removed (as an effect
    // of its parent being removed).
    if (!PathExists(devpath))
      continue;

    // Proceed only if it is a removable device
    if (!base::ReadFileToString(devpath.Append("removable"), &removable) ||
        removable != "removable")
      continue;

    // Remove device.
    if (base::WriteFile(devpath.Append("remove"), "1", 1) != 1) {
      PLOG(ERROR) << "Couldn't remove untrusted device " << devpath;
      ret = EXIT_FAILURE;
    }
  }

  // Deauthorize all thunderbolt devices.
  base::FileEnumerator tbt_iter(tbt_devices_path_, false,
                                base::FileEnumerator::DIRECTORIES);
  for (auto devpath = tbt_iter.Next(); !devpath.empty();
       devpath = tbt_iter.Next()) {
    if (DeauthorizeThunderboltDev(devpath))
      ret = EXIT_FAILURE;
  }
  return ret;
}

}  // namespace pciguard
