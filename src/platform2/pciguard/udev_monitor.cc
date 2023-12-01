// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pciguard/udev_monitor.h"
#include "pciguard/daemon.h"

#include <base/logging.h>

namespace pciguard {

namespace {

const char kUdev[] = "udev";
const char kThunderboltSubsystem[] = "thunderbolt";
const char kThunderboltDevice[] = "thunderbolt_device";
const char kPCISubsystem[] = "pci";

}  // namespace

UdevMonitor::UdevMonitor(EventHandler* ev_handler, PcidevBlockedFn callback)
    : event_handler_(ev_handler), pcidev_blocked_callback_(callback) {
  udev_ = brillo::Udev::Create();
  if (!udev_) {
    PLOG(ERROR) << "Failed to initialize udev object.";
    exit(EXIT_FAILURE);
  }

  udev_monitor_ = udev_->CreateMonitorFromNetlink(kUdev);
  if (!udev_monitor_) {
    PLOG(ERROR) << "Failed to create udev monitor.";
    exit(EXIT_FAILURE);
  }

  if (!udev_monitor_->FilterAddMatchSubsystemDeviceType(kThunderboltSubsystem,
                                                        kThunderboltDevice)) {
    PLOG(ERROR) << "Failed to add thunderbolt subsystem to udev monitor.";
    exit(EXIT_FAILURE);
  }

  if (!udev_monitor_->FilterAddMatchSubsystemDeviceType(kPCISubsystem,
                                                        nullptr)) {
    PLOG(ERROR) << "Failed to add PCI subsystem to udev monitor.";
    exit(EXIT_FAILURE);
  }

  if (!udev_monitor_->EnableReceiving()) {
    PLOG(ERROR) << "Failed to enable receiving for udev monitor.";
    exit(EXIT_FAILURE);
  }

  int fd = udev_monitor_->GetFileDescriptor();
  if (fd == brillo::UdevMonitor::kInvalidFileDescriptor) {
    PLOG(ERROR) << "Failed to get udev monitor fd.";
    exit(EXIT_FAILURE);
  }

  udev_monitor_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd,
      base::BindRepeating(&UdevMonitor::OnUdevEvent, base::Unretained(this)));
  if (!udev_monitor_watcher_) {
    PLOG(ERROR) << "Failed to start watcher for udev monitor fd.";
    exit(EXIT_FAILURE);
  }
}

void UdevMonitor::OnUdevEvent() {
  auto device = udev_monitor_->ReceiveDevice();
  if (!device) {
    LOG(ERROR) << "Udev receive device failed.";
    return;
  }

  auto path = base::FilePath(device->GetSysPath());
  if (path.empty()) {
    LOG(ERROR) << "Failed to get device syspath.";
    return;
  }

  auto action = std::string(device->GetAction());
  if (action.empty()) {
    LOG(ERROR) << "Failed to get device action.";
    return;
  }

  auto subsystem = std::string(device->GetSubsystem());
  if (subsystem.empty()) {
    LOG(ERROR) << "Failed to get device subsystem";
    return;
  }

  if (subsystem == "thunderbolt") {
    if (action == "add" || action == "remove")
      LOG(INFO) << "UdevEvent: " << subsystem << " " << action << " " << path;

    if (action == "add")
      event_handler_->OnNewThunderboltDev(path);

  } else if (subsystem == "pci" && action == "change") {
    auto property = device->GetPropertyValue("EVENT");
    auto event = std::string(property ? property : "");

    property = device->GetPropertyValue("DRVR");
    auto drvr = std::string(property ? property : "");

    LOG(INFO) << "UdevEvent: " << subsystem << " " << action << " " << event
              << " " << drvr << " " << path;

    if (event == "BLOCKED")
      pcidev_blocked_callback_(drvr);
  }
}

}  // namespace pciguard
