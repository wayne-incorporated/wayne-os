// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/udev_monitor.h"

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/udev/udev_enumerate.h>
#include <re2/re2.h>

namespace {

constexpr char kPartnerAltModeRegex[] = R"(port(\d+)-partner.(\d+))";
constexpr char kCableRegex[] = R"(port(\d+)-cable)";
constexpr char kPortRegex[] = R"(port(\d+))";
// TODO(pmalani): Add SOP'' support when the kernel also supports it.
constexpr char kSOPPrimePlugRegex[] = R"(port(\d+)-plug0)";
constexpr char kSOPPrimePlugAltModeRegex[] = R"(port(\d+)-plug0.(\d+))";
constexpr char kPdRegex[] = R"(pd\d+)";

}  // namespace

namespace typecd {

bool UdevMonitor::InitUdev() {
  udev_ = brillo::Udev::Create();
  if (!udev_) {
    LOG(ERROR) << "Couldn't initialize udev object.";
    return false;
  }

  return true;
}

bool UdevMonitor::ScanDevices() {
  DCHECK(udev_);

  auto enumerate = udev_->CreateEnumerate();
  if (!enumerate->AddMatchSubsystem(kTypeCSubsystem)) {
    PLOG(ERROR) << "Couldn't add typec to enumerator match.";
    return false;
  }

  if (!enumerate->AddMatchSubsystem(kUsbPdSubsystem)) {
    PLOG(ERROR) << "Couldn't add USB PD to enumerator match.";
    return false;
  }

  enumerate->ScanDevices();

  auto entry = enumerate->GetListEntry();
  if (!entry) {
    LOG(INFO) << "No devices found.\n";
    return true;
  }

  while (entry != nullptr) {
    HandleDeviceAddedRemoved(base::FilePath(std::string(entry->GetName())),
                             true, true);
    entry = entry->GetNext();
  }

  return true;
}

bool UdevMonitor::BeginMonitoring() {
  udev_monitor_ = udev_->CreateMonitorFromNetlink(kUdevMonitorName);
  if (!udev_monitor_) {
    LOG(ERROR) << "Failed to create udev monitor.";
    return false;
  }

  if (!udev_monitor_->FilterAddMatchSubsystemDeviceType(kTypeCSubsystem,
                                                        nullptr)) {
    PLOG(ERROR) << "Failed to add typec subsystem to udev monitor.";
    return false;
  }

  if (!udev_monitor_->FilterAddMatchSubsystemDeviceType(kUsbPdSubsystem,
                                                        nullptr)) {
    PLOG(ERROR) << "Failed to add typec subsystem to udev monitor.";
    return false;
  }

  if (!udev_monitor_->EnableReceiving()) {
    PLOG(ERROR) << "Failed to enable receiving for udev monitor.";
    return false;
  }

  int fd = udev_monitor_->GetFileDescriptor();
  if (fd == brillo::UdevMonitor::kInvalidFileDescriptor) {
    PLOG(ERROR) << "Couldn't get udev monitor fd.";
    return false;
  }

  udev_monitor_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd, base::BindRepeating(&UdevMonitor::HandleUdevEvent,
                              base::Unretained(this)));
  if (!udev_monitor_watcher_) {
    LOG(ERROR) << "Couldn't start watcher for udev monitor fd.";
    return false;
  }

  return true;
}

void UdevMonitor::AddTypecObserver(TypecObserver* obs) {
  typec_observer_list_.AddObserver(obs);
}

void UdevMonitor::RemoveTypecObserver(TypecObserver* obs) {
  typec_observer_list_.RemoveObserver(obs);
}

bool UdevMonitor::HandleDeviceAddedRemoved(const base::FilePath& path,
                                           bool added,
                                           bool is_initial_scan) {
  auto name = path.BaseName();
  int port_num;

  for (TypecObserver& observer : typec_observer_list_) {
    if (RE2::FullMatch(name.value(), kPortRegex, &port_num))
      observer.OnPortAddedOrRemoved(path, port_num, added);
    else if (RE2::FullMatch(name.value(), kPartnerRegex, &port_num))
      observer.OnPartnerAddedOrRemoved(path, port_num, added, !is_initial_scan);
    else if (RE2::FullMatch(name.value(), kPartnerAltModeRegex, &port_num))
      observer.OnPartnerAltModeAddedOrRemoved(path, port_num, added);
    else if (RE2::FullMatch(name.value(), kCableRegex, &port_num))
      observer.OnCableAddedOrRemoved(path, port_num, added);
    else if (RE2::FullMatch(name.value(), kSOPPrimePlugRegex, &port_num))
      observer.OnCablePlugAdded(path, port_num);
    else if (RE2::FullMatch(name.value(), kSOPPrimePlugAltModeRegex,
                            &port_num) &&
             added)
      observer.OnCableAltModeAdded(path, port_num);
    else if (RE2::FullMatch(name.value(), kPdRegex))
      observer.OnPdDeviceAddedOrRemoved(path, added);
  }

  return true;
}

void UdevMonitor::HandleDeviceChange(const base::FilePath& path) {
  auto name = path.BaseName();
  int port_num;

  for (auto& observer : typec_observer_list_) {
    if (RE2::FullMatch(name.value(), kPartnerRegex, &port_num))
      observer.OnPartnerChanged(port_num);
    else if (RE2::FullMatch(name.value(), kPortRegex, &port_num))
      observer.OnPortChanged(port_num);
  }
}

void UdevMonitor::HandleUdevEvent() {
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

  if (action == "add")
    HandleDeviceAddedRemoved(path, true);
  else if (action == "remove")
    HandleDeviceAddedRemoved(path, false);
  else if (action == "change")
    HandleDeviceChange(path);
}

}  // namespace typecd
