// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PCIGUARD_UDEV_MONITOR_H_
#define PCIGUARD_UDEV_MONITOR_H_

#include <libudev.h>

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_monitor.h>

#include "pciguard/event_handler.h"

namespace pciguard {

// Class to monitor thunderbolt/PCI udev events
class UdevMonitor {
 public:
  using PcidevBlockedFn = std::function<void(const std::string& drvr)>;

  explicit UdevMonitor(EventHandler* ev_handler, PcidevBlockedFn callback);
  UdevMonitor(const UdevMonitor&) = delete;
  UdevMonitor& operator=(const UdevMonitor&) = delete;
  ~UdevMonitor() = default;

 private:
  // Handle Udev events emanating from |udev_monitor_watcher_|.
  void OnUdevEvent();

  std::unique_ptr<brillo::Udev> udev_;
  std::unique_ptr<brillo::UdevMonitor> udev_monitor_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      udev_monitor_watcher_;
  std::unique_ptr<EventHandler> event_handler_;
  PcidevBlockedFn pcidev_blocked_callback_;
};

}  // namespace pciguard

#endif  // PCIGUARD_UDEV_MONITOR_H_
