// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_DEVICE_EJECTOR_H_
#define CROS_DISKS_DEVICE_EJECTOR_H_

#include <map>
#include <memory>
#include <string>

#include <brillo/process/process_reaper.h>

#include "cros-disks/sandboxed_process.h"

namespace cros_disks {

// A class for ejecting any removable media on a device.
class DeviceEjector {
 public:
  explicit DeviceEjector(brillo::ProcessReaper* process_reaper);
  DeviceEjector(const DeviceEjector&) = delete;
  DeviceEjector& operator=(const DeviceEjector&) = delete;

  virtual ~DeviceEjector();

  // Ejects any removable media on a device at |device_path| using the
  // 'eject' program. Returns true if the eject process has launched
  // successfully (but may not complete until OnEjectProcessTerminated
  // is called).
  virtual bool Eject(const std::string& device_path);

 private:
  // Invoked when an eject process has terminated.
  void OnEjectProcessTerminated(const std::string& device_path,
                                const siginfo_t& info);

  brillo::ProcessReaper* process_reaper_;

  // A list of outstanding eject processes indexed by device path.
  std::map<std::string, SandboxedProcess> eject_process_;

  base::WeakPtrFactory<DeviceEjector> weak_ptr_factory_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_DEVICE_EJECTOR_H_
