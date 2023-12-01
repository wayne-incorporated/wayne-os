// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// brillo::DevmapperTask is a lower level device-mapper construct which denotes
// an operation on a dm target. This class is mostly meant to be used as a
// building block for the simpler, application-friendly brillo::DeviceMapper
// interface.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_TASK_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_TASK_H_

#include <libdevmapper.h>
#include <memory>
#include <string>

#include <brillo/secure_blob.h>

namespace brillo {

using DmTaskPtr = std::unique_ptr<dm_task, void (*)(dm_task*)>;

// The device mapper driver maintains versions for both its kernel drivers and
// for each specific target. Specifically, version numbers are used to signal
// whether a particular feature is supported, either by the kernel driver or
// by a specific target.
struct DeviceMapperVersion {
  uint32_t major;
  uint32_t minor;
  uint32_t patchlevel;

  bool operator<(const DeviceMapperVersion& rhs) const {
    return std::tie(major, minor, patchlevel) <
           std::tie(rhs.major, rhs.minor, rhs.patchlevel);
  }
};

// Abstract class to manage DM devices.
// This class implements the bare minimum set of functions
// required to create/remove DM devices. DevmapperTask is the equivalent
// of a command to the device mapper to set/get targets associated with a
// logical DM device, but omits, for now, finer-grained commands.
// A target represents a segment of a DM device.
//
// The abstract class is strictly based on the dm_task_* functions
// from libdevmapper, but the interface provides sufficient flexibility
// for other implementations (eg. invoking dmsetup) or testing facades.
//
// The task type enum is defined in libdevmapper.h: for simplicity, the same
// enum types are reused in fake implementations of DevmapperTask.
// The following task types have been tested with DeviceMapper functions:
// - DM_DEVICE_CREATE: used in DeviceMapper::Setup.
// - DM_DEVICE_REMOVE: used in DeviceMapper::Remove.
// - DM_DEVICE_TABLE: used in DeviceMapper::GetTable and
//                    DeviceMapper::WipeTable.
// - DM_DEVICE_RELOAD: used in DeviceMapper::WipeTable.
// - DM_GET_TARGET_VERSION: used in DeviceMapper::GetVersion.
class DevmapperTask {
 public:
  virtual ~DevmapperTask() = default;
  // Sets device name for the command.
  virtual bool SetName(const std::string& name) = 0;

  // Adds a target to the command. Should be followed by a Run();
  // Parameters:
  //   start: start of target in device.
  //   sectors: number of sectors in the target.
  //   type: type of the target.
  //   parameters: target parameters.
  virtual bool AddTarget(uint64_t start,
                         uint64_t sectors,
                         const std::string& type,
                         const SecureBlob& parameters) = 0;
  // Gets the next target from the command.
  // Returns true while another target exists.
  // If no target exist for the device, GetNextTarget sets all
  // parameters to 0 and returns false.
  //
  // Parameters:
  //   start: start of target in device.
  //   sectors: number of sectors in the target.
  //   type: type of the target.
  //   parameters: target parameters.
  virtual bool GetNextTarget(uint64_t* start,
                             uint64_t* sectors,
                             std::string* type,
                             SecureBlob* parameters) = 0;
  // Run the task.
  // Returns true if the task succeeded.
  //
  // Parameters:
  //   udev_sync: Enable/Disable udev_synchronization. Defaults to false.
  //              Enable only for tasks that create/remove/rename files to
  //              prevent both udevd and libdevmapper from attempting to
  //              add or remove files.
  virtual bool Run(bool udev_sync = false) = 0;

  // Returns version for the current task's target type. Each device
  // mapper target maintains a separate version in source that acts as an
  // indicator of whether a feature (eg. keyring support for dm-crypt) is
  // supported. On failure, return {0, 0, 0} which disallows any
  // version-specific features.
  virtual DeviceMapperVersion GetVersion() = 0;

  // Set deferred removal for the task. If set to true, the device is removed
  // once the last user closes it.
  // Deferred removal is supported from kernel 3.13 onwards.
  // Returns true if the flag is successfully set.
  virtual bool SetDeferredRemove() = 0;
};

// Libdevmapper implementation for DevmapperTask.
class DevmapperTaskImpl : public DevmapperTask {
 public:
  explicit DevmapperTaskImpl(int type);
  ~DevmapperTaskImpl() override = default;
  bool SetName(const std::string& name) override;
  bool AddTarget(uint64_t start,
                 uint64_t sectors,
                 const std::string& target,
                 const SecureBlob& parameters) override;
  bool GetNextTarget(uint64_t* start,
                     uint64_t* sectors,
                     std::string* target,
                     SecureBlob* parameters) override;
  bool Run(bool udev_sync = true) override;
  DeviceMapperVersion GetVersion() override;
  bool SetDeferredRemove() override;

 private:
  DmTaskPtr task_;
  void* next_target_ = nullptr;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_DEVICE_MAPPER_TASK_H_
