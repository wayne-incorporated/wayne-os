// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_H_

#include <linux/loop.h>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <brillo/secure_blob.h>

namespace brillo {

// Forward declaration used by LoopDevice.
class LoopDeviceManager;

using LoopIoctl =
    base::RepeatingCallback<int(const base::FilePath&, int, uint64_t, int)>;

// LoopDevice provides an interface to attached loop devices.
// In order to simplify handling of loop devices, there
// is no inherent modifiable state associated within objects:
// the device number and backing file are consts.
// The intent here is for no class to create a LoopDevice
// directly; instead use LoopDeviceManager to get devices.
class BRILLO_EXPORT LoopDevice {
 public:
  // Create a loop device with a ioctl runner.
  // Parameters
  //   device_number - loop device number.
  //   backing_file - backing file for the device.
  //   ioctl_runner - function to run loop ioctls.
  LoopDevice(int device_number,
             const base::FilePath& backing_file,
             const LoopIoctl& ioctl_runner);
  ~LoopDevice() = default;

  // Set device status.
  // Parameters
  //   info - struct containing status.
  bool SetStatus(struct loop_info64 info);
  // Get device status.
  // Parameters
  //   info - struct to populate.
  bool GetStatus(struct loop_info64* info);
  // Set device name.
  // Parameters
  //   name - device name
  bool SetName(const std::string& name);
  // Detach device.
  bool Detach();
  // Check if device is valid;
  bool IsValid();

  // Getters for device parameters.
  base::FilePath GetBackingFilePath() { return backing_file_; }
  base::FilePath GetDevicePath();

 private:
  const int device_number_;
  const base::FilePath backing_file_;
  // Ioctl runner.
  LoopIoctl loop_ioctl_;
};

// Loop Device Manager handles requests for creating or fetching
// existing loop devices. If creation/fetch fails, the loop device
// manager returns nullptr.
class BRILLO_EXPORT LoopDeviceManager {
 public:
  LoopDeviceManager();
  // Create a loop device manager with a non-default ioctl runner.
  // Parameters
  //   ioctl_runner - base::RepeatingCallback to run ioctls.
  explicit LoopDeviceManager(const LoopIoctl& ioctl_runner);
  LoopDeviceManager(const LoopDeviceManager&) = delete;
  LoopDeviceManager& operator=(const LoopDeviceManager&) = delete;

  virtual ~LoopDeviceManager() = default;

  // Allocates a loop device and attaches it to a backing file.
  // Parameters
  //   backing_file - file to attach device to.
  virtual std::unique_ptr<LoopDevice> AttachDeviceToFile(
      const base::FilePath& backing_file);

  // Fetches all attached loop devices.
  std::vector<std::unique_ptr<LoopDevice>> GetAttachedDevices();

  // Fetches a loop device by device number.
  std::unique_ptr<LoopDevice> GetAttachedDeviceByNumber(int device_number);

  // Fetches a device number by name.
  std::unique_ptr<LoopDevice> GetAttachedDeviceByName(const std::string& name);

 private:
  // Search for loop devices by device number; if no device number is given,
  // default to searaching and returning all loop devices.
  virtual std::vector<std::unique_ptr<LoopDevice>> SearchLoopDevicePaths(
      int device_number = -1);
  // Create loop device with current ioctl runner.
  // Parameters
  //   device_number - device number.
  //   backing_file - path to backing file.
  std::unique_ptr<LoopDevice> CreateLoopDevice(
      int device_number, const base::FilePath& backing_file);

  LoopIoctl loop_ioctl_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_LOOP_DEVICE_H_
