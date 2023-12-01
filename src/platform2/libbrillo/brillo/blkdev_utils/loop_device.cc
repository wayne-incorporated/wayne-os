// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/blkdev_utils/loop_device.h>

#include <fcntl.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace brillo {

namespace {

constexpr char kLoopControl[] = "/dev/loop-control";
constexpr char kSysBlockPath[] = "/sys/block";
// File containing device id in /sys/block/loopX/.
constexpr char kDeviceIdPath[] = "dev";
constexpr char kLoopBackingFile[] = "loop/backing_file";
constexpr int kLoopDeviceIoctlFlags = O_RDWR | O_NOFOLLOW | O_CLOEXEC;
constexpr int kLoopControlIoctlFlags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
// Arbitrary retry limit for attempting to attach a loop device.
constexpr int kMaxLoopDeviceAttachTries = 10;

// ioctl runner for LoopDevice and LoopDeviceManager
int LoopDeviceIoctl(const base::FilePath& device,
                    int type,
                    uint64_t arg,
                    int open_flag) {
  base::ScopedFD device_fd(
      HANDLE_EINTR(open(device.value().c_str(), open_flag)));

  if (!device_fd.is_valid()) {
    PLOG(ERROR) << "Unable to open loop device";
    return -EINVAL;
  }

  // Some ioctl failures may be informational (eg. on non-existent loop
  // devices) so it is left to users of this function to log actual errors.
  int result = ioctl(device_fd.get(), type, arg);
  return result < 0 ? -errno : result;
}

// Parse the device number for a valid /sys/block/loopX path
// or symlink to such a path.
// Returns -1 if invalid.
int GetDeviceNumber(const base::FilePath& sys_block_loopdev_path) {
  std::string device_string;
  int device_number = -1;

  base::FilePath device_file = sys_block_loopdev_path.Append(kDeviceIdPath);

  if (!base::ReadFileToString(device_file, &device_string))
    return -1;

  std::vector<std::string> device_ids = base::SplitString(
      device_string, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (device_ids.size() != 2 ||
      device_ids[0] != base::NumberToString(LOOP_MAJOR))
    return -1;

  base::StringToInt(device_ids[1], &device_number);
  return device_number;
}

// For a validated loop device path, return the backing file path.
// Note that a pre-populated loop device path would return an empty
// backing file.
base::FilePath GetBackingFile(const base::FilePath& loopdev_path) {
  // Backing file contains path to associated source for loop devices.
  base::FilePath backing_file = loopdev_path.Append(kLoopBackingFile);
  std::string backing_file_content;
  // If the backing file doesn't exist, it's not an attached loop device.
  if (!base::ReadFileToString(backing_file, &backing_file_content))
    return base::FilePath();
  base::FilePath backing_file_path(
      base::TrimWhitespaceASCII(backing_file_content, base::TRIM_ALL));

  return backing_file_path;
}

base::FilePath CreateDevicePath(int device_number) {
  return base::FilePath(base::StringPrintf("/dev/loop%d", device_number));
}

}  // namespace

LoopDevice::LoopDevice(int device_number,
                       const base::FilePath& backing_file,
                       const LoopIoctl& ioctl_runner)
    : device_number_(device_number),
      backing_file_(backing_file),
      loop_ioctl_(ioctl_runner) {}

bool LoopDevice::SetStatus(struct loop_info64 info) {
  int err =
      loop_ioctl_.Run(GetDevicePath(), LOOP_SET_STATUS64,
                      reinterpret_cast<uint64_t>(&info), kLoopDeviceIoctlFlags);
  if (err < 0) {
    LOG_IF(ERROR, err != -ENXIO) << "ioctl(LOOP_SET_STATUS64) failed";
    return false;
  }
  return true;
}

bool LoopDevice::GetStatus(struct loop_info64* info) {
  int err =
      loop_ioctl_.Run(GetDevicePath(), LOOP_GET_STATUS64,
                      reinterpret_cast<uint64_t>(info), kLoopDeviceIoctlFlags);

  if (err < 0) {
    // Loop devices that are not attached to a file will fail with -ENXIO.
    LOG_IF(ERROR, err != -ENXIO)
        << "ioctl(LOOP_GET_STATUS64) failed, err: " << err;
    return false;
  }
  return true;
}

bool LoopDevice::SetName(const std::string& name) {
  struct loop_info64 info;

  memset(&info, 0, sizeof(info));
  strncpy(reinterpret_cast<char*>(info.lo_file_name), name.c_str(),
          LO_NAME_SIZE);
  return SetStatus(info);
}

bool LoopDevice::Detach() {
  int err =
      loop_ioctl_.Run(GetDevicePath(), LOOP_CLR_FD, 0, kLoopDeviceIoctlFlags);
  if (err < 0) {
    LOG_IF(ERROR, err != -ENXIO) << "ioctl(LOOP_CLR_FD) failed, err: " << err;
    return false;
  }

  return true;
}

base::FilePath LoopDevice::GetDevicePath() {
  return CreateDevicePath(device_number_);
}

bool LoopDevice::IsValid() {
  return device_number_ >= 0;
}

LoopDeviceManager::LoopDeviceManager()
    : loop_ioctl_(base::BindRepeating(&LoopDeviceIoctl)) {}

LoopDeviceManager::LoopDeviceManager(const LoopIoctl& ioctl_runner)
    : loop_ioctl_(ioctl_runner) {}

std::unique_ptr<LoopDevice> LoopDeviceManager::AttachDeviceToFile(
    const base::FilePath& backing_file) {
  int device_number = -1;
  int retries = kMaxLoopDeviceAttachTries;

  while (retries >= 0) {
    device_number =
        loop_ioctl_.Run(base::FilePath(kLoopControl), LOOP_CTL_GET_FREE, 0,
                        kLoopControlIoctlFlags);

    if (device_number < 0) {
      LOG(ERROR) << "ioctl(LOOP_CTL_GET_FREE) failed";
      return CreateLoopDevice(-1, base::FilePath());
    }

    base::ScopedFD backing_file_fd(
        HANDLE_EINTR(open(backing_file.value().c_str(), O_RDWR)));

    if (!backing_file_fd.is_valid()) {
      LOG(ERROR) << "Failed to open backing file.";
      return CreateLoopDevice(-1, base::FilePath());
    }

    base::FilePath device_path = CreateDevicePath(device_number);

    if (loop_ioctl_.Run(device_path, LOOP_SET_FD, backing_file_fd.get(),
                        kLoopDeviceIoctlFlags) == 0)
      break;

    if (errno != EBUSY) {
      LOG(ERROR) << "ioctl(LOOP_SET_FD) failed";
      return CreateLoopDevice(-1, base::FilePath());
    }

    // Other users could have set the file descriptor between get a valid
    // loop device number and using it. Continue to loop until the device is
    // created.
    retries--;
  }

  if (retries < 0) {
    LOG(ERROR) << "Failed to set up loop device after "
               << kMaxLoopDeviceAttachTries << " retries.";
    return CreateLoopDevice(-1, base::FilePath());
  }

  // Set direct I/O mode for the backing file for the loop device, if supported.
  if (loop_ioctl_.Run(CreateDevicePath(device_number), LOOP_SET_DIRECT_IO, 1,
                      kLoopDeviceIoctlFlags) != 0)
    PLOG(WARNING) << "Direct I/O mode is not supported.";

  // All steps of setting up the loop device succeeded.
  return CreateLoopDevice(device_number, backing_file);
}

std::vector<std::unique_ptr<LoopDevice>>
LoopDeviceManager::GetAttachedDevices() {
  return SearchLoopDevicePaths();
}

std::unique_ptr<LoopDevice> LoopDeviceManager::GetAttachedDeviceByNumber(
    int device_number) {
  auto devices = SearchLoopDevicePaths(device_number);

  if (devices.empty())
    return CreateLoopDevice(-1, base::FilePath());

  return std::move(devices[0]);
}

std::unique_ptr<LoopDevice> LoopDeviceManager::GetAttachedDeviceByName(
    const std::string& name) {
  std::vector<std::unique_ptr<LoopDevice>> devices = GetAttachedDevices();

  for (auto& attached_device : devices) {
    struct loop_info64 device_info;

    // GetStatus() can fail for loop devices that have LOOP_CLEAR_FD called
    // while the device node still hasn't been cleaned up by udev.
    if (!attached_device->GetStatus(&device_info)) {
      continue;
    }

    if (strcmp(reinterpret_cast<char*>(device_info.lo_file_name),
               name.c_str()) == 0)
      return std::move(attached_device);
  }

  return CreateLoopDevice(-1, base::FilePath());
}

// virtual
std::vector<std::unique_ptr<LoopDevice>>
LoopDeviceManager::SearchLoopDevicePaths(int device_number) {
  std::vector<std::unique_ptr<LoopDevice>> devices;
  base::FilePath rootdir(kSysBlockPath);

  if (device_number != -1) {
    auto loopdev_path =
        rootdir.Append(base::StringPrintf("loop%d", device_number));
    if (base::PathExists(loopdev_path))
      devices.push_back(
          CreateLoopDevice(device_number, GetBackingFile(loopdev_path)));
  } else {
    // Read /sys/block to discover all loop devices.
    base::FileEnumerator loopdev_enum(
        rootdir, false /*recursive*/,
        base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS,
        "loop*");

    for (auto loopdev = loopdev_enum.Next(); !loopdev.empty();
         loopdev = loopdev_enum.Next()) {
      int dev_number = GetDeviceNumber(loopdev);
      if (dev_number != -1) {
        auto attached_device =
            CreateLoopDevice(dev_number, GetBackingFile(loopdev));

        struct loop_info64 device_info;
        // GetStatus() can fail for loop devices that have LOOP_CLEAR_FD called
        // while the device node still hasn't been cleaned up by udev.
        if (attached_device->GetStatus(&device_info)) {
          devices.push_back(std::move(attached_device));
        }
      }
    }
  }
  return devices;
}

std::unique_ptr<LoopDevice> LoopDeviceManager::CreateLoopDevice(
    int device_number, const base::FilePath& backing_file) {
  return std::make_unique<LoopDevice>(device_number, backing_file, loop_ioctl_);
}

}  // namespace brillo
