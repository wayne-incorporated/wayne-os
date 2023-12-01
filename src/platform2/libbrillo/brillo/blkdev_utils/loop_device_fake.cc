// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/blkdev_utils/loop_device_fake.h>

#include <linux/loop.h>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/loop_device.h>

// Not a loop ioctl: we only use this to get the backing file from
// the stubbed function. All loop device ioctls start with 0x4c.
#define LOOP_GET_DEV 0x4cff

namespace brillo {
namespace fake {

namespace {

int ParseLoopDeviceNumber(const base::FilePath& device_path) {
  int device_number;
  std::string path_string = device_path.value();
  return base::StartsWith(path_string, "/dev/loop",
                          base::CompareCase::SENSITIVE) &&
                 base::StringToInt(path_string.substr(9), &device_number)
             ? device_number
             : -1;
}

base::FilePath GetLoopDevicePath(int device_number) {
  return base::FilePath(base::StringPrintf("/dev/loop%d", device_number));
}

}  // namespace

int FakeLoopDeviceManager::StubIoctlRunner(
    base::WeakPtr<FakeLoopDeviceManager> manager,
    const base::FilePath& path,
    int type,
    uint64_t arg,
    int flag) {
  if (!manager)
    return -1;
  int device_number = ParseLoopDeviceNumber(path);
  struct loop_info64* info;
  struct LoopDev* device;
  std::vector<LoopDev>& loop_device_vector = manager->loop_device_vector_;

  switch (type) {
    case LOOP_GET_STATUS64:
      if (loop_device_vector.size() <= device_number ||
          loop_device_vector[device_number].valid == false)
        return -1;
      info = reinterpret_cast<struct loop_info64*>(arg);
      memcpy(info, &loop_device_vector[device_number].info,
             sizeof(struct loop_info64));
      return 0;
    case LOOP_SET_STATUS64:
      if (loop_device_vector.size() <= device_number ||
          loop_device_vector[device_number].valid == false)
        return -1;
      info = reinterpret_cast<struct loop_info64*>(arg);
      memcpy(&loop_device_vector[device_number].info, info,
             sizeof(struct loop_info64));
      return 0;
    case LOOP_CLR_FD:
      if (loop_device_vector.size() <= device_number ||
          loop_device_vector[device_number].valid == false)
        return -1;
      loop_device_vector[device_number].valid = false;
      return 0;
    case LOOP_CTL_GET_FREE:
      device_number = loop_device_vector.size();
      loop_device_vector.push_back({true, base::FilePath(), {0}});
      return device_number;
    // Instead of passing the fd here, we pass the FilePath of the backing
    // file.
    case LOOP_SET_FD:
      if (loop_device_vector.size() <= device_number)
        return -1;
      loop_device_vector[device_number].backing_file =
          *reinterpret_cast<const base::FilePath*>(arg);
      return 0;
    // Not a loop ioctl; Only used for conveniently checking the
    // validity of the loop devices.
    case LOOP_GET_DEV:
      if (device_number >= loop_device_vector.size())
        return -1;
      device = reinterpret_cast<struct LoopDev*>(arg);
      device->valid = loop_device_vector[device_number].valid;
      device->backing_file = loop_device_vector[device_number].backing_file;
      memset(&(device->info), 0, sizeof(struct loop_info64));
      return 0;
    default:
      return -1;
  }
}

FakeLoopDeviceManager::FakeLoopDeviceManager()
    : LoopDeviceManager(LoopIoctl()) {
  // The callback passed to the parent class should be never invoked in the fake
  // environment, hence it's OK to pass it as null.
}

std::unique_ptr<LoopDevice> FakeLoopDeviceManager::AttachDeviceToFile(
    const base::FilePath& backing_file) {
  int device_number = loop_device_vector_.size();
  loop_device_vector_.push_back({true, base::FilePath(), {0}});

  if (StubIoctlRunner(weak_factory_.GetWeakPtr(),
                      GetLoopDevicePath(device_number), LOOP_SET_FD,
                      reinterpret_cast<uint64_t>(&backing_file), 0) < 0) {
    return std::make_unique<LoopDevice>(
        -1, base::FilePath(),
        base::BindRepeating(&FakeLoopDeviceManager::StubIoctlRunner,
                            weak_factory_.GetWeakPtr()));
  }

  return std::make_unique<LoopDevice>(
      device_number, backing_file,
      base::BindRepeating(&FakeLoopDeviceManager::StubIoctlRunner,
                          weak_factory_.GetWeakPtr()));
}

std::vector<std::unique_ptr<LoopDevice>>
FakeLoopDeviceManager::SearchLoopDevicePaths(int device_number) {
  std::vector<std::unique_ptr<LoopDevice>> devices;
  struct LoopDev device;

  if (device_number != -1) {
    if (StubIoctlRunner(weak_factory_.GetWeakPtr(),
                        GetLoopDevicePath(device_number), LOOP_GET_DEV,
                        reinterpret_cast<uint64_t>(&device), 0) < 0)
      return devices;

    if (device.valid) {
      devices.push_back(std::make_unique<LoopDevice>(
          device_number, device.backing_file,
          base::BindRepeating(&FakeLoopDeviceManager::StubIoctlRunner,
                              weak_factory_.GetWeakPtr())));
    }
    return devices;
  }

  int i = 0;
  while (StubIoctlRunner(weak_factory_.GetWeakPtr(), GetLoopDevicePath(i),
                         LOOP_GET_DEV, reinterpret_cast<uint64_t>(&device),
                         0) == 0) {
    if (device.valid) {
      devices.push_back(std::make_unique<LoopDevice>(
          i, device.backing_file,
          base::BindRepeating(&FakeLoopDeviceManager::StubIoctlRunner,
                              weak_factory_.GetWeakPtr())));
    }
    i++;
  }
  return devices;
}

}  // namespace fake
}  // namespace brillo
