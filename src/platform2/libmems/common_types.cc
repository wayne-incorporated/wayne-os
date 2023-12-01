// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libmems/common_types.h"

#include <libudev.h>
#include <memory>

#include <base/logging.h>

namespace libmems {

namespace {

struct UdevDeviceDeleter {
  void operator()(udev_device* dev) {
    if (dev)
      udev_device_unref(dev);
  }
};

std::vector<std::string> GetDevlinks(const std::string& syspath) {
  std::vector<std::string> out;
  auto udev = udev_new();
  if (!udev) {
    LOG(ERROR) << "udev_new failed";
    return out;
  }

  std::unique_ptr<udev_device, UdevDeviceDeleter> device(
      udev_device_new_from_syspath(udev, syspath.c_str()));
  if (!device) {
    LOG(WARNING) << "Failed to open udev device: " << syspath;
    return out;
  }

  struct udev_list_entry* devlink =
      udev_device_get_devlinks_list_entry(device.get());
  while (devlink) {
    const char* name = udev_list_entry_get_name(devlink);
    if (name)
      out.push_back(name);
    devlink = udev_list_entry_get_next(devlink);
  }

  return out;
}

}  // namespace

uint64_t IioEventCode(iio_chan_type chan_type,
                      iio_event_type event_type,
                      iio_event_direction dir,
                      int channel) {
  return (uint64_t)chan_type << 32 | (uint64_t)dir << 48 |
         (uint64_t)event_type << 56 | (uint64_t)channel;
  // TODO(chenghaoyang): use the existing IIO_EVENT_CODE instead.
  // return IIO_EVENT_CODE(chan_type_, 0, 0, dir, event_type_, channel_, 0, 0);
}

std::optional<std::string> GetIioSarSensorDevlink(const std::string& sys_path) {
  std::vector<std::string> devlinks = GetDevlinks(sys_path);
  if (devlinks.empty()) {
    LOG(WARNING) << "udev unable to discover devlinks for " << sys_path;
    return std::nullopt;
  }

  for (const auto& dl : devlinks) {
    if (dl.find("proximity-") != std::string::npos ||
        dl.find("proximity_") != std::string::npos) {
      return dl;
    }
  }

  return std::nullopt;
}

}  // namespace libmems
