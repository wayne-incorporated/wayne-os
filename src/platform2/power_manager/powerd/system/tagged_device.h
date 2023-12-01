// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_TAGGED_DEVICE_H_
#define POWER_MANAGER_POWERD_SYSTEM_TAGGED_DEVICE_H_

#include <string>
#include <unordered_set>

#include <base/files/file_path.h>

namespace power_manager::system {

// Represents a udev device with powerd tags associated to it.
class TaggedDevice {
 public:
  // Default constructor for easier use with std::map.
  TaggedDevice() = default;
  TaggedDevice(const std::string& syspath,
               const base::FilePath& wakeup_device_path,
               const std::string& tags);
  ~TaggedDevice() = default;

  const std::string& syspath() const { return syspath_; }
  const base::FilePath& wakeup_device_path() const {
    return wakeup_device_path_;
  }
  const std::unordered_set<std::string> tags() const { return tags_; }

  // Returns true if the device has the given tag.
  bool HasTag(const std::string& tag) const;

 private:
  std::string syspath_;
  // Directory (of itself/ancestor) with power/wakeup property.
  base::FilePath wakeup_device_path_;
  std::unordered_set<std::string> tags_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_TAGGED_DEVICE_H_
