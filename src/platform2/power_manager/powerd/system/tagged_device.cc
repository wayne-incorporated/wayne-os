// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/tagged_device.h"

#include <base/strings/string_tokenizer.h>

namespace power_manager::system {

TaggedDevice::TaggedDevice(const std::string& syspath,
                           const base::FilePath& wakeup_device_path,
                           const std::string& tags) {
  syspath_ = syspath;
  wakeup_device_path_ = wakeup_device_path;

  base::StringTokenizer parts(tags, " ");
  while (parts.GetNext())
    tags_.insert(parts.token());
}

bool TaggedDevice::HasTag(const std::string& tag) const {
  return tags_.find(tag) != tags_.end();
}

}  // namespace power_manager::system
