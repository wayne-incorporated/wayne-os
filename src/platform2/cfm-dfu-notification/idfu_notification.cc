// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cfm-dfu-notification/idfu_notification.h"

#include <string>

#include "cfm-dfu-notification/dfu_log_notification.h"

std::unique_ptr<IDfuNotification> IDfuNotification::For(
    const std::string& device_name) {
  return std::make_unique<DfuLogNotification>(device_name);
}
