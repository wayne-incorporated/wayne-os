// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/udev_scopers.h"

namespace permission_broker {

void UdevDeleter::operator()(udev* udev) const {
  udev_unref(udev);
}

void UdevEnumerateDeleter::operator()(udev_enumerate* enumerate) const {
  udev_enumerate_unref(enumerate);
}

void UdevDeviceDeleter::operator()(udev_device* device) const {
  udev_device_unref(device);
}

}  // namespace permission_broker
