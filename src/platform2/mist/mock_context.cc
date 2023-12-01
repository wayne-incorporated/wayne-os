// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/mock_context.h"

#include <memory>

#include <base/check.h>
#include <brillo/udev/mock_udev.h>
#include <brillo/usb/usb_device_event_notifier.h>

#include "mist/event_dispatcher.h"
#include "mist/mock_config_loader.h"

namespace mist {

bool MockContext::Initialize() {
  config_loader_.reset(new MockConfigLoader());
  CHECK(config_loader_);

  event_dispatcher_.reset(new EventDispatcher());
  CHECK(event_dispatcher_);

  udev_.reset(new brillo::MockUdev());
  CHECK(udev_);

  usb_device_event_notifier_ =
      std::make_unique<brillo::UsbDeviceEventNotifier>(udev_.get());

  // TODO(benchan): Initialize |usb_manager_| with a MockUsbManager object.
  return true;
}

MockConfigLoader* MockContext::GetMockConfigLoader() const {
  return static_cast<MockConfigLoader*>(config_loader_.get());
}

brillo::MockUdev* MockContext::GetMockUdev() const {
  return static_cast<brillo::MockUdev*>(udev_.get());
}

}  // namespace mist
