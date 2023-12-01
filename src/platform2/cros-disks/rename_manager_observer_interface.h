// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_RENAME_MANAGER_OBSERVER_INTERFACE_H_
#define CROS_DISKS_RENAME_MANAGER_OBSERVER_INTERFACE_H_

#include <string>

#include <chromeos/dbus/service_constants.h>

namespace cros_disks {

// An interface class for observing events from the rename manager.
// A derived class of this class should override the event methods
// that it would like to observe.
class RenameManagerObserverInterface {
 public:
  virtual ~RenameManagerObserverInterface() = default;

  // This method is called when a renaming operation on a device has
  // completed. |error_type| indicates whether the operation succeeded
  // or failed with a particular error.
  virtual void OnRenameCompleted(const std::string& device_path,
                                 RenameError error_type) = 0;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_RENAME_MANAGER_OBSERVER_INTERFACE_H_
