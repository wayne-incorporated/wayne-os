// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_DEV_MODE_NO_OWNER_RESTRICTION_H_
#define DEBUGD_SRC_DEV_MODE_NO_OWNER_RESTRICTION_H_

#include <base/memory/ref_counted.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>

namespace debugd {

// Provides functionality to check that the system is in dev mode and has no
// owner. Used by RestrictedToolWrapper classes to limit access to tools.
class DevModeNoOwnerRestriction {
 public:
  explicit DevModeNoOwnerRestriction(scoped_refptr<dbus::Bus> bus);
  DevModeNoOwnerRestriction(const DevModeNoOwnerRestriction&) = delete;
  DevModeNoOwnerRestriction& operator=(const DevModeNoOwnerRestriction&) =
      delete;

  virtual ~DevModeNoOwnerRestriction() = default;

  // Checks whether tool access is allowed.
  //
  // To get access to the tool, the system must be in dev mode with no owner
  // and the boot lockbox cannot be finalized.
  //
  // |error| can be NULL or a pointer to a brillo::ErrorPtr, in which case
  // it will be filled with a descriptive error message if tool access is
  // blocked.
  //
  // Returns true if tool access is allowed.
  bool AllowToolUse(brillo::ErrorPtr* error);

  // Virtual member functions to allow overrides for testing.
  // Returns true if the system is in dev mode. If not, and if |error| is
  // given, the error message is populated.
  virtual bool InDevMode(brillo::ErrorPtr* error = nullptr) const;
  virtual bool GetOwnerAndLockboxStatus(bool* owner_user_exists,
                                        bool* boot_lockbox_finalized);

 private:
  scoped_refptr<dbus::Bus> bus_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DEV_MODE_NO_OWNER_RESTRICTION_H_
