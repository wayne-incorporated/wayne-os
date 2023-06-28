// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_ARC_SIDELOAD_STATUS_INTERFACE_H_
#define LOGIN_MANAGER_ARC_SIDELOAD_STATUS_INTERFACE_H_

#include <memory>

#include <brillo/dbus/dbus_method_response.h>

namespace login_manager {

class ArcSideloadStatusInterface {
 public:
  enum class Status {
    UNDEFINED = 0,
    ENABLED = 1,
    DISABLED = 2,
    NEED_POWERWASH = 3,
  };

  virtual ~ArcSideloadStatusInterface() {}

  virtual void Initialize() = 0;

  // Returns true IFF ARC Sideload is allowed as per bootlockbox status. Can
  // return false if it's explicitly not yet allowed, or if the status is
  // still unknown, e.g. due to slowness in asking bootlockbox.
  virtual bool IsAdbSideloadAllowed() = 0;

  // Callback of EnableAdbSideload. The first argument indicates whether the
  // operation has succeeded. The second argument is the error message when
  // failed, or nullptr on success.
  // TODO(victorhsieh): Consider making convert all the Callbacks to
  // OnceCallback. It will be easier or possible once the next libchrome uprev
  // (crbug.com/909719) is done.
  using EnableAdbSideloadCallback = base::Callback<void(Status, const char*)>;

  // Handles request to allow ARC Sideload via DBus. This can only success
  // before the first user login after boot. Currently must be called after
  // initialized.
  virtual void EnableAdbSideload(EnableAdbSideloadCallback callback) = 0;

  // Callback of QueryAdbSideload. The first argument indicates whether
  // sideloading is allowed on the current device.
  using QueryAdbSideloadCallback = base::Callback<void(Status)>;

  // Handles query of the ARC Sideload status via DBus. The response will be
  // sent immediately if the status is already known - otherwise the response
  // can be deferred due to slowness in asking cryptohome.
  virtual void QueryAdbSideload(QueryAdbSideloadCallback callback) = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_ARC_SIDELOAD_STATUS_INTERFACE_H_
