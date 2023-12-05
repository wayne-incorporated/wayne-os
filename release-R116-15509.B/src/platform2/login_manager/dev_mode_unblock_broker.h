// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_DEV_MODE_UNBLOCK_BROKER_H_
#define LOGIN_MANAGER_DEV_MODE_UNBLOCK_BROKER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/service_constants.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "login_manager/vpd_process.h"

class Crossystem;

namespace dbus {
class Bus;
class ObjectProxy;
class Response;
class ScopedDBusError;
}  // namespace dbus

namespace login_manager {

class SystemUtils;

// Developer mode unblock broker class to unblock the developer
// mode in FWMP (Firmware Management Parameters) and VPD in
// collaboration with Carrier Lock, ZTE and enterprise enrollment
// modules.
class DevModeUnblockBroker {
 public:
  using CompletionCallback = base::OnceCallback<void(brillo::ErrorPtr error)>;

  // sysfs path to read the block_devmode VPD flag
  static const char kSysfsRwVdpBlockDevModePath[];
  // Path to the Flag file indicating that unblock is already received from
  // Carrier Lock module
  static const char kCarrierLockUnblockedFlag[];
  // Path to the Flag file indicating that unblock is already received from init
  // state determination  module
  static const char kInitStateDeterminationUnblockedFlag[];
  // Path to the Flag file indicating that unblock is already received from
  // Enterprise enrollment  module
  static const char kEnrollmentUnblockedFlag[];
  // Configfs path to get the modem firmware variant
  static const char kFirmwareVariantPath[];

  static std::unique_ptr<DevModeUnblockBroker> Create(
      SystemUtils* system,
      Crossystem* crossystem,
      VpdProcess* vpd_process,
      dbus::ObjectProxy* fwmp_proxy);

  DevModeUnblockBroker(SystemUtils* system,
                       Crossystem* crossystem,
                       VpdProcess* vpd_process,
                       dbus::ObjectProxy* fwmp_proxy);
  DevModeUnblockBroker(const DevModeUnblockBroker&) = delete;
  DevModeUnblockBroker& operator=(const DevModeUnblockBroker&) = delete;
  virtual ~DevModeUnblockBroker();

  // DBus method handler for unblock request from ZTE module
  void UnblockDevModeForInitialStateDetermination(
      CompletionCallback completion);
  // DBus method handler for unblock request from enterprise
  // enrollment module
  void UnblockDevModeForEnrollment(CompletionCallback completion);
  // DBus method handler for unblock request from Carrier Lock  module
  void UnblockDevModeForCarrierLock(CompletionCallback completion);
  // Returns if dev mode is currently blocked by carrier lock
  bool IsDevModeBlockedForCarrierLock() const;
  // Returns if dev mode is currently blocked by enrollment module
  bool IsDevModeBlockedForEnrollment() const;
  // Returns if dev mode is currently blocked by ZTE module
  bool IsDevModeBlockedForInitialStateDetermination() const;

 private:
  friend class DevModeUnblockBrokerTest;

  bool IsCellularDevice();
  bool IsDevModeBlocked();
  bool IsDevModeBlockedInFwmp();
  void UnblockDevModeVpdFwmpIfReady(CompletionCallback completion);
  void UnblockDevModeInFwmp(CompletionCallback completion);
  void StartRemoveFirmwareManagementParameters(CompletionCallback completion,
                                               bool service_is_ready);
  void OnFirmwareManagementParametersRemoved(CompletionCallback completion,
                                             dbus::Response* response);
  void UnblockDevModeInVpd(CompletionCallback completion);
  void UpdateVpdDevModeUnblockResult(bool success);
  void HandleVpdDevModeUnblockResult(
      bool ignore_error,
      DevModeUnblockBroker::CompletionCallback completion,
      bool success);
  void UnblockAtInit(brillo::ErrorPtr error);
  void UpdateCurrentDevModeStatus(bool service_is_ready);

  bool awaiting_unblock_carrier_lock_ = false;
  bool awaiting_unblock_enrollment_ = false;
  bool awaiting_unblock_init_state_determination_ = false;
  bool dev_mode_unblocked_ =
      false;  // To maintain if DEV mode is already unblocked
  SystemUtils* system_ = nullptr;            // Owned by the caller.
  Crossystem* crossystem_ = nullptr;         // Owned by the caller.
  VpdProcess* vpd_process_ = nullptr;        // Owned by the caller.
  dbus::ObjectProxy* fwmp_proxy_ = nullptr;  // Owned by the caller.
  base::WeakPtrFactory<DevModeUnblockBroker> weak_ptr_factory_{this};
};

}  // namespace login_manager
#endif  // LOGIN_MANAGER_DEV_MODE_UNBLOCK_BROKER_H_
