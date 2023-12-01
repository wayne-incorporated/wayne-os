// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_DAEMON_DAEMON_CALLBACK_H_
#define RMAD_DAEMON_DAEMON_CALLBACK_H_

#include <optional>
#include <string>

#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/scoped_refptr.h>

#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

using HardwareVerificationSignalCallback =
    base::RepeatingCallback<void(const HardwareVerificationResult&)>;
using UpdateRoFirmwareSignalCallback =
    base::RepeatingCallback<void(UpdateRoFirmwareStatus)>;
using CalibrationOverallSignalCallback =
    base::RepeatingCallback<void(CalibrationOverallStatus)>;
using CalibrationComponentSignalCallback =
    base::RepeatingCallback<void(CalibrationComponentStatus)>;
using ProvisionSignalCallback =
    base::RepeatingCallback<void(const ProvisionStatus&)>;
using FinalizeSignalCallback =
    base::RepeatingCallback<void(const FinalizeStatus&)>;
using WriteProtectSignalCallback = base::RepeatingCallback<void(bool)>;
using PowerCableSignalCallback = base::RepeatingCallback<void(bool)>;
using ExternalDiskSignalCallback = base::RepeatingCallback<void(bool)>;
using ExecuteMountAndWriteLogCallback = base::RepeatingCallback<void(
    uint8_t,
    const std::string&,
    const std::string&,
    const std::string&,
    const std::string&,
    base::OnceCallback<void(const std::optional<std::string>&)>)>;
using ExecuteMountAndCopyFirmwareUpdaterCallback =
    base::RepeatingCallback<void(uint8_t, base::OnceCallback<void(bool)>)>;
using ExecuteRebootEcCallback =
    base::RepeatingCallback<void(base::OnceCallback<void(bool)>)>;
using ExecuteRequestRmaPowerwashCallback =
    base::RepeatingCallback<void(base::OnceCallback<void(bool)>)>;
using ExecuteRequestBatteryCutoffCallback =
    base::RepeatingCallback<void(base::OnceCallback<void(bool)>)>;

#define DECLARE_CALLBACK(type, var)                 \
 public:                                            \
  type Get##type() const { return var; }            \
  void Set##type(type callback) { var = callback; } \
                                                    \
 private:                                           \
  type var = base::DoNothing()

// A collection of callbacks for state handlers to use.
class DaemonCallback : public base::RefCounted<DaemonCallback> {
 public:
  DaemonCallback() = default;

 protected:
  friend class base::RefCounted<DaemonCallback>;
  virtual ~DaemonCallback() = default;

  // Callbacks as private members and their public getter/setter.
  DECLARE_CALLBACK(HardwareVerificationSignalCallback,
                   hardware_verification_signal_callback);
  DECLARE_CALLBACK(UpdateRoFirmwareSignalCallback,
                   update_ro_firmware_signal_callback_);
  DECLARE_CALLBACK(CalibrationOverallSignalCallback,
                   calibration_overall_signal_callback_);
  DECLARE_CALLBACK(CalibrationComponentSignalCallback,
                   calibration_component_signal_callback_);
  DECLARE_CALLBACK(ProvisionSignalCallback, provision_signal_callback_);
  DECLARE_CALLBACK(FinalizeSignalCallback, finalize_signal_callback_);
  DECLARE_CALLBACK(WriteProtectSignalCallback, write_protect_signal_callback_);
  DECLARE_CALLBACK(PowerCableSignalCallback, power_cable_signal_callback_);
  DECLARE_CALLBACK(ExternalDiskSignalCallback, external_disk_signal_callback_);
  DECLARE_CALLBACK(ExecuteMountAndWriteLogCallback,
                   execute_mount_and_write_log_callback_);
  DECLARE_CALLBACK(ExecuteMountAndCopyFirmwareUpdaterCallback,
                   execute_mount_and_copy_firmware_updater_callback_);
  DECLARE_CALLBACK(ExecuteRebootEcCallback, execute_reboot_ec_callback_);
  DECLARE_CALLBACK(ExecuteRequestRmaPowerwashCallback,
                   execute_request_rma_powerwash_callback_);
  DECLARE_CALLBACK(ExecuteRequestBatteryCutoffCallback,
                   execute_request_battery_cutoff_callback_);
};

}  // namespace rmad

#endif  // RMAD_DAEMON_DAEMON_CALLBACK_H_
