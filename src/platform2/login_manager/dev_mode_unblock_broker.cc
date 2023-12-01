// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/dev_mode_unblock_broker.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/scoped_dbus_error.h>

#include "login_manager/crossystem.h"
#include "login_manager/dbus_util.h"
#include "login_manager/session_manager_impl.h"
#include "login_manager/system_utils.h"

namespace login_manager {

constexpr char DevModeUnblockBroker::kFirmwareVariantPath[] =
    "/run/chromeos-config/v1/modem/firmware-variant";
constexpr char DevModeUnblockBroker::kSysfsRwVdpBlockDevModePath[] =
    "/sys/firmware/vpd/rw/block_devmode";
constexpr char DevModeUnblockBroker::kCarrierLockUnblockedFlag[] =
    "/mnt/stateful_partition/dev_mode_unblock_broker/carrier_lock_unblocked";
constexpr char DevModeUnblockBroker::kInitStateDeterminationUnblockedFlag[] =
    "/mnt/stateful_partition/dev_mode_unblock_broker/"
    "init_state_determination_unblocked";
constexpr char DevModeUnblockBroker::kEnrollmentUnblockedFlag[] =
    "/mnt/stateful_partition/dev_mode_unblock_broker/enrollment_unblocked";

std::unique_ptr<DevModeUnblockBroker> DevModeUnblockBroker::Create(
    SystemUtils* system,
    Crossystem* crossystem,
    VpdProcess* vpd_process,
    dbus::ObjectProxy* fwmp_proxy) {
  return std::make_unique<DevModeUnblockBroker>(system, crossystem, vpd_process,
                                                fwmp_proxy);
}

DevModeUnblockBroker::DevModeUnblockBroker(SystemUtils* system,
                                           Crossystem* crossystem,
                                           VpdProcess* vpd_process,
                                           dbus::ObjectProxy* fwmp_proxy)
    : system_(system),
      crossystem_(crossystem),
      vpd_process_(vpd_process),
      fwmp_proxy_(fwmp_proxy) {
  // Check if this is a cellular device. For non-cellular
  // devices, broker will not wait for unblock from carrier lock
  // module.
  // Also check persistent config if we already received
  // unblock from these modules.
  awaiting_unblock_carrier_lock_ =
      IsCellularDevice() == true &&
      !system_->Exists(base::FilePath(kCarrierLockUnblockedFlag));

  awaiting_unblock_enrollment_ =
      !system_->Exists(base::FilePath(kEnrollmentUnblockedFlag));

  awaiting_unblock_init_state_determination_ =
      !system_->Exists(base::FilePath(kInitStateDeterminationUnblockedFlag));

  LOG(INFO) << __func__ << " awaiting_unblock_init_state_determination: "
            << awaiting_unblock_init_state_determination_
            << " awaiting_unblock_enrollment: " << awaiting_unblock_enrollment_
            << " awaiting_unblock_carrier_lock: "
            << awaiting_unblock_carrier_lock_;

  // Check current status of dev mode
  fwmp_proxy_->WaitForServiceToBeAvailable(
      base::BindOnce(&DevModeUnblockBroker::UpdateCurrentDevModeStatus,
                     weak_ptr_factory_.GetWeakPtr()));
}

DevModeUnblockBroker::~DevModeUnblockBroker() = default;

void DevModeUnblockBroker::UnblockDevModeForInitialStateDetermination(
    CompletionCallback completion) {
  DVLOG(1) << __func__;
  awaiting_unblock_init_state_determination_ = false;
  system_->AtomicFileWrite(base::FilePath(kInitStateDeterminationUnblockedFlag),
                           "1");
  UnblockDevModeVpdFwmpIfReady(std::move(completion));
}

void DevModeUnblockBroker::UnblockDevModeForEnrollment(
    CompletionCallback completion) {
  DVLOG(1) << __func__;
  awaiting_unblock_enrollment_ = false;
  system_->AtomicFileWrite(base::FilePath(kEnrollmentUnblockedFlag), "1");
  UnblockDevModeVpdFwmpIfReady(std::move(completion));
}

void DevModeUnblockBroker::UnblockDevModeForCarrierLock(
    CompletionCallback completion) {
  DVLOG(1) << __func__;
  awaiting_unblock_carrier_lock_ = false;
  system_->AtomicFileWrite(base::FilePath(kCarrierLockUnblockedFlag), "1");
  UnblockDevModeVpdFwmpIfReady(std::move(completion));
}

bool DevModeUnblockBroker::IsDevModeBlockedForCarrierLock() const {
  return awaiting_unblock_carrier_lock_;
}

bool DevModeUnblockBroker::IsDevModeBlockedForEnrollment() const {
  return awaiting_unblock_enrollment_;
}

bool DevModeUnblockBroker::IsDevModeBlockedForInitialStateDetermination()
    const {
  return awaiting_unblock_init_state_determination_;
}

bool DevModeUnblockBroker::IsCellularDevice() {
  bool is_cellular = false;
  const base::FilePath modem_path = base::FilePath(kFirmwareVariantPath);
  if (system_->Exists(modem_path)) {
    is_cellular = true;
    // If Carrier Lock is expected only for a specific set of modems
    // check that include list here.
  }
  DVLOG(1) << "is_cellular " << is_cellular;
  return is_cellular;
}

bool DevModeUnblockBroker::IsDevModeBlocked() {
  // Block_devmode exists at multiple locations.
  // Use the logic used by init script to detect current state
  // of dev mode.
  // - Check for FWMP space with DEVELOPER_DISABLE_BOOT flag.
  // - VPD sysyfs entry
  // - Crossystem
  bool block_dev_mode_fwmp = IsDevModeBlockedInFwmp();
  LOG(INFO) << "block_devmode_fwmp " << block_dev_mode_fwmp;

  const base::FilePath rw_vpd_block_devmode_path =
      base::FilePath(kSysfsRwVdpBlockDevModePath);
  if (system_->Exists(rw_vpd_block_devmode_path)) {
    std::string block_devmode_sysfs;
    base::ReadFileToString(rw_vpd_block_devmode_path, &block_devmode_sysfs);
    LOG(INFO) << "block_devmode_sysfs " << block_devmode_sysfs;
    if (block_devmode_sysfs == "1")
      return true;
  }

  int block_devmode_system =
      crossystem_->VbGetSystemPropertyInt(Crossystem::kBlockDevmode);
  if (block_devmode_system == -1) {
    LOG(ERROR) << "Failed to read block_devmode flag!";
  }
  LOG(INFO) << "block_devmode_system " << block_devmode_system;

  return block_devmode_system == 1;
}

bool DevModeUnblockBroker::IsDevModeBlockedInFwmp() {
  dbus::MethodCall method_call(
      user_data_auth::kInstallAttributesInterface,
      user_data_auth::kGetFirmwareManagementParameters);
  user_data_auth::GetFirmwareManagementParametersRequest request;
  user_data_auth::GetFirmwareManagementParametersReply reply;
  dbus::MessageWriter writer(&method_call);
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR)
        << "Failed to append GetFirmwareManagementParametersRequest protobuf"
           "when calling InstallAttributes method ";
    return false;
  }
  std::unique_ptr<dbus::Response> response(fwmp_proxy_->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  if (!response) {
    LOG(ERROR) << "Error contacting Cryptohomed to get FWMP.";
    return false;
  }
  if (!response.get()) {
    LOG(ERROR) << "Cannot retrieve FWMP.";
    return false;
  }
  dbus::MessageReader reader(response.get());
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    LOG(ERROR) << "Failed to parse GetFirmwareManagementParameters"
                  " response message from cryptohomed";
    return false;
  }
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "Failed to get firmware management parameters:"
               << reply.error();
    return false;
  }
  LOG(INFO) << "FWMP Flags: " << reply.fwmp().flags();
  return (reply.fwmp().flags() & cryptohome::DEVELOPER_DISABLE_BOOT);
}

void DevModeUnblockBroker::UnblockDevModeVpdFwmpIfReady(
    CompletionCallback completion) {
  LOG(INFO) << __func__ << " awaiting_unblock_init_state_determination: "
            << awaiting_unblock_init_state_determination_
            << " awaiting_unblock_enrollment: " << awaiting_unblock_enrollment_
            << " awaiting_unblock_carrier_lock: "
            << awaiting_unblock_carrier_lock_
            << " DevModeUnblocked: " << dev_mode_unblocked_;
  // Dev mode is already unblocked
  if (dev_mode_unblocked_) {
    if (!completion.is_null())
      std::move(completion).Run(brillo::ErrorPtr());
    return;
  }
  if (awaiting_unblock_init_state_determination_ ||
      awaiting_unblock_enrollment_ || awaiting_unblock_carrier_lock_) {
    if (!completion.is_null())
      std::move(completion).Run(brillo::ErrorPtr());
    return;
  }
  UnblockDevModeInFwmp(std::move(completion));
}

void DevModeUnblockBroker::UnblockDevModeInFwmp(CompletionCallback completion) {
  // D-Bus services may not be available yet, so we call
  // WaitForServiceToBeAvailable.
  fwmp_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &DevModeUnblockBroker::StartRemoveFirmwareManagementParameters,
      weak_ptr_factory_.GetWeakPtr(), std::move(completion)));
}

void DevModeUnblockBroker::StartRemoveFirmwareManagementParameters(
    CompletionCallback completion, bool service_is_ready) {
  if (!service_is_ready) {
    LOG(ERROR) << "Failed waiting for cryptohome D-Bus service availability.";
    std::move(completion)
        .Run(CreateError(dbus_error::kFwmpRemovalFailed,
                         "Cryptohome D-Bus service unavailable."));
    return;
  }

  dbus::MethodCall method_call(
      user_data_auth::kInstallAttributesInterface,
      user_data_auth::kRemoveFirmwareManagementParameters);
  dbus::MessageWriter writer(&method_call);
  user_data_auth::RemoveFirmwareManagementParametersRequest request;
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << __func__
               << "Failed to append RemoveFirmwareManagementParameters protobuf"
                  "when calling InstallAttributes method ";
    std::move(completion)
        .Run(CreateError(
            dbus_error::kFwmpRemovalFailed,
            "Failed to append RemoveFirmwareManagementParameters protobuf."));
    return;
  }
  fwmp_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(
          &DevModeUnblockBroker::OnFirmwareManagementParametersRemoved,
          weak_ptr_factory_.GetWeakPtr(), std::move(completion)));
}

void DevModeUnblockBroker::OnFirmwareManagementParametersRemoved(
    CompletionCallback completion, dbus::Response* response) {
  user_data_auth::RemoveFirmwareManagementParametersReply reply;
  if (!response) {
    LOG(ERROR) << "No response from cryptohomed";
    std::move(completion)
        .Run(CreateError(dbus_error::kFwmpRemovalFailed,
                         "No Response from cryptohomed."));
    return;
  }
  dbus::MessageReader reader(response);
  if (!reader.PopArrayOfBytesAsProto(&reply)) {
    LOG(ERROR) << "Failed to parse response message from cryptohomed";
    std::move(completion)
        .Run(CreateError(dbus_error::kFwmpRemovalFailed,
                         "Failed to parse response message from cryptohomed."));
    return;
  }
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "Failed to remove firmware management parameters.";
    std::move(completion)
        .Run(CreateError(dbus_error::kFwmpRemovalFailed,
                         "Failed to remove firmware management parameters."));
    return;
  }
  UnblockDevModeInVpd(std::move(completion));
}

void DevModeUnblockBroker::UnblockDevModeInVpd(CompletionCallback completion) {
  // The block_devmode system property needs to be set to 0 as well to unblock
  // dev mode. It is stored independently from VPD and firmware management
  // parameters.
  if (crossystem_->VbSetSystemPropertyInt(Crossystem::kBlockDevmode, 0) != 0) {
    LOG(ERROR) << "Failed to set system property ";
    std::move(completion)
        .Run(CreateError(dbus_error::kSystemPropertyUpdateFailed,
                         "Failed to set block_devmode system property to 0."));
    return;
  }
  // Clear any existing nvram_cleared flag after updating block_devmode
  // value in VPD so that init script will try to read from VPD directly
  // if sysfs entry for block_devmode is not present.
  const int nvram_cleared_value =
      crossystem_->VbGetSystemPropertyInt(Crossystem::kNvramCleared);
  if (nvram_cleared_value == -1) {
    LOG(ERROR) << "Failed to read nvram_cleared flag!";
    std::move(completion)
        .Run(CreateError(dbus_error::kNvramClearedReadFailed,
                         "Failed to read nvram_cleared flag."));
    return;
  }
  if (nvram_cleared_value != 0 && (crossystem_->VbSetSystemPropertyInt(
                                       Crossystem::kNvramCleared, 0) != 0)) {
    LOG(ERROR) << "Failed to clear nvram_cleared flag!";
    std::move(completion)
        .Run(CreateError(dbus_error::kNvramClearedUpdateFailed,
                         "Failed to clear nvram_cleared flag."));
    return;
  }
  if (!vpd_process_->RunInBackground(
          {{Crossystem::kBlockDevmode, "0"},
           {Crossystem::kCheckEnrollment, "0"}},
          false,
          base::BindOnce(&DevModeUnblockBroker::HandleVpdDevModeUnblockResult,
                         weak_ptr_factory_.GetWeakPtr(), false,
                         std::move(completion)))) {
    LOG(ERROR) << "Failed to update VPD in background ";
    std::move(completion)
        .Run(CreateError(dbus_error::kVpdUpdateFailed,
                         "Failed to run VPD update in the background."));
  }
}

void DevModeUnblockBroker::UpdateVpdDevModeUnblockResult(bool success) {
  if (success)
    dev_mode_unblocked_ = true;
}

void DevModeUnblockBroker::HandleVpdDevModeUnblockResult(
    bool ignore_error,
    DevModeUnblockBroker::CompletionCallback completion,
    bool success) {
  DVLOG(1) << __func__ << " res=" << success;
  // Update when block_devmode is cleared successfully in FWMP and VPD
  UpdateVpdDevModeUnblockResult(success);

  if (completion.is_null())
    return;

  if (success || ignore_error) {
    std::move(completion).Run(brillo::ErrorPtr());
    return;
  }
  LOG(ERROR) << "Failed to update VPD";
  std::move(completion)
      .Run(CreateError(dbus_error::kVpdUpdateFailed, "Failed to update VPD"));
}

void DevModeUnblockBroker::UnblockAtInit(brillo::ErrorPtr error) {
  if (!error) {
    UpdateVpdDevModeUnblockResult(true);
    return;
  }
  LOG(ERROR) << "error code: " << error->GetCode()
             << " error message: " << error->GetMessage();
}

void DevModeUnblockBroker::UpdateCurrentDevModeStatus(bool service_is_ready) {
  if (!service_is_ready) {
    LOG(ERROR) << "Failed waiting for cryptohome D-Bus service availability.";
    return;
  }

  if (!IsDevModeBlocked()) {
    awaiting_unblock_carrier_lock_ = false;
    awaiting_unblock_enrollment_ = false;
    awaiting_unblock_init_state_determination_ = false;
    dev_mode_unblocked_ = true;
    return;
  }
  // Dev mode is not yet unblocked but we have already received unblock from all
  // the required modules. Try to unblock dev mode here in case last VPD/FWMP
  // update was interrupted by unexpected events like reboot.
  if (!awaiting_unblock_init_state_determination_ &&
      !awaiting_unblock_enrollment_ && !awaiting_unblock_carrier_lock_) {
    UnblockDevModeVpdFwmpIfReady(base::BindOnce(
        &DevModeUnblockBroker::UnblockAtInit, weak_ptr_factory_.GetWeakPtr()));
  }
}
}  // namespace login_manager
