// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/daemon/dbus_service.h"

#include <sysexits.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/bus.h>
#include <dbus/object_path.h>
#include <dbus/rmad/dbus-constants.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>
#include <mojo/public/cpp/system/invitation.h>

#include "rmad/constants.h"
#include "rmad/daemon/daemon_callback.h"
#include "rmad/system/tpm_manager_client_impl.h"
#include "rmad/utils/cros_config_utils_impl.h"
#include "rmad/utils/crossystem_utils_impl.h"
#include "rmad/utils/dbus_utils.h"

namespace {

// We don't need a minimal Mojo version. Set it to 0.
constexpr uint32_t kMojoVersion = 0;

}  // namespace

namespace rmad {

using brillo::dbus_utils::AsyncEventSequencer;
using brillo::dbus_utils::DBusObject;

DBusService::DBusService(mojo::PlatformChannelEndpoint endpoint,
                         RmadInterface* rmad_interface)
    : brillo::DBusServiceDaemon(kRmadServiceName),
      rmad_interface_(rmad_interface),
      state_file_path_(kDefaultJsonStoreFilePath),
      is_external_utils_initialized_(false),
      is_interface_set_up_(false) {
  // Establish connection to the executor process.
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);
  // Send invitation to the executor process.
  mojo::OutgoingInvitation invitation;
  mojo::ScopedMessagePipeHandle pipe =
      invitation.AttachMessagePipe(kRmadInternalMojoPipeName);
  mojo::OutgoingInvitation::Send(std::move(invitation),
                                 base::kNullProcessHandle, std::move(endpoint));
  executor_.Bind(mojo::PendingRemote<chromeos::rmad::mojom::Executor>(
      std::move(pipe), kMojoVersion));
  // Quit the daemon when the communication disconnects.
  executor_.set_disconnect_handler(base::BindOnce(
      &DBusService::OnExecutorDisconnected, weak_ptr_factory_.GetWeakPtr()));
}

DBusService::DBusService(const scoped_refptr<dbus::Bus>& bus,
                         RmadInterface* rmad_interface,
                         const base::FilePath& state_file_path,
                         std::unique_ptr<TpmManagerClient> tpm_manager_client,
                         std::unique_ptr<CrosConfigUtils> cros_config_utils,
                         std::unique_ptr<CrosSystemUtils> crossystem_utils)
    : brillo::DBusServiceDaemon(kRmadServiceName),
      rmad_interface_(rmad_interface),
      state_file_path_(state_file_path),
      tpm_manager_client_(std::move(tpm_manager_client)),
      cros_config_utils_(std::move(cros_config_utils)),
      crossystem_utils_(std::move(crossystem_utils)),
      is_external_utils_initialized_(true),
      is_interface_set_up_(false) {
  dbus_object_ = std::make_unique<DBusObject>(
      nullptr, bus, dbus::ObjectPath(kRmadServicePath));
}

int DBusService::OnEventLoopStarted() {
  const int exit_code = DBusServiceDaemon::OnEventLoopStarted();
  if (exit_code != EX_OK) {
    return exit_code;
  }

  if (!is_external_utils_initialized_) {
    tpm_manager_client_ =
        std::make_unique<TpmManagerClientImpl>(GetSystemBus());
    cros_config_utils_ = std::make_unique<CrosConfigUtilsImpl>();
    crossystem_utils_ = std::make_unique<CrosSystemUtilsImpl>();
    is_external_utils_initialized_ = true;
  }
  is_rma_required_ = CheckRmaCriteria();
  return EX_OK;
}

void DBusService::RegisterDBusObjectsAsync(AsyncEventSequencer* sequencer) {
  if (!dbus_object_.get()) {
    CHECK(bus_.get());
    dbus_object_ = std::make_unique<DBusObject>(
        nullptr, bus_, dbus::ObjectPath(kRmadServicePath));
  }
  brillo::dbus_utils::DBusInterface* dbus_interface =
      dbus_object_->AddOrGetInterface(kRmadInterfaceName);

  dbus_interface->AddMethodHandler(kIsRmaRequiredMethod,
                                   weak_ptr_factory_.GetWeakPtr(),
                                   &DBusService::HandleIsRmaRequiredMethod);
  dbus_interface->AddMethodHandler(
      kGetCurrentStateMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<GetStateReply,
                                        &RmadInterface::GetCurrentState>);
  dbus_interface->AddMethodHandler(
      kTransitionNextStateMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<TransitionNextStateRequest,
                                        GetStateReply,
                                        &RmadInterface::TransitionNextState>);
  dbus_interface->AddMethodHandler(
      kTransitionPreviousStateMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<
          GetStateReply, &RmadInterface::TransitionPreviousState>);
  dbus_interface->AddMethodHandler(
      kAbortRmaMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<AbortRmaReply,
                                        &RmadInterface::AbortRma>);
  dbus_interface->AddMethodHandler(
      kGetLogMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<GetLogReply, &RmadInterface::GetLog>);
  dbus_interface->AddMethodHandler(
      kSaveLogMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<std::string, SaveLogReply,
                                        &RmadInterface::SaveLog>);
  dbus_interface->AddMethodHandler(
      kRecordBrowserActionMetricMethod, weak_ptr_factory_.GetWeakPtr(),
      &DBusService::DelegateToInterface<
          RecordBrowserActionMetricRequest, RecordBrowserActionMetricReply,
          &RmadInterface::RecordBrowserActionMetric>);

  error_signal_ = dbus_interface->RegisterSignal<RmadErrorCode>(kErrorSignal);
  hardware_verification_signal_ =
      dbus_interface->RegisterSignal<HardwareVerificationResult>(
          kHardwareVerificationResultSignal);
  update_ro_firmware_status_signal_ =
      dbus_interface->RegisterSignal<UpdateRoFirmwareStatus>(
          kUpdateRoFirmwareStatusSignal);
  calibration_overall_signal_ =
      dbus_interface->RegisterSignal<CalibrationOverallStatus>(
          kCalibrationOverallSignal);
  calibration_component_signal_ =
      dbus_interface->RegisterSignal<CalibrationComponentStatus>(
          kCalibrationProgressSignal);
  provision_signal_ = dbus_interface->RegisterSignal<ProvisionStatus>(
      kProvisioningProgressSignal);
  finalize_signal_ =
      dbus_interface->RegisterSignal<FinalizeStatus>(kFinalizeProgressSignal);
  hwwp_signal_ =
      dbus_interface->RegisterSignal<bool>(kHardwareWriteProtectionStateSignal);
  power_cable_signal_ =
      dbus_interface->RegisterSignal<bool>(kPowerCableStateSignal);
  external_disk_signal_ =
      dbus_interface->RegisterSignal<bool>(kExternalDiskDetectedSignal);

  dbus_object_->RegisterAsync(
      sequencer->GetHandler("Failed to register D-Bus objects.", true));
}

bool DBusService::CheckRmaCriteria() const {
  // Only allow Shimless RMA in normal mode.
  if (std::string mainfw_type;
      !crossystem_utils_->GetMainFwType(&mainfw_type) ||
      mainfw_type != "normal") {
    return false;
  }
  // Only allow Shimless RMA if it's enabled in cros_config.
  if (RmadConfig config;
      !cros_config_utils_->GetRmadConfig(&config) || !config.enabled) {
    return false;
  }
  // Shimless RMA is allowed. Trigger it when either condition is satisfied:
  // - Shimless RMA state file exists: Shimless RMA is triggered before and not
  //   completed yet.
  // - RO verification triggered: Shimless RMA is manually triggered at boot.
  if (base::PathExists(state_file_path_)) {
    return true;
  }
  CHECK(is_external_utils_initialized_);
  if (RoVerificationStatus status;
      tpm_manager_client_->GetRoVerificationStatus(&status) &&
      (status == RMAD_RO_VERIFICATION_PASS ||
       status == RMAD_RO_VERIFICATION_UNSUPPORTED_TRIGGERED)) {
    // Initialize the state file so we can reliably boot into RMA even if Chrome
    // accidentally reboots the device before calling |GetCurrentState| API.
    base::WriteFile(state_file_path_, "{}");
    return true;
  }
  return false;
}

bool DBusService::SetUpInterface() {
  CHECK(rmad_interface_);
  if (!is_interface_set_up_) {
    if (!rmad_interface_->SetUp(CreateDaemonCallback())) {
      return false;
    }
    is_interface_set_up_ = true;
    rmad_interface_->TryTransitionNextStateFromCurrentState();
  }
  return true;
}

scoped_refptr<DaemonCallback> DBusService::CreateDaemonCallback() const {
  auto daemon_callback = base::MakeRefCounted<DaemonCallback>();
  daemon_callback->SetHardwareVerificationSignalCallback(
      base::BindRepeating(&DBusService::SendHardwareVerificationResultSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetUpdateRoFirmwareSignalCallback(
      base::BindRepeating(&DBusService::SendUpdateRoFirmwareStatusSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetCalibrationOverallSignalCallback(
      base::BindRepeating(&DBusService::SendCalibrationOverallSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetCalibrationComponentSignalCallback(
      base::BindRepeating(&DBusService::SendCalibrationProgressSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetProvisionSignalCallback(
      base::BindRepeating(&DBusService::SendProvisionProgressSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetFinalizeSignalCallback(
      base::BindRepeating(&DBusService::SendFinalizeProgressSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetWriteProtectSignalCallback(
      base::BindRepeating(&DBusService::SendHardwareWriteProtectionStateSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetPowerCableSignalCallback(
      base::BindRepeating(&DBusService::SendPowerCableStateSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExternalDiskSignalCallback(
      base::BindRepeating(&DBusService::SendExternalDiskSignal,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExecuteMountAndWriteLogCallback(
      base::BindRepeating(&DBusService::ExecuteMountAndWriteLog,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExecuteMountAndCopyFirmwareUpdaterCallback(
      base::BindRepeating(&DBusService::ExecuteMountAndCopyFirmwareUpdater,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExecuteRebootEcCallback(base::BindRepeating(
      &DBusService::ExecuteRebootEc, weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExecuteRequestRmaPowerwashCallback(
      base::BindRepeating(&DBusService::ExecuteRequestRmaPowerwash,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  daemon_callback->SetExecuteRequestBatteryCutoffCallback(
      base::BindRepeating(&DBusService::ExecuteRequestBatteryCutoff,
                          weak_ptr_factory_.GetMutableWeakPtr()));
  return daemon_callback;
}

void DBusService::HandleIsRmaRequiredMethod(
    std::unique_ptr<DBusMethodResponse<bool>> response) {
  // Quit the daemon if we are not in RMA.
  bool quit_daemon = !is_rma_required_;
  SendReply(std::move(response), is_rma_required_, quit_daemon);
}

void DBusService::SendErrorSignal(RmadErrorCode error) {
  auto signal = error_signal_.lock();
  if (signal) {
    signal->Send(error);
  }
}

void DBusService::SendHardwareVerificationResultSignal(
    const HardwareVerificationResult& result) {
  auto signal = hardware_verification_signal_.lock();
  if (signal) {
    signal->Send(result);
  }
}

void DBusService::SendUpdateRoFirmwareStatusSignal(
    UpdateRoFirmwareStatus status) {
  auto signal = update_ro_firmware_status_signal_.lock();
  if (signal) {
    signal->Send(status);
  }
}

void DBusService::SendCalibrationOverallSignal(
    CalibrationOverallStatus status) {
  auto signal = calibration_overall_signal_.lock();
  if (signal) {
    signal->Send(status);
  }
}

void DBusService::SendCalibrationProgressSignal(
    CalibrationComponentStatus status) {
  auto signal = calibration_component_signal_.lock();
  if (signal) {
    signal->Send(status);
  }
}

void DBusService::SendProvisionProgressSignal(const ProvisionStatus& status) {
  auto signal = provision_signal_.lock();
  if (signal) {
    signal->Send(status);
  }
}

void DBusService::SendFinalizeProgressSignal(const FinalizeStatus& status) {
  auto signal = finalize_signal_.lock();
  if (signal) {
    signal->Send(status);
  }
}

void DBusService::SendHardwareWriteProtectionStateSignal(bool enabled) {
  auto signal = hwwp_signal_.lock();
  if (signal) {
    signal->Send(enabled);
  }
}

void DBusService::SendPowerCableStateSignal(bool plugged_in) {
  auto signal = power_cable_signal_.lock();
  if (signal) {
    signal->Send(plugged_in);
  }
}

void DBusService::SendExternalDiskSignal(bool detected) {
  auto signal = external_disk_signal_.lock();
  if (signal) {
    signal->Send(detected);
  }
}

void DBusService::ExecuteMountAndWriteLog(
    uint8_t device_id,
    const std::string& text_log,
    const std::string& json_log,
    const std::string& system_log,
    const std::string& diagnostics_log,
    base::OnceCallback<void(const std::optional<std::string>&)> callback) {
  executor_->MountAndWriteLog(device_id, text_log, json_log, system_log,
                              diagnostics_log, std::move(callback));
}

void DBusService::ExecuteMountAndCopyFirmwareUpdater(
    uint8_t device_id, base::OnceCallback<void(bool)> callback) {
  executor_->MountAndCopyFirmwareUpdater(device_id, std::move(callback));
}

void DBusService::ExecuteRebootEc(base::OnceCallback<void(bool)> callback) {
  executor_->RebootEc(std::move(callback));
}

void DBusService::ExecuteRequestRmaPowerwash(
    base::OnceCallback<void(bool)> callback) {
  executor_->RequestRmaPowerwash(std::move(callback));
}

void DBusService::ExecuteRequestBatteryCutoff(
    base::OnceCallback<void(bool)> callback) {
  executor_->RequestBatteryCutoff(std::move(callback));
}

void DBusService::OnExecutorDisconnected() {
  VLOG(1) << "Executor disconnected";
  PostQuitTask();
}

void DBusService::PostQuitTask() {
  if (bus_) {
    VLOG(1) << "Stopping DBus service";
    bus_->GetOriginTaskRunner()->PostTask(
        FROM_HERE,
        base::BindOnce(&Daemon::Quit, weak_ptr_factory_.GetWeakPtr()));
  }
}

}  // namespace rmad
