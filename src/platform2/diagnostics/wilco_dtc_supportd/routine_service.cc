// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/routine_service.h"

#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"
#include "diagnostics/mojom/public/nullable_primitives.mojom.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <mojo/public/cpp/bindings/receiver.h>

namespace diagnostics {
namespace wilco {

namespace {

namespace mojo_ipc = ::ash::cros_healthd::mojom;

// Converts from mojo's DiagnosticRoutineStatusEnum to gRPC's
// DiagnosticRoutineStatus.
bool GetGrpcStatusFromMojoStatus(
    mojo_ipc::DiagnosticRoutineStatusEnum mojo_status,
    grpc_api::DiagnosticRoutineStatus* grpc_status_out) {
  DCHECK(grpc_status_out);
  switch (mojo_status) {
    case mojo_ipc::DiagnosticRoutineStatusEnum::kReady:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_READY;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kRunning:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_RUNNING;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kWaiting:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_WAITING;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kPassed:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_PASSED;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kFailed:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_FAILED;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kError:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_ERROR;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kCancelled:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_CANCELLED;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kFailedToStart:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_FAILED_TO_START;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kRemoved:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_REMOVED;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kCancelling:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_CANCELLING;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kUnsupported:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_ERROR;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kNotRun:
      *grpc_status_out = grpc_api::ROUTINE_STATUS_FAILED_TO_START;
      return true;
    case mojo_ipc::DiagnosticRoutineStatusEnum::kUnknown:
      LOG(ERROR) << "Unknown mojo routine status: "
                 << static_cast<int>(mojo_status);
      return false;
  }
}

// Converts from mojo's DiagnosticRoutineUserMessageEnum to gRPC's
// DiagnosticRoutineUserMessage.
bool GetUserMessageFromMojoEnum(
    mojo_ipc::DiagnosticRoutineUserMessageEnum mojo_message,
    grpc_api::DiagnosticRoutineUserMessage* grpc_message_out) {
  DCHECK(grpc_message_out);
  switch (mojo_message) {
    case mojo_ipc::DiagnosticRoutineUserMessageEnum::kUnplugACPower:
      *grpc_message_out = grpc_api::ROUTINE_USER_MESSAGE_UNPLUG_AC_POWER;
      return true;
    default:
      LOG(ERROR) << "Unknown mojo user message: "
                 << static_cast<int>(mojo_message);
      return false;
  }
}

// Converts from mojo's DiagnosticRoutineEnum to gRPC's DiagnosticRoutine.
bool GetGrpcRoutineEnumFromMojoRoutineEnum(
    mojo_ipc::DiagnosticRoutineEnum mojo_enum,
    std::vector<grpc_api::DiagnosticRoutine>* grpc_enum_out) {
  DCHECK(grpc_enum_out);
  switch (mojo_enum) {
    case mojo_ipc::DiagnosticRoutineEnum::kBatteryCapacity:
      grpc_enum_out->push_back(grpc_api::ROUTINE_BATTERY);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kBatteryHealth:
      grpc_enum_out->push_back(grpc_api::ROUTINE_BATTERY_SYSFS);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kUrandom:
      grpc_enum_out->push_back(grpc_api::ROUTINE_URANDOM);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kSmartctlCheck:
    case mojo_ipc::DiagnosticRoutineEnum::kSmartctlCheckWithPercentageUsed:
      grpc_enum_out->push_back(grpc_api::ROUTINE_SMARTCTL_CHECK);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kCpuCache:
      grpc_enum_out->push_back(grpc_api::ROUTINE_CPU_CACHE);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kCpuStress:
      grpc_enum_out->push_back(grpc_api::ROUTINE_CPU_STRESS);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kFloatingPointAccuracy:
      grpc_enum_out->push_back(grpc_api::ROUTINE_FLOATING_POINT_ACCURACY);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kNvmeWearLevel:
      grpc_enum_out->push_back(grpc_api::ROUTINE_NVME_WEAR_LEVEL);
      return true;
    // There is only one mojo enum for self_test(short & extended share same
    // class), but there're 2 gRPC enum for self_test according to requirement.
    case mojo_ipc::DiagnosticRoutineEnum::kNvmeSelfTest:
      grpc_enum_out->push_back(grpc_api::ROUTINE_NVME_SHORT_SELF_TEST);
      grpc_enum_out->push_back(grpc_api::ROUTINE_NVME_LONG_SELF_TEST);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kDiskRead:
      grpc_enum_out->push_back(grpc_api::ROUTINE_DISK_LINEAR_READ);
      grpc_enum_out->push_back(grpc_api::ROUTINE_DISK_RANDOM_READ);
      return true;
    case mojo_ipc::DiagnosticRoutineEnum::kPrimeSearch:
      grpc_enum_out->push_back(grpc_api::ROUTINE_PRIME_SEARCH);
      return true;
    default:
      LOG(ERROR) << "Unknown mojo routine: " << static_cast<int>(mojo_enum);
      return false;
  }
}

// Converts from mojo's RoutineUpdate to gRPC's GetRoutineUpdateResponse.
void SetGrpcUpdateFromMojoUpdate(
    mojo_ipc::RoutineUpdatePtr mojo_update,
    grpc_api::GetRoutineUpdateResponse* grpc_update) {
  DCHECK(grpc_update);
  grpc_update->set_progress_percent(mojo_update->progress_percent);
  const auto& update_union = mojo_update->routine_update_union;
  if (update_union->is_interactive_update()) {
    grpc_api::DiagnosticRoutineUserMessage grpc_message;
    mojo_ipc::DiagnosticRoutineUserMessageEnum mojo_message =
        update_union->get_interactive_update()->user_message;
    if (!GetUserMessageFromMojoEnum(mojo_message, &grpc_message)) {
      grpc_update->set_status(grpc_api::ROUTINE_STATUS_ERROR);
    } else {
      grpc_update->set_user_message(grpc_message);
    }
  } else {
    grpc_update->set_status_message(
        update_union->get_noninteractive_update()->status_message);
    grpc_api::DiagnosticRoutineStatus grpc_status;
    auto mojo_status = update_union->get_noninteractive_update()->status;
    if (!GetGrpcStatusFromMojoStatus(mojo_status, &grpc_status)) {
      grpc_update->set_status(grpc_api::ROUTINE_STATUS_ERROR);
    } else {
      grpc_update->set_status(grpc_status);
    }
  }

  if (!mojo_update->output.is_valid()) {
    // This isn't necessarily an error, since some requests may not have
    // specified that they wanted output returned, and some routines may never
    // return any extra input. We'll log the event in the case that it was an
    // error.
    VLOG(1) << "No output in mojo update.";
    return;
  }

  auto shm_mapping = GetReadOnlySharedMemoryMappingFromMojoHandle(
      std::move(mojo_update->output));
  if (!shm_mapping.IsValid()) {
    PLOG(ERROR) << "Failed to read data from mojo handle";
    return;
  }
  grpc_update->set_output(std::string(shm_mapping.GetMemoryAs<const char>(),
                                      shm_mapping.mapped_size()));
}

// Converts from gRPC's GetRoutineUpdateRequest::Command to mojo's
// DiagnosticRoutineCommandEnum.
bool GetMojoCommandFromGrpcCommand(
    grpc_api::GetRoutineUpdateRequest::Command grpc_command,
    mojo_ipc::DiagnosticRoutineCommandEnum* mojo_command_out) {
  DCHECK(mojo_command_out);
  switch (grpc_command) {
    case grpc_api::GetRoutineUpdateRequest::RESUME:
      *mojo_command_out = mojo_ipc::DiagnosticRoutineCommandEnum::kContinue;
      return true;
    case grpc_api::GetRoutineUpdateRequest::CANCEL:
      *mojo_command_out = mojo_ipc::DiagnosticRoutineCommandEnum::kCancel;
      return true;
    case grpc_api::GetRoutineUpdateRequest::GET_STATUS:
      *mojo_command_out = mojo_ipc::DiagnosticRoutineCommandEnum::kGetStatus;
      return true;
    case grpc_api::GetRoutineUpdateRequest::REMOVE:
      *mojo_command_out = mojo_ipc::DiagnosticRoutineCommandEnum::kRemove;
      return true;
    default:
      LOG(ERROR) << "Unknown gRPC command: " << static_cast<int>(grpc_command);
      return false;
  }
}

}  // namespace

RoutineService::RoutineService(Delegate* delegate) : delegate_(delegate) {
  DCHECK(delegate_);
}

RoutineService::~RoutineService() {
  RunInFlightCallbacks();
}

void RoutineService::GetAvailableRoutines(
    GetAvailableRoutinesToServiceCallback callback) {
  if (!BindCrosHealthdDiagnosticsServiceIfNeeded()) {
    LOG(WARNING) << "GetAvailableRoutines called before mojo was bootstrapped.";
    std::move(callback).Run(std::vector<grpc_api::DiagnosticRoutine>{},
                            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
    return;
  }

  const size_t callback_key = next_get_available_routines_key_;
  next_get_available_routines_key_++;
  DCHECK_EQ(get_available_routines_callbacks_.count(callback_key), 0);
  get_available_routines_callbacks_.insert({callback_key, std::move(callback)});
  service_->GetAvailableRoutines(
      base::BindOnce(&RoutineService::ForwardGetAvailableRoutinesResponse,
                     weak_ptr_factory_.GetWeakPtr(), callback_key));
}

void RoutineService::RunRoutine(const grpc_api::RunRoutineRequest& request,
                                RunRoutineToServiceCallback callback) {
  if (!BindCrosHealthdDiagnosticsServiceIfNeeded()) {
    LOG(WARNING) << "RunRoutine called before mojo was bootstrapped.";
    std::move(callback).Run(0 /* uuid */,
                            grpc_api::ROUTINE_STATUS_FAILED_TO_START,
                            grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
    return;
  }

  const size_t callback_key = next_run_routine_key_;
  next_run_routine_key_++;
  DCHECK_EQ(run_routine_callbacks_.count(callback_key), 0);
  auto it = run_routine_callbacks_.insert({callback_key, std::move(callback)});

  switch (request.routine()) {
    case grpc_api::ROUTINE_BATTERY:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kBatteryParams);
      service_->RunBatteryCapacityRoutine(
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_BATTERY_SYSFS:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kBatterySysfsParams);
      service_->RunBatteryHealthRoutine(
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_URANDOM:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kUrandomParams);
      service_->RunUrandomRoutine(
          mojo_ipc::NullableUint32::New(
              request.urandom_params().length_seconds()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_SMARTCTL_CHECK:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kSmartctlCheckParams);
      service_->RunSmartctlCheckRoutine(
          request.smartctl_check_params().has_percentage_used_threshold()
              ? mojo_ipc::NullableUint32::New(
                    request.smartctl_check_params().percentage_used_threshold())
              : mojo_ipc::NullableUint32Ptr(),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_CPU_CACHE:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kCpuParams);
      service_->RunCpuCacheRoutine(
          mojo_ipc::NullableUint32::New(request.cpu_params().length_seconds()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_CPU_STRESS:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kCpuParams);
      service_->RunCpuStressRoutine(
          mojo_ipc::NullableUint32::New(request.cpu_params().length_seconds()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_FLOATING_POINT_ACCURACY:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kFloatingPointAccuracyParams);
      service_->RunFloatingPointAccuracyRoutine(
          mojo_ipc::NullableUint32::New(
              request.floating_point_accuracy_params().length_seconds()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_NVME_WEAR_LEVEL:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kNvmeWearLevelParams);
      service_->RunNvmeWearLevelRoutine(
          ash::cros_healthd::mojom::NullableUint32::New(
              request.nvme_wear_level_params().wear_level_threshold()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_NVME_SHORT_SELF_TEST:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kNvmeShortSelfTestParams);
      service_->RunNvmeSelfTestRoutine(
          mojo_ipc::NvmeSelfTestTypeEnum::kShortSelfTest,
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_NVME_LONG_SELF_TEST:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kNvmeLongSelfTestParams);
      service_->RunNvmeSelfTestRoutine(
          mojo_ipc::NvmeSelfTestTypeEnum::kLongSelfTest,
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_DISK_LINEAR_READ:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kDiskLinearReadParams);
      service_->RunDiskReadRoutine(
          mojo_ipc::DiskReadRoutineTypeEnum::kLinearRead,
          request.disk_linear_read_params().length_seconds(),
          request.disk_linear_read_params().file_size_mb(),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_DISK_RANDOM_READ:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kDiskRandomReadParams);
      service_->RunDiskReadRoutine(
          mojo_ipc::DiskReadRoutineTypeEnum::kRandomRead,
          request.disk_random_read_params().length_seconds(),
          request.disk_random_read_params().file_size_mb(),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    case grpc_api::ROUTINE_PRIME_SEARCH:
      DCHECK_EQ(request.parameters_case(),
                grpc_api::RunRoutineRequest::kPrimeSearchParams);
      service_->RunPrimeSearchRoutine(
          mojo_ipc::NullableUint32::New(
              request.prime_search_params().length_seconds()),
          base::BindOnce(&RoutineService::ForwardRunRoutineResponse,
                         weak_ptr_factory_.GetWeakPtr(), callback_key));
      break;
    default:
      LOG(ERROR) << "RunRoutineRequest routine not set or unrecognized.";
      std::move(it.first->second)
          .Run(0 /* uuid */, grpc_api::ROUTINE_STATUS_INVALID_FIELD,
               grpc_api::ROUTINE_SERVICE_STATUS_OK);
      run_routine_callbacks_.erase(it.first);
      break;
  }
}

void RoutineService::GetRoutineUpdate(
    int uuid,
    grpc_api::GetRoutineUpdateRequest::Command command,
    bool include_output,
    GetRoutineUpdateRequestToServiceCallback callback) {
  if (!BindCrosHealthdDiagnosticsServiceIfNeeded()) {
    LOG(WARNING) << "GetRoutineUpdate called before mojo was bootstrapped.";
    std::move(callback).Run(
        uuid, grpc_api::ROUTINE_STATUS_ERROR, 0 /* progress_percent */,
        grpc_api::ROUTINE_USER_MESSAGE_UNSET, "" /* output */,
        "" /* status_message */, grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
    return;
  }

  mojo_ipc::DiagnosticRoutineCommandEnum mojo_command;
  if (!GetMojoCommandFromGrpcCommand(command, &mojo_command)) {
    std::move(callback).Run(
        uuid, grpc_api::ROUTINE_STATUS_INVALID_FIELD, 0 /* progress_percent */,
        grpc_api::ROUTINE_USER_MESSAGE_UNSET, "" /* output */,
        "" /* status_message */, grpc_api::ROUTINE_SERVICE_STATUS_OK);
    return;
  }

  const size_t callback_key = next_get_routine_update_key_;
  next_get_routine_update_key_++;
  DCHECK_EQ(get_routine_update_callbacks_.count(callback_key), 0);
  get_routine_update_callbacks_.insert(
      {callback_key, std::make_pair(uuid, std::move(callback))});
  service_->GetRoutineUpdate(
      uuid, mojo_command, include_output,
      base::BindOnce(&RoutineService::ForwardGetRoutineUpdateResponse,
                     weak_ptr_factory_.GetWeakPtr(), callback_key));
}

void RoutineService::ForwardGetAvailableRoutinesResponse(
    size_t callback_key,
    const std::vector<mojo_ipc::DiagnosticRoutineEnum>& mojo_routines) {
  auto it = get_available_routines_callbacks_.find(callback_key);
  if (it == get_available_routines_callbacks_.end()) {
    LOG(ERROR) << "Unknown callback_key for received mojo GetAvailableRoutines "
                  "response: "
               << callback_key;
    return;
  }

  std::vector<grpc_api::DiagnosticRoutine> grpc_routines;
  for (auto mojo_routine : mojo_routines) {
    std::vector<grpc_api::DiagnosticRoutine> grpc_mojo_routines;
    if (GetGrpcRoutineEnumFromMojoRoutineEnum(mojo_routine,
                                              &grpc_mojo_routines))
      for (auto grpc_routine : grpc_mojo_routines)
        grpc_routines.push_back(grpc_routine);
  }

  std::move(it->second)
      .Run(std::move(grpc_routines), grpc_api::ROUTINE_SERVICE_STATUS_OK);
  get_available_routines_callbacks_.erase(it);
}

void RoutineService::ForwardRunRoutineResponse(
    size_t callback_key, mojo_ipc::RunRoutineResponsePtr response) {
  auto it = run_routine_callbacks_.find(callback_key);
  if (it == run_routine_callbacks_.end()) {
    LOG(ERROR) << "Unknown callback_key for received mojo GetAvailableRoutines "
                  "response: "
               << callback_key;
    return;
  }

  grpc_api::DiagnosticRoutineStatus grpc_status;
  mojo_ipc::DiagnosticRoutineStatusEnum mojo_status = response->status;
  if (!GetGrpcStatusFromMojoStatus(mojo_status, &grpc_status)) {
    std::move(it->second)
        .Run(0 /* uuid */, grpc_api::ROUTINE_STATUS_ERROR,
             grpc_api::ROUTINE_SERVICE_STATUS_OK);
  } else {
    std::move(it->second)
        .Run(response->id, grpc_status, grpc_api::ROUTINE_SERVICE_STATUS_OK);
  }
  run_routine_callbacks_.erase(it);
}

void RoutineService::ForwardGetRoutineUpdateResponse(
    size_t callback_key, mojo_ipc::RoutineUpdatePtr response) {
  auto it = get_routine_update_callbacks_.find(callback_key);
  if (it == get_routine_update_callbacks_.end()) {
    LOG(ERROR) << "Unknown callback_key for received mojo GetAvailableRoutines "
                  "response: "
               << callback_key;
    return;
  }

  grpc_api::GetRoutineUpdateResponse grpc_response;
  SetGrpcUpdateFromMojoUpdate(std::move(response), &grpc_response);
  std::move(it->second.second)
      .Run(it->second.first /* uuid */, grpc_response.status(),
           grpc_response.progress_percent(), grpc_response.user_message(),
           grpc_response.output(), grpc_response.status_message(),
           grpc_api::ROUTINE_SERVICE_STATUS_OK);
  get_routine_update_callbacks_.erase(it);
}

bool RoutineService::BindCrosHealthdDiagnosticsServiceIfNeeded() {
  if (service_.is_bound())
    return true;

  auto receiver = service_.BindNewPipeAndPassReceiver();

  service_.set_disconnect_handler(base::BindOnce(
      &RoutineService::OnDisconnect, weak_ptr_factory_.GetWeakPtr()));

  if (!delegate_->GetCrosHealthdDiagnosticsService(std::move(receiver)))
    return false;

  return true;
}

void RoutineService::OnDisconnect() {
  VLOG(1) << "cros_healthd Mojo connection closed.";
  RunInFlightCallbacks();
  service_.reset();
}

void RoutineService::RunInFlightCallbacks() {
  for (auto& it : get_available_routines_callbacks_) {
    std::move(it.second).Run(std::vector<grpc_api::DiagnosticRoutine>{},
                             grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
  }
  get_available_routines_callbacks_.clear();

  for (auto& it : run_routine_callbacks_) {
    std::move(it.second).Run(0 /* uuid */,
                             grpc_api::ROUTINE_STATUS_FAILED_TO_START,
                             grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
  }
  run_routine_callbacks_.clear();

  for (auto& it : get_routine_update_callbacks_) {
    std::move(it.second.second)
        .Run(it.second.first /* uuid */, grpc_api::ROUTINE_STATUS_ERROR,
             0 /* progress_percent */, grpc_api::ROUTINE_USER_MESSAGE_UNSET,
             "" /* output */, "" /* status_message */,
             grpc_api::ROUTINE_SERVICE_STATUS_UNAVAILABLE);
  }
  get_routine_update_callbacks_.clear();
}

}  // namespace wilco
}  // namespace diagnostics
