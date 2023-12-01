// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/interface/rmad_interface_impl.h"

#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/time/time.h>
#include <base/values.h>
#include <re2/re2.h>

#include "rmad/constants.h"
#include "rmad/logs/logs_utils.h"
#include "rmad/metrics/metrics_utils_impl.h"
#include "rmad/proto_bindings/rmad.pb.h"
#include "rmad/system/power_manager_client_impl.h"
#include "rmad/system/runtime_probe_client_impl.h"
#include "rmad/system/shill_client_impl.h"
#include "rmad/system/tpm_manager_client_impl.h"
#include "rmad/udev/udev_device.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/cmd_utils_impl.h"
#include "rmad/utils/dbus_utils.h"

namespace rmad {

namespace {

const char kCroslogCmd[] = "/usr/sbin/croslog";

const char kInitctlCmd[] = "/sbin/initctl";
const std::vector<std::string> kWaitServices = {"system-services"};
const int kWaitServicesPollInterval = 1;  // 1 second.
const int kWaitServicesRetries = 10;

constexpr char kSummaryDivider[] =
    "\n========================================="
    "=================================\n\n";

bool GetDeviceIdFromDeviceFile(const std::string& device_file,
                               char* device_id) {
  re2::StringPiece string_piece(device_file);
  re2::RE2 regexp("/dev/sd([[:lower:]])([[:digit:]]*)");
  std::string device_id_string;
  if (RE2::FullMatch(string_piece, regexp, &device_id_string)) {
    *device_id = device_id_string[0];
    return true;
  }
  return false;
}

}  // namespace

RmadInterfaceImpl::RmadInterfaceImpl()
    : RmadInterface(),
      external_utils_initialized_(false),
      current_state_case_(RmadState::STATE_NOT_SET) {}

RmadInterfaceImpl::RmadInterfaceImpl(
    scoped_refptr<JsonStore> json_store,
    std::unique_ptr<StateHandlerManager> state_handler_manager,
    std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
    std::unique_ptr<ShillClient> shill_client,
    std::unique_ptr<TpmManagerClient> tpm_manager_client,
    std::unique_ptr<PowerManagerClient> power_manager_client,
    std::unique_ptr<UdevUtils> udev_utils,
    std::unique_ptr<CmdUtils> cmd_utils,
    std::unique_ptr<MetricsUtils> metrics_utils)
    : RmadInterface(),
      json_store_(json_store),
      state_handler_manager_(std::move(state_handler_manager)),
      runtime_probe_client_(std::move(runtime_probe_client)),
      shill_client_(std::move(shill_client)),
      tpm_manager_client_(std::move(tpm_manager_client)),
      power_manager_client_(std::move(power_manager_client)),
      udev_utils_(std::move(udev_utils)),
      cmd_utils_(std::move(cmd_utils)),
      metrics_utils_(std::move(metrics_utils)),
      external_utils_initialized_(true),
      current_state_case_(RmadState::STATE_NOT_SET) {}

bool RmadInterfaceImpl::StoreStateHistory() {
  std::vector<int> state_history;
  for (auto s : state_history_) {
    state_history.push_back(RmadState::StateCase(s));
  }
  return json_store_->SetValue(kStateHistory, state_history);
}

void RmadInterfaceImpl::InitializeExternalUtils(
    scoped_refptr<DaemonCallback> daemon_callback) {
  json_store_ = base::MakeRefCounted<JsonStore>(
      base::FilePath(kDefaultJsonStoreFilePath));
  state_handler_manager_ = std::make_unique<StateHandlerManager>(json_store_);
  state_handler_manager_->RegisterStateHandlers(daemon_callback);
  runtime_probe_client_ =
      std::make_unique<RuntimeProbeClientImpl>(GetSystemBus());
  shill_client_ = std::make_unique<ShillClientImpl>(GetSystemBus());
  tpm_manager_client_ = std::make_unique<TpmManagerClientImpl>(GetSystemBus());
  power_manager_client_ =
      std::make_unique<PowerManagerClientImpl>(GetSystemBus());
  udev_utils_ = std::make_unique<UdevUtilsImpl>();
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
}

bool RmadInterfaceImpl::WaitForServices() {
  CHECK(external_utils_initialized_);
  std::string output;
  for (int i = 0; i < kWaitServicesRetries; ++i) {
    DLOG(INFO) << "Checking services";
    bool all_running = true;
    for (const std::string& service : kWaitServices) {
      cmd_utils_->GetOutput({kInitctlCmd, "status", service}, &output);
      if (output.find("running") == std::string::npos) {
        all_running = false;
        break;
      }
    }
    if (all_running) {
      return true;
    }
    sleep(kWaitServicesPollInterval);
  }
  return false;
}

bool RmadInterfaceImpl::StartFromInitialState() {
  current_state_case_ = kInitialStateCase;
  state_history_.push_back(current_state_case_);
  if (!StoreStateHistory()) {
    LOG(ERROR) << "Could not store initial state";
    // TODO(chenghan): Send a signal to Chrome that the json store failed so
    //                 a message can be displayed.
    return false;
  }
  return true;
}

bool RmadInterfaceImpl::SetUp(scoped_refptr<DaemonCallback> daemon_callback) {
  daemon_callback_ = daemon_callback;
  // Initialize external utilities if needed.
  if (!external_utils_initialized_) {
    InitializeExternalUtils(daemon_callback);
    external_utils_initialized_ = true;
    metrics_utils_ = std::make_unique<MetricsUtilsImpl>();
  }
  // Wait for system services to be ready.
  if (!WaitForServices()) {
    return false;
  }
  // Initialize |current state_|, |state_history_|, and |can_abort_| flag.
  current_state_case_ = RmadState::STATE_NOT_SET;
  state_history_.clear();
  can_abort_ = true;
  // Something's wrong with the state file. Try to clear it.
  if (json_store_->ReadOnly()) {
    LOG(WARNING) << "Corrupted RMA state file. Trying to fix it";
    if (!json_store_->Clear() || !json_store_->InitFromFile()) {
      LOG(ERROR) << "Failed to fix RMA state file";
      return false;
    }
  }
  DCHECK(!json_store_->ReadOnly());
  if (json_store_->GetReadError() != JsonStore::READ_ERROR_NO_SUCH_FILE) {
    if (std::vector<int> state_history;
        json_store_->GetReadError() == JsonStore::READ_ERROR_NONE &&
        json_store_->GetValue(kStateHistory, &state_history) &&
        state_history.size()) {
      for (int state : state_history) {
        // Reject any state that does not have a handler.
        if (RmadState::StateCase s = RmadState::StateCase(state);
            auto handler = state_handler_manager_->GetStateHandler(s)) {
          state_history_.push_back(s);
          can_abort_ &= handler->IsRepeatable();
        } else {
          // TODO(chenghan): Return to welcome screen with an error implying
          //                 an unsupported state.
          LOG(ERROR) << "Missing handler for state " << state << ".";
        }
      }
    }
    if (state_history_.size() > 0) {
      current_state_case_ = state_history_.back();
    } else {
      LOG(WARNING) << "Could not read state history from json store, reset to "
                      "initial state.";
      if (!StartFromInitialState()) {
        return false;
      }
    }
  } else if (RoVerificationStatus status;
             tpm_manager_client_->GetRoVerificationStatus(&status) &&
             (status == RMAD_RO_VERIFICATION_PASS ||
              status == RMAD_RO_VERIFICATION_UNSUPPORTED_TRIGGERED)) {
    VLOG(1) << "RO verification triggered";
    if (!StartFromInitialState()) {
      return false;
    }

    if (!json_store_->SetValue(kRoFirmwareVerified,
                               status == RMAD_RO_VERIFICATION_PASS) ||
        !MetricsUtils::SetMetricsValue(json_store_, kMetricsRoFirmwareVerified,
                                       RoVerificationStatus_Name(status))) {
      LOG(ERROR) << "Could not store RO firmware verification status";
    }
  }

  double current_timestamp = base::Time::Now().ToDoubleT();
  if (!MetricsUtils::UpdateStateMetricsOnStateTransition(
          json_store_, RmadState::STATE_NOT_SET, current_state_case_,
          current_timestamp)) {
    LOG(ERROR) << "Could not store setup time for the current state.";
    return false;
  }

  RecordRepairStartToLogs(json_store_);

  // If we are in the RMA process:
  //   1. Disable cellular to prevent accidentally using it.
  //   2. Start monitoring test files if we are running in test mode.
  // TODO(chenghan): Disable cellular in a separate thread to shorten the
  //                 response time.
  if (current_state_case_ != RmadState::STATE_NOT_SET) {
    if (ComponentsWithIdentifier components;
        runtime_probe_client_->ProbeCategories({RMAD_COMPONENT_CELLULAR}, false,
                                               &components) &&
        components.size() > 0) {
      DLOG(INFO) << "Disabling cellular network";
      CHECK(shill_client_->DisableCellular());
    }
  }

  return true;
}

RmadErrorCode RmadInterfaceImpl::GetInitializedStateHandler(
    RmadState::StateCase state_case,
    scoped_refptr<BaseStateHandler>* state_handler) const {
  auto handler = state_handler_manager_->GetStateHandler(state_case);
  if (!handler) {
    LOG(ERROR) << "No registered state handler for state " << state_case;
    return RMAD_ERROR_STATE_HANDLER_MISSING;
  }
  if (RmadErrorCode init_error = handler->InitializeState();
      init_error != RMAD_ERROR_OK) {
    LOG(ERROR) << "Failed to initialize current state " << state_case;
    return init_error;
  }
  *state_handler = handler;
  return RMAD_ERROR_OK;
}

void RmadInterfaceImpl::TryTransitionNextStateFromCurrentState() {
  DLOG(INFO) << "Trying a state transition using current state";
  TransitionNextStateInternal(TransitionNextStateRequest(), true);
}

void RmadInterfaceImpl::GetCurrentState(GetStateCallback callback) {
  GetStateReply reply = GetCurrentStateInternal();
  ReplyCallback(std::move(callback), reply);
}

GetStateReply RmadInterfaceImpl::GetCurrentStateInternal() {
  GetStateReply reply;
  scoped_refptr<BaseStateHandler> state_handler;

  if (current_state_case_ == RmadState::STATE_NOT_SET) {
    reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
  } else if (RmadErrorCode error = GetInitializedStateHandler(
                 current_state_case_, &state_handler);
             error != RMAD_ERROR_OK) {
    reply.set_error(error);
  } else {
    DLOG(INFO) << "Get current state succeeded: " << current_state_case_;
    reply.set_error(RMAD_ERROR_OK);
    reply.set_allocated_state(new RmadState(state_handler->GetState(true)));
    reply.set_can_go_back(CanGoBack());
    reply.set_can_abort(CanAbort());
  }

  return reply;
}

void RmadInterfaceImpl::TransitionNextState(
    const TransitionNextStateRequest& request, GetStateCallback callback) {
  GetStateReply reply = TransitionNextStateInternal(request, false);
  ReplyCallback(std::move(callback), reply);
}

GetStateReply RmadInterfaceImpl::TransitionNextStateInternal(
    const TransitionNextStateRequest& request, bool try_at_boot) {
  GetStateReply reply;
  if (current_state_case_ == RmadState::STATE_NOT_SET) {
    reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
    return reply;
  }

  scoped_refptr<BaseStateHandler> current_state_handler, next_state_handler;
  if (RmadErrorCode error = GetInitializedStateHandler(current_state_case_,
                                                       &current_state_handler);
      error != RMAD_ERROR_OK) {
    LOG(ERROR) << "Current state initialization failed";
    reply.set_error(error);
    return reply;
  }

  // Initialize the default reply.
  reply.set_error(RMAD_ERROR_NOT_SET);
  reply.set_allocated_state(new RmadState(current_state_handler->GetState()));
  reply.set_can_go_back(CanGoBack());
  reply.set_can_abort(CanAbort());

  auto [next_state_case_error, next_state_case] =
      try_at_boot ? current_state_handler->TryGetNextStateCaseAtBoot()
                  : current_state_handler->GetNextStateCase(request.state());
  if (next_state_case == current_state_case_) {
    DLOG(INFO) << "Transitioning to next state rejected by state "
               << current_state_case_;
    // Staying at the same state. Run it again.
    current_state_handler->RunState();
    reply.set_error(next_state_case_error);
    return reply;
  }

  CHECK(next_state_case_error == RMAD_ERROR_OK)
      << "State transition should not happen with errors.";

  if (RmadErrorCode error =
          GetInitializedStateHandler(next_state_case, &next_state_handler);
      error != RMAD_ERROR_OK) {
    // Staying at the same state. Run it again.
    current_state_handler->RunState();
    reply.set_error(error);
    return reply;
  }

  // Transition to next state.
  DLOG(INFO) << "Transition to next state succeeded: from "
             << current_state_case_ << " to " << next_state_case;
  current_state_handler->CleanUpState();
  // Append next state to stack.
  state_history_.push_back(next_state_case);
  if (!StoreStateHistory()) {
    // TODO(chenghan): Add error replies when failed to write |json_store_|.
    LOG(ERROR) << "Could not store history";
  }

  // Update state metrics.
  if (!MetricsUtils::UpdateStateMetricsOnStateTransition(
          json_store_, current_state_case_, next_state_case,
          base::Time::Now().ToDoubleT())) {
    // TODO(genechang): Add error replies when failed to update state metrics
    //                  in |json_store| -> |metrics| -> |state_metrics|.
    LOG(ERROR) << "Could not update state metrics.";
  }

  // Append to logs.
  if (!RecordStateTransitionToLogs(json_store_, current_state_case_,
                                   next_state_case)) {
    LOG(ERROR) << "Could not add state transition to logs.";
  }

  // Update state and run it.
  current_state_case_ = next_state_case;
  next_state_handler->RunState();
  // This is a one-way transition. |can_abort| cannot go from false to
  // true, unless we restart the whole RMA process.
  can_abort_ &= next_state_handler->IsRepeatable();

  reply.set_error(RMAD_ERROR_OK);
  reply.set_allocated_state(new RmadState(next_state_handler->GetState(true)));
  reply.set_can_go_back(CanGoBack());
  reply.set_can_abort(CanAbort());
  return reply;
}

void RmadInterfaceImpl::TransitionPreviousState(GetStateCallback callback) {
  GetStateReply reply = TransitionPreviousStateInternal();
  ReplyCallback(std::move(callback), reply);
}

GetStateReply RmadInterfaceImpl::TransitionPreviousStateInternal() {
  GetStateReply reply;
  if (current_state_case_ == RmadState::STATE_NOT_SET) {
    reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
    return reply;
  }

  scoped_refptr<BaseStateHandler> current_state_handler, prev_state_handler;
  if (RmadErrorCode error = GetInitializedStateHandler(current_state_case_,
                                                       &current_state_handler);
      error != RMAD_ERROR_OK) {
    LOG(ERROR) << "Current state initialization failed";
    reply.set_error(error);
    return reply;
  }

  // Initialize the default reply.
  reply.set_error(RMAD_ERROR_NOT_SET);
  reply.set_allocated_state(new RmadState(current_state_handler->GetState()));
  reply.set_can_go_back(CanGoBack());
  reply.set_can_abort(CanAbort());

  if (!CanGoBack()) {
    DLOG(INFO) << "Cannot go back to previous state";
    // Staying at the same state. Run it again.
    current_state_handler->RunState();
    reply.set_error(RMAD_ERROR_TRANSITION_FAILED);
    return reply;
  }

  RmadState::StateCase prev_state_case = *std::prev(state_history_.end(), 2);
  if (RmadErrorCode error =
          GetInitializedStateHandler(prev_state_case, &prev_state_handler);
      error != RMAD_ERROR_OK) {
    // Staying at the same state. Run it again.
    current_state_handler->RunState();
    reply.set_error(error);
    return reply;
  }

  // Transition to previous state.
  DLOG(INFO) << "Transition to previous state succeeded: from "
             << current_state_case_ << " to " << prev_state_case;
  current_state_handler->CleanUpState();
  // Remove current state from stack.
  state_history_.pop_back();
  if (!StoreStateHistory()) {
    LOG(ERROR) << "Could not store history";
  }

  // Update state metrics.
  if (!MetricsUtils::UpdateStateMetricsOnStateTransition(
          json_store_, current_state_case_, prev_state_case,
          base::Time::Now().ToDoubleT())) {
    // TODO(genechang): Add error replies when failed to update state metrics
    //                  in |json_store| -> |metrics| -> |state_metrics|.
    LOG(ERROR) << "Could not update state metrics.";
  }

  // Append to logs.
  if (!RecordStateTransitionToLogs(json_store_, current_state_case_,
                                   prev_state_case)) {
    LOG(ERROR) << "Could not add state transition to logs.";
  }

  // Update state and run it.
  current_state_case_ = prev_state_case;
  prev_state_handler->RunState();

  reply.set_error(RMAD_ERROR_OK);
  reply.set_allocated_state(new RmadState(prev_state_handler->GetState(true)));
  reply.set_can_go_back(CanGoBack());
  reply.set_can_abort(CanAbort());
  return reply;
}

void RmadInterfaceImpl::AbortRma(AbortRmaCallback callback) {
  AbortRmaReply reply;
  if (current_state_case_ == RmadState::STATE_NOT_SET) {
    reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
  } else if (can_abort_) {
    VLOG(1) << "AbortRma: Abort allowed.";
    if (!MetricsUtils::UpdateStateMetricsOnAbort(
            json_store_, current_state_case_, base::Time::Now().ToDoubleT())) {
      // TODO(genechang): Add error replies when failed to update state metrics
      //                  in |json_store| -> |metrics| -> |state_metrics|.
      LOG(ERROR) << "AbortRma: Failed to update state metrics.";
    }
    if (!metrics_utils_->RecordAll(json_store_)) {
      // TODO(genechang): Add error replies when failed to record metrics.
      LOG(ERROR) << "AbortRma: Failed to generate and record metrics.";
    }
    if (json_store_->ClearAndDeleteFile()) {
      current_state_case_ = RmadState::STATE_NOT_SET;
      reply.set_error(RMAD_ERROR_RMA_NOT_REQUIRED);
    } else {
      LOG(ERROR) << "AbortRma: Failed to clear RMA state file";
      reply.set_error(RMAD_ERROR_ABORT_FAILED);
    }
  } else {
    VLOG(1) << "AbortRma: Failed to abort.";
    reply.set_error(RMAD_ERROR_ABORT_FAILED);
  }

  ReplyCallback(std::move(callback), reply);
}

std::string RmadInterfaceImpl::GetSystemLog() const {
  std::string system_log;
  if (!cmd_utils_->GetOutput({kCroslogCmd, "--identifier=rmad"}, &system_log)) {
    return "";
  }

  return system_log;
}

bool RmadInterfaceImpl::GetLogString(std::string* log_string) const {
  *log_string = GenerateLogsText(json_store_) + kSummaryDivider +
                GenerateLogsJson(json_store_) + kSummaryDivider +
                GetSystemLog();
  return true;
}

void RmadInterfaceImpl::GetLog(GetLogCallback callback) {
  GetLogReply reply;
  if (std::string log_string; GetLogString(&log_string)) {
    reply.set_error(RMAD_ERROR_OK);
    reply.set_log(log_string);
    if (!MetricsUtils::UpdateStateMetricsOnGetLog(json_store_,
                                                  current_state_case_)) {
      // TODO(genechang): Add error replies when failed to update state metrics
      //                  in |json_store| -> |metrics| -> |state_metrics|.
      LOG(ERROR) << "GetLog: Failed to update state metrics.";
    }
  } else {
    LOG(ERROR) << "Failed to generate logs";
    reply.set_error(RMAD_ERROR_CANNOT_GET_LOG);
  }

  ReplyCallback(std::move(callback), reply);
}

void RmadInterfaceImpl::SaveLog(const std::string& diagnostics_log_text,
                                SaveLogCallback callback) {
  const std::string text_log = GenerateLogsText(json_store_);
  const std::string json_log = GenerateLogsJson(json_store_);
  const std::string system_log = GetSystemLog();
  if (text_log.empty() || json_log.empty() || system_log.empty()) {
    // Failed to generate logs.
    SaveLogReply reply;
    reply.set_error(RMAD_ERROR_CANNOT_GET_LOG);
    ReplyCallback(std::move(callback), reply);
    return;
  }

  std::vector<std::string> device_paths = GetRemovableBlockDevicePaths();
  auto device_list = std::make_unique<std::list<std::string>>(
      device_paths.begin(), device_paths.end());
  if (device_list->empty()) {
    // No detected external storage.
    SaveLogReply reply;
    reply.set_error(RMAD_ERROR_USB_NOT_FOUND);
    ReplyCallback(std::move(callback), reply);
    return;
  }

  SaveLogToFirstMountableDevice(std::move(device_list), text_log, json_log,
                                system_log, diagnostics_log_text,
                                std::move(callback));
}

void RmadInterfaceImpl::SaveLogToFirstMountableDevice(
    std::unique_ptr<std::list<std::string>> devices,
    const std::string& text_log,
    const std::string& json_log,
    const std::string& system_log,
    const std::string& diagnostics_log,
    SaveLogCallback callback) {
  if (devices->empty()) {
    // No devices left to try.
    SaveLogReply reply;
    reply.set_error(RMAD_ERROR_CANNOT_SAVE_LOG);
    ReplyCallback(std::move(callback), reply);
    return;
  }
  if (char device_id; GetDeviceIdFromDeviceFile(devices->front(), &device_id)) {
    daemon_callback_->GetExecuteMountAndWriteLogCallback().Run(
        static_cast<uint8_t>(device_id), text_log, json_log, system_log,
        diagnostics_log,
        base::BindOnce(&RmadInterfaceImpl::SaveLogExecutorCompleteCallback,
                       base::Unretained(this), std::move(devices), text_log,
                       json_log, system_log, diagnostics_log,
                       std::move(callback)));
  } else {
    // Try next device.
    devices->pop_front();
    SaveLogToFirstMountableDevice(std::move(devices), text_log, json_log,
                                  system_log, diagnostics_log,
                                  std::move(callback));
  }
}

void RmadInterfaceImpl::SaveLogExecutorCompleteCallback(
    std::unique_ptr<std::list<std::string>> devices,
    const std::string& text_log,
    const std::string& json_log,
    const std::string& system_log,
    const std::string& diagnostics_log,
    SaveLogCallback callback,
    const std::optional<std::string>& file_name) {
  CHECK(!devices->empty());
  if (file_name.has_value()) {
    // Save file succeeds.
    if (!MetricsUtils::UpdateStateMetricsOnSaveLog(json_store_,
                                                   current_state_case_)) {
      // TODO(genechang): Add error replies when failed to update state metrics
      //                  in |json_store| -> |metrics| -> |state_metrics|.
      LOG(ERROR) << "SaveLog: Failed to update state metrics.";
    }
    SaveLogReply reply;
    reply.set_error(RMAD_ERROR_OK);
    reply.set_save_path(file_name.value());
    ReplyCallback(std::move(callback), reply);
  } else {
    // Failed to save file. Try next device.
    devices->pop_front();
    SaveLogToFirstMountableDevice(std::move(devices), text_log, json_log,
                                  system_log, diagnostics_log,
                                  std::move(callback));
  }
}

void RmadInterfaceImpl::RecordBrowserActionMetric(
    const RecordBrowserActionMetricRequest& browser_action,
    RecordBrowserActionMetricCallback callback) {
  std::vector<std::string> additional_activities;
  // Ignore the return value, since it may not have been set yet.
  MetricsUtils::GetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                &additional_activities);

  // TODO(genechang): Add a table to map all actions to metrics to simplify it.
  if (browser_action.diagnostics()) {
    additional_activities.push_back(
        AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_DIAGNOSTICS));
  }

  if (browser_action.os_update()) {
    additional_activities.push_back(
        AdditionalActivity_Name(RMAD_ADDITIONAL_ACTIVITY_OS_UPDATE));
  }

  RecordBrowserActionMetricReply reply;
  if (MetricsUtils::SetMetricsValue(json_store_, kMetricsAdditionalActivities,
                                    additional_activities)) {
    reply.set_error(RMAD_ERROR_OK);
  } else {
    reply.set_error(RMAD_ERROR_CANNOT_RECORD_BROWSER_ACTION);
  }

  ReplyCallback(std::move(callback), reply);
}

bool RmadInterfaceImpl::CanGoBack() const {
  if (state_history_.size() > 1) {
    const auto current_state_handler =
        state_handler_manager_->GetStateHandler(state_history_.back());
    const auto prev_state_handler = state_handler_manager_->GetStateHandler(
        *std::prev(state_history_.end(), 2));
    CHECK(current_state_handler);
    CHECK(prev_state_handler);
    return (current_state_handler->IsRepeatable() &&
            prev_state_handler->IsRepeatable());
  }
  return false;
}

std::vector<std::string> RmadInterfaceImpl::GetRemovableBlockDevicePaths()
    const {
  std::vector<std::string> device_paths;
  for (const auto& device : udev_utils_->EnumerateBlockDevices()) {
    if (device->IsRemovable()) {
      device_paths.push_back(device->GetDeviceNode());
    }
  }
  return device_paths;
}

}  // namespace rmad
