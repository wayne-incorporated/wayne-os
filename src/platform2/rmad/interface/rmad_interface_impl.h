// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_INTERFACE_RMAD_INTERFACE_IMPL_H_
#define RMAD_INTERFACE_RMAD_INTERFACE_IMPL_H_

#include "rmad/interface/rmad_interface.h"

#include <algorithm>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/timer/timer.h>

#include "rmad/constants.h"
#include "rmad/daemon/daemon_callback.h"
#include "rmad/metrics/metrics_utils.h"
#include "rmad/state_handler/state_handler_manager.h"
#include "rmad/system/power_manager_client.h"
#include "rmad/system/runtime_probe_client.h"
#include "rmad/system/shill_client.h"
#include "rmad/system/tpm_manager_client.h"
#include "rmad/udev/udev_utils.h"
#include "rmad/utils/cmd_utils.h"
#include "rmad/utils/json_store.h"

namespace rmad {

class RmadInterfaceImpl final : public RmadInterface {
 public:
  static constexpr base::TimeDelta kTestModeMonitorInterval = base::Seconds(2);

  RmadInterfaceImpl();
  // Used to inject mocked |json_store_|, |state_handler_manager_|,
  // |runtime_probe_client_|, |shill_client_|, |tpm_manager_client_|,
  // |power_manager_client_|, |udev_utils_|, |cmd_utils_| and
  // |metrics_utils_|.
  explicit RmadInterfaceImpl(
      scoped_refptr<JsonStore> json_store,
      std::unique_ptr<StateHandlerManager> state_handler_manager,
      std::unique_ptr<RuntimeProbeClient> runtime_probe_client,
      std::unique_ptr<ShillClient> shill_client,
      std::unique_ptr<TpmManagerClient> tpm_manager_client,
      std::unique_ptr<PowerManagerClient> power_manager_client,
      std::unique_ptr<UdevUtils> udev_utils,
      std::unique_ptr<CmdUtils> cmd_utils_,
      std::unique_ptr<MetricsUtils> metrics_utils);
  RmadInterfaceImpl(const RmadInterfaceImpl&) = delete;
  RmadInterfaceImpl& operator=(const RmadInterfaceImpl&) = delete;

  ~RmadInterfaceImpl() override = default;

  bool SetUp(scoped_refptr<DaemonCallback> daemon_callback) override;

  RmadState::StateCase GetCurrentStateCase() override {
    return current_state_case_;
  }
  void TryTransitionNextStateFromCurrentState() override;
  void GetCurrentState(GetStateCallback callback) override;
  void TransitionNextState(const TransitionNextStateRequest& request,
                           GetStateCallback callback) override;
  void TransitionPreviousState(GetStateCallback callback) override;
  void AbortRma(AbortRmaCallback callback) override;
  void GetLog(GetLogCallback callback) override;
  void SaveLog(const std::string& diagnostics_log_text,
               SaveLogCallback callback) override;
  void RecordBrowserActionMetric(
      const RecordBrowserActionMetricRequest& browser_action,
      RecordBrowserActionMetricCallback callback) override;
  bool CanAbort() const override { return can_abort_; }

 private:
  void InitializeExternalUtils(scoped_refptr<DaemonCallback> daemon_callback);
  bool WaitForServices();
  bool StartFromInitialState();

  std::string GetSystemLog() const;
  bool GetLogString(std::string* log_string) const;
  void SaveLogToFirstMountableDevice(
      std::unique_ptr<std::list<std::string>> devices,
      const std::string& text_log,
      const std::string& json_log,
      const std::string& system_log,
      const std::string& diagnostics_log,
      SaveLogCallback callback);
  void SaveLogExecutorCompleteCallback(
      std::unique_ptr<std::list<std::string>> devices,
      const std::string& text_log,
      const std::string& json_log,
      const std::string& system_log,
      const std::string& diagnostics_log,
      SaveLogCallback callback,
      const std::optional<std::string>& file_name);
  std::vector<std::string> GetRemovableBlockDevicePaths() const;

  // Wrapper to trigger D-Bus callbacks.
  template <typename ReplyProtobufType>
  void ReplyCallback(
      base::OnceCallback<void(const ReplyProtobufType&, bool)> callback,
      const ReplyProtobufType reply) {
    // Quit the daemon if we are no longer in RMA, or the current state requires
    // to restart the daemon.
    bool quit_daemon = false;
    if (reply.error() == RMAD_ERROR_RMA_NOT_REQUIRED ||
        kQuitDaemonStates.contains(current_state_case_)) {
      quit_daemon = true;
    }
    std::move(callback).Run(reply, quit_daemon);
  }

  // Get and initialize the state handler for |state case|, and store it to
  // |state_handler|. If there's no state handler for |state_case|, or the
  // initialization fails, return an error, and |state_handler| is unchanged.
  RmadErrorCode GetInitializedStateHandler(
      RmadState::StateCase state_case,
      scoped_refptr<BaseStateHandler>* state_handler) const;

  GetStateReply GetCurrentStateInternal();
  GetStateReply TransitionNextStateInternal(
      const TransitionNextStateRequest& request, bool try_at_boot);
  GetStateReply TransitionPreviousStateInternal();

  // Store the state history to |json_store_|.
  bool StoreStateHistory();

  // Check if it's allowed to go back to the previous state.
  bool CanGoBack() const;

  // External utilities.
  scoped_refptr<JsonStore> json_store_;
  std::unique_ptr<StateHandlerManager> state_handler_manager_;
  std::unique_ptr<RuntimeProbeClient> runtime_probe_client_;
  std::unique_ptr<ShillClient> shill_client_;
  std::unique_ptr<TpmManagerClient> tpm_manager_client_;
  std::unique_ptr<PowerManagerClient> power_manager_client_;
  std::unique_ptr<UdevUtils> udev_utils_;
  std::unique_ptr<CmdUtils> cmd_utils_;
  std::unique_ptr<MetricsUtils> metrics_utils_;

  // External Callbacks.
  scoped_refptr<DaemonCallback> daemon_callback_;

  // Internal states.
  bool external_utils_initialized_;
  RmadState::StateCase current_state_case_;
  std::vector<RmadState::StateCase> state_history_;
  bool can_abort_;
};

}  // namespace rmad

#endif  // RMAD_INTERFACE_RMAD_INTERFACE_IMPL_H_
