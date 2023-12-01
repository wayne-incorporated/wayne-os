// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_INTERFACE_RMAD_INTERFACE_H_
#define RMAD_INTERFACE_RMAD_INTERFACE_H_

#include <string>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>

#include "rmad/daemon/daemon_callback.h"
#include "rmad/proto_bindings/rmad.pb.h"

namespace rmad {

class RmadInterface {
 public:
  RmadInterface() = default;
  virtual ~RmadInterface() = default;

  // Fully set up the interface. To minimize unnecessary initialization when RMA
  // is not required, the D-Bus APIs might be called when the class is
  // initialized by the constructor but not fully set up.
  virtual bool SetUp(scoped_refptr<DaemonCallback> daemon_callback) = 0;

  // Get the current state_case.
  virtual RmadState::StateCase GetCurrentStateCase() = 0;

  // Try to transition to the next state using the current state without
  // additional user input.
  virtual void TryTransitionNextStateFromCurrentState() = 0;

  // Callback used by all state functions to return the current state to the
  // dbus service.
  using GetStateCallback = base::OnceCallback<void(const GetStateReply&, bool)>;

  // Get the initialized current RmadState proto.
  virtual void GetCurrentState(GetStateCallback callback) = 0;
  // Update the state using the RmadState proto in the request and return the
  // resulting state after all work is done.
  virtual void TransitionNextState(const TransitionNextStateRequest& request,
                                   GetStateCallback callback) = 0;
  // Go back to the previous state if possible and return the RmadState proto.
  virtual void TransitionPreviousState(GetStateCallback callback) = 0;

  using AbortRmaCallback = base::OnceCallback<void(const AbortRmaReply&, bool)>;
  // Cancel the RMA process if possible and reboot.
  virtual void AbortRma(AbortRmaCallback callback) = 0;

  using GetLogCallback = base::OnceCallback<void(const GetLogReply&, bool)>;
  // Get the RMA logs.
  virtual void GetLog(GetLogCallback callback) = 0;

  using SaveLogCallback = base::OnceCallback<void(const SaveLogReply&, bool)>;
  // Save the RMA logs.
  virtual void SaveLog(const std::string& diagnostics_log_text,
                       SaveLogCallback callback) = 0;

  using RecordBrowserActionMetricCallback =
      base::OnceCallback<void(const RecordBrowserActionMetricReply&, bool)>;
  // Record actions from Chrome.
  virtual void RecordBrowserActionMetric(
      const RecordBrowserActionMetricRequest& browser_action,
      RecordBrowserActionMetricCallback callback) = 0;

  // Returns whether it's allowed to abort RMA now.
  virtual bool CanAbort() const = 0;
};

}  // namespace rmad

#endif  // RMAD_INTERFACE_RMAD_INTERFACE_H_
