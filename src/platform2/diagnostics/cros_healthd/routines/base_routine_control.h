// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BASE_ROUTINE_CONTROL_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BASE_ROUTINE_CONTROL_H_

#include <cstdint>
#include <string>

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// Implements the RoutineControl interface to provide common utilities for
// routines running the RoutineControl API.
//
// Specific routines should inherit from this class, and implement the |OnStart|
// function to determine how the routine will run. The inherited class should
// operate on state_ only through the protected methods. These methods will take
// care of state transition checking and notifying observers.
//
// RaiseException should be called for runtime error, where the inherited
// routine will provide the reason for the exception. on_exception_ is to
// be provided in the |SetOnExceptionCallback| function. The holder of
// BaseRoutineControl should create the on_exception_ callback, which should
// satisfy these two properties when called:
//    1. The RoutineControl object will be destructed
//    2. The observers are notified of the disconnect with reason
//
// Example:
//
// class ExampleRoutineControl : public BaseRoutineControl {
//   explicit ExampleRoutineControl() {}
//   ExampleRoutineControl(const ExampleRoutineControl&) = delete;
//   ExampleRoutineControl& operator=(const ExampleRoutineControl&) = delete;
//   ~ExampleRoutineControl() override = default;

//   void OnStart() override {
//     SetWaitingState(kWaitingReason, "reason");
//     ...
//     SetRunningState();
//     SetPercentage(50);
//     ...
//     SetFinishedState(true, mojom::XXXRoutineDetail::New(...));
//     return;
//   }
// };

class BaseRoutineControl : public ash::cros_healthd::mojom::RoutineControl {
 public:
  using ExceptionCallback =
      base::OnceCallback<void(uint32_t error, const std::string& reason)>;

  BaseRoutineControl();
  BaseRoutineControl(const BaseRoutineControl&) = delete;
  BaseRoutineControl& operator=(const BaseRoutineControl&) = delete;
  ~BaseRoutineControl() override;

  // ash::cros_healthd::mojom::RoutineControl overrides
  void Start() final;
  void GetState(GetStateCallback callback) final;
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::RoutineObserver> observer)
      final;

  // Sets the |on_exception_| callback. This function must be called before any
  // mojo message is sent/received.
  void SetOnExceptionCallback(ExceptionCallback on_exception);

 protected:
  // Calls the on_exception_ callback.
  void RaiseException(const std::string& reason);

  // Set the percentage, this can only be called if the state is in running or
  // waiting.
  void SetPercentage(uint8_t percentage);

  // Return a const reference of the current state.
  const ash::cros_healthd::mojom::RoutineStatePtr& state();

  // Set the state to running, this can only be called if the state is currently
  // waiting or running.
  void SetRunningState();

  // Set the state to waiting, this can only be called if the state is currently
  // running.
  void SetWaitingState(
      ash::cros_healthd::mojom::RoutineStateWaiting::Reason reason,
      const std::string& message);

  // Set the state fo finished, this can only be called if the state is
  // currently running.
  void SetFinishedState(bool has_passed,
                        ash::cros_healthd::mojom::RoutineDetailPtr detail);

 private:
  // Notify all observers of the state change
  void NotifyObservers();

  // The derived classes implements this to perform the actions to start the
  // routine.
  virtual void OnStart() = 0;

  // The current state of the routine control.
  ash::cros_healthd::mojom::RoutineStatePtr state_;
  // A set of observers that this routine control should notify to.
  mojo::RemoteSet<ash::cros_healthd::mojom::RoutineObserver> observers_;
  // A callback provided by the holder of BaseRoutine Control which should
  // remove the receiver from the holder's receiver_set and notify
  // disconnect with reason.
  ExceptionCallback on_exception_;

  // Exported for test.
  friend class RoutineControlImplPeer;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_BASE_ROUTINE_CONTROL_H_
