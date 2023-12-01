// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SCOPED_PROCESS_CONTROL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SCOPED_PROCESS_CONTROL_H_

#include <mojo/public/cpp/bindings/remote.h>

#include "diagnostics/cros_healthd/mojom/executor.mojom.h"

namespace diagnostics {

// Used for running callbacks after the process wrapped by ProcessControl has
// exited.
//
// This object holds a pointer to a set of ScopedClosureRunner callbacks and a
// ProcessControl remote. On destruction, the callbacks will be run and remote
// will be disconnected *after* the underlying process has exited.
class ScopedProcessControl {
 public:
  ScopedProcessControl();
  ScopedProcessControl(const ScopedProcessControl&) = delete;
  ScopedProcessControl& operator=(const ScopedProcessControl&) = delete;
  ~ScopedProcessControl();

  // A struct that will hold references to variables that outlive the lifetime
  // of this object.
  struct ProcessControlState;

  // Resets the connection of the underlying ProcessControl remote and run all
  // the callbacks. Can only be called once.
  void Reset();

  // Add callbacks that will be run when the process terminates.
  void AddOnTerminateCallback(base::ScopedClosureRunner callback);

  // Returns a pending receiver connected to the remote in |state_|.
  mojo::PendingReceiver<ash::cros_healthd::mojom::ProcessControl>
  BindNewPipeAndPassReceiver();

  // A getter to access the underlying ProcessControl interface.
  ash::cros_healthd::mojom::ProcessControl* operator->();

 private:
  // Use a raw pointer to hold state so the state is not destructed when the
  // object's destructor is called.
  ProcessControlState* state_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_SCOPED_PROCESS_CONTROL_H_
