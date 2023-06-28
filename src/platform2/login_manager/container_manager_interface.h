// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CONTAINER_MANAGER_INTERFACE_H_
#define LOGIN_MANAGER_CONTAINER_MANAGER_INTERFACE_H_

#include <sys/types.h>

#include <string>
#include <vector>

#include <base/callback_forward.h>
#include <base/files/file_path.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include "login_manager/child_exit_handler.h"

namespace login_manager {

enum class StatefulMode {
  STATEFUL,
  STATELESS,
};

// Provides methods for running and stopping containers.
//
// Containers can only be run from the verified rootfs.
class ContainerManagerInterface : public ChildExitHandler {
 public:
  using ExitCallback =
      base::Callback<void(pid_t, ArcContainerStopReason reason)>;

  // The path to the location of containers.
  constexpr static const char kContainerRunPath[] = "/run/containers";

  ~ContainerManagerInterface() override {}

  // Starts the container. Returns true on success.
  // If successful, |exit_callback| will be notified when the process exits.
  // |env| contains environment variables to be sent to the container.
  virtual bool StartContainer(const std::vector<std::string>& env,
                              const ExitCallback& exit_callback) = 0;

  // Requests to stop the container. |reason| will be propagated into
  // the arg of |exit_callback| passed to StartContainer.
  virtual void RequestJobExit(ArcContainerStopReason reason) = 0;

  // The job must be destroyed within the timeout.
  virtual void EnsureJobExit(base::TimeDelta timeout) = 0;

  // Gets the container's statefulness state.
  virtual StatefulMode GetStatefulMode() const = 0;

  // Sets the container as stateful or stateless.
  // Stateless containers use a faster teardown procedure.
  virtual void SetStatefulMode(StatefulMode mode) = 0;

  // Gets the process ID of the container.
  virtual bool GetContainerPID(pid_t* pid_out) const = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_CONTAINER_MANAGER_INTERFACE_H_
