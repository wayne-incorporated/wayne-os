// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_ANDROID_OCI_WRAPPER_H_
#define LOGIN_MANAGER_ANDROID_OCI_WRAPPER_H_

#include <string>
#include <vector>

#include <base/callback.h>

#include "login_manager/container_manager_interface.h"

namespace login_manager {

class SystemUtils;

// The wrapper class around run_oci binary to launch Android container.
// See platform2/run_oci for more details about run_oci binary, which
// provides an Open Container Initiative-compatible container runtime
// (https://github.com/opencontainers/runtime-spec).
class AndroidOciWrapper : public ContainerManagerInterface {
 public:
  // Ownership of |system_utils| remains with the caller.
  AndroidOciWrapper(SystemUtils* system_utils,
                    const base::FilePath& containers_directory);
  AndroidOciWrapper(const AndroidOciWrapper&) = delete;
  AndroidOciWrapper& operator=(const AndroidOciWrapper&) = delete;

  ~AndroidOciWrapper() override;

  // ChildExitHandler:
  bool HandleExit(const siginfo_t& status) override;

  // ContainerManagerInterface:
  bool StartContainer(const std::vector<std::string>& env,
                      const ExitCallback& exit_callback) override;
  void RequestJobExit(ArcContainerStopReason reason) override;
  void EnsureJobExit(base::TimeDelta timeout) override;
  bool GetContainerPID(pid_t* pid_out) const override;
  StatefulMode GetStatefulMode() const override;
  void SetStatefulMode(StatefulMode mode) override;

  // Relative path to container from |containers_directory_|.
  constexpr static char kContainerPath[] = "android";

  // The container ID that is used as a directory name in
  // /run/containers and a log file name prefix in /var/log.
  constexpr static char kContainerId[] = "android-run_oci";

  // Name of file containing container PID in container root under
  // |ContainerManagerInterface::kContainerRunPath|. run_oci writes init
  // process PID to this file.
  constexpr static char kContainerPidName[] = "container.pid";

  // run_oci path and arguments.
  constexpr static char kRunOciPath[] = "/usr/bin/run_oci";
  // Argument to setup run_oci's logging.
  constexpr static char kRunOciLogging[] = "--log_tag=arc-container";
  // Command sent to run_oci to start the container.
  constexpr static char kRunOciStartCommand[] = "start";
  // Command sent to run_oci to shut down container.
  constexpr static char kRunOciKillCommand[] = "kill";
  // Argument sent to run_oci kill command to forcefully shut down a container.
  constexpr static char kRunOciKillSignal[] = "--signal=KILL";
  // Command sent to run_oci to clean up container.
  constexpr static char kRunOciDestroyCommand[] = "destroy";
  // Argument to specify the location of the container's config.
  constexpr static char kRunOciConfigPath[] =
      "--container_path=/opt/google/containers/android";

  // Path to folder that contains all FDs this process opens.
  constexpr static char kProcFdPath[] = "/proc/self/fd";

 private:
  // Sets up execution environment to launch container and run run_oci with
  // |env| as its environment. This is only called in child process. This
  // function never returns.
  void ExecuteRunOciToStartContainer(const std::vector<std::string>& env);

  // Requests Android to shut down itself.
  bool RequestTermination();

  // Cleans up |container_pid_|, and calls |exit_callback_|.
  void CleanUpContainer();

  // Closes all opened files inherited from session manager. Note: It leaves
  // stdin, stdout and stderr open.
  bool CloseOpenedFiles();

  // Kills the specified process group with SIGKILL.
  void KillProcessGroup(pid_t pgid);

  // The PID of container's init process.
  pid_t container_pid_ = 0;

  // This is owned by the caller.
  SystemUtils* const system_utils_;

  // Directory that holds the container config files.
  const base::FilePath containers_directory_;

  // Callback that will get invoked when the process exits.
  ExitCallback exit_callback_;

  // Keeps the reason why this container is (being) stopped.
  login_manager::ArcContainerStopReason exit_reason_ =
      ArcContainerStopReason::CRASH;

  // Whether container is stateful or stateless.
  StatefulMode stateful_mode_ = StatefulMode::STATELESS;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_ANDROID_OCI_WRAPPER_H_
