// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_PROCESS_H_
#define ML_PROCESS_H_

#include <memory>
#include <string>
#include <unordered_map>

#include <unistd.h>

#include <base/functional/callback_forward.h>
#include <base/no_destructor.h>
#include <base/process/process_metrics.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <base/sequence_checker.h>

#include "ml/machine_learning_service_impl.h"

namespace ml {

// A singleton class to store the global process information and provide
// process management functions.
// Usage: access the global instance by calling `Process::GetInstance()`.
class Process {
 public:
  // The type of a process.
  // "kControlForTest" denotes the control process in unit tests (i.e. the
  // process that runs the ml_service_test binary). "kSingleProcessForTest"
  // means the program will not spawn worker processes and use one single
  // process for testing.
  enum class Type {
    kUnset = 0,
    kControl = 1,
    kWorker = 2,
    kControlForTest = 3,        // Like control process but with less strict
                                // sandboxing for using in testing.
    kSingleProcessForTest = 4,  // Temporary, used by old single-process tests.
  };

  // The exit code of a process.
  enum ExitCode : int {
    kSuccess = 0,
    // Only for worker process used when its mojo connection with the control
    // process breaks.
    kWorkerDisconnectWithControl = 1,
    kInvalidProcessType = 2,
    kUnexpectedCommandLine = 3,
    kModelNameNotSpecified = 4,
  };

  // The worker process info, containing object to contact and measure worker
  // process in the control process.
  struct WorkerInfo {
    // The Mojo remote to call the worker process's `MachineLearningService`
    // bindings.
    mojo::Remote<chromeos::machine_learning::mojom::MachineLearningService>
        remote;
    // The process metrics object of the worker process.
    std::unique_ptr<base::ProcessMetrics> process_metrics;
  };

  static Process* GetInstance();

  int Run();

  // Gets the process type of current process.
  Type GetType();

  // Returns true if the worker process has been started successfully and the
  // worker's pid is stored in `worker_pid`. Otherwise returns false and
  // `worker_pid` is unchanged.
  // The argument `model_name` has two usages:
  //   - it used in logging (like `metrics_model_name`).
  //   - it also determines which seccomp policy list to use in sandboxing the
  //     worker process.
  bool SpawnWorkerProcessAndGetPid(const mojo::PlatformChannel& channel,
                                   const std::string& model_name,
                                   pid_t* worker_pid);

  // Returns a reference of the remote of the worker process. The remote is hold
  // in the `worker_pid_info_map_` object.
  mojo::Remote<chromeos::machine_learning::mojom::MachineLearningService>&
  SendMojoInvitationAndGetRemote(pid_t worker_pid,
                                 mojo::PlatformChannel channel,
                                 const std::string& model_name);

  // Removes a worker process from metadata. This does not terminate the
  // worker process.
  void UnregisterWorkerProcess(pid_t pid);

  const std::unordered_map<pid_t, WorkerInfo>& GetWorkerPidInfoMap();

  // Sets the process type. Only used in testing.
  void SetTypeForTesting(Type type);

  // Sets the path of mlservice. Only used in testing.
  void SetMlServicePathForTesting(const std::string& path);

  // Sets the `reap_worker_process_succeed_callback_`, only used in testing.
  void SetReapWorkerProcessSucceedCallbackForTesting(
      base::RepeatingClosure callback);

  // Sets the `reap_worker_process_succeed_callback_`, only used in testing.
  void SetReapWorkerProcessFailCallbackForTesting(
      base::RepeatingCallback<void(std::string reason)> callback);

  // Returns if the current process is a control process (i.e. `kControl ||
  // kControlForTest`).
  bool IsControlProcess();

  // Returns if the current process is a worker process (i.e. that will do the
  // actually inference work, `kWorker || kSingleProcessForTest`).
  bool IsWorkerProcess();

 private:
  friend base::NoDestructor<Process>;

  Process();
  ~Process();

  // Can only be called by the control process.
  void ControlProcessRun();

  // Can only be called by the worker process.
  // Input: the file descriptor used to bootstrap Mojo connection.
  void WorkerProcessRun();

  // A helper function for reaping worker processes. This function is
  // unblocking. If the reap failed, it will post itself with some delay time
  // and try again.
  // - `child_pid` is the pid of the worker process to reap.
  // - `times_tried` denotes how many times we have tried to reap the worker
  // process. Every time a trial failed, we will enlarge the delay time to have
  // a next try. We will try this for at maximum of `kWaitPidMaxNumOfRetrials`
  // times. Also, when it succeeds, we will report how long it has taken.
  // - `begin_time` is the the time we start to try to reap worker process, used
  // in metric reporting.
  void ReapWorkerProcess(pid_t child_pid,
                         int times_tried,
                         base::Time begin_time);

  // The disconnect handler of control process for the mojo connection to the
  // worker process.
  void InternalPrimordialMojoPipeDisconnectHandler(pid_t child_pid);

  // The type of current process.
  Type process_type_;

  // The file descriptor to bootstrap the mojo connection of current process.
  // Only meaningful for worker process.
  int mojo_bootstrap_fd_;

  // The name of the model to be run. Used for finding the appropriate
  // seccomp policy.  Only meaningful for worker process.
  std::string model_name_;

  // Whether to disable seccomp sandboxing for the purposes of testing. Only
  // meaningful for worker processes.
  bool disable_seccomp_for_test_;

  // Path to the ml_service binary. Normally (and by default) it is
  // "/usr/bin/ml_service". We may change the value here for testing.
  std::string ml_service_path_;

  // The map from pid to the info of worker processes. Only meaningful for
  // control process.
  std::unordered_map<pid_t, WorkerInfo> worker_pid_info_map_;

  // The function called in the `kControlForTesting` process after a worker
  // process has been successfully reaped.
  base::RepeatingClosure reap_worker_process_succeed_callback_;

  // The function called in the `kControlForTesting` process if we failed to
  // reap the worker process after `kWaitPidMaxNumOfTrials` times of trials.
  // The reason of failure will be passed in as the argument.
  base::RepeatingCallback<void(std::string reason)>
      reap_worker_process_fail_callback_;

  // Mainly used for guarding `worker_pid_info_map_`.
  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace ml

#endif  // ML_PROCESS_H_
