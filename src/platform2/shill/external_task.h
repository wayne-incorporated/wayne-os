// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_EXTERNAL_TASK_H_
#define SHILL_EXTERNAL_TASK_H_

#include <sys/types.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/net/process_manager.h"
#include "shill/rpc_task.h"

namespace shill {

class ControlInterface;
class Error;

class ExternalTask : public RpcTaskDelegate {
 public:
  // |death_callback| will be called when the corresponding task is
  // terminated. By the time it is called, this ExternalTask will already be
  // Stop()'d. Clients are free to destruct the ExternalTask within the death
  // callback.
  ExternalTask(ControlInterface* control,
               ProcessManager* process_manager,
               const base::WeakPtr<RpcTaskDelegate>& task_delegate,
               base::OnceCallback<void(pid_t, int)> death_callback);
  ExternalTask(const ExternalTask&) = delete;
  ExternalTask& operator=(const ExternalTask&) = delete;

  ~ExternalTask() override;

  // Forks off a process to run |program|, with the command-line
  // arguments |arguments|, and the environment variables specified in
  // |environment|.
  //
  // If |terminate_with_parent| is true, the child process will be
  // configured to terminate itself if this process dies. Otherwise,
  // the child process will retain its default behavior.
  //
  // On success, returns true, and leaves |error| unmodified.
  // On failure, returns false, and sets |error|.
  //
  // |environment| SHOULD NOT contain kRpcTaskServiceVariable or
  // kRpcTaskPathVariable, as that may prevent the child process
  // from communicating back to the ExternalTask.
  virtual bool Start(const base::FilePath& program,
                     const std::vector<std::string>& arguments,
                     const std::map<std::string, std::string>& environment,
                     bool terminate_with_parent,
                     Error* error);

  // Forks off a process to run |program|, with the command-line arguments
  // |arguments|, and the environment variables specified in |environment|.
  // The process will be started in minijail with |minijail_options|.
  //
  // On success, returns true, and leaves |error| unmodified.
  // On failure, returns false, and sets |error|.
  //
  // |environment| SHOULD NOT contain kRpcTaskServiceVariable or
  // kRpcTaskPathVariable, as that may prevent the child process from
  // communicating back to the ExternalTask.
  virtual bool StartInMinijail(
      const base::FilePath& program,
      std::vector<std::string>* arguments,
      const std::map<std::string, std::string>& environment,
      const ProcessManager::MinijailOptions& minijail_options,
      Error* error);

  virtual void Stop();

 private:
  friend class ExternalTaskTest;
  FRIEND_TEST(ExternalTaskTest, Destructor);
  FRIEND_TEST(ExternalTaskTest, GetLogin);
  FRIEND_TEST(ExternalTaskTest, Notify);
  FRIEND_TEST(ExternalTaskTest, OnTaskDied);
  FRIEND_TEST(ExternalTaskTest, Start);
  FRIEND_TEST(ExternalTaskTest, Stop);
  FRIEND_TEST(ExternalTaskTest, StopNotStarted);

  // Implements RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& event,
              const std::map<std::string, std::string>& details) override;

  // Called when the external process exits.
  void OnTaskDied(int exit_status);

  ControlInterface* control_;
  ProcessManager* process_manager_;

  std::unique_ptr<RpcTask> rpc_task_;
  base::WeakPtr<RpcTaskDelegate> task_delegate_;
  base::OnceCallback<void(pid_t, int)> death_callback_;

  // The PID of the spawned process. May be 0 if no process has been
  // spawned yet or the process has died.
  pid_t pid_;
};

}  // namespace shill

#endif  // SHILL_EXTERNAL_TASK_H_
