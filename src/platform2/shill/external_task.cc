// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/external_task.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "shill/error.h"
#include "shill/net/process_manager.h"

namespace shill {

ExternalTask::ExternalTask(ControlInterface* control,
                           ProcessManager* process_manager,
                           const base::WeakPtr<RpcTaskDelegate>& task_delegate,
                           base::OnceCallback<void(pid_t, int)> death_callback)
    : control_(control),
      process_manager_(process_manager),
      task_delegate_(task_delegate),
      death_callback_(std::move(death_callback)),
      pid_(0) {
  CHECK(task_delegate_);
}

ExternalTask::~ExternalTask() {
  ExternalTask::Stop();
}

bool ExternalTask::Start(const base::FilePath& program,
                         const std::vector<std::string>& arguments,
                         const std::map<std::string, std::string>& environment,
                         bool terminate_with_parent,
                         Error* error) {
  CHECK(!pid_);
  CHECK(!rpc_task_);

  // Setup full environment variables.
  auto local_rpc_task = std::make_unique<RpcTask>(control_, this);
  auto env = local_rpc_task->GetEnvironment();
  env.insert(environment.begin(), environment.end());

  pid_t pid = process_manager_->StartProcess(
      FROM_HERE, program, arguments, env, /*fds_to_bind=*/{},
      terminate_with_parent,
      base::BindOnce(&ExternalTask::OnTaskDied, base::Unretained(this)));

  if (pid < 0) {
    Error::PopulateAndLog(
        FROM_HERE, error, Error::kInternalError,
        std::string("Unable to spawn: ") + program.value().c_str());
    return false;
  }
  pid_ = pid;
  rpc_task_ = std::move(local_rpc_task);
  return true;
}

bool ExternalTask::StartInMinijail(
    const base::FilePath& program,
    std::vector<std::string>* arguments,
    const std::map<std::string, std::string>& environment,
    const ProcessManager::MinijailOptions& minijail_options,
    Error* error) {
  // Checks will fail if Start or StartInMinijailWithRpcIdentifiers has already
  // been called on this object.
  CHECK(!pid_);
  CHECK(!rpc_task_);

  // Setup full environment variables.
  auto local_rpc_task = std::make_unique<RpcTask>(control_, this);
  auto env = local_rpc_task->GetEnvironment();
  env.insert(environment.begin(), environment.end());

  pid_t pid = process_manager_->StartProcessInMinijail(
      FROM_HERE, program, *arguments, env, minijail_options,
      base::BindOnce(&ExternalTask::OnTaskDied, base::Unretained(this)));

  if (pid < 0) {
    Error::PopulateAndLog(FROM_HERE, error, Error::kInternalError,
                          std::string("Unable to spawn: ") +
                              program.value().c_str() +
                              std::string(" in a minijail."));
    return false;
  }
  pid_ = pid;
  rpc_task_ = std::move(local_rpc_task);
  return true;
}

void ExternalTask::Stop() {
  if (pid_) {
    process_manager_->StopProcess(pid_);
    pid_ = 0;
  }
  rpc_task_.reset();
}

void ExternalTask::GetLogin(std::string* user, std::string* password) {
  return task_delegate_->GetLogin(user, password);
}

void ExternalTask::Notify(const std::string& event,
                          const std::map<std::string, std::string>& details) {
  return task_delegate_->Notify(event, details);
}

void ExternalTask::OnTaskDied(int exit_status) {
  CHECK(pid_);
  LOG(INFO) << __func__ << "(" << pid_ << ", " << exit_status << ")";
  pid_t old_pid = pid_;
  pid_ = 0;
  rpc_task_.reset();
  // Since this method has no more non-static member accesses below this call,
  // the death callback is free to destruct this instance.
  std::move(death_callback_).Run(old_pid, exit_status);
}

}  // namespace shill
