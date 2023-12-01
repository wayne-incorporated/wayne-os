// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/ansible_playbook_application.h"

#include <errno.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>

#include "vm_tools/common/spawn_util.h"

namespace vm_tools {
namespace garcon {
namespace {

constexpr char kStdoutCallbackEnv[] = "ANSIBLE_STDOUT_CALLBACK";
constexpr char kDefaultCallbackPluginPathEnv[] = "ANSIBLE_CALLBACK_PLUGINS";
constexpr char kStdoutCallbackName[] = "garcon";
constexpr char kDefaultCallbackPluginPath[] =
    "/usr/share/ansible/plugins/callback";
// How long we should wait for a ansible-playbook process to finish.
constexpr base::TimeDelta kAnsibleProcessTimeout = base::Hours(1);

bool CreatePipe(base::ScopedFD* read_fd,
                base::ScopedFD* write_fd,
                std::string* error_msg) {
  int fds[2];
  if (pipe2(fds, O_CLOEXEC) < 0) {
    *error_msg =
        "Failed to open target process pipe: " + base::safe_strerror(errno);
    return false;
  }
  read_fd->reset(fds[0]);
  write_fd->reset(fds[1]);
  return true;
}

}  // namespace

AnsiblePlaybookApplication::AnsiblePlaybookApplication()
    : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      weak_ptr_factory_(this) {}

void AnsiblePlaybookApplication::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void AnsiblePlaybookApplication::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

base::FilePath AnsiblePlaybookApplication::CreateAnsiblePlaybookFile(
    const std::string& playbook, std::string* error_msg) {
  base::FilePath ansible_dir;
  bool success = base::CreateNewTempDirectory("", &ansible_dir);
  if (!success) {
    *error_msg = "Failed to create directory for ansible playbook file";
    return base::FilePath();
  }

  const base::FilePath ansible_playbook_file_path =
      ansible_dir.Append("playbook.yaml");
  base::File ansible_playbook_file(
      ansible_playbook_file_path,
      base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);

  if (!ansible_playbook_file.created()) {
    *error_msg = "Failed to create file for Ansible playbook";
    return base::FilePath();
  }
  if (!ansible_playbook_file.IsValid()) {
    *error_msg = "Failed to create valid file for Ansible playbook";
    return base::FilePath();
  }

  int bytes = ansible_playbook_file.WriteAtCurrentPos(playbook.c_str(),
                                                      playbook.length());

  if (bytes != playbook.length()) {
    *error_msg = "Failed to write Ansible playbook content to file";
    return base::FilePath();
  }

  return ansible_playbook_file_path;
}

bool AnsiblePlaybookApplication::ExecuteAnsiblePlaybook(
    const base::FilePath& ansible_playbook_file_path, std::string* error_msg) {
  std::vector<std::string> argv{"ansible-playbook",
                                "--become",
                                "--connection=local",
                                "--inventory",
                                "127.0.0.1,",
                                ansible_playbook_file_path.value(),
                                "-e",
                                "ansible_python_interpreter=/usr/bin/python3"};

  std::map<std::string, std::string> env;
  env[kStdoutCallbackEnv] = kStdoutCallbackName;
  env[kDefaultCallbackPluginPathEnv] = kDefaultCallbackPluginPath;

  // Set child's process stdout and stderr to write end of pipes.
  int stdio_fd[] = {-1, -1, -1};
  if (!CreatePipe(&read_stdout_, &write_stdout_, error_msg)) {
    return false;
  }
  if (!CreatePipe(&read_stderr_, &write_stderr_, error_msg)) {
    return false;
  }
  stdio_fd[STDOUT_FILENO] = write_stdout_.get();
  stdio_fd[STDERR_FILENO] = write_stderr_.get();

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool success = task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&AnsiblePlaybookApplication::SetUpStdIOWatchers,
                     weak_ptr_factory_.GetWeakPtr(), &event, error_msg));
  event.Wait();

  if (!success) {
    *error_msg = "Failed to post task to set up ansible stdio watchers";
    return false;
  }
  if (!error_msg->empty()) {
    return false;
  }

  pid_t spawned_pid;
  if (!Spawn(std::move(argv), std::move(env), "", stdio_fd, &spawned_pid)) {
    *error_msg = "Failed to spawn ansible-playbook process";
    return false;
  }

  // As we rely on ansible process to finish and close fds, we set up a timeout
  // after which process is killed.
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&AnsiblePlaybookApplication::KillAnsibleProcess,
                     weak_ptr_factory_.GetWeakPtr(), spawned_pid),
      kAnsibleProcessTimeout);
  ClearWriteFDs();
  return true;
}

void AnsiblePlaybookApplication::SetUpStdIOWatchers(base::WaitableEvent* event,
                                                    std::string* error_msg) {
  stdout_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      read_stdout_.get(),
      base::BindRepeating(&AnsiblePlaybookApplication::OnStdoutReadable,
                          weak_ptr_factory_.GetWeakPtr()));
  if (!stdout_watcher_) {
    *error_msg = "Failed to set watcher for ansible-playbook stdout";
    event->Signal();
    return;
  }

  stderr_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      read_stderr_.get(),
      base::BindRepeating(&AnsiblePlaybookApplication::OnStderrReadable,
                          weak_ptr_factory_.GetWeakPtr()));
  if (!stderr_watcher_) {
    *error_msg = "Failed to set watcher for ansible-playbook stderr";
    event->Signal();
    return;
  }

  event->Signal();
  return;
}

void AnsiblePlaybookApplication::OnStdoutReadable() {
  char buffer[1000];
  ssize_t count = read(read_stdout_.get(), buffer, sizeof(buffer));
  if (count <= 0) {
    stdout_watcher_.reset();
    OnStdIOProcessed(false /*is_stderr*/);
    return;
  }
  stdout_.write(buffer, count);
  int index = 0;
  std::vector<std::string> lines;
  for (int i = 0; i < count; i++) {
    if (buffer[i] == '\n') {
      lines.push_back(std::string(buffer, index, i));
      index = i;
    }
  }
  if (index != count)
    lines.push_back(std::string(buffer, index, count));
  for (auto& observer : observers_) {
    observer.OnApplyAnsiblePlaybookProgress(lines);
  }
}

void AnsiblePlaybookApplication::OnStderrReadable() {
  char buffer[1000];
  int index = 0;
  std::vector<std::string> lines;
  ssize_t count = read(read_stderr_.get(), buffer, sizeof(buffer));
  if (count <= 0) {
    stderr_watcher_.reset();
    OnStdIOProcessed(true /*is_stderr*/);
    return;
  }
  stderr_.write(buffer, count);
  for (int i = 0; i < count; i++) {
    if (buffer[i] == '\n') {
      lines.push_back(std::string(buffer, index, i));
      index = i;
    }
  }
  if (index != count)
    lines.push_back(std::string(buffer, index, count));
  for (auto& observer : observers_) {
    observer.OnApplyAnsiblePlaybookProgress(lines);
  }
}

void AnsiblePlaybookApplication::OnStdIOProcessed(bool is_stderr) {
  if (is_stderr)
    is_stderr_finished_ = true;
  else
    is_stdout_finished_ = true;

  if (is_stderr_finished_ && is_stdout_finished_) {
    std::string failure_reason;
    bool success = GetPlaybookApplicationResult(&failure_reason);
    for (auto& observer : observers_)
      observer.OnApplyAnsiblePlaybookCompletion(success, failure_reason);
  }
}

bool AnsiblePlaybookApplication::GetPlaybookApplicationResult(
    std::string* failure_reason) {
  const std::string stdout = stdout_.str();
  const std::string stderr = stderr_.str();
  const std::string execution_info =
      "Ansible playbook application stdout:\n" + stdout + "\n" +
      "Ansible playbook application stderr:\n" + stderr + "\n";

  if (stdout.find("MESSAGE TO GARCON: TASK_FAILED") != std::string::npos) {
    LOG(INFO) << "Some tasks failed during container configuration";
    *failure_reason = execution_info;
    return false;
  }
  if (!stderr.empty()) {
    *failure_reason = execution_info;
    return false;
  }
  return true;
}

void AnsiblePlaybookApplication::ClearWriteFDs() {
  write_stdout_.reset();
  write_stderr_.reset();
}

void AnsiblePlaybookApplication::KillAnsibleProcess(pid_t pid) {
  if (kill(pid, SIGTERM) < 0) {
    LOG(ERROR) << "Failed to kill ansible process: "
               << base::safe_strerror(errno);
  }

  for (auto& observer : observers_)
    observer.OnApplyAnsiblePlaybookCompletion(false /*success*/,
                                              "ansible process timed out");
}

}  // namespace garcon
}  // namespace vm_tools
