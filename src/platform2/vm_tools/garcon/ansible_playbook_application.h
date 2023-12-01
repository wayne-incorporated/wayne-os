// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_ANSIBLE_PLAYBOOK_APPLICATION_H_
#define VM_TOOLS_GARCON_ANSIBLE_PLAYBOOK_APPLICATION_H_

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>

namespace base {
class FilePath;
class WaitableEvent;
}  // namespace base

namespace vm_tools {
namespace garcon {

class AnsiblePlaybookApplication {
 public:
  class Observer : public base::CheckedObserver {
   public:
    virtual void OnApplyAnsiblePlaybookCompletion(
        bool success, const std::string& failure_reason) = 0;

    virtual void OnApplyAnsiblePlaybookProgress(
        const std::vector<std::string>& status_string) = 0;
  };

  AnsiblePlaybookApplication();

  // Returns true when ansible-playbook is successfully spawned.
  bool ExecuteAnsiblePlaybook(const base::FilePath& ansible_playbook_file_path,
                              std::string* error_msg);

  base::FilePath CreateAnsiblePlaybookFile(const std::string& playbook,
                                           std::string* error_msg);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

 private:
  void SetUpStdIOWatchers(base::WaitableEvent* event, std::string* error_msg);
  void OnStdoutReadable();
  void OnStderrReadable();
  void OnStdIOProcessed(bool is_stderr);
  // Return true on successful ansible-playbook result and false otherwise.
  bool GetPlaybookApplicationResult(std::string* failure_reason);
  void ClearWriteFDs();
  void KillAnsibleProcess(pid_t pid);

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  base::ObserverList<Observer> observers_;
  bool is_stdout_finished_ = false;
  bool is_stderr_finished_ = false;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> stdout_watcher_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> stderr_watcher_;
  std::stringstream stdout_;
  std::stringstream stderr_;
  base::ScopedFD read_stdout_;
  base::ScopedFD write_stdout_;
  base::ScopedFD read_stderr_;
  base::ScopedFD write_stderr_;

  base::WeakPtrFactory<AnsiblePlaybookApplication> weak_ptr_factory_;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_ANSIBLE_PLAYBOOK_APPLICATION_H_
