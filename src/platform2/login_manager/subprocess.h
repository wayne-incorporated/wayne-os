// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SUBPROCESS_H_
#define LOGIN_MANAGER_SUBPROCESS_H_

#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <base/optional.h>
#include <base/time/time.h>

namespace login_manager {

class SystemUtils;

class SubprocessInterface {
 public:
  virtual ~SubprocessInterface() {}

  virtual void UseNewMountNamespace() = 0;
  virtual void EnterExistingMountNamespace(
      const base::FilePath& ns_mnt_path) = 0;

  // fork(), export |environment_variables|, and exec(argv, env_vars).
  // Returns false if fork() fails, true otherwise.
  virtual bool ForkAndExec(const std::vector<std::string>& args,
                           const std::vector<std::string>& env_vars) = 0;

  // Sends signal to pid_. No-op if there is no subprocess running.
  virtual void Kill(int signal) = 0;

  // Sends signal to pid_'s entire process group.
  // No-op if there is no subprocess running.
  virtual void KillEverything(int signal) = 0;

  virtual pid_t GetPid() const = 0;
  virtual void ClearPid() = 0;
};

// A class that provides functionality for creating/destroying a subprocess.
// Intended to be embedded in an implementation of ChildJobInterface.
class Subprocess : public SubprocessInterface {
 public:
  Subprocess(uid_t uid, SystemUtils* system);
  Subprocess(const Subprocess&) = delete;
  Subprocess& operator=(const Subprocess&) = delete;

  ~Subprocess() override;

  // SubprocessInterface:
  void UseNewMountNamespace() override;
  void EnterExistingMountNamespace(const base::FilePath& ns_mnt_path) override;
  bool ForkAndExec(const std::vector<std::string>& args,
                   const std::vector<std::string>& env_vars) override;
  void Kill(int signal) override;
  void KillEverything(int signal) override;
  pid_t GetPid() const override;
  void ClearPid() override;

 private:
  // The pid of the managed subprocess, when running.
  base::Optional<pid_t> pid_;

  // Run-time options for the subprocess.
  // The UID the subprocess should be run as.
  const uid_t desired_uid_;
  // Whether to enter a new mount namespace before execve(2)-ing the subprocess.
  bool new_mount_namespace_ = false;
  // If present, enter an existing mount namespace before execve(2)-ing the
  // subprocess.
  // Mutually exclusive with |new_mount_namespace_|.
  base::Optional<base::FilePath> ns_mnt_path_;

  SystemUtils* const system_;  // weak; owned by embedder.
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_SUBPROCESS_H_
