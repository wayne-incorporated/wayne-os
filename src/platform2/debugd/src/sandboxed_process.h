// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SANDBOXED_PROCESS_H_
#define DEBUGD_SRC_SANDBOXED_PROCESS_H_

#include <string>
#include <vector>

#include <base/environment.h>
#include <brillo/process/process.h>

namespace debugd {

class SandboxedProcess : public brillo::ProcessImpl {
 public:
  SandboxedProcess();
  ~SandboxedProcess() override = default;

  virtual bool Init();
  virtual bool Init(const std::vector<std::string>& minijail_extra_args);

  // Disable the default sandboxing for this process.
  virtual void DisableSandbox();

  // Change the default sandboxing for this process.
  virtual void SandboxAs(const std::string& user, const std::string& group);

  // Allow the sandbox to inherit supplementary groups from the uid.
  virtual void InheritUsergroups();

  // Set the capabilities mask for this process. Requires that the process is
  // not running as root.
  void SetCapabilities(uint64_t capabilities_mask) override;

  // Set a file to be used as the seccomp bpf file for this process.  See
  // minijail0 -S for details of what can be in this file.
  virtual void SetSeccompFilterPolicyFile(const std::string& path);

  // Allow this process to access the root mount namespace.
  virtual void AllowAccessRootMountNamespace();

  // Set additional environment variables to run the process with.
  virtual void SetEnvironmentVariables(const base::EnvironmentMap& env);

  // Kill the sandboxed process' process group.
  virtual bool KillProcessGroup();

  static const char kDefaultUser[];
  static const char kDefaultGroup[];

 private:
  bool sandboxing_;
  bool access_root_mount_ns_;
  bool set_capabilities_;
  bool inherit_usergroups_;
  std::string user_;
  std::string group_;
  std::string seccomp_filter_policy_file_;
  uint64_t capabilities_mask_;
  base::EnvironmentMap env_vars_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SANDBOXED_PROCESS_H_
