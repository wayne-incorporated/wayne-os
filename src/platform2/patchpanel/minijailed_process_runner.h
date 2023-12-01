// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MINIJAILED_PROCESS_RUNNER_H_
#define PATCHPANEL_MINIJAILED_PROCESS_RUNNER_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <brillo/minijail/minijail.h>

#include "patchpanel/iptables.h"
#include "patchpanel/system.h"

namespace patchpanel {

// Runs the current process with minimal privileges. This function is expected
// to be used by child processes that need only CAP_NET_RAW and to run as the
// patchpaneld user.
void EnterChildProcessJail();

// Enforces the expected processes are run with the correct privileges.
class MinijailedProcessRunner {
 public:
  // Ownership of |mj| is not assumed and must be managed by the caller.
  // If |mj| is null, the default instance will be used.
  explicit MinijailedProcessRunner(brillo::Minijail* mj = nullptr);
  // Provided for testing only.
  MinijailedProcessRunner(brillo::Minijail* mj, std::unique_ptr<System> system);
  MinijailedProcessRunner(const MinijailedProcessRunner&) = delete;
  MinijailedProcessRunner& operator=(const MinijailedProcessRunner&) = delete;

  virtual ~MinijailedProcessRunner() = default;

  // Runs ip.
  virtual int ip(const std::string& obj,
                 const std::string& cmd,
                 const std::vector<std::string>& args,
                 bool log_failures = true);
  virtual int ip6(const std::string& obj,
                  const std::string& cmd,
                  const std::vector<std::string>& args,
                  bool log_failures = true);

  // Runs iptables. If |output| is not nullptr, it will be filled with the
  // result from stdout of iptables command.
  virtual int iptables(Iptables::Table table,
                       Iptables::Command command,
                       const std::vector<std::string>& argv,
                       bool log_failures = true,
                       std::string* output = nullptr);

  virtual int ip6tables(Iptables::Table table,
                        Iptables::Command command,
                        const std::vector<std::string>& argv,
                        bool log_failures = true,
                        std::string* output = nullptr);

  // Installs all |modules| via modprobe.
  virtual int modprobe_all(const std::vector<std::string>& modules,
                           bool log_failures = true);

  // Creates a new named network namespace with name |netns_name|.
  virtual int ip_netns_add(const std::string& netns_name,
                           bool log_failures = true);

  // Attaches a name to the network namespace of the given pid
  // TODO(hugobenichi) How can patchpanel create a |netns_name| file in
  // /run/netns without running ip as root ?
  virtual int ip_netns_attach(const std::string& netns_name,
                              pid_t netns_pid,
                              bool log_failures = true);

  virtual int ip_netns_delete(const std::string& netns_name,
                              bool log_failures = true);

 protected:
  // Runs a process (argv[0]) with optional arguments (argv[1]...)
  // in a minijail as an unprivileged user with CAP_NET_ADMIN and
  // CAP_NET_RAW capabilities.
  virtual int Run(const std::vector<std::string>& argv,
                  bool log_failures = true);

  // Invokes RunSyncDestroy() with |mj_|. If |output| is not nullptr, it will be
  // filled with the result from stdout of the execution.
  virtual int RunSync(const std::vector<std::string>& argv,
                      bool log_failures,
                      std::string* output);

 private:
  int RunSyncDestroy(const std::vector<std::string>& argv,
                     brillo::Minijail* mj,
                     minijail* jail,
                     bool log_failures,
                     std::string* output);

  brillo::Minijail* mj_;
  std::unique_ptr<System> system_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MINIJAILED_PROCESS_RUNNER_H_
