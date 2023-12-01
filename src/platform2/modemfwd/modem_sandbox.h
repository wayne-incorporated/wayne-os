// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MODEM_SANDBOX_H_
#define MODEMFWD_MODEM_SANDBOX_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <libminijail.h>
#include <scoped_minijail.h>

namespace modemfwd {

constexpr char kSeccompPolicyDirectory[] = "/usr/share/policy";

// A timeout input of zero indicates an unlimited duration
//
// Returns:
// -errno (`man errno` for values) if the process failed to be started
// -MINIJAIL_ERR_SIG_BASE if the command was killed by signal (timed out)
//
// Otherwise, return value is exit code of the completed process, with 0
// indicating success, and positive otherwise
int RunProcessInSandboxWithTimeout(
    const std::vector<std::string>& formatted_args,
    const base::FilePath& seccomp_file_path,
    bool should_remove_capabilities,
    int* child_stdout,
    int* child_stderr,
    base::TimeDelta timeout);

int RunProcessInSandbox(const std::vector<std::string>& formatted_args,
                        const base::FilePath& seccomp_file_path,
                        bool should_remove_capabilities,
                        int* child_stdout,
                        int* child_stderr);

}  // namespace modemfwd

#endif  // MODEMFWD_MODEM_SANDBOX_H_
