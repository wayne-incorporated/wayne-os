// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SYSLOG_CAT_SYSLOGCAT_H_
#define SYSLOG_CAT_SYSLOGCAT_H_

#include <string>
#include <vector>

namespace base {
class FilePath;
};

// Executes the specified command with redirecting its stdout and stderr to the
// specified unix domain socket. This also sets up the socket by sending
// headers,
void ExecuteCommandWithRedirection(
    const std::string& target_command_str,
    const std::vector<const char*>& target_command_argv,
    const std::string& identifier,
    int severity_stdout,
    int severity_stderr,
    const base::FilePath& socket_path_stdout,
    const base::FilePath& socket_path_stderr);

#endif  // SYSLOG_CAT_SYSLOGCAT_H_
