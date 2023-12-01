// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUN_OCI_RUN_OCI_UTILS_H_
#define RUN_OCI_RUN_OCI_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/process/process.h>
#include <brillo/files/safe_fd.h>

namespace run_oci {

// A class that redirects stderr/stdout to syslog. It forks another process,
// similar to how logger(1) works.
class SyslogStdioAdapter {
 public:
  ~SyslogStdioAdapter();

  // Creates a fully-initialized instance of SyslogStdioAdapter, or nullptr if
  // something failed.
  static std::unique_ptr<SyslogStdioAdapter> Create();

 private:
  explicit SyslogStdioAdapter(base::Process child);
  SyslogStdioAdapter(const SyslogStdioAdapter&) = delete;
  SyslogStdioAdapter& operator=(const SyslogStdioAdapter&) = delete;

  // The child process' run loop. Reads from the stdout/stderr read ends of the
  // pipe and logs all lines with INFO/ERROR severity.
  //
  // Runs forever until there is an error reading the pipes (e.g. they are both
  // closed) or the parent kills it.
  static void RunLoop(base::ScopedFD stdout_fd, base::ScopedFD stderr_fd);

  // The child process.
  base::Process child_;
};

struct Mountpoint {
  base::FilePath path;
  int mountflags;
  std::string data_string;

  bool operator==(const Mountpoint&) const;
};

// Parses the mount(8) options into mount flags and data string that can be
// understood by mount(2).
std::string ParseMountOptions(const std::vector<std::string>& options,
                              int* mount_flags_out,
                              int* negated_mount_flags_out,
                              int* bind_mount_flags_out,
                              int* mount_propagation_flags_out,
                              bool* loopback_out,
                              std::string* verity_options);

// Returns all mountpoints under |root|.
std::vector<Mountpoint> GetMountpointsUnder(
    const base::FilePath& root, const base::FilePath& procSelfMountsPath);

// Returns true if the process has the CAP_SYS_ADMIN capability.
bool HasCapSysAdmin();

// Redirects all logging and stdout/stdio to |log_file|.
bool RedirectLoggingAndStdio(const base::FilePath& log_file);

// A wrapper around pipe(2) that provides base::ScopedFDs.
bool Pipe(base::ScopedFD* read_fd, base::ScopedFD* write_fd, int flags);

// Opens |config_path| for reading with brillo::OpenSafely and returns the FD.
// If |config_path| is not on an exec filesystem, sets errno to EPERM and
// returns an invalid FD.
brillo::SafeFD OpenOciConfigSafely(const base::FilePath& config_path);

// Like OpenOciConfigSafely, but for unittest, allowing callers to control
// whether to check exec filesystem.
brillo::SafeFD OpenOciConfigSafelyForTest(const base::FilePath& config_path,
                                          bool enable_noexec_check);

}  // namespace run_oci

#endif  // RUN_OCI_RUN_OCI_UTILS_H_
