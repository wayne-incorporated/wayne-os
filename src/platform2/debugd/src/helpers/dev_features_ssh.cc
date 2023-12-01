// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <brillo/flag_helper.h>

#include "debugd/src/process_with_output.h"

namespace {

const char kUsageMessage[] =
    "\n"
    "Configures sshd and SSH test key access, or queries whether sshd has\n"
    "been configured (based on the existence of the required files).\n"
    "\n";

// Source and install paths. Keeping paths and filenames separate is useful
// to avoid repeating filenames and get easy access to the individual parts when
// needed. The InstallFile class below is used to simplify combining paths.
const char kKeySourceDir[] = "/usr/share/chromeos-ssh-config/keys";
const char kKeyInstallDir[] = "/root/.ssh";
const char* const kKeyFilenames[] = {"authorized_keys"};

const char kInitSourceDir[] = "/usr/share/chromeos-ssh-config/init";
const char kInitInstallDir[] = "/etc/init";
const char kInitFilename[] = "openssh-server.conf";

// Class to help simplify file path handling.
class InstallFile {
 public:
  InstallFile(const char* source_dir,
              const char* install_dir,
              const char* filename)
      : source_path_(base::FilePath(source_dir).Append(filename)),
        install_path_(base::FilePath(install_dir).Append(filename)) {}

  ~InstallFile() = default;

  const base::FilePath& source_path() const { return source_path_; }
  const base::FilePath& install_path() const { return install_path_; }

 private:
  base::FilePath source_path_, install_path_;
};

// Checks if a file exists and is not a directory. Symlinks will return true
// as long as the path they point to exists.
bool FileExists(const base::FilePath& path) {
  return base::PathExists(path) && !base::DirectoryExists(path);
}

// Reloads the Upstart configuration and starts the SSH job.
bool StartUpstartJob() {
  // The Upstart D-Bus interface isn't well documented and reload-configuration
  // isn't listed anywhere I can find, so just use initctl for this.
  std::string error;
  int result = debugd::ProcessWithOutput::RunProcessFromHelper(
      "initctl", {"reload-configuration"},
      nullptr,  // stdin.
      nullptr,  // stdout.
      &error);  // stderr.
  if (result != EXIT_SUCCESS) {
    LOG(WARNING) << "\"initctl reload-configuration\" failed with exit code "
                 << result << ": " << error;
    return false;
  }

  // Upstart job name is the init file name without the .conf extension.
  std::string job_name(base::FilePath(kInitFilename).RemoveExtension().value());

  // The job should be known to initctl now, otherwise something has gone wrong
  // and we can't start it.
  result = debugd::ProcessWithOutput::RunProcessFromHelper("initctl",
                                                           {"status", job_name},
                                                           nullptr,  // stdin.
                                                           nullptr,  // stdout.
                                                           &error);  // stderr.
  if (result != EXIT_SUCCESS) {
    LOG(WARNING) << "\"initctl status\" can't find job '" << job_name << "' ("
                 << result << "): " << error;
    return false;
  }

  // At this point we know initctl has the job loaded so try to start it. Any
  // error here can be ignored, it just means the job has already started.
  debugd::ProcessWithOutput::RunProcessFromHelper("initctl",
                                                  {"start", job_name},
                                                  nullptr,   // stdin.
                                                  nullptr,   // stdout.
                                                  nullptr);  // stderr.

  return true;
}

// Checks if all the necessary SSH files are installed.
bool AreSshFilesInstalled(const std::vector<InstallFile>& install_files) {
  for (const auto& install_file : install_files) {
    if (!FileExists(install_file.install_path())) {
      return false;
    }
  }
  return true;
}

// Installs the required SSH files and start sshd.
bool ConfigureSsh(const std::vector<InstallFile>& install_files) {
  // Check that sources exist ahead of time so we don't link to some and then
  // error out in a half-configured state.
  for (const auto& install_file : install_files) {
    if (!FileExists(install_file.source_path())) {
      LOG(WARNING) << "Required file \"" << install_file.source_path().value()
                   << "\" is missing";
      return false;
    }
  }

  base::ScopedFD init_ns_fd(open("/proc/1/ns/mnt", O_CLOEXEC));
  // Since debugd is running in a sandboxed envrionment, the check
  // whether '/' is writable needs to be done in the init namespace,
  // instead of the debugd sandboxed namespace.
  setns(init_ns_fd.get(), CLONE_NEWNS);

  if (!base::CreateDirectory(base::FilePath(kKeyInstallDir)) ||
      !base::CreateDirectory(base::FilePath(kInitInstallDir))) {
    return false;
  }

  // Install as many symlinks as possible, if one fails mark the failure but
  // keep going and try to complete the rest. SSH could still be partially
  // usable if, for example, the Upstart file installs but the test keys don't.
  bool install_success = true;
  for (const auto& install_file : install_files) {
    // We need to overwrite anything that might be at the install location.
    brillo::DeletePathRecursively(install_file.install_path());
    if (!base::CreateSymbolicLink(install_file.source_path(),
                                  install_file.install_path())) {
      install_success = false;
      PLOG(WARNING) << "Failed to create symlink at \""
                    << install_file.install_path().value() << "\"";
    }
  }

  // Upstart needs a kick to load and start the new .conf file. Still try to
  // start the job even if not all files were installed successfully, but
  // return false if either fails.
  return StartUpstartJob() && install_success;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(q, false, "Query whether SSH has been configured");
  brillo::FlagHelper::Init(argc, argv, kUsageMessage);

  std::vector<InstallFile> install_files;
  for (const char* filename : kKeyFilenames) {
    install_files.emplace_back(kKeySourceDir, kKeyInstallDir, filename);
  }
  install_files.emplace_back(kInitSourceDir, kInitInstallDir, kInitFilename);

  if (FLAGS_q) {
    return AreSshFilesInstalled(install_files) ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  return ConfigureSsh(install_files) ? EXIT_SUCCESS : EXIT_FAILURE;
}
