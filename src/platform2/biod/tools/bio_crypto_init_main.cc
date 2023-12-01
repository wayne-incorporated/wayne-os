// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This is a program to set the various biometric managers with a TPM
// seed obtained from the TPM hardware. It is expected to execute once
// on every boot.
// This binary is expected to be called from the mount-encrypted utility
// during boot.
// It is expected to receive the tpm seed buffer from mount-encrypted via a
// file written to tmpfs. The FD for the tmpfs file is mapped to STDIN_FILENO
// by mount-encrypted. It is considered to have been unlinked by
// mount-encrypted. Consequently, closing the FD should be enough to delete
// the file.

#include "biod/crypto_init/bio_crypto_init.h"

#include <sys/types.h>

#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/process.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <libec/ec_command.h>
#include <libec/fingerprint/fp_seed_command.h>

#include "biod/biod_version.h"

namespace {
constexpr int64_t kTimeoutSeconds = 30;
// File where the TPM seed is stored, that we have to read from.
constexpr char kBioTpmSeedTmpFile[] = "/run/bio_crypto_init/seed";

int ChildProcess(biod::BioCryptoInit* bio_crypto_init) {
  // The first thing we do is read the buffer, and delete the file.
  brillo::SecureVector tpm_seed(ec::FpSeedCommand::kTpmSeedSize);
  int bytes_read =
      base::ReadFile(base::FilePath(kBioTpmSeedTmpFile),
                     reinterpret_cast<char*>(tpm_seed.data()), tpm_seed.size());
  bio_crypto_init->NukeFile(base::FilePath(kBioTpmSeedTmpFile));

  if (bytes_read != ec::FpSeedCommand::kTpmSeedSize) {
    LOG(ERROR) << "Failed to read TPM seed from tmpfile: " << bytes_read;
    return -1;
  }

  return bio_crypto_init->DoProgramSeed(tpm_seed) ? 0 : -1;
}

}  // namespace

int main(int argc, char* argv[]) {
  // Set up logging settings.
  DEFINE_string(log_dir, "/var/log/bio_crypto_init",
                "Directory where logs are written.");
  DEFINE_bool(seccomp, false,
              "Exercise all code paths to generate a good strace for seccomp.");

  brillo::FlagHelper::Init(argc, argv,
                           "bio_crypto_init, the Chromium OS binary to program "
                           "bio sensors with TPM secrets.");

  const auto log_dir_path = base::FilePath(FLAGS_log_dir);
  const auto log_file_path = log_dir_path.Append(base::StringPrintf(
      "bio_crypto_init.%s",
      brillo::GetTimeAsLogString(base::Time::Now()).c_str()));

  brillo::UpdateLogSymlinks(log_dir_path.Append("bio_crypto_init.LATEST"),
                            log_dir_path.Append("bio_crypto_init.PREVIOUS"),
                            log_file_path);

  logging::LoggingSettings logging_settings;
  logging_settings.logging_dest = logging::LOG_TO_FILE;
  logging_settings.log_file_path = log_file_path.value().c_str();
  logging_settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  logging_settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  logging::InitLogging(logging_settings);
  logging::SetLogItems(true,    // process ID
                       true,    // thread ID
                       true,    // timestamp
                       false);  // tickcount

  biod::LogVersion();

  if (FLAGS_seccomp) {
    LOG(INFO) << "WARNING: The seccomp flag is enabled. Expect errors.";
  }

  biod::BioCryptoInit bio_crypto_init(std::make_unique<ec::EcCommandFactory>());

  // We fork the process so that can we program the seed in the child, and
  // terminate it if it hangs.
  pid_t pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "Failed to fork child process for bio_wash.";
    bio_crypto_init.NukeFile(base::FilePath(kBioTpmSeedTmpFile));
    return -1;
  }

  if (pid == 0) {
    int exit_code_child = ChildProcess(&bio_crypto_init);
    if (FLAGS_seccomp) {
      // Wait for timeout to terminate this process.
      // We aren't yielding this thread, since we don't want to tamper with the
      // strace results (syscalls seen or syscall frequency).
      while (true) {
      }
    }
    return exit_code_child;
  }

  auto process = base::Process::Open(pid);
  int exit_code = -1;
  if (!process.WaitForExitWithTimeout(base::Seconds(kTimeoutSeconds),
                                      &exit_code)) {
    LOG(ERROR) << "bio_crypto_init timeout";
    process.Terminate(-1, false);
  }

  return exit_code;
}
