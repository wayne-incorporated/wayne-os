// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/stat.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/values.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>

#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"
#include "init/startup/security_manager.h"
#include "init/startup/test_mode_mount_helper.h"

namespace {

// Flag file indicating that mount encrypted stateful failed last time.
// If the file is present and mount_encrypted failed again, machine would
// enter self-repair mode.
constexpr char kMountEncryptedFailedFile[] = "mount_encrypted_failed";

}  // namespace

namespace startup {

// Constructor for TestModeMountHelper when the device is
// not in dev mode.
TestModeMountHelper::TestModeMountHelper(std::unique_ptr<Platform> platform,
                                         const startup::Flags& flags,
                                         const base::FilePath& root,
                                         const base::FilePath& stateful,
                                         const bool dev_mode)
    : startup::MountHelper(
          std::move(platform), flags, root, stateful, dev_mode) {}

bool TestModeMountHelper::DoMountVarAndHomeChronos() {
  // If this a TPM 2.0 device that supports encrypted stateful, creates and
  // persists a system key into NVRAM and backs the key up if it doesn't exist.
  // If the call create_system_key is successful, mount_var_and_home_chronos
  // will skip the normal system key generation procedure; otherwise, it will
  // generate and persist a key via its normal workflow.
  std::optional<bool> system_key = GetFlags().sys_key_util;
  bool sys_key = system_key.value_or(false);
  if (sys_key) {
    LOG(INFO) << "Creating System Key";
    CreateSystemKey(GetRoot(), GetStateful(), GetPlatform());
  }

  base::FilePath encrypted_failed =
      GetStateful().Append(kMountEncryptedFailedFile);
  struct stat statbuf;
  bool ret;
  if (!platform_->Stat(encrypted_failed, &statbuf) ||
      statbuf.st_uid != getuid()) {
    // Try to use the original handler in chromeos_startup.
    // It should not wipe whole stateful partition in this case.
    return MountVarAndHomeChronos();
  }

  ret = MountVarAndHomeChronos();
  if (!ret) {
    // Try to re-construct encrypted folders, otherwise such a failure will lead
    // to wiping whole stateful partition (including all helpful programs in
    // /usr/local/bin and sshd).
    std::string msg("Failed mounting var and home/chronos; re-created.");
    platform_->ClobberLog(msg);

    std::vector<std::string> crash_args{"--mount_failure",
                                        "--mount_device='encstateful'"};
    platform_->AddClobberCrashReport(crash_args);
    base::FilePath backup = GetStateful().Append("corrupted_encryption");
    brillo::DeletePathRecursively(backup);
    base::CreateDirectory(backup);
    if (!base::SetPosixFilePermissions(backup, 0755)) {
      PLOG(WARNING) << "chmod failed for " << backup.value();
    }

    base::FileEnumerator enumerator(GetStateful(), false /* recursive */,
                                    base::FileEnumerator::FILES);
    for (base::FilePath path = enumerator.Next(); !path.empty();
         path = enumerator.Next()) {
      if (path.BaseName().value().rfind("encrypted.", 0) == 0) {
        base::FilePath to_path = backup.Append(path.BaseName());
        base::Move(path, to_path);
      }
    }

    return MountVarAndHomeChronos();
  }
  return true;
}

startup::MountHelperType TestModeMountHelper::GetMountHelperType() const {
  return startup::MountHelperType::kTestMode;
}

}  // namespace startup
