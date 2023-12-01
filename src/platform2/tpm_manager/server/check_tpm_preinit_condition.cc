// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>
#include <rootdev/rootdev.h>

namespace {

constexpr char kLogToStderrSwitch[] = "log_to_stderr";

constexpr char kNoPreinitFlagFile[] = "/run/tpm_manager/no_preinit";

constexpr char kIsRunningFromInstaller[] = "is_running_from_installer";
constexpr char kInstallerYes[] = "yes\n";

constexpr char kDevDir[] = "/dev/";
constexpr char kSysBlock[] = "/sys/block/";
constexpr char kRemovable[] = "removable";

bool TouchNoPreinitFlagFile() {
  return base::WriteFile(base::FilePath(kNoPreinitFlagFile),
                         (base::StringPiece){});
}

std::string GetBootDeviceName() {
  char path[PATH_MAX];
  int ret = rootdev(path, sizeof(path), /* full resolution = */ true,
                    /* remove partition = */ true);
  if (ret != 0) {
    LOG(WARNING) << "rootdev failed with error code: " << ret;
    return "";
  }

  std::string boot_path(path);
  if (boot_path.substr(0, sizeof(kDevDir) - 1) != kDevDir) {
    LOG(WARNING) << "Unknown device prefix: " << boot_path;
    return "";
  }

  return boot_path.substr(sizeof(kDevDir) - 1);
}

bool IsBootFromRemoveableDevice() {
  base::FilePath file =
      base::FilePath(kSysBlock).Append(GetBootDeviceName()).Append(kRemovable);

  std::string file_content;

  if (!base::ReadFileToString(file, &file_content)) {
    return false;
  }

  std::string removable_str;
  base::TrimWhitespaceASCII(file_content, base::TRIM_ALL, &removable_str);

  int removable = 0;
  if (!base::StringToInt(removable_str, &removable)) {
    LOG(WARNING) << "removable is not a number: " << removable_str;
    return false;
  }

  return removable;
}

}  // namespace

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int flags = brillo::kLogToSyslog;
  if (cl->HasSwitch(kLogToStderrSwitch)) {
    flags |= brillo::kLogToStderr;
  }
  brillo::InitLog(flags);

  if (base::PathExists(base::FilePath(kNoPreinitFlagFile))) {
    LOG(INFO) << kNoPreinitFlagFile << " already exists. Quitting.";
    return 0;
  }

  if (USE_OS_INSTALL_SERVICE) {
    // We should not preinit the TPM if we are running the OS from the
    // installer.
    std::string output;
    if (!base::GetAppOutput({kIsRunningFromInstaller}, &output)) {
      LOG(ERROR) << "Failed to run is_running_from_installer";
    }

    if (output == kInstallerYes) {
      LOG(INFO) << "Running OS from the installer: touching "
                << kNoPreinitFlagFile;
      bool ret = TouchNoPreinitFlagFile();
      if (!ret) {
        LOG(ERROR) << ": Failed to touch " << kNoPreinitFlagFile;
      }
      return ret;
    }
    return 0;
  }

  // Normal ChromeOS case.
  if (IsBootFromRemoveableDevice()) {
    // Don't perform preinit when we are booting from removable device.
    // Because we may not store the data at correct location.
    LOG(INFO) << "Booting from removable device: touching"
              << kNoPreinitFlagFile;
    bool ret = TouchNoPreinitFlagFile();
    if (!ret) {
      LOG(ERROR) << ": Failed to touch " << kNoPreinitFlagFile;
    }
    return ret;
  }
  LOG(INFO) << "Not Booting from removable device. Quitting.";
  return 0;
}
