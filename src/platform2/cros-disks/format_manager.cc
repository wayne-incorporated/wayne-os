// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/format_manager.h"

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/containers/contains.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>
#include <chromeos/libminijail.h>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/strings/string_piece.h"
#include "cros-disks/filesystem_label.h"
#include "cros-disks/format_manager_observer_interface.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/sandboxed_process.h"

namespace cros_disks {

namespace {

struct FormatOptions {
  std::string label;
};

const char kFormatUserAndGroupName[] = "mkfs";

const char kFormatSeccompPolicy[] = "/usr/share/policy/mkfs-seccomp.policy";

// Expected locations of an external format program
const char* const kFormatProgramPaths[] = {
    "/usr/sbin/mkfs.",
    "/bin/mkfs.",
    "/sbin/mkfs.",
    "/usr/bin/mkfs.",
};

// Supported file systems
const char* const kSupportedFilesystems[] = {
    "vfat",
    "exfat",
    "ntfs",
};

const char kDefaultLabel[] = "UNTITLED";

FormatError LabelErrorToFormatError(LabelError error_code) {
  switch (error_code) {
    case LabelError::kSuccess:
      return FormatError::kSuccess;
    case LabelError::kUnsupportedFilesystem:
      return FormatError::kUnsupportedFilesystem;
    case LabelError::kLongName:
      return FormatError::kLongName;
    case LabelError::kInvalidCharacter:
      return FormatError::kInvalidCharacter;
  }
}

// Turns a flat vector of key value pairs into a format options struct. Returns
// true if a valid options struct could be extracted from the vector.
bool ExtractFormatOptions(const std::vector<std::string>& options,
                          FormatOptions* format_options) {
  if (options.size() % 2 == 1) {
    LOG(WARNING) << "Number of options passed in (" << options.size()
                 << ") is not an even number";
    return false;
  }

  for (int i = 0; i < options.size(); i += 2) {
    if (options[i] == kFormatLabelOption) {
      format_options->label = options[i + 1];
    } else {
      LOG(WARNING) << "Unknown format option " << quote(options[i]);
      return false;
    }
  }

  if (format_options->label.empty()) {
    format_options->label = kDefaultLabel;
  }
  return true;
}

std::vector<std::string> CreateFormatArguments(const std::string& filesystem,
                                               const FormatOptions& options) {
  std::vector<std::string> arguments;
  if (filesystem == "vfat") {
    // Allow to create filesystem across the entire device.
    arguments.push_back("-I");
    // FAT type should be predefined, because mkfs autodetection is faulty.
    arguments.push_back("-F");
    arguments.push_back("32");
    arguments.push_back("-n");
    arguments.push_back(options.label);
  } else if (filesystem == "exfat") {
    arguments.push_back("-n");
    arguments.push_back(options.label);
  } else if (filesystem == "ntfs") {
    // --force is used to allow creating a filesystem on devices without a
    // partition table.
    arguments.push_back("--force");
    arguments.push_back("--quick");
    arguments.push_back("--label");
    arguments.push_back(options.label);
  }
  return arguments;
}

// Initialises the process for formatting and starts it.
FormatError StartFormatProcess(const std::string& device_file,
                               const std::string& format_program,
                               const std::vector<std::string>& arguments,
                               const Platform* platform_,
                               SandboxedProcess* process) {
  process->SetNoNewPrivileges();
  process->NewMountNamespace();
  process->NewIpcNamespace();
  process->NewNetworkNamespace();
  process->SetCapabilities(0);

  if (!process->EnterPivotRoot()) {
    LOG(ERROR) << "Cannot enter pivot root";
    return FormatError::kFormatProgramFailed;
  }

  if (!process->SetUpMinimalMounts()) {
    LOG(ERROR) << "Cannot set up minimal mounts for jail";
    return FormatError::kFormatProgramFailed;
  }

  // Open device_file so we can pass only the fd path to the format program.
  base::File dev_file(base::FilePath(device_file), base::File::FLAG_OPEN |
                                                       base::File::FLAG_READ |
                                                       base::File::FLAG_WRITE);
  if (!dev_file.IsValid()) {
    PLOG(ERROR) << "Cannot open " << quote(device_file) << " for formatting: "
                << base::File::ErrorToString(dev_file.error_details());
    return FormatError::kFormatProgramFailed;
  }

  process->LoadSeccompFilterPolicy(kFormatSeccompPolicy);

  uid_t user_id;
  gid_t group_id;
  if (!platform_->GetUserAndGroupId(kFormatUserAndGroupName, &user_id,
                                    &group_id)) {
    LOG(ERROR) << "Cannot find user ID and group ID of "
               << quote(kFormatUserAndGroupName);
    return FormatError::kInternalError;
  }

  process->SetUserId(user_id);
  process->SetGroupId(group_id);

  process->AddArgument(format_program);

  for (const std::string& arg : arguments) {
    process->AddArgument(arg);
  }

  process->AddArgument(
      base::StringPrintf("/dev/fd/%d", dev_file.GetPlatformFile()));
  process->PreserveFile(dev_file.GetPlatformFile());

  // Sets an output callback, even if it does nothing, to activate the capture
  // of the generated messages.
  process->SetOutputCallback(base::DoNothing());

  if (!process->Start()) {
    LOG(ERROR) << "Cannot start " << quote(format_program) << " to format "
               << quote(device_file);
    return FormatError::kFormatProgramFailed;
  }

  LOG(INFO) << "Running " << quote(format_program) << " to format "
            << quote(device_file);
  return FormatError::kSuccess;
}

}  // namespace

FormatManager::FormatManager(Platform* platform,
                             brillo::ProcessReaper* process_reaper)
    : platform_(platform),
      process_reaper_(process_reaper),
      weak_ptr_factory_(this) {}

FormatManager::~FormatManager() = default;

FormatError FormatManager::StartFormatting(
    const std::string& device_path,
    const std::string& device_file,
    const std::string& filesystem,
    const std::vector<std::string>& options) {
  // Check if the file system is supported for formatting
  if (!IsFilesystemSupported(filesystem)) {
    LOG(WARNING) << filesystem << " filesystem is not supported for formatting";
    return FormatError::kUnsupportedFilesystem;
  }

  // Localize mkfs on disk
  std::string format_program = GetFormatProgramPath(filesystem);
  if (format_program.empty()) {
    LOG(WARNING) << "Cannot find a format program for filesystem "
                 << quote(filesystem);
    return FormatError::kFormatProgramNotFound;
  }

  FormatOptions format_options;
  if (!ExtractFormatOptions(options, &format_options)) {
    return FormatError::kInvalidOptions;
  }

  if (const LabelError error =
          ValidateVolumeLabel(format_options.label, filesystem);
      error != LabelError::kSuccess) {
    return LabelErrorToFormatError(error);
  }

  const auto [it, ok] = format_process_.try_emplace(device_path);
  SandboxedProcess& process = it->second;

  if (!ok) {
    LOG(WARNING) << "Device " << quote(device_path)
                 << " is already being formatted by "
                 << process.GetProgramName() << "[" << process.pid() << "]";
    return FormatError::kDeviceBeingFormatted;
  }

  if (const FormatError error =
          StartFormatProcess(device_file, format_program,
                             CreateFormatArguments(filesystem, format_options),
                             platform_, &process);
      error != FormatError::kSuccess) {
    format_process_.erase(it);
    return error;
  }

  process_reaper_->WatchForChild(
      FROM_HERE, process.pid(),
      base::BindOnce(&FormatManager::OnFormatProcessTerminated,
                     weak_ptr_factory_.GetWeakPtr(), device_path));
  return FormatError::kSuccess;
}

void FormatManager::OnFormatProcessTerminated(const std::string& device_path,
                                              const siginfo_t& info) {
  const auto node = format_process_.extract(device_path);
  if (!node) {
    LOG(ERROR) << "Cannot find process formatting " << quote(device_path);
    return;
  }

  DCHECK_EQ(node.key(), device_path);
  const SandboxedProcess& process = node.mapped();

  FormatError error = FormatError::kUnknownError;
  switch (info.si_code) {
    case CLD_EXITED:
      if (info.si_status == 0) {
        error = FormatError::kSuccess;
        LOG(INFO) << "Program " << quote(process.GetProgramName())
                  << " formatting " << quote(device_path) << " finished with "
                  << Process::ExitCode(info.si_status);
      } else {
        error = FormatError::kFormatProgramFailed;
        LOG(ERROR) << "Program " << quote(process.GetProgramName())
                   << " formatting " << quote(device_path) << " finished with "
                   << Process::ExitCode(info.si_status);
      }
      break;

    case CLD_DUMPED:
    case CLD_KILLED:
      error = FormatError::kFormatProgramFailed;
      LOG(ERROR) << "Program " << quote(process.GetProgramName())
                 << " formatting " << quote(device_path) << " was killed by "
                 << Process::ExitCode(MINIJAIL_ERR_SIG_BASE + info.si_status);
      break;

    default:
      LOG(ERROR) << "Unexpected si_code value: " << info.si_code;
      break;
  }

  if (error != FormatError::kSuccess && !LOG_IS_ON(INFO)) {
    // The mkfs program finished with an error, and its capture messages have
    // not been logged yet. Log them now as errors.
    for (const base::StringPiece line : process.GetCapturedOutput()) {
      LOG(ERROR) << process.GetProgramName() << ": " << line;
    }
  }

  if (observer_)
    observer_->OnFormatCompleted(device_path, error);
}

std::string FormatManager::GetFormatProgramPath(
    const std::string& filesystem) const {
  for (const char* program_path : kFormatProgramPaths) {
    std::string path = program_path + filesystem;
    if (base::PathExists(base::FilePath(path)))
      return path;
  }
  return std::string();
}

bool FormatManager::IsFilesystemSupported(const std::string& filesystem) const {
  for (const char* supported_filesystem : kSupportedFilesystems) {
    if (filesystem == supported_filesystem)
      return true;
  }
  return false;
}

}  // namespace cros_disks
