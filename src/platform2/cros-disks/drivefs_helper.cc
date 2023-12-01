// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/drivefs_helper.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

#include <utility>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/strings/string_util.h>
#include <brillo/files/safe_fd.h>

#include "cros-disks/fuse_mounter.h"
#include "cros-disks/mount_options.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/sandboxed_process.h"
#include "cros-disks/uri.h"

namespace cros_disks {
namespace {

const char kDataDirOptionPrefix[] = "datadir";
const char kIdentityOptionPrefix[] = "identity";
const char kMyFilesOptionPrefix[] = "myfiles";
const char kPathPrefixOptionPrefix[] = "prefix";

const char kHelperTool[] = "/opt/google/drive-file-stream/drivefs";
const char kType[] = "drivefs";
const char kDbusSocketPath[] = "/run/dbus";
const char kHomeBaseDir[] = "/home";

// UID of fuse-drivefs user.
constexpr uid_t kOldDriveUID = 304;

bool FindPathOption(const std::vector<std::string>& options,
                    const std::string& name,
                    base::FilePath* path) {
  std::string value;
  if (!GetParamValue(options, name, &value) || value.empty()) {
    return false;
  }
  *path = base::FilePath(value);
  return true;
}

error_t RemoveDirectory(brillo::SafeFD* parent, const base::FilePath& name) {
  if (setresuid(kOldDriveUID, kOldDriveUID, kOldDriveUID) != 0) {
    return errno;
  }

  // This function accounts for various gotchas like filesystem boundaries,
  // types, etc. If we were to chown the dir we'd have to replicate that
  // traversal approach. But for now just nuke the dir.
  brillo::SafeFD::Error error = parent->Rmdir(name.value(),
                                              /*recursive=*/true,
                                              /*max_depth=*/7,
                                              /*keep_going=*/false);
  switch (error) {
    case brillo::SafeFD::Error::kNoError:
      return 0;
    case brillo::SafeFD::Error::kIOError:
    case brillo::SafeFD::Error::kWrongType:
      return errno;
    case brillo::SafeFD::Error::kBoundaryDetected:
      return EXDEV;
    default:
      return EINVAL;
  }
}

bool FixDirectory(const base::FilePath& path) {
  brillo::SafeFD::SafeFDResult root = brillo::SafeFD::Root();
  if (brillo::SafeFD::IsError(root.second)) {
    PLOG(ERROR) << "Failed to open root dir: " << static_cast<int>(root.second);
    return false;
  }
  brillo::SafeFD::SafeFDResult parent = root.first.OpenExistingDir(
      path.DirName(), O_PATH | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
  if (brillo::SafeFD::IsError(parent.second)) {
    PLOG(ERROR) << "Failed to open parent dir: "
                << static_cast<int>(parent.second);
    return false;
  }

  // Permission on the datadir won't allow cros-disks to manipulate it
  // directly, chowning it based off path is unsafe, and fchown requires
  // an FD, which we can't obtain because permissions, so instead we fork
  // and change child's UID to freely navigate the directory tree.
  pid_t pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "Failed to fork";
    return false;
  } else if (pid == 0) {
    _exit(RemoveDirectory(&parent.first, path.BaseName()));
  } else {
    int wstatus;
    PCHECK(pid == waitpid(pid, &wstatus, 0));
    int status = EXIT_FAILURE;
    if (WIFEXITED(wstatus)) {
      status = WEXITSTATUS(wstatus);
      errno = status;
    }
    if (status != EXIT_SUCCESS) {
      PLOG(ERROR) << "Cannot remove datadir " << quote(path);
      return false;
    }
  }

  brillo::SafeFD::SafeFDResult datadir =
      parent.first.MakeDir(path.BaseName(), S_IRWXU | S_IRWXG | S_ISGID,
                           kChronosUID, kChronosAccessGID);

  if (brillo::SafeFD::IsError(datadir.second)) {
    PLOG(ERROR) << "Cannot create datadir " << quote(path);
    return false;
  }

  return true;
}

bool ValidateDirectory(const Platform* platform,
                       base::FilePath* dir,
                       bool fix_non_compliant) {
  if (dir->empty() || !dir->IsAbsolute() || dir->ReferencesParent()) {
    LOG(ERROR) << "Unsafe path " << quote(*dir);
    return false;
  }
  std::string path_string;
  if (!platform->GetRealPath(dir->value(), &path_string)) {
    LOG(ERROR) << "Unable to find real path of " << quote(*dir);
    // TODO(crbug.com/1205308): Remove extra logging when root cause found.
    LOG(ERROR) << "Checking ancestors:";
    for (base::FilePath p = *dir; p != p.DirName(); p = p.DirName()) {
      if (!platform->GetRealPath(p.value(), &path_string)) {
        LOG(ERROR) << "Unable to find real path of " << quote(p);
      }
      if (!platform->DirectoryExists(p.value())) {
        LOG(ERROR) << "Dir does not exist " << quote(p);
        continue;
      }
      uid_t uid;
      gid_t gid;
      if (platform->GetOwnership(p.value(), &uid, &gid)) {
        LOG(ERROR) << "Path " << quote(p) << " has owner " << uid << ":" << gid;
      }
      mode_t mode;
      if (platform->GetPermissions(p.value(), &mode)) {
        LOG(ERROR) << "Path " << quote(p) << " has mode " << std::oct << mode;
      }
    }
    return false;
  }
  *dir = base::FilePath(path_string);

  CHECK(dir->IsAbsolute() && !dir->ReferencesParent());

  if (!platform->DirectoryExists(dir->value())) {
    LOG(ERROR) << "Dir does not exist " << quote(*dir);
    return false;
  }

  uid_t current_uid;
  if (!platform->GetOwnership(dir->value(), &current_uid, nullptr)) {
    LOG(ERROR) << "Cannot access datadir " << quote(*dir);
    return false;
  }

  if (current_uid != kChronosUID) {
    if (!fix_non_compliant || current_uid != kOldDriveUID) {
      LOG(ERROR) << "Wrong owner of datadir: " << current_uid;
      return false;
    }

    LOG(WARNING) << "Unmigrated drivefs datadir detected";
    if (!FixDirectory(*dir)) {
      LOG(ERROR) << "Could not repair drivefs datadir ownership";
      return false;
    }
  }

  return true;
}

}  // namespace

DrivefsHelper::DrivefsHelper(const Platform* platform,
                             brillo::ProcessReaper* process_reaper)
    : FUSEMounterHelper(platform,
                        process_reaper,
                        kType,
                        /* nosymfollow= */ false,
                        &sandbox_factory_),
      sandbox_factory_(platform,
                       SandboxedExecutable{base::FilePath(kHelperTool)},
                       OwnerUser{kChronosUID, kChronosGID},
                       /* has_network_access= */ true) {}

DrivefsHelper::~DrivefsHelper() = default;

bool DrivefsHelper::CanMount(const std::string& source,
                             const std::vector<std::string>& params,
                             base::FilePath* suggested_name) const {
  const Uri uri = Uri::Parse(source);
  if (!uri.valid() || uri.scheme() != kType)
    return false;

  if (uri.path().empty())
    *suggested_name = base::FilePath(kType);
  else
    *suggested_name = base::FilePath(uri.path());
  return true;
}

MountError DrivefsHelper::ConfigureSandbox(const std::string& source,
                                           const base::FilePath& target_path,
                                           std::vector<std::string> params,
                                           SandboxedProcess* sandbox) const {
  const Uri uri = Uri::Parse(source);
  if (!uri.valid() || uri.scheme() != kType) {
    LOG(ERROR) << "Invalid source format " << quote(source);
    return MountError::kInvalidDevicePath;
  }
  if (uri.path().empty()) {
    LOG(ERROR) << "Invalid source " << quote(source);
    return MountError::kInvalidDevicePath;
  }

  base::FilePath data_dir;
  if (!FindPathOption(params, kDataDirOptionPrefix, &data_dir)) {
    LOG(ERROR) << "No data directory provided";
    return MountError::kInvalidMountOptions;
  }
  if (!ValidateDirectory(platform(), &data_dir, true)) {
    return MountError::kInsufficientPermissions;
  }

  const base::FilePath homedir(kHomeBaseDir);
  if (!homedir.IsParent(data_dir)) {
    LOG(ERROR) << "Unexpected location of " << quote(data_dir);
    return MountError::kInsufficientPermissions;
  }

  base::FilePath my_files;
  if (FindPathOption(params, kMyFilesOptionPrefix, &my_files)) {
    if (!ValidateDirectory(platform(), &my_files, false)) {
      LOG(ERROR) << "User files inaccessible";
      return MountError::kInsufficientPermissions;
    }
    if (!homedir.IsParent(my_files)) {
      LOG(ERROR) << "Unexpected location of " << quote(my_files);
      return MountError::kInsufficientPermissions;
    }
  }

  // Bind datadir, user files and DBus communication socket into the sandbox.
  if (!sandbox->Mount("tmpfs", "/home", "tmpfs", "mode=0755,size=1M")) {
    LOG(ERROR) << "Cannot mount /home";
    return MountError::kInternalError;
  }
  if (!sandbox->BindMount(data_dir.value(), data_dir.value(), true, false)) {
    LOG(ERROR) << "Cannot bind " << quote(data_dir);
    return MountError::kInternalError;
  }
  if (!sandbox->BindMount(kDbusSocketPath, kDbusSocketPath, true, false)) {
    LOG(ERROR) << "Cannot bind " << quote(kDbusSocketPath);
    return MountError::kInternalError;
  }
  if (!my_files.empty()) {
    if (!sandbox->BindMount(my_files.value(), my_files.value(), true, true)) {
      LOG(ERROR) << "Cannot bind " << quote(my_files);
      return MountError::kInternalError;
    }
  }

  // Sandboxed processes have their own tmpfs mount, but this mount is too small
  // for certain sqlite operations that DriveFS does. Tell DriveFS to use the
  // datadir for sqlite temporary file storage instead.
  sandbox->AddEnvironmentVariable("SQLITE_TMPDIR", data_dir.value());

  std::vector<std::string> args;
  SetParamValue(&args, "uid", base::NumberToString(kChronosUID));
  SetParamValue(&args, "gid", base::NumberToString(kChronosAccessGID));
  SetParamValue(&args, kDataDirOptionPrefix, data_dir.value());
  SetParamValue(&args, kIdentityOptionPrefix, uri.path());
  SetParamValue(&args, kPathPrefixOptionPrefix, target_path.value());
  if (!my_files.empty()) {
    SetParamValue(&args, kMyFilesOptionPrefix, my_files.value());
  }
  std::string options;
  if (!JoinParamsIntoOptions(args, &options)) {
    return MountError::kInvalidMountOptions;
  }
  sandbox->AddArgument("-o");
  sandbox->AddArgument(options);

  return MountError::kSuccess;
}

}  // namespace cros_disks
