// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/ui/util.h"

#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/launch.h>

namespace chromeos {
namespace ui {
namespace util {

base::FilePath GetReparentedPath(const std::string& path,
                                 const base::FilePath& parent) {
  if (parent.empty())
    return base::FilePath(path);

  CHECK(!path.empty() && path[0] == '/');
  base::FilePath relative_path(path.substr(1));
  CHECK(!relative_path.IsAbsolute());
  return parent.Append(relative_path);
}

bool SetPermissions(const base::FilePath& path,
                    uid_t uid,
                    gid_t gid,
                    mode_t mode) {
  base::ScopedFD fd(
      open(path.value().c_str(), O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Couldn't open " << path.value();
    return false;
  }

  if (getuid() == 0) {
    if (fchown(fd.get(), uid, gid) != 0) {
      PLOG(ERROR) << "Couldn't chown " << path.value() << " to " << uid << ":"
                  << gid;
      return false;
    }
  }
  if (fchmod(fd.get(), mode) != 0) {
    PLOG(ERROR) << "Unable to chmod " << path.value() << " to " << std::oct
                << mode;
    return false;
  }
  return true;
}

bool EnsureDirectoryExists(const base::FilePath& path,
                           uid_t uid,
                           gid_t gid,
                           mode_t mode) {
  if (!base::DirectoryExists(path)) {
    // Remove the existing file or link if any.
    if (!base::DeleteFile(path)) {
      PLOG(ERROR) << "Unable to delete " << path.value();
      return false;
    }
    if (!base::CreateDirectory(path)) {
      PLOG(ERROR) << "Unable to create " << path.value();
      return false;
    }
  }
  return SetPermissions(path, uid, gid, mode);
}

bool Run(const char* command, const char* arg, ...) {
  // Extra parentheses because yay C++ most vexing parse.
  base::CommandLine cl((base::FilePath(command)));
  va_list list;
  va_start(list, arg);
  while (arg) {
    cl.AppendArg(const_cast<char*>(arg));
    arg = va_arg(list, char*);
  }
  va_end(list);

  std::string output;
  int exit_code = 0;
  if (!base::GetAppOutputWithExitCode(cl, &output, &exit_code)) {
    LOG(WARNING) << "\"" << cl.GetCommandLineString() << "\" failed with "
                 << exit_code << ": " << output;
    return false;
  }

  return true;
}

}  // namespace util
}  // namespace ui
}  // namespace chromeos
