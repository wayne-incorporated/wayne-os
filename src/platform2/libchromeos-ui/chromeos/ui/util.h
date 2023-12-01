// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>

#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>

#ifndef LIBCHROMEOS_UI_CHROMEOS_UI_UTIL_H_
#define LIBCHROMEOS_UI_CHROMEOS_UI_UTIL_H_

namespace chromeos {
namespace ui {
namespace util {

// Converts an absolute path |path| into a base::FilePath. If |parent| is
// non-empty, |path| is rooted within it. For example, GetPath("/usr/bin/bar",
// base::FilePath("/tmp/foo")) returns base::FilePath("/tmp/foo/usr/bin/bar")).
BRILLO_EXPORT base::FilePath GetReparentedPath(const std::string& path,
                                               const base::FilePath& parent);

// Changes the ownership of |path| to |uid|:|gid| and sets its mode to |mode|.
// Skips updating ownership when not running as root (for use in tests).
BRILLO_EXPORT bool SetPermissions(const base::FilePath& path,
                                  uid_t uid,
                                  gid_t gid,
                                  mode_t mode);

// Ensures that |path| exists with the requested ownership and permissions,
// creating and/or updating it if needed. Returns true on success.
BRILLO_EXPORT bool EnsureDirectoryExists(const base::FilePath& path,
                                         uid_t uid,
                                         gid_t gid,
                                         mode_t mode);

// Runs the passed-in command and arguments synchronously, returning true on
// success. On failure, the command's output is logged. The path will be
// searched for |command|.
BRILLO_EXPORT bool Run(const char* command, const char* arg, ...);

}  // namespace util
}  // namespace ui
}  // namespace chromeos

#endif  // LIBCHROMEOS_UI_CHROMEOS_UI_UTIL_H_
