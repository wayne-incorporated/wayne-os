// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/xdg_util.h"

#include <base/strings/string_split.h>

namespace {
constexpr char kDataDirsEnvVar[] = "XDG_DATA_DIRS";
constexpr char kDataHomeEnvVar[] = "XDG_DATA_HOME";
constexpr char kDefaultDataDirsPaths[] = "/usr/local/share:/usr/share";
constexpr char kDefaultDataHomeSuffix[] = ".local/share";
constexpr char kHomeEnvVar[] = "HOME";
}  // namespace

namespace vm_tools {
namespace garcon {
namespace xdg {

std::vector<base::FilePath> GetDataDirectories() {
  // Start with the global data dirs
  const char* xdg_data_dirs = getenv(kDataDirsEnvVar);
  if (!xdg_data_dirs || strlen(xdg_data_dirs) == 0) {
    xdg_data_dirs = kDefaultDataDirsPaths;
  }
  // Now break it up into the paths that we should search.
  std::vector<base::StringPiece> search_dirs = base::SplitStringPiece(
      xdg_data_dirs, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  std::vector<base::FilePath> retval;
  for (const auto& curr_dir : search_dirs) {
    base::FilePath curr_path(curr_dir);
    retval.emplace_back(curr_path);
  }
  // Finally, add the user's data dir.
  const char* xdg_data_home = getenv(kDataHomeEnvVar);
  if (xdg_data_home && strlen(xdg_data_home) > 0) {
    retval.emplace_back(base::FilePath(xdg_data_home));
  } else {
    const char* user_home = getenv(kHomeEnvVar);
    if (user_home && strlen(user_home) > 0) {
      retval.emplace_back(
          base::FilePath(user_home).Append(kDefaultDataHomeSuffix));
    }
  }
  return retval;
}

}  // namespace xdg
}  // namespace garcon
}  // namespace vm_tools
