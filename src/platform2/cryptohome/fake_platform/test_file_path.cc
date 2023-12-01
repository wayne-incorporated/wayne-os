// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/test_file_path.h"

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace cryptohome {
namespace fake_platform {

base::FilePath SpliceTestFilePath(const base::FilePath& tmpfs,
                                  const base::FilePath& path) {
  DCHECK(path.IsAbsolute());
  std::string path_str = path.NormalizePathSeparators().value();
  if (path_str.length() > 0 && path_str[0] == '/') {
    path_str = path_str.substr(1);
  }
  return tmpfs.Append(path_str);
}

base::FilePath StripTestFilePath(const base::FilePath& tmpfs,
                                 const base::FilePath& path) {
  base::FilePath result("/");

  // AppendRelativePath requires path to be a strict child of tmpfs to work.
  // Handle the case of the exact match separately.
  if (tmpfs == path) {
    return result;
  }

  if (!tmpfs.AppendRelativePath(path, &result)) {
    // Not under the test root, so return as is.
    return path;
  }
  return result;
}

base::FilePath NormalizePath(const base::FilePath& path) {
  DCHECK(path.IsAbsolute());
  std::vector<std::string> components = path.GetComponents();
  std::vector<std::string> normalized_components;

  for (const auto& component : components) {
    if (component == ".") {
      continue;
    }
    if (component == "..") {
      if (normalized_components.size() > 1) {
        normalized_components.pop_back();
      }
      continue;
    }
    normalized_components.push_back(component);
  }

  base::FilePath result;
  for (const auto& component : normalized_components) {
    if (result.empty()) {
      result = base::FilePath(component);
      continue;
    }
    result = result.Append(component);
  }
  return result;
}

}  // namespace fake_platform
}  // namespace cryptohome
