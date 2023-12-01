// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_FILE_ATTRS_CLEANER_H_
#define INIT_FILE_ATTRS_CLEANER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace file_attrs_cleaner {

enum class AttributeCheckStatus {
  ERROR = 0,
  NO_ATTR,
  CLEAR_FAILED,
  CLEARED,
};

// Whether we allow `path` to be marked with immutable file attribute.
// If `path` is supposed to be a directory, set `isdir` to true.
bool ImmutableAllowed(const base::FilePath& path, bool isdir);

// Check the file attributes of the specified path.  `path` is used for logging
// and policy checking, so `fd` needs to be an open handle to it.  This helps
// with TOCTTOU issues.  If `path` is supposed to be a directory, set `isdir`
// to true.
AttributeCheckStatus CheckFileAttributes(const base::FilePath& path,
                                         bool isdir,
                                         int fd);

// Recursively scan the file attributes of paths under `dir`.
// Don't recurse into any subdirectories that exactly match any string in
// `skip_recurse`.
bool ScanDir(const base::FilePath& dir,
             const std::vector<std::string>& skip_recurse);

// Convenience function.
static inline bool ScanDir(const std::string& dir,
                           const std::vector<std::string>& skip_recurse) {
  return ScanDir(base::FilePath(dir), skip_recurse);
}

}  // namespace file_attrs_cleaner

#endif  // INIT_FILE_ATTRS_CLEANER_H_
