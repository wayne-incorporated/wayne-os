// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_ICON_FINDER_H_
#define VM_TOOLS_GARCON_ICON_FINDER_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

namespace vm_tools {
namespace garcon {

// Returns a valid file path for reading in an icon file with the specified
// parameters. The |icon_size| and |scale| are preferences rather than strict
// criteria.
base::FilePath LocateIconFile(const std::string& desktop_file_id,
                              int icon_size,
                              int scale);

// Returns a vector of directory paths under |icon_dir| that can be searched
// under for an icon. The |icon_size| and |scale| parameters are preferences
// rather than strict criteria. A directory that matches these criteria more
// closely will precede another directory that matches these criteria less
// closely in the return vector.
std::vector<base::FilePath> GetPathsForIcons(const base::FilePath& icon_dir,
                                             int icon_size,
                                             int scale);
}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_ICON_FINDER_H_
