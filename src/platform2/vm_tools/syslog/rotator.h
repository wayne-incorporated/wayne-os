// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SYSLOG_ROTATOR_H_
#define VM_TOOLS_SYSLOG_ROTATOR_H_

#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>

namespace vm_tools {
namespace syslog {

class Rotator {
 public:
  void RotateLogFiles(const base::FilePath& root_path, int max_index);
  static void GetSortedFileInfo(
      const base::FilePath& root_path,
      const std::string& pattern,
      std::vector<base::FileEnumerator::FileInfo>* info);
};

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_ROTATOR_H_
