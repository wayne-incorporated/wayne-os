// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_IMPL_H_

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/system_files_service.h"

namespace diagnostics {
namespace wilco {

class SystemFilesServiceImpl final : public SystemFilesService {
 public:
  static base::FilePath GetPathForDirectory(Directory location);
  static base::FilePath GetPathForFile(File location);
  static base::FilePath GetPathForVpdField(VpdField vpd_field);

  SystemFilesServiceImpl();
  SystemFilesServiceImpl(const SystemFilesServiceImpl&) = delete;
  SystemFilesServiceImpl& operator=(const SystemFilesServiceImpl&) = delete;

  ~SystemFilesServiceImpl() override;

  // SystemFilesService overrides:
  std::optional<FileDump> GetFileDump(File location) override;
  std::optional<FileDumps> GetDirectoryDump(Directory location) override;
  std::optional<std::string> GetVpdField(VpdField vpd_field) override;

  void set_root_dir_for_testing(const base::FilePath& dir);

 private:
  // Makes a dump of the specified file. Returns whether the dumping succeeded.
  bool MakeFileDump(const base::FilePath& path, FileDump* dump) const;

  // Constructs and, if successful, appends the dump of every file in the
  // specified directory (with the path given relative to |root_dir|) to the
  // given vector. This will follow allowable symlinks - see
  // ShouldFollowSymlink() for details.
  void SearchDirectory(const base::FilePath& root_dir,
                       std::set<std::string>* visited_paths,
                       FileDumps* file_dumps) const;

  // While dumping files in a directory, determines if we should follow a
  // symlink or not. Currently, we only follow symlinks one level down from
  // /sys/class/*/. For example, we would follow a symlink from
  // /sys/class/hwmon/hwmon0, but we would not follow a symlink from
  // /sys/class/hwmon/hwmon0/device.
  bool ShouldFollowSymlink(const base::FilePath& link) const;

  base::FilePath root_dir_{"/"};
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_FILES_SERVICE_IMPL_H_
