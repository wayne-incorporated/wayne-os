// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_ARCHIVE_MOUNTER_H_
#define CROS_DISKS_ARCHIVE_MOUNTER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/strings/string_piece.h>

#include "cros-disks/fuse_mounter.h"

namespace cros_disks {

class Metrics;

// An implementation of FUSEMounter tailored for mounting archives.
class ArchiveMounter : public FUSEMounter {
 public:
  static constexpr char kChromeNamespace[] = "/run/namespaces/mnt_chrome";

  ArchiveMounter(const Platform* platform,
                 brillo::ProcessReaper* process_reaper,
                 std::string filesystem_type,
                 std::string archive_type,
                 Metrics* metrics,
                 std::string metrics_name,
                 std::vector<int> password_needed_exit_codes,
                 std::unique_ptr<SandboxedProcessFactory> sandbox_factory,
                 std::vector<std::string> extra_command_line_options = {});
  ArchiveMounter(const ArchiveMounter&) = delete;
  ArchiveMounter& operator=(const ArchiveMounter&) = delete;

  ~ArchiveMounter() override;

  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_dir_name) const override;

  OwnerUser GetDaemonUser() const;

  // Checks if the given string might represent a realistic encoding. Allowed
  // characters are uppercase and lowercase letters, numbers, '-', '_', '.' and
  // ':'.
  static bool IsValidEncoding(base::StringPiece encoding);

 protected:
  // FUSEMounter overrides:
  std::unique_ptr<SandboxedProcess> PrepareSandbox(
      const std::string& source,
      const base::FilePath& target_path,
      std::vector<std::string> params,
      MountError* error) const final;

  virtual std::vector<std::string> GetBindPaths(
      base::StringPiece original_path) const {
    return {std::string(original_path)};
  }

 private:
  const std::string extension_;
  Metrics* const metrics_;
  const std::unique_ptr<SandboxedProcessFactory> sandbox_factory_;
  const std::vector<std::string> extra_command_line_options_;

  friend class ArchiveMounterTest;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_ARCHIVE_MOUNTER_H_
