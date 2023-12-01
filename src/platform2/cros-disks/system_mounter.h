// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_SYSTEM_MOUNTER_H_
#define CROS_DISKS_SYSTEM_MOUNTER_H_

#include <memory>
#include <string>
#include <vector>

#include "cros-disks/mount_point.h"
#include "cros-disks/mounter.h"
#include "cros-disks/platform.h"

namespace cros_disks {

// A class for mounting a device file using the system mount() call.
class SystemMounter : public Mounter {
 public:
  SystemMounter(const Platform* platform,
                std::string filesystem_type,
                bool read_only,
                std::vector<std::string> options);
  SystemMounter(const SystemMounter&) = delete;
  SystemMounter& operator=(const SystemMounter&) = delete;

  ~SystemMounter() override;

  bool read_only() const { return (flags_ & MS_RDONLY) == MS_RDONLY; }
  const std::vector<std::string>& options() const { return options_; }

  // Mounts a device file using the system mount() call.
  std::unique_ptr<MountPoint> Mount(const std::string& source,
                                    const base::FilePath& target_path,
                                    std::vector<std::string> params,
                                    MountError* error) const override;

  // As there is no way to figure out beforehand if that would work, always
  // returns true, so this mounter is a "catch-all".
  bool CanMount(const std::string& source,
                const std::vector<std::string>& params,
                base::FilePath* suggested_dir_name) const override;

 protected:
  virtual MountError ParseParams(std::vector<std::string> params,
                                 std::vector<std::string>* mount_options) const;

 private:
  const Platform* const platform_;
  const std::string filesystem_type_;
  const uint64_t flags_;
  const std::vector<std::string> options_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_SYSTEM_MOUNTER_H_
