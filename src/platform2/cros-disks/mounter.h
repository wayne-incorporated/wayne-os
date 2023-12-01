// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_MOUNTER_H_
#define CROS_DISKS_MOUNTER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <chromeos/dbus/service_constants.h>

#include "cros-disks/mount_options.h"

namespace cros_disks {

class MountPoint;

// Interface for mounting a given filesystem.
class Mounter {
 public:
  Mounter() = default;
  Mounter(const Mounter&) = delete;
  Mounter& operator=(const Mounter&) = delete;
  virtual ~Mounter() = default;

  // Mounts the filesystem. On failure returns nullptr and |error| is
  // set accordingly. Both |source| and |params| are just some strings
  // that can be interpreted by this mounter.
  virtual std::unique_ptr<MountPoint> Mount(const std::string& source,
                                            const base::FilePath& target_path,
                                            std::vector<std::string> params,
                                            MountError* error) const = 0;

  // Whether this mounter is able to mount given |source| with provided
  // |params|. If so - it may suggest a directory name for the mount point
  // to be created. Note that in many cases it's impossible to tell beforehand
  // if the particular source is mountable so it may blanketly return true for
  // any arguments.
  virtual bool CanMount(const std::string& source,
                        const std::vector<std::string>& params,
                        base::FilePath* suggested_dir_name) const = 0;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_MOUNTER_H_
