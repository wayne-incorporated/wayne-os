// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_STARTUP_STATEFUL_MOUNT_H_
#define INIT_STARTUP_STATEFUL_MOUNT_H_

#include <memory>
#include <stack>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/blkdev_utils/lvm.h>
#include <metrics/bootstat.h>

#include "init/startup/flags.h"
#include "init/startup/mount_helper.h"
#include "init/startup/platform_impl.h"

namespace startup {

// This is the class for stateful mount functionality. It contains
// the logic and functions used for mounting the stateful partition,
// as well as other functionality related to the stateful partition.
class StatefulMount {
 public:
  std::vector<std::string> GenerateExt4Features(
      const std::string state_dumpe2fs);

  StatefulMount(const Flags& flags,
                const base::FilePath& root,
                const base::FilePath& stateful,
                Platform* platform,
                std::unique_ptr<brillo::LogicalVolumeManager> lvm,
                MountHelper* mount_helper);

  virtual ~StatefulMount() = default;

  bool HibernateResumeBoot();

  static bool GetImageVars(base::FilePath json_file,
                           std::string key,
                           base::Value* vars);

  void SetStateDevForTest(const base::FilePath& dev);
  base::FilePath GetStateDev();
  base::FilePath GetDevImage();

  void MountStateful();

  bool DevUpdateStatefulPartition(const std::string& args);
  void DevGatherLogs(const base::FilePath& base_dir);
  void DevMountPackages(const base::FilePath& device);

 private:
  bool IsQuotaEnabled();
  void AppendQuotaFeaturesAndOptions(const std::string& fs_features,
                                     const std::string& state_dumpe2fs,
                                     std::vector<std::string>* sb_options,
                                     std::vector<std::string>* sb_features);
  void EnableExt4Features();
  std::vector<std::string> GenerateExt4FeaturesWrapper();

  const Flags flags_;
  const base::FilePath root_;
  const base::FilePath stateful_;
  Platform* platform_;
  std::unique_ptr<brillo::LogicalVolumeManager> lvm_;
  MountHelper* mount_helper_;
  bootstat::BootStat bootstat_;

  base::FilePath root_dev_type_;
  base::FilePath state_dev_;
  base::FilePath dev_image_;
  std::optional<brillo::VolumeGroup> volume_group_;
};

}  // namespace startup

#endif  // INIT_STARTUP_STATEFUL_MOUNT_H_
