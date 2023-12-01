// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_H_

#include "brillo/blkdev_utils/lvm_device.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/values.h>

namespace brillo {

// LogicalVolumeManager acts as the interface for an any application that
// needs to deal with logical volumes. The intended use of this class is to
// either create or get existing lvm2 devices and to then use the device objects
// to perform operations. Note that the objects returned from this class are
// only representative of the state of the system at the time and should be
// short-lived.
class BRILLO_EXPORT LogicalVolumeManager {
 public:
  LogicalVolumeManager();
  explicit LogicalVolumeManager(std::shared_ptr<LvmCommandRunner> lvm);
  virtual ~LogicalVolumeManager() = default;

  // Returns the physical volume on device, if it exists.
  virtual std::optional<PhysicalVolume> GetPhysicalVolume(
      const base::FilePath& device_path);

  // Returns the volume group on the physical volume, if it exists.
  virtual std::optional<VolumeGroup> GetVolumeGroup(const PhysicalVolume& pv);

  // Returns a thinpool named |thinpool_name| on volume group |vg|, if it
  // exists.
  virtual std::optional<Thinpool> GetThinpool(const VolumeGroup& vg,
                                              const std::string& thinpool_name);

  // Lists all logical volumes on the volume group.
  // Empty pattern implies no filtering.
  virtual std::vector<LogicalVolume> ListLogicalVolumes(
      const VolumeGroup& vg, const std::string& pattern = "");

  // Returns a logical volume named |lv_name|, if it exists on volume group |vg|
  virtual std::optional<LogicalVolume> GetLogicalVolume(
      const VolumeGroup& vg, const std::string& lv_name);

  // Creates a physical volume on |device_path|.
  virtual std::optional<PhysicalVolume> CreatePhysicalVolume(
      const base::FilePath& device_path);

  // Creates a volume group |vg_name| on physical volume |pv|.
  virtual std::optional<VolumeGroup> CreateVolumeGroup(
      const PhysicalVolume& pv, const std::string& vg_name);

  // Creates a thinpool with configuration |config| on volume group |vg|.
  virtual std::optional<Thinpool> CreateThinpool(const VolumeGroup& vg,
                                                 const base::Value& config);

  // Creates a thin logical volume with configuration |config| on volume group
  // |vg|.
  virtual std::optional<LogicalVolume> CreateLogicalVolume(
      const VolumeGroup& vg,
      const Thinpool& thinpool,
      const base::Value::Dict& config);

  // Removes a logical volume, if it exists. Returns false if the logical volume
  // exists and failed removal.
  virtual bool RemoveLogicalVolume(const VolumeGroup& vg,
                                   const std::string& lv_name);

 private:
  // Validates whether |lv_name| exists as either a logical volume or thinpool
  // (depending on |is_thinpool|) on volume group |vg|.
  bool ValidateLogicalVolume(const VolumeGroup& vg,
                             const std::string& lv_name,
                             bool is_thinpool);

  // Validates if a physical volume exists on |device_path| and optionally
  // returns the volume group name, if a volume group exists.
  bool ValidatePhysicalVolume(const base::FilePath& device_path,
                              std::string* vg_name);

  std::shared_ptr<LvmCommandRunner> lvm_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_H_
