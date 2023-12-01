// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_DEVICE_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_DEVICE_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>
#include <brillo/brillo_export.h>

namespace brillo {
// LvmCommandRunner acts as an abstract interface to run LVM2 commands.
class BRILLO_EXPORT LvmCommandRunner {
 public:
  LvmCommandRunner();
  virtual ~LvmCommandRunner();

  // Run the command using liblvm2cmd: the command looks the same as what
  // would be run on the command line but saves the step of creating and
  // launching an extra process.
  virtual bool RunCommand(const std::vector<std::string>& cmd);
  // thin-provisioning tools are not packaged as a part of lvm2cmd. Use a
  // process runner instead. Additionally, instead of overloading the
  // lvm2_log_fn to access the output of a command, we prefer to use a process.
  virtual bool RunProcess(const std::vector<std::string>& cmd,
                          std::string* output = nullptr);

  // Unwraps LVM2 JSON reports into the contents stored at |key|.
  virtual std::optional<base::Value> UnwrapReportContents(
      const std::string& output, const std::string& key);
};

// LVM objects are short-lived objects that represent the state of the system
// at the time of query: it is expected that users will create a new PV/VG/LV
// object, use it to perform housekeeping operations and then destroy the object
// instead of persistent storage for these objects.
class BRILLO_EXPORT PhysicalVolume {
 public:
  PhysicalVolume(const base::FilePath& device_path,
                 std::shared_ptr<LvmCommandRunner> lvm);
  ~PhysicalVolume() = default;

  bool Check();
  bool Repair();
  bool Remove();
  base::FilePath GetPath() const { return device_path_; }
  bool IsValid() { return device_path_ != base::FilePath(); }

 private:
  base::FilePath device_path_;
  std::shared_ptr<LvmCommandRunner> lvm_;
};

class BRILLO_EXPORT VolumeGroup {
 public:
  VolumeGroup(const std::string& volume_group_name,
              std::shared_ptr<LvmCommandRunner> lvm);
  ~VolumeGroup() = default;
  bool Activate();
  bool Check();
  bool Repair();
  bool Deactivate();
  bool Remove();
  bool Rename(const std::string& volume_group_name);
  std::string GetName() const { return volume_group_name_; }
  bool IsValid() { return !volume_group_name_.empty(); }
  base::FilePath GetPath() const;

 private:
  std::string volume_group_name_;
  std::shared_ptr<LvmCommandRunner> lvm_;
};

class BRILLO_EXPORT Thinpool {
 public:
  Thinpool(const std::string& thinpool_name,
           const std::string& volume_group_name,
           std::shared_ptr<LvmCommandRunner> lvm_);
  ~Thinpool() = default;
  bool Activate();
  bool Check();
  bool Repair();
  bool Deactivate();
  std::string GetName() const {
    return thinpool_name_.empty() ? ""
                                  : volume_group_name_ + "/" + thinpool_name_;
  }
  std::string GetRawName() const { return thinpool_name_; }
  std::string GetVolumeGroupName() const { return volume_group_name_; }
  bool IsValid() { return !thinpool_name_.empty(); }
  bool Remove();
  bool GetTotalSpace(int64_t* size);
  bool GetFreeSpace(int64_t* size);

 private:
  std::string thinpool_name_;
  std::string volume_group_name_;
  std::shared_ptr<LvmCommandRunner> lvm_;
};

class BRILLO_EXPORT LogicalVolume {
 public:
  LogicalVolume(const std::string& logical_volume_name,
                const std::string& volume_group_name,
                std::shared_ptr<LvmCommandRunner> lvm);
  ~LogicalVolume() = default;
  bool Activate();
  bool Deactivate();
  bool Remove();
  bool IsValid() { return !logical_volume_name_.empty(); }
  base::FilePath GetPath();
  std::string GetName() const {
    return logical_volume_name_.empty()
               ? ""
               : volume_group_name_ + "/" + logical_volume_name_;
  }
  std::string GetRawName() const { return logical_volume_name_; }
  std::string GetVolumeGroupName() { return volume_group_name_; }

 private:
  std::string logical_volume_name_;
  std::string volume_group_name_;
  std::shared_ptr<LvmCommandRunner> lvm_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_LVM_DEVICE_H_
