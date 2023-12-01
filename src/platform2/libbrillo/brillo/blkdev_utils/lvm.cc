// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// There are several methods to use lvm2 constructs from C or C++ code:
// - liblvm2app (deprecated) is a natural interface to creating and using
//   lvm2 construct objects and performing operations on them. However, the
//   deprecation of this library renders its use a non-starter.
// - executing the command line utilities directly.
// - liblvm2cmd provides an interface to run lvm2 commands without the
//   indirection of another process execution. While this is faster, the output
//   collection mechanism for liblvm2cmd relies on overriding the logging
//   function.
// - lvmdbusd is a daemon (written in Python) with a D-Bus interface which
//   exec()s the relevant commands. However, this library is additionally
//   intended to be used in situations where D-Bus may or may not be running.
//
// To strike a balance between speed and usability, the following class uses
// liblvm2cmd for commands without output (eg. pvcreate, vgcreate ...) and
// uses a process invocation for the rest.

#include "brillo/blkdev_utils/lvm.h"

#include <optional>

#include <base/logging.h>
#include <base/strings/pattern.h>

namespace brillo {

LogicalVolumeManager::LogicalVolumeManager()
    : LogicalVolumeManager(std::make_shared<LvmCommandRunner>()) {}

LogicalVolumeManager::LogicalVolumeManager(
    std::shared_ptr<LvmCommandRunner> lvm)
    : lvm_(lvm) {}

bool LogicalVolumeManager::ValidatePhysicalVolume(
    const base::FilePath& device_path, std::string* volume_group_name) {
  std::string output;

  if (!lvm_->RunProcess(
          {"/sbin/pvs", "--reportformat", "json", device_path.value()},
          &output)) {
    LOG(ERROR) << "Failed to get output from pvs";
    return false;
  }

  std::optional<base::Value> pv_value =
      lvm_->UnwrapReportContents(output, "pv");

  if (!pv_value || !pv_value->is_dict()) {
    LOG(ERROR) << "Failed to get report contents";
    return false;
  }
  const auto& pv_dictionary = pv_value->GetDict();

  const std::string* pv_name = pv_dictionary.FindString("pv_name");
  if (!pv_name) {
    LOG(ERROR) << "Missing value \"pv_name\".";
    return false;
  } else if (*pv_name != device_path.value()) {
    LOG(ERROR) << "Mismatched value: expected: " << device_path
               << " actual: " << *pv_name;
    return false;
  }

  if (volume_group_name) {
    const std::string* vg_name = pv_dictionary.FindString("vg_name");
    if (!vg_name) {
      LOG(ERROR) << "Failed to fetch volume group name";
      return false;
    }
    *volume_group_name = *vg_name;
  }

  return true;
}

std::optional<PhysicalVolume> LogicalVolumeManager::GetPhysicalVolume(
    const base::FilePath& device_path) {
  return ValidatePhysicalVolume(device_path, nullptr)
             ? std::make_optional(PhysicalVolume(device_path, lvm_))
             : std::nullopt;
}

std::optional<VolumeGroup> LogicalVolumeManager::GetVolumeGroup(
    const PhysicalVolume& pv) {
  std::string vg_name;
  return ValidatePhysicalVolume(pv.GetPath(), &vg_name)
             ? std::make_optional(VolumeGroup(vg_name, lvm_))
             : std::nullopt;
}

bool LogicalVolumeManager::ValidateLogicalVolume(const VolumeGroup& vg,
                                                 const std::string& lv_name,
                                                 bool is_thinpool) {
  std::string output;
  const std::string vg_name = vg.GetName();

  std::string pool_lv_check = is_thinpool ? "pool_lv=\"\"" : "pool_lv!=\"\"";

  if (!lvm_->RunProcess({"/sbin/lvs", "-S", pool_lv_check, "--reportformat",
                         "json", vg_name + "/" + lv_name},
                        &output)) {
    LOG(ERROR) << "Failed to get output from lvs";
    return false;
  }

  std::optional<base::Value> lv_value =
      lvm_->UnwrapReportContents(output, "lv");

  if (!lv_value || !lv_value->is_dict()) {
    LOG(ERROR) << "Failed to get report contents";
    return false;
  }
  const auto& lv_dictionary = lv_value->GetDict();

  const std::string* output_lv_name = lv_dictionary.FindString("lv_name");
  if (!output_lv_name) {
    LOG(ERROR) << "Missing value \"lv_name\".";
    return false;
  } else if (*output_lv_name != lv_name) {
    LOG(ERROR) << "Mismatched value: expected: " << lv_name
               << " actual: " << *output_lv_name;
    return false;
  }

  return true;
}

std::optional<Thinpool> LogicalVolumeManager::GetThinpool(
    const VolumeGroup& vg, const std::string& thinpool_name) {
  return ValidateLogicalVolume(vg, thinpool_name, true /* is_thinpool */)
             ? std::make_optional(Thinpool(thinpool_name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::optional<LogicalVolume> LogicalVolumeManager::GetLogicalVolume(
    const VolumeGroup& vg, const std::string& lv_name) {
  return ValidateLogicalVolume(vg, lv_name, false /* is_thinpool */)
             ? std::make_optional(LogicalVolume(lv_name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::vector<LogicalVolume> LogicalVolumeManager::ListLogicalVolumes(
    const VolumeGroup& vg, const std::string& pattern) {
  std::string output;
  std::string vg_name = vg.GetName();
  std::vector<LogicalVolume> lv_vector;

  if (!lvm_->RunProcess({"/sbin/lvs", "-S", "pool_lv!=\"\"", "--reportformat",
                         "json", vg_name},
                        &output)) {
    LOG(ERROR) << "Failed to get output from lvs";
    return lv_vector;
  }

  std::optional<base::Value> lv_list = lvm_->UnwrapReportContents(output, "lv");
  if (!lv_list || !lv_list->is_list()) {
    LOG(ERROR) << "Failed to get report contents";
    return lv_vector;
  }

  for (const auto& lv_value : lv_list->GetList()) {
    if (!lv_value.is_dict()) {
      LOG(ERROR) << "Failed to get dictionary value for physical volume";
      continue;
    }
    const auto& lv_dictionary = lv_value.GetDict();

    const std::string* output_lv_name = lv_dictionary.FindString("lv_name");
    if (!output_lv_name) {
      LOG(ERROR) << "Failed to get logical volume name";
      continue;
    }

    if (!pattern.empty() && !base::MatchPattern(*output_lv_name, pattern)) {
      LOG(INFO) << "Logical volume=" << *output_lv_name
                << " does not match pattern=" << pattern;
      continue;
    }

    lv_vector.push_back(LogicalVolume(*output_lv_name, vg_name, lvm_));
  }

  return lv_vector;
}

std::optional<PhysicalVolume> LogicalVolumeManager::CreatePhysicalVolume(
    const base::FilePath& device_path) {
  return lvm_->RunCommand({"pvcreate", "-ff", "--yes", device_path.value()})
             ? std::make_optional(PhysicalVolume(device_path, lvm_))
             : std::nullopt;
}

std::optional<VolumeGroup> LogicalVolumeManager::CreateVolumeGroup(
    const PhysicalVolume& pv, const std::string& vg_name) {
  return lvm_->RunCommand(
             {"vgcreate", "-p", "1", vg_name, pv.GetPath().value()})
             ? std::make_optional(VolumeGroup(vg_name, lvm_))
             : std::nullopt;
}

std::optional<Thinpool> LogicalVolumeManager::CreateThinpool(
    const VolumeGroup& vg, const base::Value& config) {
  if (!config.is_dict()) {
    LOG(ERROR) << "Invalid configuration";
    return std::nullopt;
  }
  const auto& config_dict = config.GetDict();

  std::vector<std::string> cmd = {"lvcreate"};
  const std::string* size = config_dict.FindString("size");
  const std::string* metadata_size = config_dict.FindString("metadata_size");
  const std::string* name = config_dict.FindString("name");
  if (!size || !name || !metadata_size) {
    LOG(ERROR) << "Invalid configuration";
    return std::nullopt;
  }

  cmd.insert(cmd.end(),
             {"--zero", "n", "--size", *size + "M", "--poolmetadatasize",
              *metadata_size + "M", "--thinpool", *name, vg.GetName()});

  return lvm_->RunCommand(cmd)
             ? std::make_optional(Thinpool(*name, vg.GetName(), lvm_))
             : std::nullopt;
}

std::optional<LogicalVolume> LogicalVolumeManager::CreateLogicalVolume(
    const VolumeGroup& vg,
    const Thinpool& thinpool,
    const base::Value::Dict& config) {
  std::vector<std::string> cmd = {"lvcreate", "--thin"};
  const std::string* size = config.FindString("size");
  const std::string* name = config.FindString("name");
  if (!size || !name) {
    LOG(ERROR) << "Invalid configuration";
    return std::nullopt;
  }

  cmd.insert(cmd.end(), {"-V", *size + "M", "-n", *name, thinpool.GetName()});

  return lvm_->RunCommand(cmd)
             ? std::make_optional(LogicalVolume(*name, vg.GetName(), lvm_))
             : std::nullopt;
}

bool LogicalVolumeManager::RemoveLogicalVolume(const VolumeGroup& vg,
                                               const std::string& lv_name) {
  std::optional<LogicalVolume> lv = GetLogicalVolume(vg, lv_name);

  if (!lv || !lv->IsValid()) {
    LOG(WARNING) << "Logical volume " << lv_name << " does not exist.";
    return true;
  }

  bool ret = lv->Remove();
  if (!ret) {
    LOG(ERROR) << "Failed to remove logical volume.";
  }

  return ret;
}

}  // namespace brillo
