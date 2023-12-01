// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/lvm/lvmd_proxy_wrapper.h"

#include <memory>
#include <utility>
#include <vector>

#include "dlcservice/system_state.h"

// TODO(b/254557435): Reduce the # of calls made into lvmd.
namespace dlcservice {
namespace {

// CrOS currently only uses "thinpool" as thinpool name.
constexpr char kThinpoolName[] = "thinpool";

}  // namespace

LvmdProxyWrapper::LvmdProxyWrapper(
    std::unique_ptr<org::chromium::LvmdProxyInterface> lvmd_proxy)
    : lvmd_proxy_(std::move(lvmd_proxy)) {}

bool LvmdProxyWrapper::GetPhysicalVolume(const std::string& device_path,
                                         lvmd::PhysicalVolume* pv) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->GetPhysicalVolume(device_path, pv, &err)) {
    LOG(WARNING) << "Failed to GetPhysicalVolume from lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::GetVolumeGroup(const lvmd::PhysicalVolume& pv,
                                      lvmd::VolumeGroup* vg) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->GetVolumeGroup(pv, vg, &err)) {
    LOG(WARNING) << "Failed to GetVolumeGroup from lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::GetThinpool(const lvmd::VolumeGroup& vg,
                                   lvmd::Thinpool* thinpool) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->GetThinpool(vg, kThinpoolName, thinpool, &err)) {
    LOG(WARNING) << "Failed to GetThinpool from lvmd: " << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::GetLogicalVolume(const lvmd::VolumeGroup& vg,
                                        const std::string& lv_name,
                                        lvmd::LogicalVolume* lv) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->GetLogicalVolume(vg, lv_name, lv, &err)) {
    LOG(WARNING) << "Failed to GetLogicalVolume from lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::GetLogicalVolume(const std::string& lv_name,
                                        lvmd::LogicalVolume* lv) {
  auto stateful_path =
      SystemState::Get()->boot_slot()->GetStatefulPartitionPath();

  if (stateful_path.empty()) {
    LOG(ERROR) << "Failed to GetStatefulPartitionPath.";
    return false;
  }

  lvmd::PhysicalVolume pv;
  if (!GetPhysicalVolume(stateful_path.value(), &pv)) {
    LOG(ERROR) << "Failed to GetPhysicalVolume.";
    return false;
  }

  lvmd::VolumeGroup vg;
  if (!GetVolumeGroup(pv, &vg)) {
    LOG(ERROR) << "Failed to GetVolumeGroup.";
    return false;
  }

  brillo::ErrorPtr err;
  if (!lvmd_proxy_->GetLogicalVolume(vg, lv_name, lv, &err)) {
    LOG(ERROR) << "Failed to GetLogicalVolume.";
    return false;
  }

  return true;
}

bool LvmdProxyWrapper::CreateLogicalVolume(
    const lvmd::Thinpool& thinpool,
    const lvmd::LogicalVolumeConfiguration& lv_config,
    lvmd::LogicalVolume* lv) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->CreateLogicalVolume(thinpool, lv_config, lv, &err)) {
    LOG(WARNING) << "Failed to CreateLogicalVolume in lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::RemoveLogicalVolume(const lvmd::LogicalVolume& lv) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->RemoveLogicalVolume(lv, &err)) {
    LOG(WARNING) << "Failed to CreateLogicalVolume in lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::ToggleLogicalVolumeActivation(
    const lvmd::LogicalVolume& lv, bool activate) {
  brillo::ErrorPtr err;
  if (!lvmd_proxy_->ToggleLogicalVolumeActivation(lv, activate, &err)) {
    LOG(WARNING) << "Failed to ToggleLogicalVolumeActivation in lvmd: "
                 << Error::ToString(err);
    return false;
  }
  return true;
}

bool LvmdProxyWrapper::CreateLogicalVolumes(
    const std::vector<lvmd::LogicalVolumeConfiguration>& lv_configs) {
  auto stateful_path =
      SystemState::Get()->boot_slot()->GetStatefulPartitionPath();

  if (stateful_path.empty()) {
    LOG(ERROR) << "Failed to GetStatefulPartitionPath.";
    return false;
  }

  lvmd::PhysicalVolume pv;
  if (!GetPhysicalVolume(stateful_path.value(), &pv)) {
    LOG(ERROR) << "Failed to GetPhysicalVolume.";
    return false;
  }

  lvmd::VolumeGroup vg;
  if (!GetVolumeGroup(pv, &vg)) {
    LOG(ERROR) << "Failed to GetVolumeGroup.";
    return false;
  }

  lvmd::Thinpool thinpool;
  if (!GetThinpool(vg, &thinpool)) {
    LOG(ERROR) << "Failed to GetThinpool.";
    return false;
  }

  // Prefer using thinpool's volume group as thinpool is passed into creating
  // the logical volumes.
  lvmd::LogicalVolume lv;
  for (const auto& lv_config : lv_configs) {
    auto lv_name = lv_config.name();
    if (GetLogicalVolume(thinpool.volume_group(), lv_name, &lv)) {
      if (!ToggleLogicalVolumeActivation(lv, /*activate=*/true)) {
        LOG(ERROR) << "Failed to ToggleLogicalVolumeActivation name="
                   << lv_name;
        return false;
      }
    } else if (SystemState::Get()->resuming_from_hibernate()) {
      LOG(ERROR) << "Failed to CreateLogicalVolume "
                    "during resume from hibernate, name="
                 << lv_name;
      return false;

    } else if (!CreateLogicalVolume(thinpool, lv_config, &lv)) {
      LOG(ERROR) << "Failed to CreateLogicalVolume name=" << lv_name;
      return false;
    }
  }
  // TODO(b/254373821): Unsparse the logical volumes.
  return true;
}

bool LvmdProxyWrapper::RemoveLogicalVolumes(
    const std::vector<std::string>& lv_names) {
  auto stateful_path =
      SystemState::Get()->boot_slot()->GetStatefulPartitionPath();

  lvmd::PhysicalVolume pv;
  if (!GetPhysicalVolume(stateful_path.value(), &pv)) {
    LOG(ERROR) << "Failed to GetPhysicalVolume.";
    return false;
  }

  lvmd::VolumeGroup vg;
  if (!GetVolumeGroup(pv, &vg)) {
    LOG(ERROR) << "Failed to GetVolumeGroup.";
    return false;
  }

  bool ret = true;
  lvmd::LogicalVolume lv;
  for (const auto& lv_name : lv_names) {
    if (!GetLogicalVolume(vg, lv_name, &lv)) {
      LOG(WARNING) << "Failed to GetLogicalVolume name=" << lv_name;
      continue;
    }
    if (!RemoveLogicalVolume(lv)) {
      LOG(ERROR) << "Failed to RemoveLogicalVolume name=" << lv_name;
      ret = false;
    }
  }
  return ret;
}

bool LvmdProxyWrapper::ActivateLogicalVolume(const std::string& lv_name) {
  auto stateful_path =
      SystemState::Get()->boot_slot()->GetStatefulPartitionPath();

  lvmd::PhysicalVolume pv;
  if (!GetPhysicalVolume(stateful_path.value(), &pv)) {
    LOG(ERROR) << "Failed to GetPhysicalVolume.";
    return false;
  }

  lvmd::VolumeGroup vg;
  if (!GetVolumeGroup(pv, &vg)) {
    LOG(ERROR) << "Failed to GetVolumeGroup.";
    return false;
  }

  lvmd::LogicalVolume lv;
  if (!GetLogicalVolume(vg, lv_name, &lv)) {
    LOG(ERROR) << "Failed to GetLogicalVolume.";
    return false;
  }

  if (!ToggleLogicalVolumeActivation(lv, /*activate=*/true)) {
    LOG(ERROR) << "Failed to ToggleLogicalVolumeActivation from lvmd.";
    return false;
  }
  return true;
}

std::string LvmdProxyWrapper::GetLogicalVolumePath(const std::string& lv_name) {
  lvmd::LogicalVolume lv;
  return GetLogicalVolume(lv_name, &lv) ? lv.path() : "";
}

}  // namespace dlcservice
