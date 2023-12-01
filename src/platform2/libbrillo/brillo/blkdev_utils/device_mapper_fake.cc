// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check_op.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace brillo {
namespace fake {

namespace {

// Stub DmTask runs into a map for easy reference.
bool StubDmRunTask(DmTask* task, bool udev_sync) {
  std::string dev_name = task->name;
  std::string params;
  int type = task->type;
  static auto& dm_target_map_ =
      *new std::unordered_map<std::string, std::vector<DmTarget>>();

  switch (type) {
    case DM_DEVICE_CREATE:
      CHECK_EQ(udev_sync, true);
      if (dm_target_map_.find(dev_name) != dm_target_map_.end())
        return false;
      dm_target_map_.insert(std::make_pair(dev_name, task->targets));
      break;
    case DM_DEVICE_REMOVE:
      CHECK_EQ(udev_sync, true);
      if (dm_target_map_.find(dev_name) == dm_target_map_.end())
        return false;
      dm_target_map_.erase(dev_name);
      break;
    case DM_DEVICE_TABLE:
      CHECK_EQ(udev_sync, false);
      if (dm_target_map_.find(dev_name) == dm_target_map_.end())
        return false;
      task->targets = dm_target_map_[dev_name];
      break;
    case DM_DEVICE_RELOAD:
      CHECK_EQ(udev_sync, false);
      if (dm_target_map_.find(dev_name) == dm_target_map_.end())
        return false;
      dm_target_map_.erase(dev_name);
      dm_target_map_.insert(std::make_pair(dev_name, task->targets));
      break;
    default:
      return false;
  }
  return true;
}

std::unique_ptr<DmTask> DmTaskCreate(int type) {
  auto t = std::make_unique<DmTask>();
  t->type = type;
  t->deferred = false;
  return t;
}

}  // namespace

FakeDevmapperTask::FakeDevmapperTask(int type) : task_(DmTaskCreate(type)) {}

bool FakeDevmapperTask::SetName(const std::string& name) {
  task_->name = std::string(name);
  return true;
}

bool FakeDevmapperTask::AddTarget(uint64_t start,
                                  uint64_t sectors,
                                  const std::string& type,
                                  const SecureBlob& parameters) {
  DmTarget dmt;
  dmt.start = start;
  dmt.size = sectors;
  dmt.type = type;
  dmt.parameters = parameters;
  task_->targets.push_back(dmt);
  return true;
}

bool FakeDevmapperTask::GetNextTarget(uint64_t* start,
                                      uint64_t* sectors,
                                      std::string* type,
                                      SecureBlob* parameters) {
  if (task_->targets.empty())
    return false;

  DmTarget dmt = task_->targets[0];
  *start = dmt.start;
  *sectors = dmt.size;
  *type = dmt.type;
  *parameters = dmt.parameters;
  task_->targets.erase(task_->targets.begin());

  return !task_->targets.empty();
}

bool FakeDevmapperTask::Run(bool udev_sync) {
  return StubDmRunTask(task_.get(), udev_sync);
}

bool FakeDevmapperTask::SetDeferredRemove() {
  // Make sure that deferred remove is only set for remove tasks.
  if (task_->type != DM_DEVICE_REMOVE)
    return false;

  task_->deferred = true;
  return true;
}

std::unique_ptr<DevmapperTask> CreateDevmapperTask(int type) {
  return std::make_unique<FakeDevmapperTask>(type);
}

DeviceMapperVersion FakeDevmapperTask::GetVersion() {
  DeviceMapperVersion version({1, 21, 0});
  return version;
}

}  // namespace fake
}  // namespace brillo
