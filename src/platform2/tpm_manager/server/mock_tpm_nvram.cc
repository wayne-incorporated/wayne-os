// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_tpm_nvram.h"

#include <string>
#include <vector>

namespace tpm_manager {

using testing::_;
using testing::Invoke;
using testing::Return;

MockTpmNvram::MockTpmNvram() {
  ON_CALL(*this, DefineSpace(_, _, _, _, _))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeDefineSpace));
  ON_CALL(*this, DestroySpace(_))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeDestroySpace));
  ON_CALL(*this, WriteSpace(_, _, _))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeWriteSpace));
  ON_CALL(*this, ReadSpace(_, _, _))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeReadSpace));
  ON_CALL(*this, LockSpace(_, _, _, _))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeLockSpace));
  ON_CALL(*this, ListSpaces(_))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeListSpaces));
  ON_CALL(*this, GetSpaceInfo(_, _, _, _, _, _))
      .WillByDefault(Invoke(this, &MockTpmNvram::FakeGetSpaceInfo));
}

MockTpmNvram::~MockTpmNvram() {}

NvramResult MockTpmNvram::FakeDefineSpace(
    uint32_t index,
    size_t size,
    const std::vector<NvramSpaceAttribute>& attributes,
    const std::string& authorization_value,
    NvramSpacePolicy policy) {
  if (size == 0) {
    return NVRAM_RESULT_INVALID_PARAMETER;
  }
  if (nvram_map_.count(index) != 0) {
    return NVRAM_RESULT_SPACE_ALREADY_EXISTS;
  }
  NvSpace ns;
  ns.data.resize(size, '\xff');
  ns.read_locked = false;
  ns.write_locked = false;
  ns.attributes = attributes;
  ns.authorization_value = authorization_value;
  ns.policy = policy;
  nvram_map_[index] = ns;
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeDestroySpace(uint32_t index) {
  if (nvram_map_.count(index) == 0) {
    return NVRAM_RESULT_SPACE_DOES_NOT_EXIST;
  }
  nvram_map_.erase(index);
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeWriteSpace(
    uint32_t index,
    const std::string& data,
    const std::string& authorization_value) {
  if (nvram_map_.count(index) == 0) {
    return NVRAM_RESULT_SPACE_DOES_NOT_EXIST;
  }
  if (nvram_map_[index].authorization_value != authorization_value) {
    return NVRAM_RESULT_ACCESS_DENIED;
  }
  if (nvram_map_[index].write_locked) {
    return NVRAM_RESULT_OPERATION_DISABLED;
  }
  std::string& space_data = nvram_map_[index].data;
  size_t size = space_data.size();
  if (data.size() > size) {
    return NVRAM_RESULT_INVALID_PARAMETER;
  }
  space_data = data;
  space_data.resize(size);
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeReadSpace(
    uint32_t index, std::string* data, const std::string& authorization_value) {
  if (nvram_map_.count(index) == 0) {
    return NVRAM_RESULT_SPACE_DOES_NOT_EXIST;
  }
  if (nvram_map_[index].authorization_value != authorization_value) {
    return NVRAM_RESULT_ACCESS_DENIED;
  }
  if (nvram_map_[index].read_locked) {
    return NVRAM_RESULT_OPERATION_DISABLED;
  }
  *data = nvram_map_[index].data;
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeLockSpace(
    uint32_t index,
    bool lock_read,
    bool lock_write,
    const std::string& authorization_value) {
  if (nvram_map_.count(index) == 0) {
    return NVRAM_RESULT_SPACE_DOES_NOT_EXIST;
  }
  if (nvram_map_[index].authorization_value != authorization_value) {
    return NVRAM_RESULT_ACCESS_DENIED;
  }
  if (lock_read) {
    nvram_map_[index].read_locked = true;
  }
  if (lock_write) {
    nvram_map_[index].write_locked = true;
  }
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeListSpaces(std::vector<uint32_t>* index_list) {
  for (auto iter : nvram_map_) {
    index_list->push_back(iter.first);
  }
  return NVRAM_RESULT_SUCCESS;
}

NvramResult MockTpmNvram::FakeGetSpaceInfo(
    uint32_t index,
    uint32_t* size,
    bool* is_read_locked,
    bool* is_write_locked,
    std::vector<NvramSpaceAttribute>* attributes,
    NvramSpacePolicy* policy) {
  if (nvram_map_.count(index) == 0) {
    return NVRAM_RESULT_SPACE_DOES_NOT_EXIST;
  }
  NvSpace& space = nvram_map_[index];
  *size = static_cast<uint32_t>(space.data.size());
  *is_read_locked = space.read_locked;
  *is_write_locked = space.write_locked;
  *attributes = space.attributes;
  *policy = space.policy;
  return NVRAM_RESULT_SUCCESS;
}

}  // namespace tpm_manager
