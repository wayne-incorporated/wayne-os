// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_BLKDEV_UTILS_MOCK_LVM_H_
#define LIBBRILLO_BRILLO_BLKDEV_UTILS_MOCK_LVM_H_

#include <brillo/process/process_mock.h>
#include <gmock/gmock.h>

#include "brillo/blkdev_utils/lvm.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

using testing::_;
using testing::Return;
using testing::SetArgPointee;
using testing::WithArg;

namespace brillo {

class MockLvmCommandRunner : public LvmCommandRunner {
 public:
  MockLvmCommandRunner() : LvmCommandRunner() {
    ON_CALL(*this, RunCommand(_)).WillByDefault(Return(true));
    ON_CALL(*this, RunProcess(_, _)).WillByDefault(Return(true));
  }

  virtual ~MockLvmCommandRunner() {}

  MOCK_METHOD(bool, RunCommand, (const std::vector<std::string>&), (override));
  MOCK_METHOD(bool,
              RunProcess,
              (const std::vector<std::string>&, std::string*),
              (override));
};

class MockLogicalVolumeManager : public LogicalVolumeManager {
 public:
  MockLogicalVolumeManager()
      : LogicalVolumeManager(std::make_shared<MockLvmCommandRunner>()) {}
  virtual ~MockLogicalVolumeManager() {}

  MOCK_METHOD(std::optional<PhysicalVolume>,
              GetPhysicalVolume,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(std::optional<VolumeGroup>,
              GetVolumeGroup,
              (const PhysicalVolume&),
              (override));
  MOCK_METHOD(std::optional<Thinpool>,
              GetThinpool,
              (const VolumeGroup&, const std::string&),
              (override));
  MOCK_METHOD(std::optional<LogicalVolume>,
              GetLogicalVolume,
              (const VolumeGroup&, const std::string&),
              (override));
  MOCK_METHOD(std::vector<LogicalVolume>,
              ListLogicalVolumes,
              (const VolumeGroup&, const std::string&),
              (override));

  MOCK_METHOD(std::optional<PhysicalVolume>,
              CreatePhysicalVolume,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(std::optional<VolumeGroup>,
              CreateVolumeGroup,
              (const PhysicalVolume&, const std::string&),
              (override));
  MOCK_METHOD(std::optional<Thinpool>,
              CreateThinpool,
              (const VolumeGroup&, const base::Value&),
              (override));
  MOCK_METHOD(std::optional<LogicalVolume>,
              CreateLogicalVolume,
              (const VolumeGroup&, const Thinpool&, const base::Value::Dict&),
              (override));
  MOCK_METHOD(bool,
              RemoveLogicalVolume,
              (const VolumeGroup&, const std::string&),
              (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_BLKDEV_UTILS_MOCK_LVM_H_
