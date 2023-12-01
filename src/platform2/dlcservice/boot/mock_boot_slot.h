// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_BOOT_MOCK_BOOT_SLOT_H_
#define DLCSERVICE_BOOT_MOCK_BOOT_SLOT_H_

#include "dlcservice/boot/boot_slot.h"

#include <string>

#include <base/files/file_path.h>

namespace dlcservice {

class MockBootSlot : public BootSlotInterface {
 public:
  MockBootSlot() = default;
  MockBootSlot(const MockBootSlot&) = delete;
  MockBootSlot& operator=(const MockBootSlot&) = delete;

  MOCK_METHOD(bool, Init, (), (override));
  MOCK_METHOD(bool, IsDeviceRemovable, (), (override));
  MOCK_METHOD(std::string, GetDeviceName, (), (override));
  MOCK_METHOD(BootSlotInterface::Slot, GetSlot, (), (override));
  MOCK_METHOD(base::FilePath, GetStatefulPartitionPath, (), (override));
};

}  // namespace dlcservice

#endif  // DLCSERVICE_BOOT_MOCK_BOOT_SLOT_H_
