// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_BOOT_BOOT_SLOT_H_
#define DLCSERVICE_BOOT_BOOT_SLOT_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace dlcservice {

class BootDeviceInterface;

class BootSlotInterface {
 public:
  enum class Slot : int {
    A = 0,
    B = 1,
  };

  virtual ~BootSlotInterface() = default;

  // Initialize boot slot state.
  virtual bool Init() = 0;

  // Returns true if boot device is removable.
  virtual bool IsDeviceRemovable() = 0;

  // Returns the boot device name.
  virtual std::string GetDeviceName() = 0;

  // Returns the boot slot.
  virtual Slot GetSlot() = 0;

  // Returns the device path to stateful partition.
  virtual base::FilePath GetStatefulPartitionPath() = 0;
};

class BootSlot : public BootSlotInterface {
 public:
  explicit BootSlot(std::unique_ptr<BootDeviceInterface> boot_device);
  ~BootSlot() override = default;

  BootSlot(const BootSlot&) = delete;
  BootSlot& operator=(const BootSlot&) = delete;

  // `BootSlotInterface` overrides.
  bool Init() override;
  bool IsDeviceRemovable() override;
  std::string GetDeviceName() override;
  Slot GetSlot() override;
  base::FilePath GetStatefulPartitionPath() override;

  // Returns the string representation of |Slot|.
  static std::string ToString(Slot slot);

 private:
  std::unique_ptr<BootDeviceInterface> boot_device_;
  base::FilePath device_path_;
  std::string device_name_;
  int partition_num_ = 0;
  Slot slot_;
  bool is_removable_;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_BOOT_BOOT_SLOT_H_
