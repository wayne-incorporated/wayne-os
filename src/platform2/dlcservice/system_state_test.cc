// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "dlcservice/boot/boot_slot.h"
#include "dlcservice/system_state.h"
#include "dlcservice/test_utils.h"

using testing::_;
using testing::Return;

namespace dlcservice {

class SystemStateTest : public BaseTest {
  void SetUp() override {
    ON_CALL(*mock_boot_slot_ptr_, GetSlot())
        .WillByDefault(Return(BootSlotInterface::Slot::B));
    ON_CALL(*mock_boot_slot_ptr_, IsDeviceRemovable())
        .WillByDefault(Return(false));
    BaseTest::SetUp();
  }
};

TEST_F(SystemStateTest, GettersTest) {
  auto* system_state = SystemState::Get();
  const auto temp_path = scoped_temp_dir_.GetPath();

  EXPECT_EQ(system_state->manifest_dir(), temp_path.Append("rootfs"));
  EXPECT_EQ(system_state->preloaded_content_dir(),
            temp_path.Append("preloaded_stateful"));
  EXPECT_EQ(system_state->content_dir(), temp_path.Append("stateful"));
  EXPECT_EQ(system_state->prefs_dir(), temp_path.Append("var_lib_dlcservice"));
  EXPECT_EQ(system_state->dlc_prefs_dir(),
            temp_path.Append("var_lib_dlcservice").Append("dlc"));
  EXPECT_EQ(system_state->active_boot_slot(), BootSlotInterface::Slot::B);
  EXPECT_EQ(system_state->inactive_boot_slot(), BootSlotInterface::Slot::A);
  EXPECT_EQ(system_state->users_dir(), temp_path.Append("users"));
  EXPECT_FALSE(system_state->IsDeviceRemovable());

  EXPECT_EQ(system_state->clock(), &clock_);

  update_engine::StatusResult status;
  status.set_current_operation(update_engine::Operation::DOWNLOADING);
  system_state->set_update_engine_status(status);
  EXPECT_EQ(system_state->update_engine_status().current_operation(),
            update_engine::Operation::DOWNLOADING);
}

#if USE_LVM_STATEFUL_PARTITION
TEST_F(SystemStateTest, IsLvmStackEnabled) {
  auto* ptr = SystemState::Get();

  ptr->ResetIsLvmStackEnabled();

  EXPECT_CALL(*mock_lvmd_proxy_wrapper_ptr_, GetPhysicalVolume(_, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(ptr->IsLvmStackEnabled());

  // Call to test caching.
  EXPECT_TRUE(ptr->IsLvmStackEnabled());
}
#endif  // USE_LVM_STATEFUL_PARTITION

}  // namespace dlcservice
