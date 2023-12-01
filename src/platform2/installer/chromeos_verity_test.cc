// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/chromeos_verity.h"

#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <verity/mock-dm-bht.h>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace verity {

class ChromeOSVerityTest : public ::testing::Test {
 public:
  void SetUp() override { CHECK(scoped_temp_dir_.CreateUniqueTempDir()); }

 protected:
  base::ScopedTempDir scoped_temp_dir_;
  NiceMock<verity::MockDmBht> mock_bht_;
};

TEST_F(ChromeOSVerityTest, VerityTest) {
  base::FilePath device = scoped_temp_dir_.GetPath().Append("device");

  // Create device bits.
  constexpr int kBlockSize = PAGE_SIZE / 8;
  constexpr int kNumBlocks = 1;
  std::vector<char> buf(kBlockSize * kNumBlocks);

  EXPECT_CALL(mock_bht_, Sectors()).WillOnce(Return(1));
  EXPECT_CALL(mock_bht_, StoreBlock(_, _)).Times(1);

  brillo::WriteToFile(device, buf.data(), buf.size());
  EXPECT_EQ(0, chromeos_verity(&mock_bht_,
                               /*alg=*/"",
                               /*device=*/device,
                               /*blocksize=*/kBlockSize,
                               /*fs_blocks=*/kNumBlocks,
                               /*salt=*/"",
                               /*expected=*/"",
                               /*enforce_rootfs_verification=*/false));
}

TEST_F(ChromeOSVerityTest, VerityMultiplePageTest) {
  base::FilePath device = scoped_temp_dir_.GetPath().Append("device");

  // Create device bits.
  constexpr int kBlockSize = PAGE_SIZE / 8;
  constexpr int kNumBlocks = 1024;
  std::vector<char> buf(kBlockSize * kNumBlocks);

  EXPECT_CALL(mock_bht_, Sectors()).WillOnce(Return(1));
  EXPECT_CALL(mock_bht_, StoreBlock(_, _)).Times(kNumBlocks);

  brillo::WriteToFile(device, buf.data(), buf.size());
  EXPECT_EQ(0, chromeos_verity(&mock_bht_,
                               /*alg=*/"",
                               /*device=*/device,
                               /*blocksize=*/kBlockSize,
                               /*fs_blocks=*/kNumBlocks,
                               /*salt=*/"",
                               /*expected=*/"",
                               /*enforce_rootfs_verification=*/false));
}

}  // namespace verity
