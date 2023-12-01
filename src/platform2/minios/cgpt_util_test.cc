// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "minios/cgpt_util.h"
#include "minios/mock_cgpt_wrapper.h"

namespace minios {
using ::testing::_;
using ::testing::DoAll;
using ::testing::Optional;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SaveArgPointee;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

class CgptTest : public ::testing::Test {
 protected:
  void SetUp() override {
    cgpt_wrapper_ = std::make_shared<StrictMock<MockCgptWrapper>>();
    cgpt_util_ = std::make_unique<CgptUtil>(root_file_path, cgpt_wrapper_);
  }
  base::FilePath root_file_path{"path/to/root"};
  std::unique_ptr<CgptUtil> cgpt_util_;
  std::shared_ptr<StrictMock<MockCgptWrapper>> cgpt_wrapper_;
};

TEST_F(CgptTest, FindPartitionsSuccessfully) {
  // Find is a success iff hits = 1.
  CgptFindParams result_param = {.hits = 1, .match_partnum = 10};
  CgptFindParams received_param;
  const std::string test_label = "test_label";

  EXPECT_CALL(*cgpt_wrapper_, CgptFind(_))
      .WillOnce(DoAll(SaveArgPointee<0>(&received_param),
                      SetArgPointee<0>(result_param)));

  EXPECT_THAT(cgpt_util_->GetPartitionNumber(test_label), Optional(10));
  // Verify we are called with the right params.
  EXPECT_EQ(std::string{received_param.drive_name}, root_file_path.value());
  EXPECT_EQ(std::string{received_param.label}, test_label);
}

TEST_F(CgptTest, FindPartitionsUnsuccessfully) {
  // Verify hits > 1 or < 1 results in a `nullopt`.
  CgptFindParams result_param = {.hits = 2, .match_partnum = 10};
  EXPECT_CALL(*cgpt_wrapper_, CgptFind(_))
      .WillOnce(SetArgPointee<0>(result_param));
  EXPECT_EQ(cgpt_util_->GetPartitionNumber("test_label"), std::nullopt);

  result_param.hits = 0;
  EXPECT_CALL(*cgpt_wrapper_, CgptFind(_))
      .WillOnce(SetArgPointee<0>(result_param));
  EXPECT_EQ(cgpt_util_->GetPartitionNumber("test_label"), std::nullopt);
}

TEST_F(CgptTest, GetSizeSuccessful) {
  CgptAddParams result_param = {.size = 5};
  CgptAddParams received_param;
  const int test_partition = 9;

  // Return ok so that size is forwarded.
  EXPECT_CALL(*cgpt_wrapper_, CgptGetPartitionDetails(_))
      .WillOnce(DoAll(SaveArgPointee<0>(&received_param),
                      SetArgPointee<0>(result_param), Return(CGPT_OK)));
  EXPECT_THAT(cgpt_util_->GetSize(test_partition), Optional(5));
  EXPECT_EQ(std::string{received_param.drive_name}, root_file_path.value());
  EXPECT_EQ(received_param.partition, test_partition);
}

TEST_F(CgptTest, GetSizeUnsuccessful) {
  // CgptGetPartitionDetails returning failure should result in `nullopt`.
  EXPECT_CALL(*cgpt_wrapper_, CgptGetPartitionDetails(_))
      .WillOnce(Return(CGPT_FAILED));
  EXPECT_EQ(cgpt_util_->GetSize(0), std::nullopt);
}

}  // namespace minios
