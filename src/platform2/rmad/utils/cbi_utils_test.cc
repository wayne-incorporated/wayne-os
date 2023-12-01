// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cbi_utils_impl.h"

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/utils/mock_cmd_utils.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace {

constexpr char kGetIntSuccessOutput[] = R"(
As uint: 1234 (0x4d2)
As binary: d2 04
)";
constexpr char kGetStrSuccessOutput[] = "part_num";
constexpr char kRandomOutput[] = "*[)^";

}  // namespace

namespace rmad {

class CbiUtilsTest : public testing::Test {
 public:
  CbiUtilsTest() = default;
  ~CbiUtilsTest() override = default;
};

TEST_F(CbiUtilsTest, GetSkuId_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kGetIntSuccessOutput), Return(true)));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  uint64_t sku_id;
  EXPECT_TRUE(cbi_utils->GetSkuId(&sku_id));
  EXPECT_EQ(sku_id, 1234);
}

TEST_F(CbiUtilsTest, GetSkuId_Success_ParseFail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kRandomOutput), Return(true)));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  uint64_t sku_id;
  EXPECT_FALSE(cbi_utils->GetSkuId(&sku_id));
}

TEST_F(CbiUtilsTest, GetSkuId_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  uint64_t sku_id;
  EXPECT_FALSE(cbi_utils->GetSkuId(&sku_id));
}

TEST_F(CbiUtilsTest, GetSkuId_Nullptr) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_DEATH(cbi_utils->GetSkuId(nullptr), "");
}

TEST_F(CbiUtilsTest, GetDramPartNum_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kGetStrSuccessOutput), Return(true)));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  std::string part_num;
  EXPECT_TRUE(cbi_utils->GetDramPartNum(&part_num));
  EXPECT_EQ(part_num, "part_num");
}

TEST_F(CbiUtilsTest, GetDramPartNum_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  std::string part_num;
  EXPECT_FALSE(cbi_utils->GetDramPartNum(&part_num));
}

TEST_F(CbiUtilsTest, GetDramPartNum_Nullptr) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_DEATH(cbi_utils->GetDramPartNum(nullptr), "");
}

TEST_F(CbiUtilsTest, SetSkuId_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cbi_utils->SetSkuId(1));
}

TEST_F(CbiUtilsTest, SetSkuId_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cbi_utils->SetSkuId(123));
}

TEST_F(CbiUtilsTest, SetDramPartNum_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cbi_utils->SetDramPartNum("part_num"));
}

TEST_F(CbiUtilsTest, SetDramPartNum_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cbi_utils = std::make_unique<CbiUtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cbi_utils->SetDramPartNum("part_num"));
}

}  // namespace rmad
