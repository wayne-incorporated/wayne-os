// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cr50_utils_impl.h"

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/file_utils.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "rmad/constants.h"
#include "rmad/utils/mock_cmd_utils.h"

using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace {

constexpr char kChallengeCodeResponse[] =
    "CHALLENGE="
    "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH"
    "1111122222333334444455555666667777788888\n";
constexpr char kFactoryModeEnabledResponse[] = R"(
State: Locked
---
---
Capabilities are modified.
)";
constexpr char kFactoryModeDisabledResponse[] = R"(
State: Locked
---
---
Capabilities are default.
)";
constexpr char kGetBoardIdResponse[] = R"(
BID_TYPE=5a5a4352
BID_TYPE_INV=a5a5bcad
BID_FLAGS=00007f80
BID_RLZ=ZZCR
)";
constexpr char kExpectedBoardIdType[] = "5a5a4352";
constexpr char kExpectedBoardIdFlags[] = "00007f80";

}  // namespace

namespace rmad {

class Cr50UtilsTest : public testing::Test {
 public:
  Cr50UtilsTest() = default;
  ~Cr50UtilsTest() override = default;
};

TEST_F(Cr50UtilsTest, GetRsuChallengeCode_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kChallengeCodeResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string challenge_code;
  EXPECT_TRUE(cr50_utils->GetRsuChallengeCode(&challenge_code));
  EXPECT_EQ(challenge_code,
            "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFGGGGGHHHHH"
            "1111122222333334444455555666667777788888");
}

TEST_F(Cr50UtilsTest, GetRsuChallengeCode_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string challenge_code;
  EXPECT_FALSE(cr50_utils->GetRsuChallengeCode(&challenge_code));
}

TEST_F(Cr50UtilsTest, PerformRsu_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->PerformRsu(""));
}

TEST_F(Cr50UtilsTest, PerformRsu_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->PerformRsu(""));
}

TEST_F(Cr50UtilsTest, IsFactoryModeEnabled_Enabled) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFactoryModeEnabledResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->IsFactoryModeEnabled());
}

TEST_F(Cr50UtilsTest, IsFactoryModeEnabled_Disabled) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFactoryModeDisabledResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->IsFactoryModeEnabled());
}

TEST_F(Cr50UtilsTest, IsFactoryModeEnabled_NoResponse) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->IsFactoryModeEnabled());
}

TEST_F(Cr50UtilsTest, EnableFactoryMode_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  {
    InSequence seq;
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(kFactoryModeDisabledResponse),
                        Return(true)));
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  }
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->EnableFactoryMode());
}

TEST_F(Cr50UtilsTest, EnableFactoryMode_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  {
    InSequence seq;
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(kFactoryModeDisabledResponse),
                        Return(true)));
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  }
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->EnableFactoryMode());
}

TEST_F(Cr50UtilsTest, EnableFactoryMode_AlreadyEnabled) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFactoryModeEnabledResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->EnableFactoryMode());
}

TEST_F(Cr50UtilsTest, DisableFactoryMode_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  {
    InSequence seq;
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
        .WillOnce(
            DoAll(SetArgPointee<1>(kFactoryModeEnabledResponse), Return(true)));
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  }
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->DisableFactoryMode());
}

TEST_F(Cr50UtilsTest, DisableFactoryMode_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  {
    InSequence seq;
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
        .WillOnce(
            DoAll(SetArgPointee<1>(kFactoryModeEnabledResponse), Return(true)));
    EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  }
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->DisableFactoryMode());
}

TEST_F(Cr50UtilsTest, DisableFactoryMode_AlreadyDisabled) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFactoryModeDisabledResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->DisableFactoryMode());
}

TEST_F(Cr50UtilsTest, GetBoardIdType_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kGetBoardIdResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string board_id_type;
  EXPECT_TRUE(cr50_utils->GetBoardIdType(&board_id_type));
  EXPECT_EQ(board_id_type, kExpectedBoardIdType);
}

TEST_F(Cr50UtilsTest, GetBoardIdType_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string board_id_type;
  EXPECT_FALSE(cr50_utils->GetBoardIdType(&board_id_type));
}

TEST_F(Cr50UtilsTest, GetBoardIdFlags_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kGetBoardIdResponse), Return(true)));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string board_id_flags;
  EXPECT_TRUE(cr50_utils->GetBoardIdFlags(&board_id_flags));
  EXPECT_EQ(board_id_flags, kExpectedBoardIdFlags);
}

TEST_F(Cr50UtilsTest, GetBoardIdFlags_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  std::string board_id_flags;
  EXPECT_FALSE(cr50_utils->GetBoardIdFlags(&board_id_flags));
}

TEST_F(Cr50UtilsTest, SetBoardId_Success) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(true));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_TRUE(cr50_utils->SetBoardId(true));
}

TEST_F(Cr50UtilsTest, SetBoardId_Fail) {
  auto mock_cmd_utils = std::make_unique<StrictMock<MockCmdUtils>>();
  EXPECT_CALL(*mock_cmd_utils, GetOutput(_, _)).WillOnce(Return(false));
  auto cr50_utils = std::make_unique<Cr50UtilsImpl>(std::move(mock_cmd_utils));

  EXPECT_FALSE(cr50_utils->SetBoardId(true));
}

}  // namespace rmad
