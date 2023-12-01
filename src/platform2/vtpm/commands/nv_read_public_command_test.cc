// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/nv_read_public_command.h"

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <trunks/authorization_delegate.h>
#include <trunks/mock_command_parser.h>
#include <trunks/mock_response_serializer.h>
#include <trunks/tpm_generated.h>

#include "vtpm/backends/mock_nv_space_manager.h"
#include "vtpm/backends/mock_static_analyzer.h"

namespace vtpm {

namespace {

using ::testing::_;
using ::testing::AtMost;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::SetArgReferee;
using ::testing::StrictMock;

constexpr char kFakeRequest[] = "fake request";
constexpr char kTestResponse[] = "test response";
constexpr trunks::TPMI_RH_NV_INDEX kFakeIndex = 0x69696969;
constexpr trunks::UINT16 kFakeDataSize = 449;
constexpr trunks::TPMA_NV kFakeAttributes = 0x123;
constexpr trunks::TPMI_ALG_HASH kFakeNameAlgorithm = trunks::TPM_ALG_SHA256;
constexpr trunks::TPMS_NV_PUBLIC kFakeNvPublic = {
    .nv_index = kFakeIndex,
    .name_alg = kFakeNameAlgorithm,
    .attributes = kFakeAttributes,
    .auth_policy = {},
    .data_size = kFakeDataSize,
};

// This is desibgned to show a bug of test itself because `ASSERT_XXX()` can't
// used for functions with a non-void return value.
constexpr char kBadSerializedData[] = "bad serialized data";

std::string GetFakeNvName_TPM2B_NV_PUBLIC(
    const trunks::TPM2B_NV_PUBLIC& nv_public) {
  std::string out;
  if (trunks::Serialize_TPM2B_NV_PUBLIC(nv_public, &out) !=
      trunks::TPM_RC_SUCCESS) {
    return kBadSerializedData;
  }
  return "name of " + out;
}

std::string GetFakeNvName_TPMS_NV_PUBLIC(
    const trunks::TPMS_NV_PUBLIC& nv_public) {
  return GetFakeNvName_TPM2B_NV_PUBLIC(trunks::Make_TPM2B_NV_PUBLIC(nv_public));
}

trunks::TPM_RC ComputeNvNameFake(const trunks::TPMS_NV_PUBLIC& nv_public,
                                 std::string& nv_name) {
  nv_name = GetFakeNvName_TPMS_NV_PUBLIC(nv_public);
  return trunks::TPM_RC_SUCCESS;
}

bool IsEuqalTo(const trunks::TPM2B_NV_PUBLIC& tpm2b,
               const trunks::TPMS_NV_PUBLIC& tpms) {
  const trunks::TPM2B_NV_PUBLIC tpm2b_from_tpms =
      trunks::Make_TPM2B_NV_PUBLIC(tpms);
  if (tpm2b_from_tpms.size != tpm2b.size) {
    return false;
  }
  return tpm2b.nv_public.nv_index == tpms.nv_index &&
         tpm2b.nv_public.name_alg == tpms.name_alg &&
         tpm2b.nv_public.attributes == tpms.attributes &&
         tpm2b.nv_public.auth_policy.size == tpms.auth_policy.size &&
         memcmp(tpm2b.nv_public.auth_policy.buffer, tpms.auth_policy.buffer,
                tpms.auth_policy.size) == 0 &&
         tpm2b.nv_public.data_size == tpms.data_size;
}

bool IsEuqalTo(const trunks::TPM2B_NAME tpm2b, const std::string& s) {
  return trunks::StringFrom_TPM2B_NAME(tpm2b) == s;
}

MATCHER_P(IsSerializedFrom, object, "") {
  return IsEuqalTo(arg, object);
}

}  // namespace

class NvReadPublicCommandTest : public testing::Test {
 public:
  void SetUp() override {
    ON_CALL(mock_static_analyzer_, ComputeNvName(_, _))
        .WillByDefault(ComputeNvNameFake);
  }

 protected:
  StrictMock<trunks::MockCommandParser> mock_cmd_parser_;
  StrictMock<trunks::MockResponseSerializer> mock_resp_serializer_;
  StrictMock<MockNvSpaceManager> mock_nv_space_manager_;
  StrictMock<MockStaticAnalyzer> mock_static_analyzer_;

  NvReadPublicCommand command_{&mock_cmd_parser_, &mock_resp_serializer_,
                               &mock_nv_space_manager_, &mock_static_analyzer_};
};

namespace {

TEST_F(NvReadPublicCommandTest, Success) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakeIndex), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetDataSize(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeDataSize),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetAttributes(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeAttributes),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetNameAlgorithm(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeNameAlgorithm),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, ComputeNvName(_, _));
  EXPECT_CALL(
      mock_resp_serializer_,
      SerializeResponseNvReadPublic(
          IsSerializedFrom(kFakeNvPublic),
          IsSerializedFrom(GetFakeNvName_TPMS_NV_PUBLIC(kFakeNvPublic)), _))
      .WillOnce(SetArgPointee<2>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadPublicCommandTest, FailureNvName) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakeIndex), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetDataSize(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeDataSize),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetAttributes(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeAttributes),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetNameAlgorithm(kFakeIndex, _))
      .WillOnce(DoAll(SetArgReferee<1>(kFakeNameAlgorithm),
                      Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_static_analyzer_, ComputeNvName(_, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadPublicCommandTest, FailureGetDataSize) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakeIndex), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_nv_space_manager_, GetDataSize(kFakeIndex, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_nv_space_manager_, GetAttributes(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeAttributes),
                            Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetNameAlgorithm(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeNameAlgorithm),
                            Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadPublicCommandTest, FailureGetAttributes) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakeIndex), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetDataSize(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeDataSize),
                            Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_nv_space_manager_, GetAttributes(kFakeIndex, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_nv_space_manager_, GetNameAlgorithm(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeNameAlgorithm),
                            Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadPublicCommandTest, FailureGetAlgorithmName) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakeIndex), Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetDataSize(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeDataSize),
                            Return(trunks::TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_nv_space_manager_, GetAttributes(kFakeIndex, _))
      .Times(AtMost(1))
      .WillRepeatedly(DoAll(SetArgReferee<1>(kFakeAttributes),
                            Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_nv_space_manager_, GetNameAlgorithm(kFakeIndex, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

TEST_F(NvReadPublicCommandTest, FailureParseCommand) {
  std::string response;
  CommandResponseCallback callback =
      base::BindOnce([](std::string* resp_out,
                        const std::string& resp_in) { *resp_out = resp_in; },
                     &response);
  EXPECT_CALL(mock_cmd_parser_,
              ParseCommandNvReadPublic(Pointee(std::string(kFakeRequest)), _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_CALL(mock_resp_serializer_,
              SerializeHeaderOnlyResponse(trunks::TPM_RC_FAILURE, _))
      .WillOnce(SetArgPointee<1>(kTestResponse));

  command_.Run(kFakeRequest, std::move(callback));
  EXPECT_EQ(response, kTestResponse);
}

}  // namespace

}  // namespace vtpm
