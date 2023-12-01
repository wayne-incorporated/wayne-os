// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_connection.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/test_utils/tpm1/test_fixture.h>

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

const TSS_HCONTEXT kFakeContext = 99999;
const TSS_HTPM kFakeTpm = 66666;

}  // namespace

namespace tpm_manager {

class TpmConnectionTest : public ::hwsec::Tpm1HwsecTest {
 public:
  TpmConnectionTest() = default;
  ~TpmConnectionTest() override = default;
  void SetUp() override {
    ON_CALL_OVERALLS(Ospi_Context_Create(_))
        .WillByDefault(
            DoAll(SetArgPointee<0>(kFakeContext), Return(TSS_SUCCESS)));
    ON_CALL_OVERALLS(Ospi_Context_GetTpmObject(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(kFakeTpm), Return(TSS_SUCCESS)));
  }
};

TEST_F(TpmConnectionTest, CannotCreateContext) {
  EXPECT_CALL_OVERALLS(Ospi_Context_Connect(_, _)).Times(0);
  TpmConnection result_connection;
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_))
      .WillOnce(Return(TSP_ERROR(TSS_E_INTERNAL_ERROR)));
  EXPECT_EQ(result_connection.GetContext(), 0);
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_))
      .WillOnce(Return(TSP_ERROR(TSS_E_INTERNAL_ERROR)));
  EXPECT_EQ(result_connection.GetTpm(), 0);
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_))
      .WillOnce(DoAll(SetArgPointee<0>(0), Return(TSS_SUCCESS)));
  EXPECT_EQ(result_connection.GetContext(), 0);
}

TEST_F(TpmConnectionTest, ConnectContextSuccess) {
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_)).Times(1);
  EXPECT_CALL_OVERALLS(Ospi_Context_Connect(_, nullptr))
      .WillOnce(Return(TSS_SUCCESS));
  TpmConnection result_connection;
  EXPECT_EQ(result_connection.GetContext(), kFakeContext);
  EXPECT_EQ(result_connection.GetTpm(), kFakeTpm);

  EXPECT_CALL_OVERALLS(Ospi_Context_GetTpmObject(_, _))
      .WillOnce(Return(TSS_E_BAD_PARAMETER));
  EXPECT_EQ(result_connection.GetTpm(), 0);
}

// Checks if the retry loop is works as expected.
TEST_F(TpmConnectionTest, ConnectContextError) {
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_)).Times(1);
  TpmConnection result_connection;
  // The connection attempt should stop after communication failure for 10
  // times.
  EXPECT_CALL_OVERALLS(Ospi_Context_Connect(_, nullptr))
      .Times(10)
      .WillRepeatedly(Return(TSP_ERROR(TSS_E_COMM_FAILURE)));
  EXPECT_EQ(result_connection.GetContext(), 0);

  // Any error other than communication failure should break the retry loop.
  EXPECT_CALL_OVERALLS(Ospi_Context_Create(_)).Times(1);
  EXPECT_CALL_OVERALLS(Ospi_Context_Connect(_, nullptr))
      .Times(5)
      .WillOnce(Return(TSP_ERROR(TSS_E_COMM_FAILURE)))
      .WillOnce(Return(TSP_ERROR(TSS_E_COMM_FAILURE)))
      .WillOnce(Return(TSP_ERROR(TSS_E_COMM_FAILURE)))
      .WillOnce(Return(TSP_ERROR(TSS_E_COMM_FAILURE)))
      .WillOnce(Return(TSP_ERROR(TSS_E_INVALID_HANDLE)));
  EXPECT_EQ(result_connection.GetContext(), 0);
}

}  // namespace tpm_manager
