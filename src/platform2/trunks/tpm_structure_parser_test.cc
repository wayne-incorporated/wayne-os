// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_structure_parser.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/tpm_generated.h"

namespace trunks {

// A placeholder test fixture to prevent typos.
class TpmStructureParserTest : public testing::Test {};

namespace {

TEST_F(TpmStructureParserTest, ParsePrimitives) {
  std::string payload;
  constexpr UINT32 kTestValue1 = 0x0806449;
  constexpr UINT16 kTestValue2 = 9487;
  constexpr UINT8 kTestValue3 = 007;
  ASSERT_EQ(Serialize_UINT32(kTestValue1, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT16(kTestValue2, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT8(kTestValue3, &payload), TPM_RC_SUCCESS);

  TpmStructureParser parser(payload);
  UINT32 out1 = 0;
  UINT16 out2 = 0;
  UINT8 out3 = 0;
  EXPECT_EQ(parser.Parse(out1, out2, out3), TPM_RC_SUCCESS);
  EXPECT_EQ(kTestValue1, out1);
  EXPECT_EQ(kTestValue2, out2);
  EXPECT_EQ(kTestValue3, out3);
  EXPECT_TRUE(parser.payload().empty());
}

TEST_F(TpmStructureParserTest, ParsePrimitivesHasLeftover) {
  std::string payload;
  constexpr UINT32 kTestValue1 = 0x0806449;
  constexpr UINT16 kTestValue2 = 9487;
  constexpr UINT8 kTestValue3 = 007;
  ASSERT_EQ(Serialize_UINT32(kTestValue1, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT16(kTestValue2, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT8(kTestValue3, &payload), TPM_RC_SUCCESS);
  const std::string leftover = "left over";

  TpmStructureParser parser(payload + leftover);
  UINT32 out1 = 0;
  UINT16 out2 = 0;
  UINT8 out3 = 0;
  EXPECT_EQ(parser.Parse(out1, out2, out3), TPM_RC_SUCCESS);
  EXPECT_EQ(kTestValue1, out1);
  EXPECT_EQ(kTestValue2, out2);
  EXPECT_EQ(kTestValue3, out3);
  EXPECT_EQ(parser.payload(), leftover);
}

TEST_F(TpmStructureParserTest, ParsePrimitivesErrorTooShort) {
  std::string payload;
  constexpr UINT32 kTestValue1 = 0x0806449;
  constexpr UINT16 kTestValue2 = 9487;
  constexpr UINT8 kTestValue3 = 007;
  ASSERT_EQ(Serialize_UINT32(kTestValue1, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT16(kTestValue2, &payload), TPM_RC_SUCCESS);
  ASSERT_EQ(Serialize_UINT8(kTestValue3, &payload), TPM_RC_SUCCESS);

  TpmStructureParser parser(payload);
  UINT32 out1 = 0;
  UINT32 out2 = 0;
  UINT32 out3 = 0;
  EXPECT_NE(parser.Parse(out1, out2, out3), TPM_RC_SUCCESS);
}

}  // namespace

}  // namespace trunks
