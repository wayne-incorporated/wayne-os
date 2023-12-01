// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/real_response_serializer.h"

#include <algorithm>
#include <cstring>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "trunks/command_parser.h"
#include "trunks/password_authorization_delegate.h"
#include "trunks/tpm_generated.h"

namespace trunks {

namespace {

void InitializeFake(TPMS_CAPABILITY_DATA* data) {
  memset(data, 0, sizeof(*data));
  data->capability = TPM_CAP_HANDLES;
  data->data = TPMU_CAPABILITIES{.handles = TPML_HANDLE{}};
  for (int i = 0; i < 3; ++i) {
    data->data.handles.handle[data->data.handles.count] = i;
    ++data->data.handles.count;
  }
}

}  // namespace

// A placeholder test fixture.
class RealResponseSerializerTest : public testing::Test {
 protected:
  RealResponseSerializer serializer_;
};

namespace {

TEST_F(RealResponseSerializerTest, SerializeHeaderOnlyResponse) {
  std::string response;
  const TPM_RC rc = TPM_RC_LOCKOUT;
  serializer_.SerializeHeaderOnlyResponse(rc, &response);

  TPMI_ST_COMMAND_TAG tag = TPM_ST_NULL;
  EXPECT_EQ(Parse_TPMI_ST_COMMAND_TAG(&response, &tag, nullptr),
            TPM_RC_SUCCESS);
  EXPECT_EQ(tag, TPM_ST_NO_SESSIONS);

  UINT32 size = 0;
  EXPECT_EQ(Parse_UINT32(&response, &size, nullptr), TPM_RC_SUCCESS);
  EXPECT_EQ(size, kHeaderSize);

  TPM_RC rc_out = TPM_RC_SUCCESS;
  EXPECT_EQ(Parse_TPM_RC(&response, &rc_out, nullptr), TPM_RC_SUCCESS);
  EXPECT_EQ(rc_out, rc);
}

TEST_F(RealResponseSerializerTest, SerializeHeaderOnlyResponseBadTag) {
  std::string response;
  const TPM_RC rc = TPM_RC_BAD_TAG;
  serializer_.SerializeHeaderOnlyResponse(rc, &response);

  TPMI_ST_COMMAND_TAG tag = TPM_ST_NULL;
  EXPECT_EQ(Parse_TPMI_ST_COMMAND_TAG(&response, &tag, nullptr),
            TPM_RC_SUCCESS);
  EXPECT_EQ(tag, TPM_ST_RSP_COMMAND);

  UINT32 size = 0;
  EXPECT_EQ(Parse_UINT32(&response, &size, nullptr), TPM_RC_SUCCESS);
  EXPECT_EQ(size, kHeaderSize);

  TPM_RC rc_out = TPM_RC_SUCCESS;
  EXPECT_EQ(Parse_TPM_RC(&response, &rc_out, nullptr), TPM_RC_SUCCESS);
  EXPECT_EQ(rc_out, rc);
}

TEST_F(RealResponseSerializerTest, SerializeResponseGetCapability) {
  const TPMI_YES_NO more = YES;
  TPMS_CAPABILITY_DATA data;
  InitializeFake(&data);
  std::string response;
  serializer_.SerializeResponseGetCapability(more, data, &response);

  TPMI_YES_NO more_out = NO;
  TPMS_CAPABILITY_DATA data_out = {};

  ASSERT_EQ(
      Tpm::ParseResponse_GetCapability(response, &more_out, &data_out,
                                       /*authorization_delegate=*/nullptr),
      TPM_RC_SUCCESS);
  EXPECT_EQ(more_out, more);
  EXPECT_EQ(data.capability, data_out.capability);
  EXPECT_EQ(data.capability, TPM_CAP_HANDLES);
  EXPECT_EQ(data.data.handles.count, data_out.data.handles.count);
  EXPECT_EQ(memcmp(data.data.handles.handle, data_out.data.handles.handle,
                   sizeof(TPM_HANDLE) * data_out.data.handles.count),
            0);
}

TEST_F(RealResponseSerializerTest, SerializeResponseNvRead) {
  const std::string fake_data = "fake data";
  const TPM2B_MAX_NV_BUFFER data = Make_TPM2B_MAX_NV_BUFFER(fake_data);

  std::string response;
  serializer_.SerializeResponseNvRead(data, &response);

  TPM2B_MAX_NV_BUFFER data_out = {};

  PasswordAuthorizationDelegate fake_password_authorization(
      "password placeholder");

  ASSERT_EQ(Tpm::ParseResponse_NV_Read(response, &data_out,
                                       &fake_password_authorization),
            TPM_RC_SUCCESS);
  EXPECT_EQ(std::string(data_out.buffer, data_out.buffer + data_out.size),
            fake_data);
}

TEST_F(RealResponseSerializerTest, SerializeResponseNvReadPublic) {
  const std::string kFakeAuthPolicy = "fake auth policy";
  const TPMS_NV_PUBLIC tpms_nv_public = {
      .nv_index = 222,
      .name_alg = TPM_ALG_SHA256,
      .attributes = 123,
      .auth_policy = Make_TPM2B_DIGEST(kFakeAuthPolicy),
      .data_size = 66,
  };
  const TPM2B_NV_PUBLIC nv_public = Make_TPM2B_NV_PUBLIC(tpms_nv_public);
  const std::string kFakeNvName = "fake nv name";
  const TPM2B_NAME nv_name = Make_TPM2B_NAME(kFakeNvName);

  std::string response;
  serializer_.SerializeResponseNvReadPublic(nv_public, nv_name, &response);

  TPM2B_NV_PUBLIC nv_public_out = {};
  TPM2B_NAME nv_name_out = {};

  ASSERT_EQ(Tpm::ParseResponse_NV_ReadPublic(response, &nv_public_out,
                                             &nv_name_out, nullptr),
            TPM_RC_SUCCESS);

  EXPECT_EQ(nv_public_out.size, nv_public.size);
  EXPECT_EQ(nv_public_out.nv_public.nv_index, nv_public.nv_public.nv_index);
  EXPECT_EQ(nv_public_out.nv_public.name_alg, nv_public.nv_public.name_alg);
  EXPECT_EQ(nv_public_out.nv_public.attributes, nv_public.nv_public.attributes);
  EXPECT_EQ(nv_public_out.nv_public.auth_policy.size,
            nv_public.nv_public.auth_policy.size);
  ASSERT_LE(nv_public_out.nv_public.auth_policy.size,
            sizeof(nv_public_out.nv_public.auth_policy.buffer));
  EXPECT_EQ(memcmp(nv_public_out.nv_public.auth_policy.buffer,
                   nv_public.nv_public.auth_policy.buffer,
                   nv_public_out.nv_public.auth_policy.size),
            0);
  EXPECT_EQ(nv_public_out.nv_public.auth_policy.size,
            nv_public.nv_public.auth_policy.size);
  EXPECT_EQ(nv_public_out.nv_public.data_size, nv_public.nv_public.data_size);

  ASSERT_LE(sizeof(nv_name_out.size) + nv_name_out.size, sizeof(nv_name_out));
  EXPECT_EQ(memcmp(&nv_name_out, &nv_name,
                   sizeof(nv_name_out.size) + nv_name_out.size),
            0);
}

}  // namespace

}  // namespace trunks
