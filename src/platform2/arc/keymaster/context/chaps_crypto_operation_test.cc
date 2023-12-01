// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/chaps_crypto_operation.h"

#include <cstdint>
#include <iterator>
#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <chaps/attributes.h>
#include <chaps/chaps_proxy_mock.h>
#include <chaps/pkcs11/cryptoki.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/keymaster/context/context_adaptor.h"
#include "arc/keymaster/context/crypto_operation.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace arc {
namespace keymaster {
namespace context {

namespace {

// CK_SLOT_IDs for user and system slot. Arbitrary but distinct.
constexpr uint64_t kSystemSlotId = 2;
constexpr uint64_t kUserSlotId = 4;
// Arbitrary non-zero CK_SESSION_HANDLE.
constexpr uint64_t kSessionId = 9;
// Arbitrary single-element list.
const std::vector<uint64_t> kObjectList = {7};

// Arbitrary 32 byte key.
const std::vector<uint8_t> kKeyBlob(32, 99);

// Arbitrary blob representing some signature.
const std::vector<uint8_t> kSignatureBlob(32, 55);

// Arbitrary blob of data.
const std::vector<uint8_t> kDataBlob(42, 77);

// Valid serialized KeyPermissions protobuf.
const std::vector<uint8_t> kArcKeyPermissionTrue = {10, 4, 8, 1, 16, 1};

constexpr char kLabel[] = "object_label";

const brillo::Blob kId(10, 10);

const MechanismDescription kDescription = kCkmRsaPkcsSign;

// Must be a valid test name (no spaces etc.). Makes the test show up as e.g.
// ChapsCryptoOperation/ChapsCryptoOperationTest.Update/UserSlot.
std::string TestName(testing::TestParamInfo<ContextAdaptor::Slot> param_info) {
  return param_info.param == ContextAdaptor::Slot::kUser ? "UserSlot"
                                                         : "SystemSlot";
}

}  // anonymous namespace

// Fixture for chaps client tests.
class ChapsCryptoOperationTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<ContextAdaptor::Slot> {
 public:
  ChapsCryptoOperationTest()
      : chaps_mock_(/* is_initialized */ true),
        operation_(context_adaptor_.GetWeakPtr(), GetParam(), kLabel, kId) {}

  uint32_t FakeGetKeyBlob(const brillo::SecureBlob& isolate_credential,
                          uint64_t session_id,
                          uint64_t object_handle,
                          const std::vector<uint8_t>& attributes_in,
                          std::vector<uint8_t>* attributes_out) {
    chaps::Attributes parsed;
    parsed.Parse(attributes_in);
    std::vector<uint8_t> out_blob = parsed.attributes()[0].type == CKA_VALUE
                                        ? kKeyBlob
                                        : kArcKeyPermissionTrue;
    parsed.attributes()[0].ulValueLen = out_blob.size();
    if (parsed.attributes()[0].pValue) {
      memcpy(parsed.attributes()[0].pValue, out_blob.data(), out_blob.size());
    }
    parsed.Serialize(attributes_out);
    return CKR_OK;
  }

 protected:
  void SetUp() override {
    uint64_t slot_id;
    switch (GetParam()) {
      case ContextAdaptor::Slot::kUser:
        slot_id = kUserSlotId;
        context_adaptor_.set_user_slot_for_tests(kUserSlotId);
        break;
      case ContextAdaptor::Slot::kSystem:
        slot_id = kSystemSlotId;
        context_adaptor_.set_system_slot_for_tests(kSystemSlotId);
        break;
    }

    ON_CALL(chaps_mock_, OpenSession(_, slot_id, _, _))
        .WillByDefault(DoAll(SetArgPointee<3>(kSessionId), Return(CKR_OK)));
    ON_CALL(chaps_mock_, CloseSession(_, _)).WillByDefault(Return(CKR_OK));
    ON_CALL(chaps_mock_, FindObjectsInit(_, _, _))
        .WillByDefault(Return(CKR_OK));
    ON_CALL(chaps_mock_, FindObjects(_, _, _, _))
        .WillByDefault(DoAll(SetArgPointee<3>(kObjectList), Return(CKR_OK)));
    ON_CALL(chaps_mock_, FindObjectsFinal(_, _)).WillByDefault(Return(CKR_OK));
    ON_CALL(chaps_mock_, GetAttributeValue(_, _, _, _, _))
        .WillByDefault(Invoke(/* obj_ptr */ this,
                              &ChapsCryptoOperationTest::FakeGetKeyBlob));
    ON_CALL(chaps_mock_, SignFinal(_, _, _, _, _))
        .WillByDefault(DoAll(SetArgPointee<4>(kSignatureBlob), Return(CKR_OK)));
  }

  ::testing::NiceMock<::chaps::ChapsProxyMock> chaps_mock_;
  ContextAdaptor context_adaptor_;
  ChapsCryptoOperation operation_;
};

TEST_P(ChapsCryptoOperationTest, BeginForwardsLabelAndId) {
  // Prepare an attributes list with the expected parameters.
  CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
  std::string mutable_label(kLabel);
  CK_ATTRIBUTE findAttributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
      {CKA_ID, const_cast<uint8_t*>(kId.data()), kId.size()},
  };
  chaps::Attributes parsed(findAttributes, std::size(findAttributes));
  std::vector<uint8_t> serialized_attributes;
  parsed.Serialize(&serialized_attributes);

  // Expect chaps will receive the correct attributes.
  EXPECT_CALL(chaps_mock_, FindObjectsInit(_, _, Eq(serialized_attributes)));

  // Call Begin.
  operation_.Begin(kDescription);
}

TEST_P(ChapsCryptoOperationTest, BeginUsesCorrectMechanism) {
  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_RSA_PKCS), _, _));
  operation_.Begin(kCkmRsaPkcsSign);

  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_MD5_RSA_PKCS), _, _));
  operation_.Begin(kCkmMd5RsaPkcsSign);

  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_SHA1_RSA_PKCS), _, _));
  operation_.Begin(kCkmSha1RsaPkcsSign);

  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_SHA256_RSA_PKCS), _, _));
  operation_.Begin(kCkmSha256RsaPkcsSign);

  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_SHA384_RSA_PKCS), _, _));
  operation_.Begin(kCkmSha384RsaPkcsSign);

  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(CKM_SHA512_RSA_PKCS), _, _));
  operation_.Begin(kCkmSha512RsaPkcsSign);
}

TEST_P(ChapsCryptoOperationTest, Update) {
  operation_.Begin(kDescription);
  std::optional<brillo::Blob> result = operation_.Update(kDataBlob);

  ASSERT_TRUE(result.has_value());
  ASSERT_TRUE(result->empty());
}

TEST_P(ChapsCryptoOperationTest, Finish) {
  operation_.Begin(kDescription);
  std::optional<brillo::Blob> result = operation_.Finish();

  ASSERT_TRUE(result.has_value());
  ASSERT_EQ(result.value(), kSignatureBlob);
}

TEST_P(ChapsCryptoOperationTest, Abort) {
  operation_.Begin(kDescription);
  bool result = operation_.Abort();

  ASSERT_TRUE(result);
}

INSTANTIATE_TEST_SUITE_P(ChapsCryptoOperation,
                         ChapsCryptoOperationTest,
                         ::testing::Values(ContextAdaptor::Slot::kUser,
                                           ContextAdaptor::Slot::kSystem),
                         TestName);

}  // namespace context
}  // namespace keymaster
}  // namespace arc
