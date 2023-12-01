// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/chaps_client.h"

#include <cstdint>
#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <chaps/attributes.h>
#include <chaps/chaps_proxy_mock.h>
#include <chaps/pkcs11/cryptoki.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/keymaster/context/context_adaptor.h"

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
constexpr uint64_t kSystemSlotId = 7;
constexpr uint64_t kUserSlotId = 13;
// Arbitrary non-zero CK_SESSION_HANDLE.
constexpr uint64_t kSessionId = 9;
// Arbitrary single-element list.
const std::vector<uint64_t> kObjectList = {7};
const std::vector<uint64_t> kEmptyObjectList = {};

// Arbitrary 32 byte key.
const std::vector<uint8_t> kKeyBlob(32, 99);

// Arbitrary blob containing a valid certificate x509 in DER format.
const std::vector<uint8_t> kCertificateDer = {
    48,  130, 3,   107, 48,  130, 2,   83,  160, 3,   2,   1,   2,   2,   20,
    105, 145, 5,   180, 104, 132, 151, 128, 121, 135, 72,  134, 120, 62,  120,
    253, 190, 80,  104, 131, 48,  13,  6,   9,   42,  134, 72,  134, 247, 13,
    1,   1,   11,  5,   0,   48,  69,  49,  11,  48,  9,   6,   3,   85,  4,
    6,   19,  2,   65,  85,  49,  19,  48,  17,  6,   3,   85,  4,   8,   12,
    10,  83,  111, 109, 101, 45,  83,  116, 97,  116, 101, 49,  33,  48,  31,
    6,   3,   85,  4,   10,  12,  24,  73,  110, 116, 101, 114, 110, 101, 116,
    32,  87,  105, 100, 103, 105, 116, 115, 32,  80,  116, 121, 32,  76,  116,
    100, 48,  30,  23,  13,  50,  48,  49,  50,  48,  51,  49,  48,  53,  49,
    48,  49,  90,  23,  13,  50,  49,  49,  50,  48,  51,  49,  48,  53,  49,
    48,  49,  90,  48,  69,  49,  11,  48,  9,   6,   3,   85,  4,   6,   19,
    2,   65,  85,  49,  19,  48,  17,  6,   3,   85,  4,   8,   12,  10,  83,
    111, 109, 101, 45,  83,  116, 97,  116, 101, 49,  33,  48,  31,  6,   3,
    85,  4,   10,  12,  24,  73,  110, 116, 101, 114, 110, 101, 116, 32,  87,
    105, 100, 103, 105, 116, 115, 32,  80,  116, 121, 32,  76,  116, 100, 48,
    130, 1,   34,  48,  13,  6,   9,   42,  134, 72,  134, 247, 13,  1,   1,
    1,   5,   0,   3,   130, 1,   15,  0,   48,  130, 1,   10,  2,   130, 1,
    1,   0,   175, 103, 224, 10,  106, 96,  140, 64,  134, 186, 210, 5,   92,
    160, 224, 117, 88,  148, 184, 148, 135, 242, 95,  65,  112, 75,  77,  80,
    68,  216, 98,  95,  39,  219, 229, 176, 19,  25,  149, 142, 151, 1,   221,
    192, 6,   7,   201, 133, 186, 45,  237, 28,  210, 126, 136, 190, 68,  242,
    232, 131, 168, 236, 18,  236, 236, 163, 33,  130, 235, 131, 210, 49,  236,
    108, 245, 182, 26,  249, 109, 223, 158, 33,  187, 222, 89,  151, 134, 213,
    46,  198, 215, 57,  239, 143, 132, 108, 69,  106, 97,  158, 144, 13,  112,
    226, 137, 186, 234, 91,  48,  97,  253, 248, 245, 123, 101, 183, 137, 183,
    39,  115, 26,  19,  201, 248, 71,  210, 172, 110, 98,  136, 224, 103, 222,
    212, 156, 219, 69,  50,  18,  85,  180, 83,  84,  209, 176, 62,  94,  166,
    91,  99,  78,  59,  36,  23,  23,  152, 215, 145, 248, 5,   253, 240, 29,
    42,  125, 130, 109, 243, 10,  175, 149, 169, 102, 61,  106, 63,  156, 17,
    185, 134, 199, 84,  7,   99,  231, 161, 222, 146, 161, 16,  27,  247, 178,
    137, 57,  111, 252, 132, 113, 190, 46,  75,  107, 243, 125, 1,   153, 133,
    86,  88,  141, 187, 27,  13,  53,  74,  156, 169, 87,  82,  192, 169, 44,
    101, 3,   145, 251, 83,  171, 123, 188, 141, 137, 120, 26,  100, 45,  102,
    145, 171, 178, 135, 238, 2,   32,  239, 53,  61,  78,  56,  139, 134, 46,
    212, 55,  39,  2,   3,   1,   0,   1,   163, 83,  48,  81,  48,  29,  6,
    3,   85,  29,  14,  4,   22,  4,   20,  22,  217, 14,  167, 113, 102, 100,
    7,   234, 117, 42,  153, 36,  99,  160, 163, 39,  151, 159, 181, 48,  31,
    6,   3,   85,  29,  35,  4,   24,  48,  22,  128, 20,  22,  217, 14,  167,
    113, 102, 100, 7,   234, 117, 42,  153, 36,  99,  160, 163, 39,  151, 159,
    181, 48,  15,  6,   3,   85,  29,  19,  1,   1,   255, 4,   5,   48,  3,
    1,   1,   255, 48,  13,  6,   9,   42,  134, 72,  134, 247, 13,  1,   1,
    11,  5,   0,   3,   130, 1,   1,   0,   124, 63,  26,  197, 170, 235, 130,
    152, 65,  23,  47,  77,  128, 163, 203, 225, 192, 160, 236, 217, 174, 38,
    32,  245, 235, 61,  238, 39,  254, 114, 31,  247, 28,  175, 76,  128, 82,
    111, 95,  67,  186, 21,  149, 252, 153, 229, 193, 17,  94,  49,  102, 210,
    29,  113, 227, 38,  251, 161, 238, 87,  140, 147, 27,  171, 73,  115, 181,
    101, 200, 28,  2,   243, 194, 27,  77,  87,  195, 50,  67,  87,  184, 223,
    79,  87,  148, 48,  11,  87,  79,  30,  153, 12,  53,  71,  60,  33,  232,
    158, 32,  109, 90,  196, 104, 22,  31,  251, 86,  174, 133, 7,   146, 104,
    111, 142, 215, 73,  140, 108, 226, 123, 36,  216, 2,   65,  177, 87,  47,
    145, 62,  80,  137, 189, 122, 206, 175, 16,  52,  112, 233, 69,  248, 148,
    221, 147, 40,  16,  104, 112, 87,  229, 228, 9,   108, 89,  129, 117, 141,
    104, 23,  35,  113, 61,  22,  246, 73,  176, 254, 189, 7,   223, 49,  71,
    194, 238, 211, 87,  166, 67,  172, 125, 63,  136, 68,  231, 213, 13,  61,
    102, 14,  177, 131, 103, 9,   250, 198, 190, 153, 233, 75,  127, 79,  203,
    163, 41,  68,  201, 215, 234, 167, 147, 15,  73,  6,   146, 119, 185, 133,
    15,  40,  208, 103, 247, 149, 83,  185, 99,  10,  134, 89,  33,  179, 65,
    143, 55,  37,  93,  139, 174, 64,  52,  22,  8,   128, 240, 93,  164, 135,
    9,   217, 64,  54,  66,  245, 42,  148, 64};

// The public key of |kCertificateDer|.
const std::vector<uint8_t> kCertificateSpkiDer = {
    48,  130, 1,   34,  48,  13,  6,   9,   42,  134, 72,  134, 247, 13,  1,
    1,   1,   5,   0,   3,   130, 1,   15,  0,   48,  130, 1,   10,  2,   130,
    1,   1,   0,   175, 103, 224, 10,  106, 96,  140, 64,  134, 186, 210, 5,
    92,  160, 224, 117, 88,  148, 184, 148, 135, 242, 95,  65,  112, 75,  77,
    80,  68,  216, 98,  95,  39,  219, 229, 176, 19,  25,  149, 142, 151, 1,
    221, 192, 6,   7,   201, 133, 186, 45,  237, 28,  210, 126, 136, 190, 68,
    242, 232, 131, 168, 236, 18,  236, 236, 163, 33,  130, 235, 131, 210, 49,
    236, 108, 245, 182, 26,  249, 109, 223, 158, 33,  187, 222, 89,  151, 134,
    213, 46,  198, 215, 57,  239, 143, 132, 108, 69,  106, 97,  158, 144, 13,
    112, 226, 137, 186, 234, 91,  48,  97,  253, 248, 245, 123, 101, 183, 137,
    183, 39,  115, 26,  19,  201, 248, 71,  210, 172, 110, 98,  136, 224, 103,
    222, 212, 156, 219, 69,  50,  18,  85,  180, 83,  84,  209, 176, 62,  94,
    166, 91,  99,  78,  59,  36,  23,  23,  152, 215, 145, 248, 5,   253, 240,
    29,  42,  125, 130, 109, 243, 10,  175, 149, 169, 102, 61,  106, 63,  156,
    17,  185, 134, 199, 84,  7,   99,  231, 161, 222, 146, 161, 16,  27,  247,
    178, 137, 57,  111, 252, 132, 113, 190, 46,  75,  107, 243, 125, 1,   153,
    133, 86,  88,  141, 187, 27,  13,  53,  74,  156, 169, 87,  82,  192, 169,
    44,  101, 3,   145, 251, 83,  171, 123, 188, 141, 137, 120, 26,  100, 45,
    102, 145, 171, 178, 135, 238, 2,   32,  239, 53,  61,  78,  56,  139, 134,
    46,  212, 55,  39,  2,   3,   1,   0,   1};

// Arbitrary blob representing some signature.
const std::vector<uint8_t> kSignatureBlob(32, 55);

// Arbitrary blob of data.
const std::vector<uint8_t> kDataBlob(42, 77);

// Valid serialized KeyPermissions protobuf.
const std::vector<uint8_t> kArcKeyPermissionTrue = {10, 4, 8, 1, 16, 1};
const std::vector<uint8_t> kArcKeyPermissionFalse = {10, 2, 8, 1};

constexpr char kLabel[] = "object_label";
const brillo::Blob kId(10, 10);

// Must be a valid test name (no spaces etc.). Makes the test show up as e.g.
// ChapsClient/ChapsClientTest.UsesSlotFromAdaptor/UserSlot.
std::string TestName(testing::TestParamInfo<ContextAdaptor::Slot> param_info) {
  return param_info.param == ContextAdaptor::Slot::kUser ? "UserSlot"
                                                         : "SystemSlot";
}

}  // anonymous namespace

// Fixture for chaps client tests.
class ChapsClientTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<ContextAdaptor::Slot> {
 public:
  ChapsClientTest()
      : chaps_mock_(/* is_initialized */ true),
        chaps_client_(context_adaptor_.GetWeakPtr(), GetParam()) {}

  uint32_t FakeGetCertificateBlob(const brillo::SecureBlob& isolate_credential,
                                  uint64_t session_id,
                                  uint64_t object_handle,
                                  const std::vector<uint8_t>& attributes_in,
                                  std::vector<uint8_t>* attributes_out) {
    return ParseAttribute(kCertificateDer, attributes_in, attributes_out);
  }

  uint32_t FakeGetAttribute(const brillo::SecureBlob& isolate_credential,
                            uint64_t session_id,
                            uint64_t object_handle,
                            const std::vector<uint8_t>& attributes_in,
                            std::vector<uint8_t>* attributes_out) {
    chaps::Attributes input;
    input.Parse(attributes_in);
    if (input.attributes()[0].type == CKA_VALUE)
      return ParseAttribute(kKeyBlob, attributes_in, attributes_out);
    return ParseAttribute(kArcKeyPermissionTrue, attributes_in, attributes_out);
  }

  uint32_t FakeGetAttributeWithoutArcPermission(
      const brillo::SecureBlob& isolate_credential,
      uint64_t session_id,
      uint64_t object_handle,
      const std::vector<uint8_t>& attributes_in,
      std::vector<uint8_t>* attributes_out) {
    chaps::Attributes input;
    input.Parse(attributes_in);
    if (input.attributes()[0].type == CKA_VALUE)
      return ParseAttribute(kKeyBlob, attributes_in, attributes_out);
    return ParseAttribute(kArcKeyPermissionFalse, attributes_in,
                          attributes_out);
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
        .WillByDefault(
            Invoke(/* obj_ptr */ this, &ChapsClientTest::FakeGetAttribute));
  }

  ::testing::NiceMock<::chaps::ChapsProxyMock> chaps_mock_;
  ContextAdaptor context_adaptor_;
  ChapsClient chaps_client_;

 private:
  uint32_t ParseAttribute(const std::vector<uint8_t>& blob,
                          const std::vector<uint8_t>& attributes_in,
                          std::vector<uint8_t>* attributes_out) {
    chaps::Attributes parsed;
    parsed.Parse(attributes_in);
    parsed.attributes()[0].ulValueLen = blob.size();
    if (parsed.attributes()[0].pValue) {
      memcpy(parsed.attributes()[0].pValue, blob.data(), blob.size());
    }
    parsed.Serialize(attributes_out);
    return CKR_OK;
  }
};

TEST_P(ChapsClientTest, UsesSlotFromAdaptor) {
  // Setup a fake slot in the cache.
  uint64_t slot = 42;
  switch (GetParam()) {
    case ContextAdaptor::Slot::kUser:
      context_adaptor_.set_user_slot_for_tests(slot);
      break;
    case ContextAdaptor::Slot::kSystem:
      context_adaptor_.set_system_slot_for_tests(slot);
      break;
  }

  // Expect chaps client will use the given slot.
  EXPECT_CALL(chaps_mock_, OpenSession(_, Eq(slot), _, _));

  // Call an operation that triggers slot usage.
  chaps_client_.session_handle();
}

TEST_P(ChapsClientTest, ExportExistingEncryptionKey) {
  // An existing key is prepared in fixture setup, expect no generation happens.
  EXPECT_CALL(chaps_mock_, GenerateKey(_, _, _, _, _, _)).Times(0);

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify output.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

TEST_P(ChapsClientTest, ExportGeneratedEncryptionKey) {
  // Expect no existing key is found and generation is called.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kEmptyObjectList), Return(CKR_OK)));
  EXPECT_CALL(chaps_mock_, GenerateKey(_, _, _, _, _, _))
      .WillOnce(Return(CKR_OK));

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify output.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

TEST_P(ChapsClientTest, CachesExportedEncryptionKey) {
  // Expect chaps is queried only once.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _)).Times(1);

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify exported key is cached in adaptor
  ASSERT_TRUE(context_adaptor_.encryption_key().has_value());
  std::vector<uint8_t> key(context_adaptor_.encryption_key()->begin(),
                           context_adaptor_.encryption_key()->end());
  EXPECT_EQ(kKeyBlob, key);

  // Verify exporting key again won't trigger more FindObject calls.
  for (int i = 0; i < 10; ++i)
    chaps_client_.ExportOrGenerateEncryptionKey();
}

TEST_P(ChapsClientTest, ReturnsCachedEncryptionKey) {
  // Prepare the adaptor cache with a key.
  brillo::SecureBlob in_key(kKeyBlob.begin(), kKeyBlob.end());
  context_adaptor_.set_encryption_key(in_key);

  // Expect chaps is never asked to find nor generate a key.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _)).Times(0);
  EXPECT_CALL(chaps_mock_, GenerateKey(_, _, _, _, _, _)).Times(0);

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify exported key is what we prepared in adaptor cache.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

TEST_P(ChapsClientTest, InitializeSignature) {
  // Expect the correct parameters are forwarded to chaps.
  CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
  CK_OBJECT_HANDLE handle = 42;
  EXPECT_CALL(chaps_mock_, SignInit(_, _, Eq(mechanism), _, Eq(handle)));

  bool result = chaps_client_.InitializeSignature(mechanism, handle);
  ASSERT_TRUE(result);
}

TEST_P(ChapsClientTest, InitializeSignatureObeysKeyPermissions) {
  CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
  CK_OBJECT_HANDLE handle = 42;

  EXPECT_CALL(chaps_mock_, GetAttributeValue(_, _, _, _, _))
      .WillOnce(Invoke(/* obj_ptr */ this,
                       &ChapsClientTest::FakeGetAttributeWithoutArcPermission))
      .WillOnce(Invoke(/* obj_ptr */ this,
                       &ChapsClientTest::FakeGetAttributeWithoutArcPermission))
      .WillRepeatedly(
          Invoke(/* obj_ptr */ this, &ChapsClientTest::FakeGetAttribute));

  // The first call receives kArcKeyPermissionFalse and should fail.
  bool result = chaps_client_.InitializeSignature(mechanism, handle);
  ASSERT_FALSE(result);

  // Following calls receive kArcKeyPermissionTrue and should work.
  bool new_result = chaps_client_.InitializeSignature(mechanism, handle);
  ASSERT_TRUE(new_result);
}

TEST_P(ChapsClientTest, UpdateSignature) {
  // Expect the correct parameters are forwarded to chaps.
  EXPECT_CALL(chaps_mock_, SignUpdate(_, _, Eq(kDataBlob)));

  bool result = chaps_client_.UpdateSignature(kDataBlob);
  ASSERT_TRUE(result);
}

TEST_P(ChapsClientTest, FinalizeSignature) {
  // Expect the output is forwarded from chaps.
  EXPECT_CALL(chaps_mock_, SignFinal(_, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kSignatureBlob), Return(CKR_OK)));
  std::optional<brillo::Blob> signature = chaps_client_.FinalizeSignature();
  ASSERT_EQ(kSignatureBlob, signature);
}

TEST_P(ChapsClientTest, FindObjectHandlesInvalidSession) {
  // Expect a retry if FindObjects returns CKR_SESSION_HANDLE_INVALID.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(DoAll(SetArgPointee<3>(kObjectList), Return(CKR_OK)));

  // Call find object.
  std::optional<CK_OBJECT_HANDLE> handle =
      chaps_client_.FindObject(CKO_CERTIFICATE, std::string(kLabel), kId);

  // Verify the correct handle is returned.
  ASSERT_TRUE(handle.has_value());
  EXPECT_EQ(handle.value(), kObjectList[0]);
}

TEST_P(ChapsClientTest, ExportSubjectPublicKeyInfoHandlesInvalidSession) {
  // Expect a retry if FindObjects returns CKR_SESSION_HANDLE_INVALID.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(DoAll(SetArgPointee<3>(kObjectList), Return(CKR_OK)));
  EXPECT_CALL(chaps_mock_, GetAttributeValue(_, _, _, _, _))
      .WillRepeatedly(
          Invoke(/* obj_ptr */ this, &ChapsClientTest::FakeGetCertificateBlob));

  // Call export SPKI.
  std::optional<brillo::Blob> spki =
      chaps_client_.ExportSubjectPublicKeyInfo(std::string(kLabel), kId);

  // Verify the correct blob is returned.
  ASSERT_TRUE(spki.has_value());
  EXPECT_EQ(kCertificateSpkiDer, spki.value());
}

// std::optional<brillo::Blob> ExportSubjectPublicKeyInfo(
//    const std::string& label, const brillo::Blob& id);

TEST_P(ChapsClientTest, FindKeyHandlesInvalidSession) {
  // Expect a retry if FindObjects returns CKR_SESSION_HANDLE_INVALID.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(DoAll(SetArgPointee<3>(kObjectList), Return(CKR_OK)));

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify key is exported successfully.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

TEST_P(ChapsClientTest, GenerateKeyHandlesInvalidSession) {
  // Expect a retry if GenerateKey returns CKR_SESSION_HANDLE_INVALID.
  EXPECT_CALL(chaps_mock_, FindObjects(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kEmptyObjectList), Return(CKR_OK)));
  EXPECT_CALL(chaps_mock_, GenerateKey(_, _, _, _, _, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_OK));

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify output.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

TEST_P(ChapsClientTest, GetAttributeHandlesInvalidSession) {
  // Expect a retry if GetAttribute returns CKR_SESSION_HANDLE_INVALID.
  EXPECT_CALL(chaps_mock_, GetAttributeValue(_, _, _, _, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID))
      .WillRepeatedly(
          Invoke(/* obj_ptr */ this, &ChapsClientTest::FakeGetAttribute));

  // Call export key.
  std::optional<brillo::SecureBlob> encryption_key =
      chaps_client_.ExportOrGenerateEncryptionKey();

  // Verify output.
  ASSERT_TRUE(encryption_key.has_value());
  std::vector<uint8_t> key(encryption_key->begin(), encryption_key->end());
  EXPECT_EQ(kKeyBlob, key);
}

INSTANTIATE_TEST_SUITE_P(ChapsClient,
                         ChapsClientTest,
                         ::testing::Values(ContextAdaptor::Slot::kUser,
                                           ContextAdaptor::Slot::kSystem),
                         TestName);

}  // namespace context
}  // namespace keymaster
}  // namespace arc
