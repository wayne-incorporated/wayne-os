// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymint/context/arc_keymint_context.h"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/stl_util.h>
#include <brillo/secure_blob.h>
#include <chaps/chaps_proxy_mock.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <keymaster/android_keymaster.h>
#include "keymaster/android_keymaster_messages.h"
#include <keymaster/authorization_set.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/UniquePtr.h>

#include "arc/keymint/context/context_adaptor.h"
#include "arc/keymint/context/openssl_utils.h"
#include "arc/keymint/key_data.pb.h"
#include "keymaster/android_keymaster_utils.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace arc::keymint::context {

namespace {

constexpr size_t kKeymasterOperationTableSize = 16;

// TODO(b/274723555): Update these patch levels
constexpr uint32_t kOsVersion = 9;
constexpr uint32_t kOsPatchlevel = 20200205;
constexpr int32_t kKeyMintMessageVersion = 4;
constexpr ::keymaster::KmVersion kKeyMintVersion =
    ::keymaster::KmVersion::KEYMINT_2;

// Arbitrary CK_SLOT_ID for user slot.
constexpr uint64_t kUserSlotId = 11;
// Arbitrary non-zero id.
constexpr uint64_t kSessionId = 42;
// Arbitrary 32 byte keys.
const brillo::SecureBlob kEncryptionKey(32, 99);
// Arbitrary blobs of data.
constexpr std::array<uint8_t, 3> kBlob1{0, 42, 55};
constexpr std::array<uint8_t, 5> kBlob2{0, 17, 66, 4, 92};
// Serialized blobs from valid test keys.
const brillo::Blob kValidKeyBlob1 = {
    75,  239, 39,  15,  44,  24,  183, 240, 205, 96,  48,  161, 139, 175, 60,
    252, 201, 96,  14,  154, 190, 11,  68,  0,   61,  180, 143, 160, 180, 14,
    163, 208, 39,  83,  236, 52,  242, 6,   112, 87,  217, 108, 133, 27,  228,
    207, 181, 148, 102, 141, 175, 18,  143, 248, 138, 65,  62,  111, 62,  67,
    11,  51,  20,  157, 107, 2,   78,  5,   230, 94,  185, 211, 123, 6,   185,
    87,  63,  154, 50,  30,  138, 253, 200, 2,   188, 243, 166, 68,  108, 185,
    58,  146, 14,  203, 189, 92,  36,  228, 185, 249, 71,  201, 6,   231, 204,
    99,  177, 26,  122, 19,  140, 203, 148, 196, 137, 204, 161, 244, 55,  119,
    14,  251, 216, 102, 151, 191, 40,  192, 94,  56,  9,   115, 67,  84,  37,
    31,  108, 185, 56,  218, 137, 57,  169, 245, 176, 5,   100, 200, 177, 246,
    38,  45,  224, 32,  118, 12,  251, 197, 87,  216, 207, 135, 65,  196, 90,
    196, 196, 188, 241, 108, 96,  136, 238, 120, 22,  100, 141, 72,  129, 178,
    194, 89,  42,  198, 166, 27,  224, 197, 216, 208, 250, 245, 137, 67,  55,
    208, 77,  156, 68,  50,  243, 78,  223, 167, 131, 96,  114, 55,  67,  168,
    188, 134, 183, 15,  125, 108, 159, 183, 15,  65,  107, 88,  184, 19,  110,
    146, 113, 40,  35,  31,  109, 137, 201, 2,   233, 0,   122, 236, 253, 148,
    228, 60,  193, 240, 251, 68,  201, 78,  189, 59,  130, 221, 27,  122, 234,
    79,  83,  154, 22,  127, 48,  2,   170, 160, 98,  58,  78};
const brillo::Blob kValidKeyBlob2 = {
    100, 242, 215, 67,  236, 151, 238, 119, 169, 114, 21,  128, 52,  185,
    38,  181, 68,  148, 223, 177, 141, 137, 207, 52,  224, 96,  242, 124,
    3,   144, 146, 99,  112, 190, 97,  5,   57,  226, 45,  10,  141, 116,
    101, 142, 136, 135, 30,  38,  199, 204, 41,  239, 254, 135, 47,  18,
    113, 92,  28,  213, 154, 156, 43,  13,  43,  110, 144, 147, 194, 114,
    8,   247, 139, 174, 114, 155, 8,   69,  21,  135, 114, 164, 116, 150,
    142, 181, 213, 109, 174, 238, 31,  2,   72,  194, 219, 49};

const brillo::Blob kValidMaterial = {
    48,  130, 4,   163, 2,   1,   0,   2,   130, 1,   1,   0,   169, 114, 100,
    45,  165, 138, 30,  149, 75,  204, 124, 25,  207, 50,  252, 15,  50,  63,
    4,   95,  130, 1,   224, 28,  101, 220, 127, 17,  97,  219, 194, 79,  248,
    174, 229, 118, 11,  197, 253, 213, 209, 186, 83,  215, 108, 194, 74,  30,
    228, 200, 38,  36,  62,  85,  184, 62,  43,  132, 247, 137, 185, 60,  184,
    71,  60,  74,  5,   241, 182, 83,  228, 198, 2,   19,  94,  248, 187, 68,
    179, 202, 54,  119, 240, 244, 196, 41,  189, 252, 97,  193, 75,  199, 238,
    213, 89,  176, 8,   66,  248, 146, 27,  169, 244, 238, 79,  240, 17,  23,
    52,  172, 61,  29,  143, 42,  99,  191, 18,  42,  148, 237, 98,  73,  107,
    121, 41,  195, 245, 234, 118, 65,  99,  86,  10,  111, 146, 218, 191, 92,
    198, 114, 23,  253, 42,  30,  240, 34,  35,  200, 230, 116, 145, 32,  56,
    39,  163, 224, 185, 131, 47,  119, 114, 190, 176, 63,  39,  72,  41,  44,
    0,   29,  151, 252, 98,  235, 93,  75,  101, 84,  254, 186, 113, 100, 200,
    123, 243, 157, 57,  15,  84,  104, 124, 35,  229, 130, 218, 8,   134, 30,
    64,  17,  2,   245, 174, 200, 220, 149, 131, 229, 73,  130, 167, 21,  196,
    215, 113, 211, 173, 39,  124, 5,   118, 190, 55,  122, 203, 163, 35,  170,
    193, 116, 212, 231, 89,  83,  220, 31,  90,  88,  179, 74,  71,  42,  199,
    138, 37,  124, 15,  185, 247, 238, 40,  0,   121, 64,  205, 255, 2,   3,
    1,   0,   1,   2,   130, 1,   0,   62,  55,  109, 216, 34,  217, 193, 156,
    0,   238, 110, 188, 205, 75,  3,   169, 18,  194, 119, 185, 23,  211, 215,
    117, 165, 227, 29,  215, 4,   142, 251, 220, 128, 75,  187, 158, 41,  249,
    131, 88,  0,   191, 129, 44,  110, 215, 49,  255, 0,   243, 10,  170, 49,
    39,  41,  84,  206, 134, 238, 155, 39,  164, 71,  103, 132, 152, 11,  113,
    178, 136, 64,  78,  130, 17,  153, 196, 11,  130, 208, 223, 21,  59,  218,
    2,   13,  138, 228, 34,  232, 195, 224, 46,  227, 159, 123, 228, 122, 76,
    24,  216, 17,  7,   73,  19,  61,  207, 192, 126, 188, 76,  231, 205, 212,
    52,  244, 214, 1,   246, 23,  163, 199, 252, 124, 85,  75,  68,  20,  37,
    111, 52,  160, 216, 144, 57,  12,  85,  229, 29,  112, 188, 21,  33,  55,
    96,  221, 60,  116, 4,   173, 59,  155, 206, 104, 47,  231, 74,  162, 189,
    249, 8,   21,  138, 225, 134, 244, 16,  20,  174, 104, 115, 41,  66,  254,
    133, 214, 200, 206, 62,  130, 191, 44,  234, 68,  178, 151, 79,  220, 143,
    53,  235, 85,  196, 62,  16,  64,  103, 189, 88,  28,  35,  41,  160, 242,
    85,  132, 118, 24,  84,  58,  79,  165, 224, 228, 49,  109, 53,  74,  45,
    133, 112, 113, 74,  137, 7,   67,  201, 123, 65,  31,  137, 236, 34,  213,
    135, 102, 224, 159, 17,  126, 136, 22,  102, 254, 4,   32,  63,  117, 163,
    145, 107, 43,  168, 207, 227, 113, 105, 2,   129, 129, 0,   218, 33,  181,
    14,  63,  218, 102, 38,  183, 40,  84,  254, 197, 134, 14,  184, 243, 161,
    46,  230, 191, 99,  241, 224, 45,  216, 0,   6,   51,  157, 179, 87,  7,
    65,  159, 145, 109, 206, 183, 207, 2,   249, 240, 117, 93,  85,  217, 229,
    167, 153, 243, 60,  133, 64,  97,  159, 62,  41,  23,  140, 34,  241, 201,
    149, 73,  75,  224, 140, 119, 247, 148, 191, 26,  137, 222, 57,  219, 180,
    173, 198, 82,  166, 219, 252, 251, 204, 44,  53,  68,  176, 197, 181, 94,
    173, 112, 129, 119, 96,  158, 126, 171, 90,  133, 101, 60,  162, 68,  110,
    139, 245, 100, 125, 31,  169, 140, 54,  181, 29,  23,  133, 129, 187, 42,
    58,  214, 238, 36,  137, 2,   129, 129, 0,   198, 221, 3,   146, 157, 219,
    113, 0,   206, 49,  220, 15,  15,  147, 229, 15,  176, 214, 214, 176, 157,
    242, 133, 28,  116, 90,  64,  144, 91,  50,  148, 77,  84,  96,  113, 4,
    121, 176, 215, 30,  236, 28,  145, 32,  90,  12,  226, 131, 207, 131, 207,
    78,  204, 33,  169, 67,  146, 146, 8,   38,  68,  23,  90,  101, 20,  73,
    84,  230, 199, 59,  32,  149, 223, 227, 77,  53,  228, 93,  167, 178, 67,
    132, 7,   99,  228, 123, 146, 189, 140, 88,  25,  60,  75,  19,  213, 25,
    68,  151, 141, 174, 145, 233, 210, 219, 252, 10,  166, 9,   84,  116, 11,
    229, 22,  28,  39,  242, 85,  67,  91,  197, 65,  180, 201, 36,  184, 124,
    76,  71,  2,   129, 129, 0,   207, 131, 159, 166, 53,  178, 196, 217, 114,
    7,   73,  140, 178, 70,  205, 124, 192, 49,  135, 215, 247, 29,  210, 190,
    77,  126, 158, 207, 71,  141, 112, 78,  139, 213, 175, 66,  255, 238, 215,
    200, 117, 113, 103, 131, 143, 206, 155, 163, 178, 37,  112, 84,  20,  4,
    98,  154, 198, 220, 250, 204, 211, 117, 168, 43,  128, 118, 81,  225, 240,
    67,  53,  91,  244, 152, 82,  52,  66,  194, 137, 75,  17,  216, 49,  146,
    99,  205, 34,  5,   111, 26,  168, 139, 217, 205, 48,  41,  202, 114, 189,
    117, 141, 248, 104, 205, 29,  184, 213, 87,  65,  136, 171, 23,  169, 230,
    119, 64,  152, 94,  91,  193, 35,  224, 245, 212, 210, 33,  237, 217, 2,
    129, 128, 5,   233, 250, 186, 56,  129, 151, 41,  187, 248, 21,  160, 73,
    9,   79,  237, 152, 135, 187, 24,  195, 137, 187, 213, 173, 204, 37,  81,
    101, 180, 234, 94,  38,  93,  59,  223, 51,  51,  68,  34,  130, 73,  19,
    51,  208, 25,  195, 254, 193, 132, 28,  253, 45,  234, 238, 90,  185, 24,
    40,  175, 226, 164, 131, 38,  176, 100, 193, 230, 159, 20,  46,  18,  230,
    246, 158, 140, 52,  191, 104, 70,  79,  229, 180, 70,  143, 59,  241, 144,
    59,  133, 63,  50,  224, 212, 181, 40,  172, 54,  137, 155, 32,  113, 192,
    184, 148, 21,  72,  252, 204, 11,  43,  115, 99,  165, 240, 182, 47,  60,
    242, 148, 186, 48,  131, 46,  217, 97,  176, 239, 2,   129, 128, 21,  166,
    0,   0,   108, 202, 23,  139, 113, 4,   116, 69,  178, 45,  140, 11,  58,
    75,  189, 174, 134, 16,  251, 11,  11,  224, 112, 132, 240, 155, 111, 110,
    161, 110, 228, 220, 151, 196, 187, 170, 92,  181, 25,  206, 103, 158, 112,
    49,  108, 205, 142, 85,  95,  175, 245, 122, 47,  205, 207, 77,  119, 50,
    169, 154, 55,  116, 11,  171, 114, 248, 217, 180, 9,   141, 3,   145, 104,
    59,  79,  31,  56,  191, 190, 66,  127, 143, 106, 153, 119, 185, 214, 108,
    133, 118, 242, 188, 219, 143, 142, 47,  142, 40,  242, 148, 219, 123, 12,
    226, 135, 101, 108, 107, 44,  138, 151, 2,   11,  71,  55,  110, 36,  185,
    216, 173, 250, 125, 226, 236};

// The base 64 SPKI of |kValidMaterial|.
constexpr char kValidBase64Spki[] =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXJkLaWKHpVLzHwZzzL8DzI/BF+CAe"
    "AcZdx/EWHbwk/4ruV2C8X91dG6U9dswkoe5MgmJD5VuD4rhPeJuTy4RzxKBfG2U+TGAhNe+LtE"
    "s8o2d/D0xCm9/GHBS8fu1VmwCEL4khup9O5P8BEXNKw9HY8qY78SKpTtYklreSnD9ep2QWNWCm"
    "+S2r9cxnIX/Soe8CIjyOZ0kSA4J6PguYMvd3K+sD8nSCksAB2X/GLrXUtlVP66cWTIe/OdOQ9U"
    "aHwj5YLaCIYeQBEC9a7I3JWD5UmCpxXE13HTrSd8BXa+N3rLoyOqwXTU51lT3B9aWLNKRyrHii"
    "V8D7n37igAeUDN/wIDAQAB";

constexpr char kChapsKeyLabel[] = "chaps_key_label";
constexpr std::array<uint8_t, 10> kChapsKeyId{61, 11, 8,  28, 36,
                                              64, 69, 42, 96, 14};

::testing::AssertionResult KeyBlobEquals(
    const ::keymaster::KeymasterKeyBlob& a,
    const ::keymaster::KeymasterKeyBlob& b) {
  if (a.key_material_size != b.key_material_size) {
    return ::testing::AssertionFailure()
           << "Sizes differ: a=" << a.key_material_size
           << " b=" << b.key_material_size;
  }

  for (size_t i = 0; i < a.key_material_size; ++i) {
    if (a.key_material[i] != b.key_material[i]) {
      return ::testing::AssertionFailure()
             << "Elements differ: i=" << i << " a=" << a.key_material[i]
             << " b=" << b.key_material[i];
    }
  }
  return ::testing::AssertionSuccess();
}

::testing::AssertionResult AuthorizationSetEquals(
    const ::keymaster::AuthorizationSet& a,
    const ::keymaster::AuthorizationSet& b) {
  if (a.size() != b.size()) {
    return ::testing::AssertionFailure()
           << "Sizes differ: a=" << a.size() << " b=" << b.size();
  }

  for (size_t i = 0; i < a.size(); ++i) {
    if (keymaster_param_compare(&a[i], &b[i]) != 0) {
      return ::testing::AssertionFailure() << "Elements differ at index=" << i;
    }
  }
  return ::testing::AssertionSuccess();
}

keymaster_error_t generateTestKey(
    ::keymaster::AndroidKeymaster* keymaster,
    ::keymaster::KeymasterKeyBlob* generated_key) {
  ::keymaster::GenerateKeyRequest request(kKeyMintMessageVersion);
  ::keymaster::AuthorizationSetBuilder();
  request.key_description =
      ::keymaster::AuthorizationSetBuilder()
          .AesEncryptionKey(128)
          .Padding(KM_PAD_NONE)
          .Authorization(::keymaster::TAG_NO_AUTH_REQUIRED)
          .build();
  ::keymaster::GenerateKeyResponse response(kKeyMintMessageVersion);
  keymaster->GenerateKey(request, &response);
  generated_key->Reset(response.key_blob.key_material_size);
  std::copy(
      response.key_blob.key_material,
      response.key_blob.key_material + response.key_blob.key_material_size,
      generated_key->writable_data());
  return response.error;
}

}  // anonymous namespace

// Expose interesting private members of ArcKeyMintContext for tests.
class ContextTestPeer {
 public:
  static keymaster_error_t SerializeKeyDataBlob(
      const ArcKeyMintContext& context,
      const ::keymaster::KeymasterKeyBlob& key_material,
      const ::keymaster::AuthorizationSet& hidden,
      const ::keymaster::AuthorizationSet& hw_enforced,
      const ::keymaster::AuthorizationSet& sw_enforced,
      ::keymaster::KeymasterKeyBlob* key_blob) {
    return context.SerializeKeyDataBlob(key_material, hidden, hw_enforced,
                                        sw_enforced, key_blob);
  }

  static keymaster_error_t DeserializeKeyDataBlob(
      const ArcKeyMintContext& context,
      const ::keymaster::KeymasterKeyBlob& key_blob,
      const ::keymaster::AuthorizationSet& hidden,
      ::keymaster::KeymasterKeyBlob* key_material,
      ::keymaster::AuthorizationSet* hw_enforced,
      ::keymaster::AuthorizationSet* sw_enforced) {
    return context.DeserializeKeyDataBlob(key_blob, hidden, key_material,
                                          hw_enforced, sw_enforced,
                                          /*key=*/nullptr);
  }

  static size_t PlaceholderKeysSize(ArcKeyMintContext* context) {
    return context->placeholder_keys_.size();
  }

  static ContextAdaptor& context_adaptor(ArcKeyMintContext* context) {
    return context->context_adaptor_;
  }
};

// Provides common values used in tests and sets up the context adaptor
// beforehand so that the context makes no calls to Chaps.
class ArcKeyMintContextTest : public ::testing::Test {
 protected:
  ArcKeyMintContextTest()
      : context_(new ArcKeyMintContext(kKeyMintVersion)),
        keymint_(context_, kKeymasterOperationTableSize),
        key_material_(kBlob1.data(), kBlob1.size()),
        valid_key_blob_(kValidKeyBlob1.data(), kValidKeyBlob1.size()),
        invalid_key_blob_(kBlob2.data(), kBlob2.size()) {}

  void SetUp() override {
    ContextTestPeer::context_adaptor(context_).set_user_slot_for_tests(
        kUserSlotId);
    ContextTestPeer::context_adaptor(context_).set_encryption_key(
        kEncryptionKey);
    // All values pushed into authorization sets below are arbitrary.
    hidden_.push_back(::keymaster::TAG_APPLICATION_ID, kBlob1.data(),
                      kBlob1.size());
    hidden_.push_back(::keymaster::TAG_APPLICATION_DATA, kBlob2.data(),
                      kBlob2.size());
    hw_enforced_.push_back(::keymaster::TAG_CALLER_NONCE);
    hw_enforced_.push_back(::keymaster::TAG_NONCE, kBlob1.data(),
                           kBlob1.size());
    sw_enforced_.push_back(::keymaster::TAG_KEY_SIZE, 47);
    sw_enforced_.push_back(::keymaster::TAG_NO_AUTH_REQUIRED);
  }

  ArcKeyMintContext* context_;  // Owned by |keymint_|.
  ::keymaster::AndroidKeymaster keymint_;
  const ::keymaster::KeymasterKeyBlob key_material_;
  const ::keymaster::KeymasterKeyBlob valid_key_blob_;
  // This blob is invalid because it is not long enough.
  const ::keymaster::KeymasterKeyBlob invalid_key_blob_;
  ::keymaster::AuthorizationSet hidden_;
  ::keymaster::AuthorizationSet hw_enforced_;
  ::keymaster::AuthorizationSet sw_enforced_;
};

TEST_F(ArcKeyMintContextTest, CreateKeyBlob) {
  // Create a valid key blob.
  ::keymaster::KeymasterKeyBlob key_material(kValidMaterial.data(),
                                             kValidMaterial.size());
  ::keymaster::AuthorizationSet description;
  ::keymaster::KeymasterKeyBlob blob;
  ::keymaster::AuthorizationSet hw_enforced;
  ::keymaster::AuthorizationSet sw_enforced;
  keymaster_error_t error =
      context_->CreateKeyBlob(description, KM_ORIGIN_GENERATED, key_material,
                              &blob, &hw_enforced, &sw_enforced);

  // Verify operation succeeds.
  ASSERT_EQ(KM_ERROR_OK, error);
}

TEST_F(ArcKeyMintContextTest, ParseKeyBlob) {
  // Parse a valid key blob.
  ::keymaster::KeymasterKeyBlob blob(kValidKeyBlob1.data(),
                                     kValidKeyBlob1.size());
  ::keymaster::AuthorizationSet additional;
  ::keymaster::UniquePtr<::keymaster::Key> key;
  keymaster_error_t error = context_->ParseKeyBlob(blob, additional, &key);

  // Verify operation succeeds.
  ASSERT_EQ(KM_ERROR_OK, error);
}

TEST_F(ArcKeyMintContextTest, CreateThenParseKeyBlob) {
  // Create a valid key blob.
  ::keymaster::KeymasterKeyBlob key_material(kValidMaterial.data(),
                                             kValidMaterial.size());
  ::keymaster::AuthorizationSet description;
  description.push_back(::keymaster::TAG_ALGORITHM, KM_ALGORITHM_RSA);
  ::keymaster::KeymasterKeyBlob blob;
  ::keymaster::AuthorizationSet hw_enforced;
  ::keymaster::AuthorizationSet sw_enforced;
  keymaster_error_t error =
      context_->CreateKeyBlob(description, KM_ORIGIN_GENERATED, key_material,
                              &blob, &hw_enforced, &sw_enforced);

  // Verify creation succeeds.
  ASSERT_EQ(KM_ERROR_OK, error);

  // Parse the created blob.
  ::keymaster::AuthorizationSet additional;
  ::keymaster::UniquePtr<::keymaster::Key> key;
  error = context_->ParseKeyBlob(blob, additional, &key);

  // Verify parsing succeeds and |key| contains the right |key_material|.
  ASSERT_EQ(KM_ERROR_OK, error);
  EXPECT_TRUE(KeyBlobEquals(key_material, key->key_material()));
}

TEST_F(ArcKeyMintContextTest, CreateThenParseChapsKeyBlob) {
  // Set up a Chaps placeholder key for the |kValidMaterial| we will install.
  mojom::ChapsKeyDataPtr key_data = mojom::ChapsKeyData::New(
      std::string(kChapsKeyLabel),
      std::string(kChapsKeyId.begin(), kChapsKeyId.end()));
  mojom::ChromeOsKeyPtr cros_key = mojom::ChromeOsKey::New(
      kValidBase64Spki, mojom::KeyData::NewChapsKeyData(std::move(key_data)));
  std::vector<mojom::ChromeOsKeyPtr> placeholders;
  placeholders.push_back(std::move(cros_key));
  context_->set_placeholder_keys(std::move(placeholders));

  EXPECT_EQ(ContextTestPeer::PlaceholderKeysSize(context_), 1);

  // Create a valid key blob.
  ::keymaster::KeymasterKeyBlob key_material(kValidMaterial.data(),
                                             kValidMaterial.size());
  ::keymaster::AuthorizationSet description;
  description.push_back(::keymaster::TAG_ALGORITHM, KM_ALGORITHM_RSA);
  ::keymaster::KeymasterKeyBlob blob;
  ::keymaster::AuthorizationSet hw_enforced;
  ::keymaster::AuthorizationSet sw_enforced;
  keymaster_error_t error =
      context_->CreateKeyBlob(description, KM_ORIGIN_GENERATED, key_material,
                              &blob, &hw_enforced, &sw_enforced);

  // Verify creation succeeds and the placeholder key is consumed.
  ASSERT_EQ(KM_ERROR_OK, error);
  EXPECT_EQ(ContextTestPeer::PlaceholderKeysSize(context_), 0);

  // Parse the created blob.
  ::keymaster::AuthorizationSet additional;
  ::keymaster::UniquePtr<::keymaster::Key> key;
  error = context_->ParseKeyBlob(blob, additional, &key);

  // Verify parsing succeeds and |key| contains the right ChapsKey.
  ASSERT_EQ(KM_ERROR_OK, error);
  ChapsKey* chaps_key = static_cast<ChapsKey*>(key.get());
  ASSERT_NE(chaps_key, nullptr);
  EXPECT_EQ(chaps_key->label(), kChapsKeyLabel);
  EXPECT_EQ(chaps_key->id(),
            brillo::Blob(kChapsKeyId.begin(), kChapsKeyId.end()));
}

TEST_F(ArcKeyMintContextTest, SerializeKeyDataBlob) {
  // Serialize.
  ::keymaster::KeymasterKeyBlob key_blob;
  keymaster_error_t error = ContextTestPeer::SerializeKeyDataBlob(
      *context_, key_material_, hidden_, hw_enforced_, sw_enforced_, &key_blob);

  // Verify operation succeeds and blob is at least the size of IV and tag.
  ASSERT_EQ(KM_ERROR_OK, error);
  ASSERT_GT(key_blob.key_material_size, kIvSize + kTagSize);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob) {
  // Prepare.
  ::keymaster::KeymasterKeyBlob key_blob(kValidKeyBlob2.data(),
                                         kValidKeyBlob2.size());

  // Deserialize.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);

  // Verify operation succeeded.
  ASSERT_EQ(KM_ERROR_OK, error);
}

TEST_F(ArcKeyMintContextTest, SerializeThenDeserialize) {
  // Serialize.
  ::keymaster::KeymasterKeyBlob key_blob;
  keymaster_error_t error = ContextTestPeer::SerializeKeyDataBlob(
      *context_, key_material_, hidden_, hw_enforced_, sw_enforced_, &key_blob);
  ASSERT_EQ(KM_ERROR_OK, error);

  // Deserialize.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);
  ASSERT_EQ(KM_ERROR_OK, error);

  // Verify results.
  EXPECT_TRUE(KeyBlobEquals(key_material_, out_key_material));
  EXPECT_TRUE(AuthorizationSetEquals(hw_enforced_, out_hw_enforced));
  EXPECT_TRUE(AuthorizationSetEquals(sw_enforced_, out_sw_enforced));
}

TEST_F(ArcKeyMintContextTest, UpgradeKeyBlob) {
  // Prepare a key generated at an arbitrary system version.
  context_->SetSystemVersion(kOsVersion, kOsPatchlevel);
  ::keymaster::KeymasterKeyBlob generated_key;
  keymaster_error_t error = generateTestKey(&keymint_, &generated_key);
  ASSERT_EQ(error, KM_ERROR_OK);

  // Verify the old blob can't be used after a system upgrade.
  context_->SetSystemVersion(kOsVersion, kOsPatchlevel + 1);
  ::keymaster::GetKeyCharacteristicsRequest characteristicsRequest1(
      kKeyMintMessageVersion);
  characteristicsRequest1.SetKeyMaterial(generated_key);
  ::keymaster::GetKeyCharacteristicsResponse characteristicsResponse1(
      kKeyMintMessageVersion);
  keymint_.GetKeyCharacteristics(characteristicsRequest1,
                                 &characteristicsResponse1);
  ASSERT_EQ(characteristicsResponse1.error, KM_ERROR_KEY_REQUIRES_UPGRADE);

  // Upgrade the key blob.
  ::keymaster::KeymasterKeyBlob key_blob(generated_key);
  ::keymaster::KeymasterKeyBlob upgraded_key_blob;
  ::keymaster::AuthorizationSet upgrade_params;
  error =
      context_->UpgradeKeyBlob(key_blob, upgrade_params, &upgraded_key_blob);
  ASSERT_EQ(error, KM_ERROR_OK);

  // Verify the blob can be used without errors once upgraded.
  ::keymaster::GetKeyCharacteristicsRequest characteristicsRequest2(
      kKeyMintMessageVersion);
  characteristicsRequest2.SetKeyMaterial(upgraded_key_blob);
  ::keymaster::GetKeyCharacteristicsResponse characteristicsResponse2(
      kKeyMintMessageVersion);
  keymint_.GetKeyCharacteristics(characteristicsRequest2,
                                 &characteristicsResponse2);
  ASSERT_EQ(characteristicsResponse2.error, KM_ERROR_OK);
}

TEST_F(ArcKeyMintContextTest, UpgradeKeyBlobAlreadyUpToDate) {
  // Prepare a key generated at an arbitrary system version.
  context_->SetSystemVersion(kOsVersion, kOsPatchlevel);
  ::keymaster::KeymasterKeyBlob generated_key;
  keymaster_error_t error = generateTestKey(&keymint_, &generated_key);
  ASSERT_EQ(error, KM_ERROR_OK);

  // Verify upgrading the blob does nothing (returns an empty blob).
  ::keymaster::KeymasterKeyBlob key_blob(generated_key);
  ::keymaster::KeymasterKeyBlob upgraded_key_blob;
  ::keymaster::AuthorizationSet upgrade_params;
  error =
      context_->UpgradeKeyBlob(key_blob, upgrade_params, &upgraded_key_blob);
  ASSERT_EQ(error, KM_ERROR_OK);
  ASSERT_EQ(upgraded_key_blob.key_material_size, 0);
}

TEST_F(ArcKeyMintContextTest, UpgradeKeyBlobLowerVersionError) {
  // Prepare a key generated at an arbitrary system version.
  context_->SetSystemVersion(kOsVersion, kOsPatchlevel);
  ::keymaster::KeymasterKeyBlob generated_key;
  keymaster_error_t error = generateTestKey(&keymint_, &generated_key);
  ASSERT_EQ(error, KM_ERROR_OK);

  // Downgrade the system to a previous version.
  context_->SetSystemVersion(kOsVersion, kOsPatchlevel - 1);

  // Verify the old blob becomes invalid.
  ::keymaster::GetKeyCharacteristicsRequest characteristicsRequest1(
      kKeyMintMessageVersion);
  characteristicsRequest1.SetKeyMaterial(generated_key);
  ::keymaster::GetKeyCharacteristicsResponse characteristicsResponse1(
      kKeyMintMessageVersion);
  keymint_.GetKeyCharacteristics(characteristicsRequest1,
                                 &characteristicsResponse1);
  EXPECT_EQ(characteristicsResponse1.error, KM_ERROR_INVALID_KEY_BLOB);

  // Verify the blob cannot be upgraded.
  ::keymaster::KeymasterKeyBlob key_blob(generated_key);
  ::keymaster::KeymasterKeyBlob upgraded_key_blob;
  ::keymaster::AuthorizationSet upgrade_params;
  error =
      context_->UpgradeKeyBlob(key_blob, upgrade_params, &upgraded_key_blob);
  ASSERT_EQ(error, KM_ERROR_INVALID_ARGUMENT);
}

TEST_F(ArcKeyMintContextTest, WrongHiddenSet) {
  // Serialize.
  ::keymaster::KeymasterKeyBlob key_blob;
  keymaster_error_t error = ContextTestPeer::SerializeKeyDataBlob(
      *context_, key_material_, hidden_, hw_enforced_, sw_enforced_, &key_blob);
  ASSERT_EQ(KM_ERROR_OK, error);

  // Deserialize the same key_blob with a different hidden authorization set.
  ::keymaster::AuthorizationSet other_hidden(hw_enforced_);
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, other_hidden, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);

  // Verify operation fails.
  ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, error);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob_ShortInputError) {
  // Prepare an input so short it can't be valid.
  ::keymaster::KeymasterKeyBlob key_blob(invalid_key_blob_);

  // Deserialize.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);

  // Verify operation fails.
  ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, error);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob_InvalidSignatureError) {
  // Prepare an invalid input by changing one byte from a valid blob.
  ::keymaster::KeymasterKeyBlob key_blob(kValidKeyBlob2.data(),
                                         kValidKeyBlob2.size());
  // Change last byte because that's part of signature.
  key_blob.writable_data()[kValidKeyBlob2.size() - 1] = 42;

  // Deserialize.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);

  // Verify operation fails.
  ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, error);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob_InvalidKeyDataBlobError) {
  // Prepare an invalid input by changing one byte from a valid blob.
  ::keymaster::KeymasterKeyBlob key_blob(kValidKeyBlob2.data(),
                                         kValidKeyBlob2.size());
  // Change first byte because that's part of encrypted key data.
  key_blob.writable_data()[0] = 42;

  // Deserialize.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);

  // Verify results.
  ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, error);
}

TEST_F(ArcKeyMintContextTest, ParseKeyBlob_NullOutputParameterError) {
  // Verify ParseKeyBlob returns error if the |key| output parameter is null.
  ::keymaster::KeymasterKeyBlob blob(kValidKeyBlob1.data(),
                                     kValidKeyBlob1.size());
  ::keymaster::AuthorizationSet additional;
  keymaster_error_t error =
      context_->ParseKeyBlob(blob, additional, /* key */ nullptr);
  ASSERT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL, error);
}

TEST_F(ArcKeyMintContextTest, SerializeKeyDataBlob_NullOutputParameterError) {
  // Verify serialize returns error if the output parameter is null.
  keymaster_error_t error = ContextTestPeer::SerializeKeyDataBlob(
      *context_, key_material_, hidden_, hw_enforced_, sw_enforced_,
      /* key_blob */ nullptr);
  ASSERT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL, error);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob_NullOutputParameterError) {
  // Verify deserialize returns error if any of the output parameters are null.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;

  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, valid_key_blob_, hidden_, /* key_material */ nullptr,
      &out_hw_enforced, &out_sw_enforced);
  ASSERT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL, error);

  error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, valid_key_blob_, hidden_, &out_key_material,
      /* hw_enforced */ nullptr, &out_sw_enforced);
  ASSERT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL, error);

  error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, valid_key_blob_, hidden_, &out_key_material, &out_hw_enforced,
      /* sw_enforced */ nullptr);
  ASSERT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL, error);
}

TEST_F(ArcKeyMintContextTest, SerializeKeyDataBlob_EncryptionKeyError) {
  // Clear the cached encryption key.
  ContextTestPeer::context_adaptor(context_).set_encryption_key(std::nullopt);
  // Make sure an existing key won't be found in chaps.
  ::testing::StrictMock<::chaps::ChapsProxyMock> chaps_mock(
      /* is_initialized */ true);
  EXPECT_CALL(chaps_mock, OpenSession(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSessionId), Return(CKR_OK)));
  EXPECT_CALL(chaps_mock, CloseSession(_, _)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(chaps_mock, FindObjectsInit(_, _, _))
      .WillOnce(Return(CKR_ATTRIBUTE_TYPE_INVALID));
  // Attempt to generate a new key will fail.
  EXPECT_CALL(chaps_mock, GenerateKey(_, _, _, _, _, _))
      .WillOnce(Return(CKR_ATTRIBUTE_TYPE_INVALID));

  // Serialize.
  ::keymaster::KeymasterKeyBlob key_blob;
  keymaster_error_t error = ContextTestPeer::SerializeKeyDataBlob(
      *context_, key_material_, hidden_, hw_enforced_, sw_enforced_, &key_blob);

  // Verify it errors.
  ASSERT_EQ(KM_ERROR_UNKNOWN_ERROR, error);
}

TEST_F(ArcKeyMintContextTest, DeserializeKeyDataBlob_InvalidKeyDataError) {
  // Prepare a valid encryption of an invalid KeyData (missing auth sets).
  KeyData key_data;
  key_data.mutable_arc_key()->set_key_material("arbitrary key material");
  brillo::SecureBlob key_data_blob(key_data.ByteSizeLong());
  key_data.SerializeWithCachedSizesToArray(key_data_blob.data());
  brillo::Blob hidden_blob =
      context_->TestSerializeAuthorizationSetToBlob(hidden_);
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(kEncryptionKey, hidden_blob, key_data_blob);
  ASSERT_TRUE(encrypted.has_value());

  // Copy encrypted data to keymaster key blob.
  ::keymaster::KeymasterKeyBlob key_blob(encrypted->data(), encrypted->size());

  // Verify deserialize returns error.
  ::keymaster::KeymasterKeyBlob out_key_material;
  ::keymaster::AuthorizationSet out_hw_enforced;
  ::keymaster::AuthorizationSet out_sw_enforced;
  keymaster_error_t error = ContextTestPeer::DeserializeKeyDataBlob(
      *context_, key_blob, hidden_, &out_key_material, &out_hw_enforced,
      &out_sw_enforced);
  ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, error);
}

}  // namespace arc::keymint::context
