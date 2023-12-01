// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/pkcs11_key_store.h"

#include <cstring>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include "nss/pkcs11t.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/data_encoding.h>
#include <chaps/attributes.h>
#include <chaps/chaps_proxy_mock.h>
#include <chaps/token_manager_client_mock.h>
#include <brillo/cryptohome.h>
#include <brillo/map_utils.h>
#include <gmock/gmock.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/stubs/strutil.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::Truly;

namespace {

const uint64_t kSession = 7;  // Arbitrary non-zero value.
const char kDefaultUser[] = "test_user";

const char kValidRsaPublicKeyHex[] =
    "3082010A0282010100"
    "961037BC12D2A298BEBF06B2D5F8C9B64B832A2237F8CF27D5F96407A6041A4D"
    "AD383CB5F88E625F412E8ACD5E9D69DF0F4FA81FCE7955829A38366CBBA5A2B1"
    "CE3B48C14B59E9F094B51F0A39155874C8DE18A0C299EBF7A88114F806BE4F25"
    "3C29A509B10E4B19E31675AFE3B2DA77077D94F43D8CE61C205781ED04D183B4"
    "C349F61B1956C64B5398A3A98FAFF17D1B3D9120C832763EDFC8F4137F6EFBEF"
    "46D8F6DE03BD00E49DEF987C10BDD5B6F8758B6A855C23C982DDA14D8F0F2B74"
    "E6DEFA7EEE5A6FC717EB0FF103CB8049F693A2C8A5039EF1F5C025DC44BD8435"
    "E8D8375DADE00E0C0F5C196E04B8483CC98B1D5B03DCD7E0048B2AB343FFC11F"
    "0203"
    "010001";

const char kValidRsaCertificateHex[] =
    "3082040f308202f7a003020102020900bd0f8fd6bf496b67300d06092a864886"
    "f70d01010b050030819d310b3009060355040613025553311330110603550408"
    "0c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e20"
    "5669657731133011060355040a0c0a4368726f6d69756d4f533111300f060355"
    "040b0c08556e6974546573743117301506035504030c0e506b637331314b6579"
    "53746f72653120301e06092a864886f70d010901161174657374406368726f6d"
    "69756d2e6f7267301e170d3135303231383137303132345a170d313731313133"
    "3137303132345a30819d310b3009060355040613025553311330110603550408"
    "0c0a43616c69666f726e69613116301406035504070c0d4d6f756e7461696e20"
    "5669657731133011060355040a0c0a4368726f6d69756d4f533111300f060355"
    "040b0c08556e6974546573743117301506035504030c0e506b637331314b6579"
    "53746f72653120301e06092a864886f70d010901161174657374406368726f6d"
    "69756d2e6f726730820122300d06092a864886f70d01010105000382010f0030"
    "82010a0282010100a8fb9e12b1e5298b9a24fabc3901d00c32057392c763836e"
    "0b55cff8e67d39b9b9853920fd615688b3e13c03a10cb5668187819172d1d269"
    "70f0ff8d4371ac581f6970a0e43a1d0d61a94741a771fe86aee45ab0ca059b1f"
    "c067f7416f08544cc4d08ec884b6d4327bb3ec0dc0789639375bd159df0efd87"
    "1cf4d605778c7a68c96b94cf0a6c29f9a23bc027e8250084eb2dfca817b20f57"
    "a6fe09513f884389db7b90788aea70c6e1638f24e39553ac0f859e585965c425"
    "9ed7b9680fde3e059f254d8c9494f6ab425ede80d63366dfcb7cc311f5bc6fb0"
    "1c27d81f4c5112d04b7614c37ba19c014916816372c773e4e44564fac34565ad"
    "ebf38fe56c1413170203010001a350304e301d0603551d0e04160414fe13c7db"
    "459bd2881e9113198e1f072e16cea144301f0603551d23041830168014fe13c7"
    "db459bd2881e9113198e1f072e16cea144300c0603551d13040530030101ff30"
    "0d06092a864886f70d01010b05000382010100a163d636ac64bd6f67eca53708"
    "5f92abc993a40fd0c0222a56b262c29f88057a3edf9abac024756ad85d7453d8"
    "4782e0be65d176aecfb0fbfc88ca567d17124fa190cb5ce832264360dd6daee1"
    "e121428de28dda0b8ba117a1be3cf438efd060a3b5fc812e7eba70cec12cb609"
    "738fc7d0912546c42b5aaadb142adce2167c7f30cd9e0049687d384334335aff"
    "72aebd1745a0aac4be816365969347f064f36f7fdec69f970f28b87061650470"
    "c63be8475bb23d0485985fb77c7cdd9d9fe008211a9ddd0fe68efb0b47cf629c"
    "941d31e3c2f88e670e7e4ef1129febad000e6a16222779fbfe34641e5243ca38"
    "74e2ad06f9585a00bec014744d3175ecc4808d";

constexpr char kValidEccPublicKeyHex[] =
    "3059301306072A8648CE3D020106082A8648CE3D030107034200045C9633047E7518B3E0DF"
    "6C019BAA7CC8D0CB1F18DB781B382E02273054A304CCBEEAD2ED273DA1D6FCDFAB8B55DE4E"
    "830FF43899F82DB6104381615992542F3D";

constexpr char kValidEccCertificateHex[] =
    "3082032930820211a00302010202160174fb9852da9f991b7fd47ebd190000000000001418"
    "300d06092a864886f70d01010505003081853120301e060355040313175072697661637920"
    "434120496e7465726d65646961746531123010060355040b13094368726f6d65204f533113"
    "3011060355040a130a476f6f676c6520496e63311630140603550407130d4d6f756e746169"
    "6e2056696577311330110603550408130a43616c69666f726e6961310b3009060355040613"
    "025553301e170d3230313030363034313032395a170d3232313030363034313032395a303d"
    "31183016060355040b130f73746174653a646576656c6f7065723121301f060355040a1318"
    "4368726f6d652044657669636520456e74657270726973653059301306072a8648ce3d0201"
    "06082a8648ce3d030107034200045c9633047e7518b3e0df6c019baa7cc8d0cb1f18db781b"
    "382e02273054a304ccbeead2ed273da1d6fcdfab8b55de4e830ff43899f82db61043816159"
    "92542f3da381a030819d30290603551d0e04220420837f40ecb000f7ffccda6dab8cd526d9"
    "43b6fe8ce56c84be5dc70cd3ed8f7410302b0603551d23042430228020f420b6d9d862f68b"
    "0915ce8b57a4fc574eb8c17ca5f9e656dbd0529429bd6d7f300e0603551d0f0101ff040403"
    "020780300c0603551d130101ff0402300030110603551d20040a300830060604551d200030"
    "12060a2b06010401d679020113040404020802300d06092a864886f70d0101050500038201"
    "010028a2e3a90c10a850cbee4e575da068bee21753212cc551b0f09eb327a15df01dffec87"
    "2509dedf06c9f34a5e9c987fb5c0d0878a400056c082f015d3153159a38dd71b6dd73e8dad"
    "2f1ce6ac43ed7cf550e8627b5d21dcf41661fcbc58075be7993b8cd7c06941b712ae052609"
    "6a20e559c9fb0cf3da807d261563cdddc74c18998ebd2859b26156d0c8bee2784dc8d6aeff"
    "d5400331466bdec5f6384cdad7f5e5eb620a246eb0e0ac8624e2f76d70207a4574adb53277"
    "4974ef08aedfb8dd3c05979b126414d17a7c1ad5bbc13f0bf95b1cded312837839aa344979"
    "151dc4f70ad86c842091d305a9b667b4e4bd67d6b2e3aa1df385a09553ae2028c9f18b45";

std::string HexDecode(const std::string hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return std::string(reinterpret_cast<char*>(output.data()), output.size());
}

std::string Sha1(const std::string& input) {
  unsigned char output[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char*>(input.data()), input.size(),
       output);
  return std::string(reinterpret_cast<char*>(output), SHA_DIGEST_LENGTH);
}

class ScopedFakeSalt {
 public:
  ScopedFakeSalt() : salt_(128, 0) {
    brillo::cryptohome::home::SetSystemSalt(&salt_);
  }
  ~ScopedFakeSalt() { brillo::cryptohome::home::SetSystemSalt(nullptr); }

 private:
  std::string salt_;
};

class ScopedDisableVerboseLogging {
 public:
  ScopedDisableVerboseLogging()
      : original_severity_(logging::GetMinLogLevel()) {
    logging::SetMinLogLevel(logging::LOGGING_INFO);
  }
  ~ScopedDisableVerboseLogging() {
    logging::SetMinLogLevel(original_severity_);
  }

 private:
  logging::LogSeverity original_severity_;
};

}  // namespace

namespace attestation {

typedef chaps::ChapsProxyMock Pkcs11Mock;

// Implements a fake PKCS #11 object store.  Labeled data blobs can be stored
// and later retrieved.  The mocked interface is ChapsInterface so these
// tests must be linked with the Chaps PKCS #11 library.  The mock class itself
// is part of the Chaps package; it is reused here to avoid duplication (see
// chaps_proxy_mock.h).
class KeyStoreTest : public testing::Test {
 public:
  KeyStoreTest()
      : pkcs11_(false),  // Do not pre-initialize the mock PKCS #11 library.
                         // This just controls whether the first call to
                         // C_Initialize returns 'already initialized'.
        next_handle_(1) {}
  KeyStoreTest(const KeyStoreTest&) = delete;
  KeyStoreTest& operator=(const KeyStoreTest&) = delete;

  ~KeyStoreTest() override = default;

  void SetUp() override {
    std::vector<uint64_t> slot_list = {0, 1};
    ON_CALL(pkcs11_, GetSlotList(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(slot_list), Return(0)));
    ON_CALL(pkcs11_, OpenSession(_, _, _, _))
        .WillByDefault(DoAll(SetArgPointee<3>(kSession), Return(0)));
    ON_CALL(pkcs11_, CloseSession(_, _)).WillByDefault(Return(0));
    ON_CALL(pkcs11_, CreateObject(_, _, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::CreateObject));
    ON_CALL(pkcs11_, DestroyObject(_, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::DestroyObject));
    ON_CALL(pkcs11_, GetAttributeValue(_, _, _, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::GetAttributeValue));
    ON_CALL(pkcs11_, SetAttributeValue(_, _, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::SetAttributeValue));
    ON_CALL(pkcs11_, FindObjectsInit(_, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::FindObjectsInit));
    ON_CALL(pkcs11_, FindObjects(_, _, _, _))
        .WillByDefault(Invoke(this, &KeyStoreTest::FindObjects));
    ON_CALL(pkcs11_, FindObjectsFinal(_, _)).WillByDefault(Return(0));
    base::FilePath system_path("/var/lib/chaps");
    ON_CALL(token_manager_, GetTokenPath(_, 0, _))
        .WillByDefault(DoAll(SetArgPointee<2>(system_path), Return(true)));
    base::FilePath user_path(brillo::cryptohome::home::GetDaemonStorePath(
        brillo::cryptohome::home::Username(kDefaultUser), "chaps"));
    ON_CALL(token_manager_, GetTokenPath(_, 1, _))
        .WillByDefault(DoAll(SetArgPointee<2>(user_path), Return(true)));
  }

  // Stores a new labeled object, only CKA_LABEL and CKA_VALUE are relevant.
  virtual uint32_t CreateObject(const brillo::SecureBlob& isolate,
                                uint64_t session_id,
                                const std::vector<uint8_t>& attributes,
                                uint64_t* new_object_handle) {
    *new_object_handle = next_handle_++;
    std::string label = GetValue(attributes, CKA_LABEL);
    handles_[*new_object_handle] = label;
    values_[label] = GetValue(attributes, CKA_VALUE);
    labels_[label] = *new_object_handle;
    return CKR_OK;
  }

  // Deletes a labeled object.
  virtual uint32_t DestroyObject(const brillo::SecureBlob& isolate,
                                 uint64_t session_id,
                                 uint64_t object_handle) {
    std::string label = handles_[object_handle];
    handles_.erase(object_handle);
    values_.erase(label);
    labels_.erase(label);
    return CKR_OK;
  }

  // Supports reading CKA_VALUE.
  virtual uint32_t GetAttributeValue(const brillo::SecureBlob& isolate,
                                     uint64_t session_id,
                                     uint64_t object_handle,
                                     const std::vector<uint8_t>& attributes_in,
                                     std::vector<uint8_t>* attributes_out) {
    std::string label = handles_[object_handle];
    std::string value = values_[label];
    chaps::Attributes parsed;
    parsed.Parse(attributes_in);
    if (parsed.num_attributes() == 1 &&
        parsed.attributes()[0].type == CKA_LABEL)
      value = label;
    if (parsed.num_attributes() != 1 ||
        (parsed.attributes()[0].type != CKA_VALUE &&
         parsed.attributes()[0].type != CKA_LABEL) ||
        (parsed.attributes()[0].pValue &&
         parsed.attributes()[0].ulValueLen != value.size()))
      return CKR_GENERAL_ERROR;
    parsed.attributes()[0].ulValueLen = value.size();
    if (parsed.attributes()[0].pValue)
      memcpy(parsed.attributes()[0].pValue, value.data(), value.size());
    parsed.Serialize(attributes_out);
    return CKR_OK;
  }

  // Supports writing CKA_VALUE.
  virtual uint32_t SetAttributeValue(const brillo::SecureBlob& isolate,
                                     uint64_t session_id,
                                     uint64_t object_handle,
                                     const std::vector<uint8_t>& attributes) {
    values_[handles_[object_handle]] = GetValue(attributes, CKA_VALUE);
    return CKR_OK;
  }

  // Finds stored objects by CKA_LABEL or CKA_VALUE. If no CKA_LABEL or
  // CKA_VALUE, find all objects.
  virtual uint32_t FindObjectsInit(const brillo::SecureBlob& isolate,
                                   uint64_t session_id,
                                   const std::vector<uint8_t>& attributes) {
    std::string label = GetValue(attributes, CKA_LABEL);
    std::string value = GetValue(attributes, CKA_VALUE);
    found_objects_.clear();
    if (label.empty() && value.empty()) {
      // Find all objects.
      found_objects_ = brillo::GetMapKeysAsVector(handles_);
    } else if (!label.empty() && labels_.count(label) > 0) {
      // Find only the object with |label|.
      found_objects_.push_back(labels_[label]);
    } else {
      // Find all objects with |value|.
      for (const auto& item : values_) {
        if (item.second == value && labels_.count(item.first) > 0) {
          found_objects_.push_back(labels_[item.first]);
        }
      }
    }
    return CKR_OK;
  }

  // Reports a 'found' object based on find_status_.
  virtual uint32_t FindObjects(const brillo::SecureBlob& isolate,
                               uint64_t session_id,
                               uint64_t max_object_count,
                               std::vector<uint64_t>* object_list) {
    while (!found_objects_.empty() && object_list->size() < max_object_count) {
      object_list->push_back(found_objects_.back());
      found_objects_.pop_back();
    }
    return CKR_OK;
  }

  static std::function<bool(const std::vector<uint8_t>&)> CheckCkaId(
      uint64_t expected_key_type) {
    return [expected_key_type](const std::vector<uint8_t> attrs) {
      auto klass_str = GetValue(attrs, CKA_CLASS);
      EXPECT_EQ(klass_str.length(), sizeof(CKO_PRIVATE_KEY));
      unsigned long klass = 0;  // NOLINT (size is platform dependent)
      std::memcpy(&klass, klass_str.c_str(), sizeof(CKO_PRIVATE_KEY));

      //  CKA_KEY_TYPE and {CKA_MODULUS, CKA_EC_POINT} not specified for
      //  CKO_CERTIFICATE
      if (klass != CKO_PUBLIC_KEY && klass != CKO_PRIVATE_KEY) {
        return true;
      }

      auto cka_id = GetValue(attrs, CKA_ID);
      auto cka_key_type = GetValue(attrs, CKA_KEY_TYPE);
      EXPECT_EQ(cka_key_type.length(), sizeof(CKK_RSA));
      unsigned long key_type = 0;  // NOLINT (size is platform dependent)
      std::memcpy(&key_type, cka_key_type.c_str(), sizeof(CKK_RSA));
      EXPECT_EQ(expected_key_type, key_type);
      if (key_type == CKK_EC) {
        auto ecc_point = GetValue(attrs, CKA_EC_POINT);
        //  remove ASN.1 tag + len
        EXPECT_EQ(Sha1(ecc_point.substr(2)), cka_id);
      }
      if (key_type == CKK_RSA) {
        auto modulus = GetValue(attrs, CKA_MODULUS);
        EXPECT_EQ(Sha1(modulus), cka_id);
      }
      return true;
    };
  }

 protected:
  NiceMock<Pkcs11Mock> pkcs11_;
  NiceMock<chaps::TokenManagerClientMock> token_manager_;

 private:
  // A helper to pull the value for a given attribute out of a serialized
  // template.
  static std::string GetValue(const std::vector<uint8_t>& attributes,
                              CK_ATTRIBUTE_TYPE type) {
    chaps::Attributes parsed;
    parsed.Parse(attributes);
    CK_ATTRIBUTE_PTR array = parsed.attributes();
    for (CK_ULONG i = 0; i < parsed.num_attributes(); ++i) {
      if (array[i].type == type) {
        if (!array[i].pValue)
          return "";
        return std::string(reinterpret_cast<char*>(array[i].pValue),
                           array[i].ulValueLen);
      }
    }
    return "";
  }

  std::map<std::string, std::string> values_;  // The fake store: label->value
  std::map<uint64_t, std::string> handles_;    // The fake store: handle->label
  std::map<std::string, uint64_t> labels_;     // The fake store: label->handle
  std::vector<uint64_t> found_objects_;        // The most recent search results
  uint64_t next_handle_;                       // Tracks handle assignment
  ScopedFakeSalt fake_system_salt_;
  // We want to avoid all the Chaps verbose logging.
  ScopedDisableVerboseLogging no_verbose_logging;
};

// This test assumes that chaps in not available on the system running the test.
// The purpose of this test is to exercise the C_Initialize failure code path.
// Without a mock, the Chaps library will attempt to connect to the Chaps daemon
// unsuccessfully, resulting in a C_Initialize failure.
TEST(KeyStoreTest_NoMock, Pkcs11NotAvailable) {
  chaps::TokenManagerClient token_manager;
  Pkcs11KeyStore key_store(&token_manager);
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_FALSE(key_store.Write(kDefaultUser, "test", blob));
  EXPECT_FALSE(key_store.Read("", "test", &blob));
  EXPECT_FALSE(key_store.Write("", "test", blob));
}

// Exercises the key store when PKCS #11 returns success.  This exercises all
// non-error-handling code paths.
TEST_F(KeyStoreTest, Pkcs11Success) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Try with a different key name.
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test2", &blob));
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test2", "test_data2"));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "test2", &blob));
  EXPECT_EQ("test_data2", blob);
  // Read the original key again.
  EXPECT_TRUE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Replace key data.
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data3"));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_EQ("test_data3", blob);
  // Delete key data.
  EXPECT_TRUE(key_store.Delete(kDefaultUser, "test2"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test2", &blob));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "test", &blob));
}

TEST_F(KeyStoreTest, Pkcs11Success_NoUser) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_FALSE(key_store.Read("", "test", &blob));
  EXPECT_TRUE(key_store.Write("", "test", "test_data"));
  EXPECT_TRUE(key_store.Read("", "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Try with a different key name.
  EXPECT_FALSE(key_store.Read("", "test2", &blob));
  EXPECT_TRUE(key_store.Write("", "test2", "test_data2"));
  EXPECT_TRUE(key_store.Read("", "test2", &blob));
  EXPECT_EQ("test_data2", blob);
  // Read the original key again.
  EXPECT_TRUE(key_store.Read("", "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Replace key data.
  EXPECT_TRUE(key_store.Write("", "test", "test_data3"));
  EXPECT_TRUE(key_store.Read("", "test", &blob));
  EXPECT_EQ("test_data3", blob);
  // Delete key data.
  EXPECT_TRUE(key_store.Delete("", "test2"));
  EXPECT_FALSE(key_store.Read("", "test2", &blob));
  EXPECT_TRUE(key_store.Read("", "test", &blob));
}

// Tests the key store when PKCS #11 has no token for the given user.
TEST_F(KeyStoreTest, TokenNotAvailable) {
  EXPECT_CALL(token_manager_, GetTokenPath(_, _, _))
      .WillRepeatedly(Return(false));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
  EXPECT_FALSE(key_store.Write(kDefaultUser, "test", blob));
  EXPECT_FALSE(key_store.Read("", "test", &blob));
  EXPECT_FALSE(key_store.Write("", "test", blob));
}

// Tests the key store when PKCS #11 fails to open a session.
TEST_F(KeyStoreTest, NoSession) {
  EXPECT_CALL(pkcs11_, OpenSession(_, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_FALSE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
}

// Tests the key store when PKCS #11 fails to create an object.
TEST_F(KeyStoreTest, CreateObjectFail) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_FALSE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
}

// Tests the key store when PKCS #11 fails to read attribute values.
TEST_F(KeyStoreTest, ReadValueFail) {
  EXPECT_CALL(pkcs11_, GetAttributeValue(_, _, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
}

// Tests the key store when PKCS #11 fails to delete key data.
TEST_F(KeyStoreTest, DeleteValueFail) {
  EXPECT_CALL(pkcs11_, DestroyObject(_, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11KeyStore key_store(&token_manager_);
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Write(kDefaultUser, "test", "test_data2"));
  EXPECT_FALSE(key_store.Delete(kDefaultUser, "test"));
}

// Tests the key store when PKCS #11 fails to find objects.  Tests each part of
// the multi-part find operation individually.
TEST_F(KeyStoreTest, FindFail) {
  EXPECT_CALL(pkcs11_, FindObjectsInit(_, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));

  EXPECT_CALL(pkcs11_, FindObjectsInit(_, _, _)).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(pkcs11_, FindObjects(_, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));

  EXPECT_CALL(pkcs11_, FindObjects(_, _, _, _)).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(pkcs11_, FindObjectsFinal(_, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
}

// Tests the key store when PKCS #11 successfully finds zero objects.
TEST_F(KeyStoreTest, FindNoObjects) {
  std::vector<uint64_t> empty;
  EXPECT_CALL(pkcs11_, FindObjects(_, _, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<3>(empty), Return(CKR_OK)));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string blob;
  EXPECT_TRUE(key_store.Write(kDefaultUser, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "test", &blob));
}

TEST_F(KeyStoreTest, RegisterKeyWithoutCertificate) {
  Pkcs11KeyStore key_store(&token_manager_);
  // Try with a malformed public key.
  EXPECT_FALSE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                  KEY_USAGE_SIGN, "private_key_blob",
                                  "bad_pubkey", ""));
  // Try with a well-formed public key.
  std::string public_key_der = HexDecode(kValidRsaPublicKeyHex);
  EXPECT_CALL(pkcs11_, CreateObject(_, _, Truly(CheckCkaId(CKK_RSA)), _))
      .Times(2)  // Public, private (no certificate).
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, ""));
}

TEST_F(KeyStoreTest, RegisterKeyWithCertificate) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, Truly(CheckCkaId(CKK_RSA)), _))
      .Times(3)  // Public, private, and certificate.
      .WillRepeatedly(Return(CKR_OK));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string public_key_der = HexDecode(kValidRsaPublicKeyHex);
  std::string certificate_der = HexDecode(kValidRsaCertificateHex);
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, certificate_der));
  // Also try with the system token.
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .Times(3)  // Public, private, and certificate.
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, certificate_der));
}

TEST_F(KeyStoreTest, RegisterEccKeyWithoutCertificate) {
  Pkcs11KeyStore key_store(&token_manager_);
  // Try with a malformed public key.
  EXPECT_FALSE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_ECC,
                                  KEY_USAGE_SIGN, "private_key_blob",
                                  "bad_pubkey", ""));
  // Try with a well-formed public key.
  std::string public_key_der = HexDecode(kValidEccPublicKeyHex);
  EXPECT_CALL(pkcs11_, CreateObject(_, _, Truly(CheckCkaId(CKK_EC)), _))
      .Times(2)  // Public, private (no certificate).
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_ECC,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, ""));
}

TEST_F(KeyStoreTest, RegisterEccKeyWithCertificate) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, Truly(CheckCkaId(CKK_EC)), _))
      .Times(3)  // Public, private, and certificate.
      .WillRepeatedly(Return(CKR_OK));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string public_key_der = HexDecode(kValidEccPublicKeyHex);
  std::string certificate_der = HexDecode(kValidEccCertificateHex);
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_ECC,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, certificate_der));
  // Also try with the system token.
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .Times(3)  // Public, private, and certificate.
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_ECC,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, certificate_der));
}

TEST_F(KeyStoreTest, RegisterKeyWithBadCertificate) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .Times(3)  // Public, private, and certificate.
      .WillRepeatedly(Return(CKR_OK));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string public_key_der = HexDecode(kValidRsaPublicKeyHex);
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                 KEY_USAGE_SIGN, "private_key_blob",
                                 public_key_der, "bad_certificate"));
}

TEST_F(KeyStoreTest, RegisterWithWrongKeyType) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string public_key_der = HexDecode(kValidRsaPublicKeyHex);
  EXPECT_FALSE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_ECC,
                                  KEY_USAGE_SIGN, "private_key_blob",
                                  public_key_der, ""));
}

TEST_F(KeyStoreTest, RegisterDecryptionKey) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _)).WillRepeatedly(Return(CKR_OK));
  Pkcs11KeyStore key_store(&token_manager_);
  std::string public_key_der = HexDecode(kValidRsaPublicKeyHex);
  EXPECT_TRUE(key_store.Register(kDefaultUser, "test_label", KEY_TYPE_RSA,
                                 KEY_USAGE_DECRYPT, "private_key_blob",
                                 public_key_der, ""));
}

TEST_F(KeyStoreTest, RegisterCertificate) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string certificate_der = HexDecode(kValidRsaCertificateHex);
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .Times(2);  // Once for valid, once for invalid.
  // Try with a valid certificate (hit multiple times to check dup logic).
  EXPECT_TRUE(key_store.RegisterCertificate(kDefaultUser, certificate_der));
  EXPECT_TRUE(key_store.RegisterCertificate(kDefaultUser, certificate_der));
  EXPECT_TRUE(key_store.RegisterCertificate(kDefaultUser, certificate_der));
  // Try with an invalid certificate.
  EXPECT_TRUE(key_store.RegisterCertificate(kDefaultUser, "bad_certificate"));
}

TEST_F(KeyStoreTest, RegisterCertificateError) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string certificate_der = HexDecode(kValidRsaCertificateHex);
  // Handle an error from PKCS #11.
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .WillOnce(Return(CKR_GENERAL_ERROR));
  EXPECT_FALSE(key_store.RegisterCertificate(kDefaultUser, certificate_der));
}

TEST_F(KeyStoreTest, RegisterCertificateSystemToken) {
  Pkcs11KeyStore key_store(&token_manager_);
  std::string certificate_der = HexDecode(kValidRsaCertificateHex);
  // Try with the system token.
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _)).WillOnce(Return(CKR_OK));
  EXPECT_TRUE(key_store.RegisterCertificate(kDefaultUser, certificate_der));
}

// Tests that the DeleteByPrefix() method removes the correct objects and only
// the correct objects.
TEST_F(KeyStoreTest, DeleteByPrefix) {
  Pkcs11KeyStore key_store(&token_manager_);

  // Test with no keys.
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultUser, "prefix"));

  // Test with a single matching key.
  ASSERT_TRUE(key_store.Write(kDefaultUser, "prefix_test", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultUser, "prefix"));
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultUser, "prefix_test", &blob));

  // Test with a single non-matching key.
  ASSERT_TRUE(key_store.Write(kDefaultUser, "_prefix_", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultUser, "prefix"));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "_prefix_", &blob));

  // Test with an empty prefix.
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultUser, ""));
  EXPECT_FALSE(key_store.Read(kDefaultUser, "_prefix_", &blob));

  // Test with multiple matching and non-matching keys.
  const int kNumKeys = 110;  // Pkcs11KeyStore max is 100 for FindObjects.
  key_store.Write(kDefaultUser, "other1", "test");
  for (int i = 0; i < kNumKeys; ++i) {
    std::string key_name = std::string("prefix") + base::NumberToString(i);
    key_store.Write(kDefaultUser, key_name, std::string(key_name));
  }
  ASSERT_TRUE(key_store.Write(kDefaultUser, "other2", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultUser, "prefix"));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "other1", &blob));
  EXPECT_TRUE(key_store.Read(kDefaultUser, "other2", &blob));
  for (int i = 0; i < kNumKeys; ++i) {
    std::string key_name = std::string("prefix") + base::NumberToString(i);
    EXPECT_FALSE(key_store.Read(kDefaultUser, key_name, &blob));
  }
}

}  // namespace attestation
