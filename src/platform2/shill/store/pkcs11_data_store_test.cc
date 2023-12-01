// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_data_store.h"

#include <map>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/cryptohome.h>
#include <brillo/map_utils.h>
#include <chaps/attributes.h>
#include <chaps/chaps_proxy_mock.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace {

const uint64_t kSession = 7;  // Arbitrary non-zero value.
const CK_SLOT_ID kDefaultSlot = 1;

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

namespace shill {

typedef chaps::ChapsProxyMock Pkcs11Mock;

// Implements a fake PKCS #11 object store.  Labeled data blobs can be stored
// and later retrieved.  The mocked interface is ChapsInterface so these
// tests must be linked with the Chaps PKCS #11 library.  The mock class itself
// is part of the Chaps package; it is reused here to avoid duplication (see
// chaps_proxy_mock.h).
class PKCS11DataStoreTest : public testing::Test {
 public:
  PKCS11DataStoreTest()
      : pkcs11_(false),  // Do not pre-initialize the mock PKCS #11 library.
                         // This just controls whether the first call to
                         // C_Initialize returns 'already initialized'.
        next_handle_(1) {}
  PKCS11DataStoreTest(const PKCS11DataStoreTest&) = delete;
  PKCS11DataStoreTest& operator=(const PKCS11DataStoreTest&) = delete;

  ~PKCS11DataStoreTest() override = default;

  void SetUp() override {
    std::vector<uint64_t> slot_list = {0, 1};
    ON_CALL(pkcs11_, GetSlotList(_, _, _))
        .WillByDefault(DoAll(SetArgPointee<2>(slot_list), Return(0)));
    ON_CALL(pkcs11_, OpenSession(_, _, _, _))
        .WillByDefault(DoAll(SetArgPointee<3>(kSession), Return(0)));
    ON_CALL(pkcs11_, CloseSession(_, _)).WillByDefault(Return(0));
    ON_CALL(pkcs11_, CreateObject(_, _, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::CreateObject));
    ON_CALL(pkcs11_, DestroyObject(_, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::DestroyObject));
    ON_CALL(pkcs11_, GetAttributeValue(_, _, _, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::GetAttributeValue));
    ON_CALL(pkcs11_, SetAttributeValue(_, _, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::SetAttributeValue));
    ON_CALL(pkcs11_, FindObjectsInit(_, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::FindObjectsInit));
    ON_CALL(pkcs11_, FindObjects(_, _, _, _))
        .WillByDefault(Invoke(this, &PKCS11DataStoreTest::FindObjects));
    ON_CALL(pkcs11_, FindObjectsFinal(_, _)).WillByDefault(Return(0));
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

 protected:
  NiceMock<Pkcs11Mock> pkcs11_;

 private:
  // A helper to pull the value for a given attribute out of a serialized
  // template.
  std::string GetValue(const std::vector<uint8_t>& attributes,
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

// Exercises the key store when PKCS #11 returns success.  This exercises all
// non-error-handling code paths.
TEST_F(PKCS11DataStoreTest, Pkcs11Success) {
  Pkcs11DataStore key_store;
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test", &blob));
  EXPECT_TRUE(key_store.Write(kDefaultSlot, "test", "test_data"));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Try with a different key name.
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test2", &blob));
  EXPECT_TRUE(key_store.Write(kDefaultSlot, "test2", "test_data2"));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "test2", &blob));
  EXPECT_EQ("test_data2", blob);
  // Read the original key again.
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "test", &blob));
  EXPECT_EQ("test_data", blob);
  // Replace key data.
  EXPECT_TRUE(key_store.Write(kDefaultSlot, "test", "test_data3"));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "test", &blob));
  EXPECT_EQ("test_data3", blob);
  // Delete key data.
  EXPECT_TRUE(key_store.Delete(kDefaultSlot, "test2"));
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test2", &blob));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "test", &blob));
}

// Tests the key store when PKCS #11 fails to open a session.
TEST_F(PKCS11DataStoreTest, NoSession) {
  EXPECT_CALL(pkcs11_, OpenSession(_, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11DataStore key_store;
  std::string blob;
  EXPECT_FALSE(key_store.Write(kDefaultSlot, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test", &blob));
}

// Tests the key store when PKCS #11 fails to create an object.
TEST_F(PKCS11DataStoreTest, CreateObjectFail) {
  EXPECT_CALL(pkcs11_, CreateObject(_, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11DataStore key_store;
  std::string blob;
  EXPECT_FALSE(key_store.Write(kDefaultSlot, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test", &blob));
}

// Tests the key store when PKCS #11 fails to read attribute values.
TEST_F(PKCS11DataStoreTest, ReadValueFail) {
  EXPECT_CALL(pkcs11_, GetAttributeValue(_, _, _, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11DataStore key_store;
  std::string blob;
  EXPECT_TRUE(key_store.Write(kDefaultSlot, "test", "test_data"));
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "test", &blob));
}

// Tests the key store when PKCS #11 fails to delete key data.
TEST_F(PKCS11DataStoreTest, DeleteValueFail) {
  EXPECT_CALL(pkcs11_, DestroyObject(_, _, _))
      .WillRepeatedly(Return(CKR_GENERAL_ERROR));
  Pkcs11DataStore key_store;
  EXPECT_TRUE(key_store.Write(kDefaultSlot, "test", "test_data"));
  EXPECT_FALSE(key_store.Write(kDefaultSlot, "test", "test_data2"));
  EXPECT_FALSE(key_store.Delete(kDefaultSlot, "test"));
}

// Tests that the DeleteByPrefix() method removes the correct objects and only
// the correct objects.
TEST_F(PKCS11DataStoreTest, DeleteByPrefix) {
  Pkcs11DataStore key_store;

  // Test with no keys.
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultSlot, "prefix"));

  // Test with a single matching key.
  ASSERT_TRUE(key_store.Write(kDefaultSlot, "prefix_test", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultSlot, "prefix"));
  std::string blob;
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "prefix_test", &blob));

  // Test with a single non-matching key.
  ASSERT_TRUE(key_store.Write(kDefaultSlot, "_prefix_", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultSlot, "prefix"));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "_prefix_", &blob));

  // Test with an empty prefix.
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultSlot, ""));
  EXPECT_FALSE(key_store.Read(kDefaultSlot, "_prefix_", &blob));

  // Test with multiple matching and non-matching keys.
  const int kNumKeys = 110;  // Pkcs11DataStore max is 100 for FindObjects.
  key_store.Write(kDefaultSlot, "other1", "test");
  for (int i = 0; i < kNumKeys; ++i) {
    std::string key_name = std::string("prefix") + base::NumberToString(i);
    key_store.Write(kDefaultSlot, key_name, std::string(key_name));
  }
  ASSERT_TRUE(key_store.Write(kDefaultSlot, "other2", "test"));
  ASSERT_TRUE(key_store.DeleteByPrefix(kDefaultSlot, "prefix"));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "other1", &blob));
  EXPECT_TRUE(key_store.Read(kDefaultSlot, "other2", &blob));
  for (int i = 0; i < kNumKeys; ++i) {
    std::string key_name = std::string("prefix") + base::NumberToString(i);
    EXPECT_FALSE(key_store.Read(kDefaultSlot, key_name, &blob));
  }
}

}  // namespace shill
