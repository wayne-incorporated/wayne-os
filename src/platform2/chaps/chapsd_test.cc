// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <inttypes.h>

#include <memory>
#include <string>
#include <vector>

#include <base/command_line.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

#include "chaps/attributes.h"
#include "chaps/chaps_interface.h"
#include "chaps/chaps_proxy.h"
#include "chaps/chaps_utility.h"
#include "chaps/isolate.h"

using brillo::SecureBlob;
using std::string;
using std::vector;

namespace chaps {

static chaps::ChapsInterface* CreateChapsInstance() {
  auto proxy = ChapsProxyImpl::Create(/*shadow_at_exit=*/false,
                                      chaps::ThreadingMode::kCurrentThread);
  if (!proxy)
    return nullptr;
  return proxy.release();
}

static bool SerializeAttributes(CK_ATTRIBUTE_PTR attributes,
                                CK_ULONG num_attributes,
                                vector<uint8_t>* serialized) {
  Attributes tmp(attributes, num_attributes);
  return tmp.Serialize(serialized);
}

static bool ParseAndFillAttributes(const vector<uint8_t>& serialized,
                                   CK_ATTRIBUTE_PTR attributes,
                                   CK_ULONG num_attributes) {
  Attributes tmp(attributes, num_attributes);
  return tmp.ParseAndFill(serialized);
}

static vector<uint8_t> SubVector(const vector<uint8_t>& v,
                                 int offset,
                                 int size) {
  const uint8_t* front = v.data() + offset;
  return vector<uint8_t>(front, front + size);
}

// Default test fixture for PKCS #11 calls.
class TestP11 : public ::testing::Test {
 protected:
  void SetUp() override {
    // The current user's token will be used so the token will already be
    // initialized and changes to token objects will persist.  The user pin can
    // be assumed to be "111111" and the so pin can be assumed to be "000000".
    // This approach will be used as long as we redirect to openCryptoki.
    chaps_.reset(CreateChapsInstance());
    ASSERT_TRUE(chaps_ != NULL);
    so_pin_ = "000000";
    user_pin_ = "111111";
    credential_ = IsolateCredentialManager::GetDefaultIsolateCredential();
  }
  std::unique_ptr<chaps::ChapsInterface> chaps_;
  string so_pin_;
  string user_pin_;
  SecureBlob credential_;
};

// Test fixture for testing with a valid open session.
class TestP11PublicSession : public TestP11 {
 protected:
  void SetUp() override {
    TestP11::SetUp();
    ASSERT_EQ(CKR_OK, chaps_->OpenSession(credential_, 0,
                                          CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                          &session_id_));
    uint32_t result = chaps_->Logout(credential_, session_id_);
    ASSERT_TRUE(result == CKR_OK || result == CKR_USER_NOT_LOGGED_IN);
  }
  void TearDown() override {
    SecureBlob isolate_credential;
    uint32_t result = chaps_->Logout(credential_, session_id_);
    ASSERT_TRUE(result == CKR_OK || result == CKR_USER_NOT_LOGGED_IN);
    EXPECT_EQ(CKR_OK, chaps_->CloseSession(credential_, session_id_));
    TestP11::TearDown();
  }
  uint64_t session_id_;
};

class TestP11UserSession : public TestP11PublicSession {
 protected:
  void SetUp() override {
    TestP11PublicSession::SetUp();
    uint32_t result =
        chaps_->Login(credential_, session_id_, CKU_USER, &user_pin_);
    ASSERT_TRUE(result == CKR_OK || result == CKR_USER_ALREADY_LOGGED_IN);
  }
  void TearDown() override { TestP11PublicSession::TearDown(); }
};

class TestP11SOSession : public TestP11PublicSession {
 protected:
  void SetUp() override {
    TestP11PublicSession::SetUp();
    uint32_t result = chaps_->Login(credential_, session_id_, CKU_SO, &so_pin_);
    ASSERT_TRUE(result == CKR_OK || result == CKR_USER_ALREADY_LOGGED_IN);
  }
  void TearDown() override { TestP11PublicSession::TearDown(); }
};

class TestP11Object : public TestP11PublicSession {
 protected:
  void SetUp() override {
    TestP11PublicSession::SetUp();
    CK_OBJECT_CLASS class_value = CKO_DATA;
    CK_UTF8CHAR label[] = "A data object";
    CK_UTF8CHAR application[] = "An application";
    CK_BYTE data[] = "Sample data";
    CK_BBOOL false_value = CK_FALSE;
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &class_value, sizeof(class_value)},
        {CKA_TOKEN, &false_value, sizeof(false_value)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_APPLICATION, application, sizeof(application) - 1},
        {CKA_VALUE, data, sizeof(data)}};
    vector<uint8_t> serialized;
    ASSERT_TRUE(SerializeAttributes(attributes, 5, &serialized));
    ASSERT_EQ(CKR_OK, chaps_->CreateObject(credential_, session_id_, serialized,
                                           &object_handle_));
  }
  void TearDown() override {
    ASSERT_EQ(CKR_OK,
              chaps_->DestroyObject(credential_, session_id_, object_handle_));
    TestP11PublicSession::TearDown();
  }
  uint64_t object_handle_;
};

TEST_F(TestP11, SlotList) {
  vector<uint64_t> slot_list;
  uint32_t result = chaps_->GetSlotList(credential_, false, &slot_list);
  EXPECT_EQ(CKR_OK, result);
  EXPECT_LT(0, slot_list.size());
  printf("Slots: ");
  for (size_t i = 0; i < slot_list.size(); ++i) {
    printf("%d ", static_cast<int>(slot_list[i]));
  }
  printf("\n");
  result = chaps_->GetSlotList(credential_, false, NULL);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, result);
}

TEST_F(TestP11, SlotInfo) {
  SlotInfo slot_info;
  uint32_t result = chaps_->GetSlotInfo(credential_, 0, &slot_info);
  EXPECT_EQ(CKR_OK, result);
  result = chaps_->GetSlotInfo(credential_, 0, nullptr);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, result);
  result = chaps_->GetSlotInfo(credential_, 17, &slot_info);
  EXPECT_NE(CKR_OK, result);
}

TEST_F(TestP11, TokenInfo) {
  TokenInfo token_info;
  uint32_t result = chaps_->GetTokenInfo(credential_, 0, &token_info);
  EXPECT_EQ(CKR_OK, result);
  result = chaps_->GetTokenInfo(credential_, 0, nullptr);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, result);
  result = chaps_->GetTokenInfo(credential_, 17, &token_info);
  EXPECT_NE(CKR_OK, result);
}

TEST_F(TestP11, MechList) {
  vector<uint64_t> mech_list;
  uint32_t result = chaps_->GetMechanismList(credential_, 0, &mech_list);
  EXPECT_EQ(CKR_OK, result);
  EXPECT_LT(0, mech_list.size());
  printf("Mech List [0]: %d\n", static_cast<int>(mech_list[0]));
  result = chaps_->GetMechanismList(credential_, 0, NULL);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, result);
  result = chaps_->GetMechanismList(credential_, 17, &mech_list);
  EXPECT_NE(CKR_OK, result);
}

TEST_F(TestP11, MechInfo) {
  MechanismInfo mechanism_info;
  uint32_t result =
      chaps_->GetMechanismInfo(credential_, 0, CKM_RSA_PKCS, &mechanism_info);
  EXPECT_EQ(CKR_OK, result);
  printf("RSA Key Sizes: %" PRIu64 " - %" PRIu64 "\n",
         mechanism_info.min_key_size(), mechanism_info.max_key_size());
  result = chaps_->GetMechanismInfo(credential_, 0, 0xFFFF, &mechanism_info);
  EXPECT_EQ(CKR_MECHANISM_INVALID, result);
  result =
      chaps_->GetMechanismInfo(credential_, 17, CKM_RSA_PKCS, &mechanism_info);
  EXPECT_NE(CKR_OK, result);
  result = chaps_->GetMechanismInfo(credential_, 0, CKM_RSA_PKCS, nullptr);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, result);
}

TEST_F(TestP11, OpenCloseSession) {
  uint64_t session = 0;
  // Test successful RO and RW sessions.
  EXPECT_EQ(CKR_OK,
            chaps_->OpenSession(credential_, 0, CKF_SERIAL_SESSION, &session));
  EXPECT_EQ(CKR_OK, chaps_->CloseSession(credential_, session));
  EXPECT_EQ(CKR_OK,
            chaps_->OpenSession(credential_, 0,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION, &session));
  EXPECT_EQ(CKR_OK, chaps_->CloseSession(credential_, session));
  // Test double close.
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->CloseSession(credential_, session));
  // Test error cases.
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->OpenSession(credential_, 0, CKF_SERIAL_SESSION, NULL));
  EXPECT_EQ(CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            chaps_->OpenSession(credential_, 0, 0, &session));
}

TEST_F(TestP11PublicSession, GetSessionInfo) {
  SessionInfo session_info;
  EXPECT_EQ(CKR_OK,
            chaps_->GetSessionInfo(credential_, session_id_, &session_info));
  EXPECT_EQ(0, session_info.slot_id());
  EXPECT_TRUE(session_info.state() == CKS_RW_PUBLIC_SESSION ||
              session_info.state() == CKS_RW_USER_FUNCTIONS);
  EXPECT_EQ(CKF_SERIAL_SESSION | CKF_RW_SESSION, session_info.flags());
  uint64_t readonly_session_id;
  ASSERT_EQ(CKR_OK, chaps_->OpenSession(credential_, 0, CKF_SERIAL_SESSION,
                                        &readonly_session_id));
  EXPECT_EQ(CKR_OK, chaps_->GetSessionInfo(credential_, readonly_session_id,
                                           &session_info));
  EXPECT_EQ(CKR_OK, chaps_->CloseSession(credential_, readonly_session_id));
  EXPECT_EQ(0, session_info.slot_id());
  EXPECT_TRUE(session_info.state() == CKS_RO_PUBLIC_SESSION ||
              session_info.state() == CKS_RO_USER_FUNCTIONS);
  EXPECT_EQ(CKF_SERIAL_SESSION, session_info.flags());
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->GetSessionInfo(credential_, 17, &session_info));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->GetSessionInfo(credential_, session_id_, nullptr));
}

TEST_F(TestP11PublicSession, GetOperationState) {
  vector<uint8_t> state;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->GetOperationState(credential_, 17, &state));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->GetOperationState(credential_, session_id_, NULL));
}

TEST_F(TestP11PublicSession, SetOperationState) {
  vector<uint8_t> state(10, 0);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->SetOperationState(credential_, 17, state, 0, 0));
}

TEST_F(TestP11PublicSession, Login) {
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->Login(credential_, 17, CKU_USER, &user_pin_));
  EXPECT_EQ(CKR_USER_TYPE_INVALID,
            chaps_->Login(credential_, session_id_, 17, &user_pin_));
  EXPECT_EQ(CKR_OK, chaps_->Login(credential_, session_id_, CKU_USER, NULL));
  EXPECT_EQ(CKR_OK,
            chaps_->Login(credential_, session_id_, CKU_USER, &user_pin_));
}

TEST_F(TestP11PublicSession, Logout) {
  CK_RV result = chaps_->Logout(credential_, session_id_);
  EXPECT_TRUE(result == CKR_USER_NOT_LOGGED_IN || result == CKR_OK);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, chaps_->Logout(credential_, 17));
  ASSERT_EQ(CKR_OK,
            chaps_->Login(credential_, session_id_, CKU_USER, &user_pin_));
  EXPECT_EQ(CKR_OK, chaps_->Logout(credential_, session_id_));
}

TEST_F(TestP11PublicSession, CreateObject) {
  CK_OBJECT_CLASS class_value = CKO_DATA;
  CK_UTF8CHAR label[] = "A data object";
  CK_UTF8CHAR application[] = "An application";
  CK_BYTE data[] = "Sample data";
  CK_BYTE data2[] = "Sample data 2";
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &class_value, sizeof(class_value)},
      {CKA_TOKEN, &false_value, sizeof(false_value)},
      {CKA_LABEL, label, sizeof(label) - 1},
      {CKA_APPLICATION, application, sizeof(application) - 1},
      {CKA_VALUE, data, sizeof(data)}};
  CK_ATTRIBUTE attributes2[] = {{CKA_VALUE, data2, sizeof(data2)}};
  vector<uint8_t> attribute_serial;
  ASSERT_TRUE(SerializeAttributes(attributes, 5, &attribute_serial));
  uint64_t handle = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, chaps_->CreateObject(credential_, session_id_,
                                                    attribute_serial, NULL));
  EXPECT_EQ(CKR_OK, chaps_->CreateObject(credential_, session_id_,
                                         attribute_serial, &handle));
  vector<uint8_t> attribute_serial2;
  ASSERT_TRUE(SerializeAttributes(attributes2, 1, &attribute_serial2));
  uint64_t handle2 = 0;
  EXPECT_EQ(CKR_OK, chaps_->CopyObject(credential_, session_id_, handle,
                                       attribute_serial2, &handle2));
  EXPECT_EQ(CKR_OK, chaps_->DestroyObject(credential_, session_id_, handle));
  EXPECT_EQ(CKR_OK, chaps_->DestroyObject(credential_, session_id_, handle2));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->CreateObject(credential_, 17, attribute_serial, &handle));
  EXPECT_EQ(CKR_TEMPLATE_INCOMPLETE,
            chaps_->CreateObject(credential_, session_id_, attribute_serial2,
                                 &handle));
}

TEST_F(TestP11Object, GetObjectSize) {
  uint64_t size;
  EXPECT_EQ(CKR_OK, chaps_->GetObjectSize(credential_, session_id_,
                                          object_handle_, &size));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, chaps_->GetObjectSize(credential_, session_id_,
                                                     object_handle_, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->GetObjectSize(credential_, 17, object_handle_, &size));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            chaps_->GetObjectSize(credential_, session_id_, 17, &size));
}

TEST_F(TestP11Object, GetAttributeValue) {
  CK_BYTE buffer[100];
  CK_ATTRIBUTE query[1] = {{CKA_VALUE, buffer, sizeof(buffer)}};
  vector<uint8_t> serial_query;
  ASSERT_TRUE(SerializeAttributes(query, 1, &serial_query));
  vector<uint8_t> response;
  EXPECT_EQ(CKR_OK,
            chaps_->GetAttributeValue(credential_, session_id_, object_handle_,
                                      serial_query, &response));
  EXPECT_TRUE(ParseAndFillAttributes(response, query, 1));
  CK_BYTE data[] = "Sample data";
  EXPECT_EQ(sizeof(data), query[0].ulValueLen);
  EXPECT_EQ(0, memcmp(data, query[0].pValue, query[0].ulValueLen));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->GetAttributeValue(credential_, session_id_, object_handle_,
                                      serial_query, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->GetAttributeValue(credential_, 17, object_handle_,
                                      serial_query, &response));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            chaps_->GetAttributeValue(credential_, session_id_, 17,
                                      serial_query, &response));
}

TEST_F(TestP11Object, SetAttributeValue) {
  CK_BYTE buffer[100];
  memset(buffer, 0xAA, sizeof(buffer));
  CK_ATTRIBUTE attributes[1] = {{CKA_LABEL, buffer, sizeof(buffer)}};
  vector<uint8_t> serial;
  ASSERT_TRUE(SerializeAttributes(attributes, 1, &serial));
  EXPECT_EQ(CKR_OK, chaps_->SetAttributeValue(credential_, session_id_,
                                              object_handle_, serial));
  CK_BYTE buffer2[100];
  memset(buffer2, 0xBB, sizeof(buffer2));
  attributes[0].pValue = buffer2;
  ASSERT_TRUE(SerializeAttributes(attributes, 1, &serial));
  vector<uint8_t> response;
  EXPECT_EQ(CKR_OK,
            chaps_->GetAttributeValue(credential_, session_id_, object_handle_,
                                      serial, &response));
  EXPECT_TRUE(ParseAndFillAttributes(response, attributes, 1));
  EXPECT_EQ(0, memcmp(buffer, buffer2, 100));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->SetAttributeValue(credential_, 17, object_handle_, serial));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            chaps_->SetAttributeValue(credential_, session_id_, 17, serial));
}

TEST_F(TestP11Object, FindObjects) {
  vector<uint64_t> objects;
  vector<uint8_t> empty;
  EXPECT_EQ(CKR_OK, chaps_->FindObjectsInit(credential_, session_id_, empty));
  EXPECT_EQ(CKR_OK,
            chaps_->FindObjects(credential_, session_id_, 10, &objects));
  EXPECT_EQ(CKR_OK, chaps_->FindObjectsFinal(credential_, session_id_));
  EXPECT_GT(objects.size(), 0);
  EXPECT_LT(objects.size(), 11);

  CK_OBJECT_CLASS class_value = CKO_DATA;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[2] = {{CKA_CLASS, &class_value, sizeof(class_value)},
                                {CKA_TOKEN, &false_value, sizeof(false_value)}};
  vector<uint8_t> serial;
  ASSERT_TRUE(SerializeAttributes(attributes, 2, &serial));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            chaps_->FindObjectsInit(credential_, session_id_,
                                    vector<uint8_t>(20, 0)));
  EXPECT_EQ(CKR_OK, chaps_->FindObjectsInit(credential_, session_id_, serial));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->FindObjects(credential_, session_id_, 10, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->FindObjects(credential_, session_id_, 10, &objects));
  objects.clear();
  EXPECT_EQ(CKR_OK,
            chaps_->FindObjects(credential_, session_id_, 10, &objects));
  EXPECT_EQ(CKR_OK, chaps_->FindObjectsFinal(credential_, session_id_));
  EXPECT_EQ(objects.size(), 1);
  // Operation state management tests.
  objects.clear();
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            chaps_->FindObjects(credential_, session_id_, 10, &objects));
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            chaps_->FindObjectsFinal(credential_, session_id_));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->FindObjectsInit(credential_, 17, empty));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->FindObjects(credential_, 17, 10, &objects));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            chaps_->FindObjectsFinal(credential_, 17));
}

TEST_F(TestP11PublicSession, Encrypt) {
  // Create a session key.
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_AES;
  CK_BYTE key_value[32] = {0};
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                             {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                             {CKA_TOKEN, &false_value, sizeof(false_value)},
                             {CKA_ENCRYPT, &true_value, sizeof(true_value)},
                             {CKA_DECRYPT, &true_value, sizeof(true_value)},
                             {CKA_VALUE, key_value, sizeof(key_value)}};
  vector<uint8_t> key;
  ASSERT_TRUE(SerializeAttributes(key_desc, 6, &key));
  uint64_t key_handle = 0;
  ASSERT_EQ(CKR_OK,
            chaps_->CreateObject(credential_, session_id_, key, &key_handle));
  // Test encrypt.
  vector<uint8_t> parameter;
  EXPECT_EQ(CKR_OK, chaps_->EncryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  vector<uint8_t> data(48, 2), encrypted;
  uint64_t not_used = 0;
  const uint64_t max_out_length = 100;
  EXPECT_EQ(CKR_OK, chaps_->Encrypt(credential_, session_id_, data,
                                    max_out_length, &not_used, &encrypted));
  EXPECT_EQ(CKR_OK, chaps_->EncryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  vector<uint8_t> encrypted2, tmp;
  EXPECT_EQ(CKR_OK, chaps_->EncryptUpdate(credential_, session_id_,
                                          SubVector(data, 0, 3), max_out_length,
                                          &not_used, &tmp));
  encrypted2.insert(encrypted2.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->EncryptUpdate(credential_, session_id_,
                                          SubVector(data, 3, 27),
                                          max_out_length, &not_used, &tmp));
  encrypted2.insert(encrypted2.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->EncryptUpdate(credential_, session_id_,
                                          SubVector(data, 30, 18),
                                          max_out_length, &not_used, &tmp));
  encrypted2.insert(encrypted2.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->EncryptFinal(credential_, session_id_,
                                         max_out_length, &not_used, &tmp));
  encrypted2.insert(encrypted2.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_TRUE(
      std::equal(encrypted.begin(), encrypted.end(), encrypted2.begin()));
  // Test decrypt.
  EXPECT_EQ(CKR_OK, chaps_->DecryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  vector<uint8_t> decrypted;
  EXPECT_EQ(CKR_OK, chaps_->Decrypt(credential_, session_id_, encrypted,
                                    max_out_length, &not_used, &decrypted));
  EXPECT_TRUE(std::equal(data.begin(), data.end(), decrypted.begin()));
  decrypted.clear();
  EXPECT_EQ(CKR_OK, chaps_->DecryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  EXPECT_EQ(CKR_OK, chaps_->DecryptUpdate(credential_, session_id_,
                                          SubVector(encrypted, 0, 16),
                                          max_out_length, &not_used, &tmp));
  decrypted.insert(decrypted.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->DecryptUpdate(credential_, session_id_,
                                          SubVector(encrypted, 16, 17),
                                          max_out_length, &not_used, &tmp));
  decrypted.insert(decrypted.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->DecryptUpdate(credential_, session_id_,
                                          SubVector(encrypted, 33, 15),
                                          max_out_length, &not_used, &tmp));
  decrypted.insert(decrypted.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_EQ(CKR_OK, chaps_->DecryptFinal(credential_, session_id_,
                                         max_out_length, &not_used, &tmp));
  decrypted.insert(decrypted.end(), tmp.begin(), tmp.end());
  tmp.clear();
  EXPECT_TRUE(std::equal(data.begin(), data.end(), decrypted.begin()));
  // Bad arg cases.
  EXPECT_EQ(CKR_OK, chaps_->EncryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, chaps_->Encrypt(credential_, session_id_, data,
                                               max_out_length, NULL, NULL));
  EXPECT_EQ(CKR_OK, chaps_->DecryptInit(credential_, session_id_, CKM_AES_ECB,
                                        parameter, key_handle));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, chaps_->Decrypt(credential_, session_id_, data,
                                               max_out_length, NULL, NULL));
}

TEST_F(TestP11PublicSession, Digest) {
  vector<uint8_t> parameter;
  vector<uint8_t> data(100, 2), digest;
  uint64_t not_used = 0;
  const uint64_t max_out_length = 100;
  EXPECT_EQ(CKR_OK,
            chaps_->DigestInit(credential_, session_id_, CKM_SHA_1, parameter));
  EXPECT_EQ(CKR_OK, chaps_->Digest(credential_, session_id_, data,
                                   max_out_length, &not_used, &digest));
  EXPECT_EQ(CKR_OK,
            chaps_->DigestInit(credential_, session_id_, CKM_SHA_1, parameter));
  EXPECT_EQ(CKR_OK, chaps_->DigestUpdate(credential_, session_id_,
                                         SubVector(data, 0, 10)));
  EXPECT_EQ(CKR_OK, chaps_->DigestUpdate(credential_, session_id_,
                                         SubVector(data, 10, 90)));
  vector<uint8_t> digest2;
  EXPECT_EQ(CKR_OK, chaps_->DigestFinal(credential_, session_id_,
                                        max_out_length, &not_used, &digest2));
  EXPECT_TRUE(std::equal(digest.begin(), digest.end(), digest2.begin()));

  // Create a session key.
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  CK_BYTE key_value[100] = {0};
  memcpy(key_value, data.data(), 100);
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                             {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                             {CKA_TOKEN, &false_value, sizeof(false_value)},
                             {CKA_SIGN, &true_value, sizeof(true_value)},
                             {CKA_VERIFY, &true_value, sizeof(true_value)},
                             {CKA_VALUE, key_value, sizeof(key_value)}};
  vector<uint8_t> key;
  ASSERT_TRUE(SerializeAttributes(key_desc, 6, &key));
  uint64_t key_handle = 0;
  ASSERT_EQ(CKR_OK,
            chaps_->CreateObject(credential_, session_id_, key, &key_handle));
  EXPECT_EQ(CKR_OK,
            chaps_->DigestInit(credential_, session_id_, CKM_SHA_1, parameter));
  EXPECT_EQ(CKR_KEY_INDIGESTIBLE,
            chaps_->DigestKey(credential_, session_id_, key_handle));
}

TEST_F(TestP11PublicSession, Sign) {
  // Create a session key.
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  CK_BYTE key_value[32] = {0};
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE key_desc[] = {{CKA_CLASS, &key_class, sizeof(key_class)},
                             {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                             {CKA_TOKEN, &false_value, sizeof(false_value)},
                             {CKA_SIGN, &true_value, sizeof(true_value)},
                             {CKA_VERIFY, &true_value, sizeof(true_value)},
                             {CKA_VALUE, key_value, sizeof(key_value)}};
  vector<uint8_t> key;
  ASSERT_TRUE(SerializeAttributes(key_desc, 6, &key));
  uint64_t key_handle = 0;
  ASSERT_EQ(CKR_OK,
            chaps_->CreateObject(credential_, session_id_, key, &key_handle));
  // Sign / Verify using SHA-1 HMAC.
  vector<uint8_t> parameter;
  EXPECT_EQ(CKR_OK, chaps_->SignInit(credential_, session_id_, CKM_SHA_1_HMAC,
                                     parameter, key_handle));
  vector<uint8_t> data(100, 2), signature;
  uint64_t not_used = 0;
  const uint64_t max_out_length = 100;
  EXPECT_EQ(CKR_OK, chaps_->Sign(credential_, session_id_, data, max_out_length,
                                 &not_used, &signature));
  EXPECT_EQ(signature.size(), 20);
  EXPECT_EQ(CKR_OK, chaps_->VerifyInit(credential_, session_id_, CKM_SHA_1_HMAC,
                                       parameter, key_handle));
  EXPECT_EQ(CKR_OK, chaps_->Verify(credential_, session_id_, data, signature));
}

TEST_F(TestP11UserSession, GenerateKey) {
  vector<uint8_t> empty;
  uint64_t key_handle;
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ULONG key_length = 32;
  CK_ATTRIBUTE attributes[] = {
      {CKA_TOKEN, &false_value, sizeof(false_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ENCRYPT, &true_value, sizeof(true_value)},
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_VALUE_LEN, &key_length, sizeof(key_length)}};
  vector<uint8_t> serialized;
  ASSERT_TRUE(SerializeAttributes(attributes, 5, &serialized));
  ASSERT_EQ(CKR_OK,
            chaps_->GenerateKey(credential_, session_id_, CKM_AES_KEY_GEN,
                                empty, serialized, &key_handle));
  EXPECT_EQ(CKR_OK,
            chaps_->DestroyObject(credential_, session_id_, key_handle));
}

TEST_F(TestP11UserSession, GenerateKeyPair) {
  vector<uint8_t> empty;
  uint64_t public_key, private_key;
  CK_ULONG bits = 1024;
  CK_BYTE e[] = {1, 0, 1};
  CK_BBOOL false_value = CK_FALSE;
  CK_BBOOL true_value = CK_TRUE;
  CK_ATTRIBUTE public_attributes[] = {
      {CKA_ENCRYPT, &true_value, sizeof(true_value)},
      {CKA_VERIFY, &true_value, sizeof(true_value)},
      {CKA_WRAP, &false_value, sizeof(false_value)},
      {CKA_TOKEN, &false_value, sizeof(false_value)},
      {CKA_PRIVATE, &false_value, sizeof(false_value)},
      {CKA_MODULUS_BITS, &bits, sizeof(bits)},
      {CKA_PUBLIC_EXPONENT, e, sizeof(e)}};
  CK_BYTE id[] = {'A'};
  CK_ATTRIBUTE private_attributes[] = {
      {CKA_DECRYPT, &true_value, sizeof(true_value)},
      {CKA_SIGN, &true_value, sizeof(true_value)},
      {CKA_UNWRAP, &false_value, sizeof(false_value)},
      {CKA_SENSITIVE, &true_value, sizeof(true_value)},
      {CKA_TOKEN, &false_value, sizeof(false_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_ID, &id, sizeof(id)},
  };
  vector<uint8_t> public_serialized, private_serialized;
  ASSERT_TRUE(SerializeAttributes(public_attributes, 7, &public_serialized));
  ASSERT_TRUE(SerializeAttributes(private_attributes, 7, &private_serialized));
  ASSERT_EQ(CKR_OK, chaps_->GenerateKeyPair(
                        credential_, session_id_, CKM_RSA_PKCS_KEY_PAIR_GEN,
                        empty, public_serialized, private_serialized,
                        &public_key, &private_key));
  EXPECT_EQ(CKR_OK,
            chaps_->DestroyObject(credential_, session_id_, public_key));
  EXPECT_EQ(CKR_OK,
            chaps_->DestroyObject(credential_, session_id_, private_key));
}

TEST_F(TestP11PublicSession, WrapKey) {
  uint64_t not_used;
  vector<uint8_t> empty;
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->WrapKey(credential_, session_id_, CKM_RSA_PKCS, empty, 0, 1,
                            1000, &not_used, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->UnwrapKey(credential_, session_id_, CKM_RSA_PKCS, empty, 0,
                              empty, empty, NULL));
}

TEST_F(TestP11PublicSession, DeriveKey) {
  vector<uint8_t> empty;
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            chaps_->DeriveKey(credential_, session_id_, CKM_SHA1_KEY_DERIVATION,
                              empty, 1, empty, NULL));
}

TEST_F(TestP11PublicSession, Random) {
  vector<uint8_t> data(8, 0xAA);
  EXPECT_EQ(CKR_OK, chaps_->SeedRandom(credential_, session_id_, data));
  EXPECT_EQ(CKR_OK,
            chaps_->GenerateRandom(credential_, session_id_, 32, &data));
}

}  // namespace chaps
