// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/chaps_service.h"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/isolate.h"
#include "chaps/object_mock.h"
#include "chaps/session_mock.h"
#include "chaps/slot_manager_mock.h"

using brillo::SecureBlob;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace chaps {

// Invalid initialization test.
TEST(InitDeathTest, InvalidInit) {
  EXPECT_DEATH_IF_SUPPORTED(ChapsServiceImpl(nullptr), "Check failed");
}

// Test fixture for an initialized service instance.
class TestService : public ::testing::Test {
 protected:
  void SetUp() override {
    service_.reset(new ChapsServiceImpl(&slot_manager_));
    // Setup parsable and un-parsable serialized attributes.
    CK_ATTRIBUTE attributes[] = {{CKA_VALUE, nullptr, 0}};
    CK_ATTRIBUTE attributes2[] = {{CKA_VALUE, const_cast<char*>("test"), 4}};
    attribute_ = attributes[0];
    attribute2_ = attributes2[0];
    Attributes tmp(attributes, 1);
    tmp.Serialize(&good_attributes_);
    Attributes tmp2(attributes2, 1);
    tmp2.Serialize(&good_attributes2_);
    bad_attributes_ = vector<uint8_t>(100, 0xAA);
    ic_ = IsolateCredentialManager::GetDefaultIsolateCredential();
  }
  SlotManagerMock slot_manager_;
  SessionMock session_;
  ObjectMock object_;
  std::unique_ptr<ChapsServiceImpl> service_;
  vector<uint8_t> bad_attributes_;
  vector<uint8_t> good_attributes_;
  vector<uint8_t> good_attributes2_;
  CK_ATTRIBUTE attribute_;
  CK_ATTRIBUTE attribute2_;
  SecureBlob ic_;
};

TEST_F(TestService, GetSlotList) {
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillRepeatedly(Return(false));
  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetSlotList(ic_, false, NULL));
  vector<uint64_t> slot_list;
  slot_list.push_back(0);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetSlotList(ic_, false, &slot_list));
  // Try normal use cases.
  slot_list.clear();
  EXPECT_EQ(CKR_OK, service_->GetSlotList(ic_, true, &slot_list));
  EXPECT_EQ(0, slot_list.size());
  EXPECT_EQ(CKR_OK, service_->GetSlotList(ic_, false, &slot_list));
  EXPECT_EQ(2, slot_list.size());

  // Check that when tokens are not accessible to an isolate, the slot list is
  // filtered.
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  slot_list.clear();
  EXPECT_EQ(CKR_OK, service_->GetSlotList(ic_, false, &slot_list));
  EXPECT_EQ(1, slot_list.size());
}

TEST_F(TestService, GetSlotInfo) {
  CK_SLOT_INFO test_info;
  memset(&test_info, 0, sizeof(CK_SLOT_INFO));
  test_info.flags = 17;
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, GetSlotInfo(ic_, 0, _))
      .WillRepeatedly(SetArgPointee<2>(test_info));

  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetSlotInfo(ic_, 0, nullptr));
  // Try invalid slot ID.
  SlotInfo slot_info;
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->GetSlotInfo(ic_, 2, &slot_info));
  // Try the normal case.
  EXPECT_EQ(CKR_OK, service_->GetSlotInfo(ic_, 0, &slot_info));
  EXPECT_EQ(slot_info.flags(), 17);
}

TEST_F(TestService, GetTokenInfo) {
  CK_TOKEN_INFO test_info;
  memset(&test_info, 0, sizeof(CK_TOKEN_INFO));
  test_info.flags = 17;
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, GetTokenInfo(ic_, 0, _))
      .WillRepeatedly(SetArgPointee<2>(test_info));

  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetTokenInfo(ic_, 0, nullptr));
  // Try invalid slot ID.
  TokenInfo token_info;
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->GetTokenInfo(ic_, 3, &token_info));
  EXPECT_EQ(CKR_TOKEN_NOT_PRESENT, service_->GetTokenInfo(ic_, 0, &token_info));
  // Try the normal case.
  EXPECT_EQ(CKR_OK, service_->GetTokenInfo(ic_, 0, &token_info));
  EXPECT_EQ(token_info.flags(), 17);
}

TEST_F(TestService, GetMechanismList) {
  MechanismMap test_list;
  CK_MECHANISM_INFO test_info;
  memset(&test_info, 0, sizeof(CK_MECHANISM_INFO));
  test_list[123UL] = test_info;
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, GetMechanismInfo(ic_, 0))
      .WillRepeatedly(Return(&test_list));
  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetMechanismList(ic_, 0, NULL));
  // Try invalid slot ID.
  vector<uint64_t> output;
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->GetMechanismList(ic_, 2, &output));
  EXPECT_EQ(CKR_TOKEN_NOT_PRESENT, service_->GetMechanismList(ic_, 0, &output));
  // Try the normal case.
  ASSERT_EQ(CKR_OK, service_->GetMechanismList(ic_, 0, &output));
  ASSERT_EQ(output.size(), 1);
  EXPECT_EQ(output[0], 123);
}

TEST_F(TestService, GetMechanismInfo) {
  MechanismMap test_list;
  CK_MECHANISM_INFO test_info;
  memset(&test_info, 0, sizeof(CK_MECHANISM_INFO));
  test_info.flags = 17;
  test_list[123UL] = test_info;
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, GetMechanismInfo(ic_, 0))
      .WillRepeatedly(Return(&test_list));
  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->GetMechanismInfo(ic_, 0, 123, nullptr));
  // Try invalid slot ID.
  MechanismInfo mechanism_info;
  EXPECT_EQ(CKR_SLOT_ID_INVALID,
            service_->GetMechanismInfo(ic_, 2, 123, &mechanism_info));
  EXPECT_EQ(CKR_TOKEN_NOT_PRESENT,
            service_->GetMechanismInfo(ic_, 0, 123, &mechanism_info));
  // Try the normal case.
  ASSERT_EQ(CKR_OK, service_->GetMechanismInfo(ic_, 0, 123, &mechanism_info));
  EXPECT_EQ(mechanism_info.flags(), 17);
}

TEST_F(TestService, InitToken) {
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  vector<uint8_t> bad_label;
  vector<uint8_t> good_label(chaps::kTokenLabelSize, 0x20);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->InitToken(ic_, 0, NULL, bad_label));
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->InitToken(ic_, 2, NULL, good_label));
  EXPECT_EQ(CKR_TOKEN_NOT_PRESENT,
            service_->InitToken(ic_, 0, NULL, good_label));
  EXPECT_EQ(CKR_PIN_INCORRECT, service_->InitToken(ic_, 0, NULL, good_label));
}

TEST_F(TestService, InitPIN) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 0, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->InitPIN(ic_, 0, NULL));
  EXPECT_EQ(CKR_USER_NOT_LOGGED_IN, service_->InitPIN(ic_, 0, NULL));
}

TEST_F(TestService, SetPIN) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 0, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->SetPIN(ic_, 0, NULL, NULL));
  EXPECT_EQ(CKR_PIN_INVALID, service_->SetPIN(ic_, 0, NULL, NULL));
}

TEST_F(TestService, OpenSession) {
  EXPECT_CALL(slot_manager_, GetSlotCount()).WillRepeatedly(Return(2));
  EXPECT_CALL(slot_manager_, IsTokenAccessible(ic_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, IsTokenPresent(ic_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(slot_manager_, OpenSession(ic_, 0, true))
      .WillRepeatedly(Return(10));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->OpenSession(ic_, 0, 0, NULL));
  uint64_t session;
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->OpenSession(ic_, 2, 0, &session));
  EXPECT_EQ(CKR_SLOT_ID_INVALID, service_->OpenSession(ic_, 0, 0, &session));
  EXPECT_EQ(CKR_TOKEN_NOT_PRESENT, service_->OpenSession(ic_, 0, 0, &session));
  EXPECT_EQ(CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            service_->OpenSession(ic_, 0, 0, &session));
  ASSERT_EQ(CKR_OK,
            service_->OpenSession(ic_, 0, CKF_SERIAL_SESSION, &session));
  EXPECT_EQ(session, 10);
}

TEST_F(TestService, CloseSession) {
  EXPECT_CALL(slot_manager_, CloseSession(ic_, 0))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->CloseSession(ic_, 0));
  EXPECT_EQ(CKR_OK, service_->CloseSession(ic_, 0));
}

TEST_F(TestService, GetSessionInfo) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetSlot()).WillRepeatedly(Return(15));
  EXPECT_CALL(session_, GetState()).WillRepeatedly(Return(16));
  EXPECT_CALL(session_, IsReadOnly()).WillRepeatedly(Return(false));
  // Try bad arguments.
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetSessionInfo(ic_, 1, nullptr));
  SessionInfo session_info;
  // Try invalid session handle.
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GetSessionInfo(ic_, 1, &session_info));
  // Try normal case.
  ASSERT_EQ(CKR_OK, service_->GetSessionInfo(ic_, 1, &session_info));
  EXPECT_EQ(session_info.slot_id(), 15);
  EXPECT_EQ(session_info.state(), 16);
  EXPECT_EQ(session_info.flags(), CKF_RW_SESSION | CKF_SERIAL_SESSION);
}

TEST_F(TestService, GetOperationState) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, IsOperationActive(_)).WillRepeatedly(Return(false));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetOperationState(ic_, 1, NULL));
  vector<uint8_t> state;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GetOperationState(ic_, 1, &state));
  EXPECT_EQ(CKR_OPERATION_NOT_INITIALIZED,
            service_->GetOperationState(ic_, 1, &state));
  EXPECT_CALL(session_, IsOperationActive(_)).WillRepeatedly(Return(true));
  EXPECT_EQ(CKR_STATE_UNSAVEABLE, service_->GetOperationState(ic_, 1, &state));
}

TEST_F(TestService, SetOperationState) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  vector<uint8_t> state;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->SetOperationState(ic_, 1, state, 0, 0));
  EXPECT_EQ(CKR_SAVED_STATE_INVALID,
            service_->SetOperationState(ic_, 1, state, 0, 0));
}

TEST_F(TestService, Login) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, IsPrivateLoaded()).WillRepeatedly(Return(true));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->Login(ic_, 1, CKU_USER, NULL));
  string bad_pin("1234");
  string good_pin("111111");
  EXPECT_EQ(CKR_PIN_INCORRECT, service_->Login(ic_, 1, CKU_SO, &good_pin));
  EXPECT_EQ(CKR_PIN_INCORRECT, service_->Login(ic_, 1, CKU_USER, &bad_pin));
  EXPECT_EQ(CKR_OK, service_->Login(ic_, 1, CKU_USER, &good_pin));
  EXPECT_EQ(CKR_OK, service_->Login(ic_, 1, CKU_USER, NULL));
}

TEST_F(TestService, LoginNoPrivate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, IsPrivateLoaded()).WillRepeatedly(Return(false));
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS,
            service_->Login(ic_, 1, CKU_USER, NULL));
}

TEST_F(TestService, Logout) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->Logout(ic_, 1));
  EXPECT_EQ(CKR_OK, service_->Logout(ic_, 1));
}

TEST_F(TestService, CreateObject) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, CreateObject(_, 1, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(2), Return(CKR_OK)));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->CreateObject(ic_, 1, good_attributes_, NULL));
  uint64_t object_handle;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->CreateObject(ic_, 1, good_attributes_, &object_handle));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->CreateObject(ic_, 1, bad_attributes_, &object_handle));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->CreateObject(ic_, 1, good_attributes_, &object_handle));
  EXPECT_EQ(CKR_OK,
            service_->CreateObject(ic_, 1, good_attributes_, &object_handle));
  EXPECT_EQ(object_handle, 2);
}

TEST_F(TestService, CopyObject) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, CopyObject(_, 1, 2, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<3>(3), Return(CKR_OK)));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->CopyObject(ic_, 1, 2, good_attributes_, NULL));
  uint64_t object_handle;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->CopyObject(ic_, 1, 2, good_attributes_, &object_handle));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->CopyObject(ic_, 1, 2, bad_attributes_, &object_handle));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->CopyObject(ic_, 1, 2, good_attributes_, &object_handle));
  EXPECT_EQ(CKR_OK,
            service_->CopyObject(ic_, 1, 2, good_attributes_, &object_handle));
  EXPECT_EQ(object_handle, 3);
}

TEST_F(TestService, DestroyObject) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, DestroyObject(_))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->DestroyObject(ic_, 1, 2));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->DestroyObject(ic_, 1, 2));
  EXPECT_EQ(CKR_OK, service_->DestroyObject(ic_, 1, 2));
}

TEST_F(TestService, GetObjectSize) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(2, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(object_, GetSize()).WillRepeatedly(Return(3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->GetObjectSize(ic_, 1, 2, NULL));
  uint64_t size = 0;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GetObjectSize(ic_, 1, 2, &size));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            service_->GetObjectSize(ic_, 1, 2, &size));
  EXPECT_EQ(CKR_OK, service_->GetObjectSize(ic_, 1, 2, &size));
  EXPECT_EQ(size, 3);
}

TEST_F(TestService, GetAttributeValue) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(2, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(object_, GetAttributes(_, 1))
      .WillOnce(Return(CKR_TEMPLATE_INCONSISTENT))
      .WillOnce(Return(CKR_ATTRIBUTE_SENSITIVE))
      .WillOnce(Return(CKR_ATTRIBUTE_TYPE_INVALID))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, NULL));
  vector<uint8_t> output;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, &output));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, &output));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->GetAttributeValue(ic_, 1, 2, bad_attributes_, &output));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, &output));
  EXPECT_EQ(output.size(), 0);
  EXPECT_EQ(CKR_ATTRIBUTE_SENSITIVE,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, &output));

  // Construct a template with a valid pointer to test serialization when the
  // mock returns CKR_ATTRIBUTE_TYPE_INVALID.
  int out_value = 1234;
  CK_ATTRIBUTE invalid_type = {0, &out_value, ~0UL};
  Attributes tmp(&invalid_type, 1);
  vector<uint8_t> tmp_serialized;
  tmp.Serialize(&tmp_serialized);
  EXPECT_EQ(CKR_ATTRIBUTE_TYPE_INVALID,
            service_->GetAttributeValue(ic_, 1, 2, tmp_serialized, &output));
  EXPECT_EQ(CKR_OK,
            service_->GetAttributeValue(ic_, 1, 2, good_attributes_, &output));
}

TEST_F(TestService, SetAttributeValue) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetModifiableObject(2, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(session_, FlushModifiableObject(_))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(object_, SetAttributes(_, 1))
      .WillOnce(Return(CKR_TEMPLATE_INCONSISTENT))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> output;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->SetAttributeValue(ic_, 1, 2, good_attributes_));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            service_->SetAttributeValue(ic_, 1, 2, good_attributes_));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->SetAttributeValue(ic_, 1, 2, bad_attributes_));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->SetAttributeValue(ic_, 1, 2, good_attributes_));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->SetAttributeValue(ic_, 1, 2, good_attributes_));
  EXPECT_EQ(CKR_OK, service_->SetAttributeValue(ic_, 1, 2, good_attributes_));
}

TEST_F(TestService, FindObjectsInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, FindObjectsInit(_, 1))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->FindObjectsInit(ic_, 1, good_attributes_));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->FindObjectsInit(ic_, 1, bad_attributes_));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->FindObjectsInit(ic_, 1, good_attributes_));
  EXPECT_EQ(CKR_OK, service_->FindObjectsInit(ic_, 1, good_attributes_));
}

TEST_F(TestService, FindObjects) {
  vector<uint64_t> objects_ret(12, 12);
  vector<int> objects_mock(12, 12);
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, FindObjects(2, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<1>(objects_mock), Return(CKR_OK)));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->FindObjects(ic_, 1, 2, NULL));
  vector<uint64_t> objects(1, 1);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->FindObjects(ic_, 1, 2, &objects));
  objects.clear();
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->FindObjects(ic_, 1, 2, &objects));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->FindObjects(ic_, 1, 2, &objects));
  EXPECT_EQ(CKR_OK, service_->FindObjects(ic_, 1, 2, &objects));
  EXPECT_TRUE(objects == objects_ret);
}

TEST_F(TestService, FindObjectsFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, FindObjectsFinal())
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->FindObjectsFinal(ic_, 1));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->FindObjectsFinal(ic_, 1));
  EXPECT_EQ(CKR_OK, service_->FindObjectsFinal(ic_, 1));
}

TEST_F(TestService, EncryptInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(3, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(session_, OperationInit(kEncrypt, 2, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> p(10, 0x10);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->EncryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_KEY_HANDLE_INVALID, service_->EncryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->EncryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_OK, service_->EncryptInit(ic_, 1, 2, p, 3));
}

TEST_F(TestService, Encrypt) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationSinglePart(kEncrypt, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Encrypt(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Encrypt(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->Encrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->Encrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->Encrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, EncryptUpdate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kEncrypt, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->EncryptUpdate(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->EncryptUpdate(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->EncryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->EncryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->EncryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, EncryptFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationFinal(kEncrypt, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<1>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->EncryptFinal(ic_, 1, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->EncryptFinal(ic_, 1, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->EncryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->EncryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->EncryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, DecryptInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(3, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(session_, OperationInit(kDecrypt, 2, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> p(10, 0x10);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->DecryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_KEY_HANDLE_INVALID, service_->DecryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->DecryptInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_OK, service_->DecryptInit(ic_, 1, 2, p, 3));
}

TEST_F(TestService, Decrypt) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationSinglePart(kDecrypt, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Decrypt(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Decrypt(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->Decrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->Decrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->Decrypt(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, DecryptUpdate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kDecrypt, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->DecryptUpdate(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            service_->DecryptUpdate(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->DecryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->DecryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->DecryptUpdate(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, DecryptFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationFinal(kDecrypt, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<1>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->DecryptFinal(ic_, 1, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->DecryptFinal(ic_, 1, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->DecryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->DecryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->DecryptFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, DigestInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationInit(kDigest, 2, _, NULL))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> p(10, 0x10);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->DigestInit(ic_, 1, 2, p));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->DigestInit(ic_, 1, 2, p));
  EXPECT_EQ(CKR_OK, service_->DigestInit(ic_, 1, 2, p));
}

TEST_F(TestService, Digest) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationSinglePart(kDigest, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Digest(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Digest(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->Digest(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->Digest(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->Digest(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, DigestUpdate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kDigest, _, NULL, NULL))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> data;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->DigestUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->DigestUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_OK, service_->DigestUpdate(ic_, 1, data));
}

TEST_F(TestService, DigestFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationFinal(kDigest, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<1>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->DigestFinal(ic_, 1, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->DigestFinal(ic_, 1, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->DigestFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->DigestFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->DigestFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, SignInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(3, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(session_, OperationInit(kSign, 2, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> p(10, 0x10);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->SignInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_KEY_HANDLE_INVALID, service_->SignInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->SignInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_OK, service_->SignInit(ic_, 1, 2, p, 3));
}

TEST_F(TestService, Sign) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationSinglePart(kSign, _, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<2>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Sign(ic_, 1, data, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->Sign(ic_, 1, data, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->Sign(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->Sign(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->Sign(ic_, 1, data, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, SignUpdate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kSign, _, NULL, NULL))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> data;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->SignUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->SignUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_OK, service_->SignUpdate(ic_, 1, data));
}

TEST_F(TestService, SignFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationFinal(kSign, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<1>(7), Return(CKR_OK)));
  vector<uint8_t> data;
  uint64_t len = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->SignFinal(ic_, 1, 2, NULL, &data));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, service_->SignFinal(ic_, 1, 2, &len, NULL));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->SignFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->SignFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(CKR_OK, service_->SignFinal(ic_, 1, 2, &len, &data));
  EXPECT_EQ(len, 7);
}

TEST_F(TestService, VerifyInit) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GetObject(3, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(&object_), Return(true)));
  EXPECT_CALL(session_, OperationInit(kVerify, 2, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> p(10, 0x10);
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->VerifyInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_KEY_HANDLE_INVALID, service_->VerifyInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->VerifyInit(ic_, 1, 2, p, 3));
  EXPECT_EQ(CKR_OK, service_->VerifyInit(ic_, 1, 2, p, 3));
}

TEST_F(TestService, Verify) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kVerify, _, NULL, NULL))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(session_, VerifyFinal(_))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> data;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->Verify(ic_, 1, data, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->Verify(ic_, 1, data, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->Verify(ic_, 1, data, data));
  EXPECT_EQ(CKR_OK, service_->Verify(ic_, 1, data, data));
}

TEST_F(TestService, VerifyUpdate) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, OperationUpdate(kVerify, _, NULL, NULL))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> data;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->VerifyUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->VerifyUpdate(ic_, 1, data));
  EXPECT_EQ(CKR_OK, service_->VerifyUpdate(ic_, 1, data));
}

TEST_F(TestService, VerifyFinal) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, VerifyFinal(_))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(Return(CKR_OK));
  vector<uint8_t> data;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->VerifyFinal(ic_, 1, data));
  EXPECT_EQ(CKR_FUNCTION_FAILED, service_->VerifyFinal(ic_, 1, data));
  EXPECT_EQ(CKR_OK, service_->VerifyFinal(ic_, 1, data));
}

TEST_F(TestService, GenerateKey) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GenerateKey(2, _, _, 1, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(DoAll(SetArgPointee<4>(3), Return(CKR_OK)));
  vector<uint8_t> param;
  uint64_t handle;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GenerateKey(ic_, 1, 2, param, good_attributes_, &handle));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->GenerateKey(ic_, 1, 2, param, bad_attributes_, &handle));
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            service_->GenerateKey(ic_, 1, 2, param, good_attributes_, &handle));
  EXPECT_EQ(CKR_OK,
            service_->GenerateKey(ic_, 1, 2, param, good_attributes_, &handle));
  EXPECT_EQ(handle, 3);
}

TEST_F(TestService, GenerateKeyPair) {
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GenerateKeyPair(2, _, _, 1, _, 1, _, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED))
      .WillRepeatedly(
          DoAll(SetArgPointee<6>(3), SetArgPointee<7>(4), Return(CKR_OK)));
  vector<uint8_t> param;
  uint64_t handle[2];
  EXPECT_EQ(
      CKR_SESSION_HANDLE_INVALID,
      service_->GenerateKeyPair(ic_, 1, 2, param, good_attributes_,
                                good_attributes2_, &handle[0], &handle[1]));
  EXPECT_EQ(
      CKR_TEMPLATE_INCONSISTENT,
      service_->GenerateKeyPair(ic_, 1, 2, param, bad_attributes_,
                                good_attributes2_, &handle[0], &handle[1]));
  EXPECT_EQ(CKR_TEMPLATE_INCONSISTENT,
            service_->GenerateKeyPair(ic_, 1, 2, param, good_attributes_,
                                      bad_attributes_, &handle[0], &handle[1]));
  EXPECT_EQ(
      CKR_FUNCTION_FAILED,
      service_->GenerateKeyPair(ic_, 1, 2, param, good_attributes_,
                                good_attributes2_, &handle[0], &handle[1]));
  EXPECT_EQ(CKR_OK, service_->GenerateKeyPair(
                        ic_, 1, 2, param, good_attributes_, good_attributes2_,
                        &handle[0], &handle[1]));
  EXPECT_EQ(handle[0], 3);
  EXPECT_EQ(handle[1], 4);
}

TEST_F(TestService, SeedRandom) {
  vector<uint8_t> seed(3, 'A');
  string seed_str("AAA");
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, SeedRandom(seed_str)).WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, service_->SeedRandom(ic_, 1, seed));
  EXPECT_EQ(CKR_OK, service_->SeedRandom(ic_, 1, seed));
}

TEST_F(TestService, GenerateRandom) {
  vector<uint8_t> random_data(3, 'B');
  string random_data_str("BBB");
  EXPECT_CALL(slot_manager_, GetSession(ic_, 1, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<2>(&session_), Return(true)));
  EXPECT_CALL(session_, GenerateRandom(8, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(random_data_str), Return(CKR_OK)));
  vector<uint8_t> output;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            service_->GenerateRandom(ic_, 1, 8, &output));
  EXPECT_EQ(CKR_OK, service_->GenerateRandom(ic_, 1, 8, &output));
  EXPECT_TRUE(output == random_data);
}

}  // namespace chaps
