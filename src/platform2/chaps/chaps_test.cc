// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Chaps client unit tests. These tests exercise the client layer (chaps.cc) and
// use a mock for the proxy interface so no D-Bus code is run.
//

#include "chaps/chaps_proxy_mock.h"

#include <iterator>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/attributes.h"
#include "pkcs11/cryptoki.h"

using std::string;
using std::vector;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::WithArg;

namespace chaps {

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

// Initialize / Finalize tests
TEST(TestInitialize, InitializeNULL) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_OK, C_Initialize(NULL_PTR));
  EXPECT_EQ(CKR_OK, C_Finalize(NULL_PTR));
}

TEST(TestInitializeDeathTest, InitializeOutOfMem) {
  EnableMockProxy(NULL, NULL, false);
  EXPECT_DEATH_IF_SUPPORTED(C_Initialize(NULL_PTR), "Check failed");
  DisableMockProxy();
}

TEST(TestInitialize, InitializeTwice) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_OK, C_Initialize(NULL_PTR));
  EXPECT_EQ(CKR_CRYPTOKI_ALREADY_INITIALIZED, C_Initialize(NULL_PTR));
  EXPECT_EQ(CKR_OK, C_Finalize(NULL_PTR));
}

TEST(TestInitialize, InitializeWithArgs) {
  ChapsProxyMock proxy(false);
  CK_C_INITIALIZE_ARGS args;
  memset(&args, 0, sizeof(args));
  EXPECT_EQ(CKR_OK, C_Initialize(&args));
  EXPECT_EQ(CKR_OK, C_Finalize(NULL_PTR));
}

TEST(TestInitialize, InitializeWithBadArgs) {
  ChapsProxyMock proxy(false);
  CK_C_INITIALIZE_ARGS args;
  memset(&args, 0, sizeof(args));
  args.CreateMutex = (CK_CREATEMUTEX)1;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Initialize(&args));
  memset(&args, 0, sizeof(args));
  args.LibraryParameters = reinterpret_cast<CK_CHAR_PTR*>(1);
  args.pReserved = (CK_VOID_PTR)1;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Initialize(&args));
}

TEST(TestInitialize, InitializeNoLocking) {
  ChapsProxyMock proxy(false);
  CK_C_INITIALIZE_ARGS args;
  memset(&args, 0xFF, sizeof(args));
  args.flags = 0;
  args.pReserved = 0;
  EXPECT_EQ(CKR_CANT_LOCK, C_Initialize(&args));
}

TEST(TestInitialize, FinalizeWithArgs) {
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Finalize(reinterpret_cast<void*>(1)));
}

TEST(TestInitialize, FinalizeNotInit) {
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Finalize(NULL_PTR));
}

TEST(TestInitialize, Reinitialize) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_OK, C_Initialize(NULL_PTR));
  EXPECT_EQ(CKR_OK, C_Finalize(NULL_PTR));
  EXPECT_EQ(CKR_OK, C_Initialize(NULL_PTR));
}

// Library Information Tests
TEST(TestLibInfo, LibInfoOK) {
  ChapsProxyMock proxy(true);
  CK_INFO info;
  EXPECT_EQ(CKR_OK, C_GetInfo(&info));
}

TEST(TestLibInfo, LibInfoNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetInfo(NULL));
}

TEST(TestLibInfo, LibInfoNotInit) {
  ChapsProxyMock proxy(false);
  CK_INFO info;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetInfo(&info));
}

// Slot List Tests
class TestSlotList : public ::testing::Test {
 protected:
  void SetUp() override {
    uint64_t slot_array[3] = {1, 2, 3};
    slot_list_all_.assign(&slot_array[0], &slot_array[3]);
    slot_list_present_.assign(&slot_array[1], &slot_array[3]);
  }
  vector<uint64_t> slot_list_all_;
  vector<uint64_t> slot_list_present_;
};

TEST_F(TestSlotList, SlotListOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_all_), Return(CKR_OK)));
  CK_SLOT_ID slots[3];
  CK_ULONG num_slots = 3;
  EXPECT_EQ(CKR_OK, C_GetSlotList(CK_FALSE, slots, &num_slots));
  EXPECT_EQ(num_slots, slot_list_all_.size());
  EXPECT_EQ(slots[0], slot_list_all_[0]);
  EXPECT_EQ(slots[1], slot_list_all_[1]);
  EXPECT_EQ(slots[2], slot_list_all_[2]);
}

TEST_F(TestSlotList, SlotListNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetSlotList(CK_FALSE, NULL, NULL));
}

TEST_F(TestSlotList, SlotListNotInit) {
  ChapsProxyMock proxy(false);
  CK_SLOT_ID slots[3];
  CK_ULONG num_slots = 3;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_GetSlotList(CK_FALSE, slots, &num_slots));
}

TEST_F(TestSlotList, SlotListNoBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_all_), Return(CKR_OK)));
  CK_ULONG num_slots = 17;
  EXPECT_EQ(CKR_OK, C_GetSlotList(CK_FALSE, NULL, &num_slots));
  EXPECT_EQ(num_slots, slot_list_all_.size());
}

TEST_F(TestSlotList, SlotListSmallBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_all_), Return(CKR_OK)));
  CK_SLOT_ID slots[2];
  CK_ULONG num_slots = 2;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL, C_GetSlotList(CK_FALSE, slots, &num_slots));
  EXPECT_EQ(num_slots, slot_list_all_.size());
}

TEST_F(TestSlotList, SlotListLargeBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_all_), Return(CKR_OK)));
  CK_SLOT_ID slots[4];
  CK_ULONG num_slots = 4;
  EXPECT_EQ(CKR_OK, C_GetSlotList(CK_FALSE, slots, &num_slots));
  EXPECT_EQ(num_slots, slot_list_all_.size());
  EXPECT_EQ(slots[0], slot_list_all_[0]);
  EXPECT_EQ(slots[1], slot_list_all_[1]);
  EXPECT_EQ(slots[2], slot_list_all_[2]);
}

TEST_F(TestSlotList, SlotListPresentOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, true, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_present_), Return(CKR_OK)));
  CK_SLOT_ID slots[4];
  CK_ULONG num_slots = 4;
  EXPECT_EQ(CKR_OK, C_GetSlotList(CK_TRUE, slots, &num_slots));
  EXPECT_EQ(num_slots, slot_list_present_.size());
  EXPECT_EQ(slots[0], slot_list_present_[0]);
  EXPECT_EQ(slots[1], slot_list_present_[1]);
}

TEST_F(TestSlotList, SlotListFailure) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(slot_list_present_),
                      Return(CKR_FUNCTION_FAILED)));
  CK_SLOT_ID slots[4];
  CK_ULONG num_slots = 4;
  EXPECT_EQ(CKR_FUNCTION_FAILED, C_GetSlotList(CK_FALSE, slots, &num_slots));
}

// Slot Info Tests
namespace {

void SetSlotInfo(SlotInfo* slot_info) {
  slot_info->set_slot_description(std::string(64, ' '));
  slot_info->set_manufacturer_id(std::string(32, ' '));
  slot_info->set_flags(1);
  slot_info->mutable_hardware_version()->set_major(2);
  slot_info->mutable_hardware_version()->set_minor(20);
  slot_info->mutable_firmware_version()->set_major(3);
  slot_info->mutable_firmware_version()->set_minor(30);
}

}  // namespace

TEST(TestSlotInfo, SlotInfoOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotInfo(_, 1, _))
      .WillOnce(DoAll(WithArg<2>(Invoke(&SetSlotInfo)), Return(CKR_OK)));
  CK_SLOT_INFO info;
  memset(&info, 0, sizeof(info));
  EXPECT_EQ(CKR_OK, C_GetSlotInfo(1, &info));
  uint8_t spaces[64];
  memset(spaces, ' ', std::size(spaces));
  EXPECT_EQ(0, memcmp(spaces, info.slotDescription, 64));
  EXPECT_EQ(0, memcmp(spaces, info.manufacturerID, 32));
  EXPECT_EQ(1, info.flags);
  EXPECT_EQ(2, info.hardwareVersion.major);
  EXPECT_EQ(20, info.hardwareVersion.minor);
  EXPECT_EQ(3, info.firmwareVersion.major);
  EXPECT_EQ(30, info.firmwareVersion.minor);
}

TEST(TestSlotInfo, SlotInfoNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetSlotInfo(1, NULL));
}

TEST(TestSlotInfo, SlotInfoNotInit) {
  ChapsProxyMock proxy(false);
  CK_SLOT_INFO info;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetSlotInfo(1, &info));
}

TEST(TestSlotInfo, SlotInfoFailure) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSlotInfo(_, 1, _))
      .WillOnce(Return(CKR_FUNCTION_FAILED));
  CK_SLOT_INFO info;
  EXPECT_EQ(CKR_FUNCTION_FAILED, C_GetSlotInfo(1, &info));
}

// Token Info Tests
namespace {

void SetTokenInfo(TokenInfo* token_info) {
  token_info->set_label(std::string(32, ' '));
  token_info->set_manufacturer_id(std::string(32, ' '));
  token_info->set_model(std::string(16, ' '));
  token_info->set_serial_number(std::string(16, ' '));
  token_info->set_flags(1);
  token_info->set_max_session_count(7);
  token_info->set_session_count(6);
  token_info->set_max_session_count_rw(5);
  token_info->set_session_count_rw(2);
  token_info->set_max_pin_len(8);
  token_info->set_min_pin_len(4);
  token_info->set_total_public_memory(1048576);
  token_info->set_free_public_memory(531441);
  token_info->set_total_private_memory(2097152);
  token_info->set_free_private_memory(1594323);
  token_info->mutable_hardware_version()->set_major(2);
  token_info->mutable_hardware_version()->set_minor(20);
  token_info->mutable_firmware_version()->set_major(3);
  token_info->mutable_firmware_version()->set_minor(30);
}

}  // namespace

TEST(TestTokenInfo, TokenInfoOK) {
  ChapsProxyMock proxy(true);
  CK_TOKEN_INFO info;
  EXPECT_CALL(proxy, GetTokenInfo(_, 1, _))
      .WillOnce(DoAll(WithArg<2>(Invoke(&SetTokenInfo)), Return(CKR_OK)));
  memset(&info, 0, sizeof(info));
  EXPECT_EQ(CKR_OK, C_GetTokenInfo(1, &info));
  uint8_t spaces[64];
  memset(spaces, ' ', std::size(spaces));
  EXPECT_EQ(0, memcmp(spaces, info.label, 32));
  EXPECT_EQ(0, memcmp(spaces, info.manufacturerID, 32));
  EXPECT_EQ(0, memcmp(spaces, info.model, 16));
  EXPECT_EQ(0, memcmp(spaces, info.serialNumber, 16));
  EXPECT_EQ(1, info.flags);
  EXPECT_EQ(7, info.ulMaxSessionCount);
  EXPECT_EQ(6, info.ulSessionCount);
  EXPECT_EQ(5, info.ulMaxRwSessionCount);
  EXPECT_EQ(2, info.ulRwSessionCount);
  EXPECT_EQ(8, info.ulMaxPinLen);
  EXPECT_EQ(4, info.ulMinPinLen);
  EXPECT_EQ(1048576, info.ulTotalPublicMemory);
  EXPECT_EQ(531441, info.ulFreePublicMemory);
  EXPECT_EQ(2097152, info.ulTotalPrivateMemory);
  EXPECT_EQ(1594323, info.ulFreePrivateMemory);
  EXPECT_EQ(2, info.hardwareVersion.major);
  EXPECT_EQ(20, info.hardwareVersion.minor);
  EXPECT_EQ(3, info.firmwareVersion.major);
  EXPECT_EQ(30, info.firmwareVersion.minor);
}

TEST(TestTokenInfo, TokenInfoNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetTokenInfo(1, NULL));
}

TEST(TestTokenInfo, TokenInfoNotInit) {
  ChapsProxyMock proxy(false);
  CK_TOKEN_INFO info;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetTokenInfo(1, &info));
}

// WaitSlotEvent Tests
TEST(TestWaitSlotEvent, SlotEventNonBlock) {
  ChapsProxyMock proxy(true);
  CK_SLOT_ID slot = 0;
  EXPECT_EQ(CKR_NO_EVENT, C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot, NULL));
}

// This is a helper function for the SlotEventBlock test.
static void* CallFinalize(void* reserved) {
  // The main thread has likely already proceeded into C_WaitForSlotEvent but to
  // increase this chance we'll yield for a bit. The test will pass even in the
  // unlikely event that we hit C_Finalize before the main thread begins
  // waiting.
  usleep(10000);
  C_Finalize(NULL);
  return NULL;
}

TEST(TestWaitSlotEvent, SlotEventBlock) {
  ChapsProxyMock proxy(true);
  CK_SLOT_ID slot = 0;
  pthread_t thread;
  pthread_create(&thread, NULL, CallFinalize, NULL);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_WaitForSlotEvent(0, &slot, NULL));
}

TEST(TestWaitSlotEvent, SlotEventNotInit) {
  ChapsProxyMock proxy(false);
  CK_SLOT_ID slot = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_WaitForSlotEvent(0, &slot, NULL));
}

TEST(TestWaitSlotEvent, SlotEventBadArgs) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_WaitForSlotEvent(0, NULL, NULL));
}

// Mechanism List Tests
class TestMechList : public ::testing::Test {
 protected:
  void SetUp() override {
    uint64_t mech_array[3] = {1, 2, 3};
    mech_list_all_.assign(&mech_array[0], &mech_array[3]);
    mech_list_present_.assign(&mech_array[1], &mech_array[3]);
  }
  vector<uint64_t> mech_list_all_;
  vector<uint64_t> mech_list_present_;
};

TEST_F(TestMechList, MechListOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_all_), Return(CKR_OK)));
  CK_SLOT_ID mechs[3];
  CK_ULONG num_mechs = 3;
  EXPECT_EQ(CKR_OK, C_GetMechanismList(CK_FALSE, mechs, &num_mechs));
  EXPECT_EQ(num_mechs, mech_list_all_.size());
  EXPECT_EQ(mechs[0], mech_list_all_[0]);
  EXPECT_EQ(mechs[1], mech_list_all_[1]);
  EXPECT_EQ(mechs[2], mech_list_all_[2]);
}

TEST_F(TestMechList, MechListNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetMechanismList(CK_FALSE, NULL, NULL));
}

TEST_F(TestMechList, MechListNotInit) {
  ChapsProxyMock proxy(false);
  CK_SLOT_ID mechs[3];
  CK_ULONG num_mechs = 3;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_GetMechanismList(CK_FALSE, mechs, &num_mechs));
}

TEST_F(TestMechList, MechListNoBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_all_), Return(CKR_OK)));
  CK_ULONG num_mechs = 17;
  EXPECT_EQ(CKR_OK, C_GetMechanismList(CK_FALSE, NULL, &num_mechs));
  EXPECT_EQ(num_mechs, mech_list_all_.size());
}

TEST_F(TestMechList, MechListSmallBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_all_), Return(CKR_OK)));
  CK_SLOT_ID mechs[2];
  CK_ULONG num_mechs = 2;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            C_GetMechanismList(CK_FALSE, mechs, &num_mechs));
  EXPECT_EQ(num_mechs, mech_list_all_.size());
}

TEST_F(TestMechList, MechListLargeBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_all_), Return(CKR_OK)));
  CK_SLOT_ID mechs[4];
  CK_ULONG num_mechs = 4;
  EXPECT_EQ(CKR_OK, C_GetMechanismList(CK_FALSE, mechs, &num_mechs));
  EXPECT_EQ(num_mechs, mech_list_all_.size());
  EXPECT_EQ(mechs[0], mech_list_all_[0]);
  EXPECT_EQ(mechs[1], mech_list_all_[1]);
  EXPECT_EQ(mechs[2], mech_list_all_[2]);
}

TEST_F(TestMechList, MechListPresentOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, true, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_present_), Return(CKR_OK)));
  CK_SLOT_ID mechs[4];
  CK_ULONG num_mechs = 4;
  EXPECT_EQ(CKR_OK, C_GetMechanismList(CK_TRUE, mechs, &num_mechs));
  EXPECT_EQ(num_mechs, mech_list_present_.size());
  EXPECT_EQ(mechs[0], mech_list_present_[0]);
  EXPECT_EQ(mechs[1], mech_list_present_[1]);
}

TEST_F(TestMechList, MechListFailure) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismList(_, false, _))
      .WillOnce(DoAll(SetArgPointee<2>(mech_list_present_),
                      Return(CKR_FUNCTION_FAILED)));
  CK_SLOT_ID mechs[4];
  CK_ULONG num_mechs = 4;
  EXPECT_EQ(CKR_FUNCTION_FAILED,
            C_GetMechanismList(CK_FALSE, mechs, &num_mechs));
}

// Mechanism Info Tests
namespace {

void SetMechanismInfo(MechanismInfo* mechanism_info) {
  mechanism_info->set_min_key_size(1024);
  mechanism_info->set_max_key_size(2048);
  mechanism_info->set_flags(1);
}

}  // namespace

TEST(TestMechInfo, MechInfoOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismInfo(_, 1, 2, _))
      .WillOnce(DoAll(WithArg<3>(Invoke(&SetMechanismInfo)), Return(CKR_OK)));
  CK_MECHANISM_INFO info;
  memset(&info, 0, sizeof(info));
  EXPECT_EQ(CKR_OK, C_GetMechanismInfo(1, 2, &info));
  EXPECT_EQ(1024, info.ulMinKeySize);
  EXPECT_EQ(2048, info.ulMaxKeySize);
  EXPECT_EQ(1, info.flags);
}

TEST(TestMechInfo, MechInfoNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetMechanismInfo(1, 2, NULL));
}

TEST(TestMechInfo, MechInfoNotInit) {
  ChapsProxyMock proxy(false);
  CK_MECHANISM_INFO info;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetMechanismInfo(1, 2, &info));
}

TEST(TestMechInfo, MechInfoFailure) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetMechanismInfo(_, 1, 2, _))
      .WillOnce(Return(CKR_MECHANISM_INVALID));
  CK_MECHANISM_INFO info;
  EXPECT_EQ(CKR_MECHANISM_INVALID, C_GetMechanismInfo(1, 2, &info));
}

// Init Token Tests
TEST(TestInitToken, InitTokenOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitToken(_, 1, _, _)).WillOnce(Return(CKR_OK));
  CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) "test";
  CK_UTF8CHAR label[32];
  memset(label, ' ', 32);
  memcpy(label, "test", 4);
  EXPECT_EQ(CKR_OK, C_InitToken(1, pin, 4, label));
}

TEST(TestInitToken, InitTokenNotInit) {
  ChapsProxyMock proxy(false);
  CK_UTF8CHAR label[32];
  memset(label, ' ', 32);
  memcpy(label, "test", 4);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_InitToken(1, NULL, 0, label));
}

TEST(TestInitToken, InitTokenNULLLabel) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_InitToken(1, NULL, 0, NULL));
}

TEST(TestInitToken, InitTokenNULLPin) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitToken(_, 1, _, _)).WillOnce(Return(CKR_OK));
  CK_UTF8CHAR label[32];
  memset(label, ' ', 32);
  memcpy(label, "test", 4);
  EXPECT_EQ(CKR_OK, C_InitToken(1, NULL, 0, label));
}

TEST(TestInitToken, InitTokenFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitToken(_, 1, _, _)).WillOnce(Return(CKR_PIN_INVALID));
  CK_UTF8CHAR label[32];
  memset(label, ' ', 32);
  memcpy(label, "test", 4);
  EXPECT_EQ(CKR_PIN_INVALID, C_InitToken(1, NULL, 0, label));
}

// Init PIN Tests
TEST(TestInitPIN, InitPINOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitPIN(_, 1, _)).WillOnce(Return(CKR_OK));
  CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) "test";
  EXPECT_EQ(CKR_OK, C_InitPIN(1, pin, 4));
}

TEST(TestInitPIN, InitPINNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_InitPIN(1, NULL, 0));
}

TEST(TestInitPIN, InitPINNULLPin) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitPIN(_, 1, _)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_InitPIN(1, NULL, 0));
}

TEST(TestInitPIN, InitPINFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, InitPIN(_, 1, _)).WillOnce(Return(CKR_PIN_INVALID));
  EXPECT_EQ(CKR_PIN_INVALID, C_InitPIN(1, NULL, 0));
}

// Set PIN Tests
TEST(TestSetPIN, SetPINOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetPIN(_, 1, _, _)).WillOnce(Return(CKR_OK));
  CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) "test";
  EXPECT_EQ(CKR_OK, C_SetPIN(1, pin, 4, pin, 4));
}

TEST(TestSetPIN, SetPINNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SetPIN(1, NULL, 0, NULL, 0));
}

TEST(TestSetPIN, SetPINNULLPin) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetPIN(_, 1, _, _)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_SetPIN(1, NULL, 0, NULL, 0));
}

TEST(TestSetPIN, SetPINFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetPIN(_, 1, _, _)).WillOnce(Return(CKR_PIN_INVALID));
  EXPECT_EQ(CKR_PIN_INVALID, C_SetPIN(1, NULL, 0, NULL, 0));
}

// Open Session Tests
TEST(TestOpenSession, OpenSessionOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, OpenSession(_, 1, CKF_SERIAL_SESSION, _))
      .WillOnce(DoAll(SetArgPointee<3>(3), Return(CKR_OK)));
  CK_SESSION_HANDLE session;
  EXPECT_EQ(CKR_OK, C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &session));
  EXPECT_EQ(session, 3);
}

TEST(TestOpenSession, OpenSessionNotInit) {
  ChapsProxyMock proxy(false);
  CK_SESSION_HANDLE session;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &session));
}

TEST(TestOpenSession, OpenSessionNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, NULL));
}

TEST(TestOpenSession, OpenSessionFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, OpenSession(_, 1, CKF_SERIAL_SESSION, _))
      .WillOnce(Return(CKR_SESSION_COUNT));
  CK_SESSION_HANDLE session;
  EXPECT_EQ(CKR_SESSION_COUNT,
            C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &session));
}

// Close Session Tests
TEST(TestCloseSession, CloseSessionOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CloseSession(_, 1)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_CloseSession(1));
}

TEST(TestCloseSession, CloseSessionNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_CloseSession(1));
}

TEST(TestCloseSession, CloseSessionFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CloseSession(_, 1))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, C_CloseSession(1));
}

TEST(TestCloseSession, CloseAllSessionsOK) {
  ChapsProxyMock proxy(true);

  constexpr uint64_t kSlot1 = 1;
  constexpr uint64_t kSlot2 = 2;

  constexpr CK_SESSION_HANDLE kSession1 = 5;
  constexpr CK_SESSION_HANDLE kSession2 = 6;
  constexpr CK_SESSION_HANDLE kSession3 = 7;

  // Open 3 sessions, 2 of them belong to slot1 (5,6) and 1 of them slot2 (7).
  EXPECT_CALL(proxy, OpenSession(_, kSlot1, CKF_SERIAL_SESSION, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSession1), Return(CKR_OK)))
      .WillOnce(DoAll(SetArgPointee<3>(kSession2), Return(CKR_OK)));
  EXPECT_CALL(proxy, OpenSession(_, kSlot2, CKF_SERIAL_SESSION, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSession3), Return(CKR_OK)));

  CK_SESSION_HANDLE session1, session2, session3;
  EXPECT_EQ(CKR_OK,
            C_OpenSession(kSlot1, CKF_SERIAL_SESSION, NULL, NULL, &session1));
  EXPECT_EQ(CKR_OK,
            C_OpenSession(kSlot1, CKF_SERIAL_SESSION, NULL, NULL, &session2));
  EXPECT_EQ(CKR_OK,
            C_OpenSession(kSlot2, CKF_SERIAL_SESSION, NULL, NULL, &session3));

  EXPECT_CALL(proxy, CloseSession(_, kSession1)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, CloseSession(_, kSession2)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, CloseSession(_, kSession3)).Times(0);

  EXPECT_EQ(CKR_OK, C_CloseAllSessions(kSlot1));
}

TEST(TestCloseSession, CloseAllSessionsNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_CloseAllSessions(1));
}

TEST(TestCloseSession, CloseAllSessionsFail) {
  ChapsProxyMock proxy(true);

  constexpr uint64_t kSlot1 = 1;

  constexpr CK_SESSION_HANDLE kSession1 = 5;
  constexpr CK_SESSION_HANDLE kSession2 = 6;

  // Open 2 sessions belonging to slot1.
  EXPECT_CALL(proxy, OpenSession(_, kSlot1, CKF_SERIAL_SESSION, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSession1), Return(CKR_OK)))
      .WillOnce(DoAll(SetArgPointee<3>(kSession2), Return(CKR_OK)));

  CK_SESSION_HANDLE session1, session2;
  EXPECT_EQ(CKR_OK,
            C_OpenSession(kSlot1, CKF_SERIAL_SESSION, NULL, NULL, &session1));
  EXPECT_EQ(CKR_OK,
            C_OpenSession(kSlot1, CKF_SERIAL_SESSION, NULL, NULL, &session2));

  // When closing one of the handles failed, the function should fail.
  EXPECT_CALL(proxy, CloseSession(_, kSession1))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID));
  EXPECT_CALL(proxy, CloseSession(_, kSession2)).WillOnce(Return(CKR_OK));

  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, C_CloseAllSessions(kSlot1));
}

// Get Session Info Tests
namespace {

void SetSessionInfo(SessionInfo* session_info) {
  session_info->set_slot_id(2);
  session_info->set_state(3);
  session_info->set_flags(5);
  session_info->set_device_error(0);
}

}  // namespace

TEST(TestGetSessionInfo, GetSessionInfoOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSessionInfo(_, 1, _))
      .WillOnce(DoAll(WithArg<2>(Invoke(&SetSessionInfo)), Return(CKR_OK)));
  CK_SESSION_INFO info;
  EXPECT_EQ(CKR_OK, C_GetSessionInfo(1, &info));
  EXPECT_EQ(2, info.slotID);
  EXPECT_EQ(3, info.state);
  EXPECT_EQ(5, info.flags);
  EXPECT_EQ(0, info.ulDeviceError);
}

TEST(TestGetSessionInfo, GetSessionInfoNotInit) {
  ChapsProxyMock proxy(false);
  CK_SESSION_INFO info;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetSessionInfo(1, &info));
}

TEST(TestGetSessionInfo, GetSessionInfoNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetSessionInfo(1, NULL));
}

TEST(TestGetSessionInfo, GetSessionInfoFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetSessionInfo(_, 1, _))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID));
  CK_SESSION_INFO info;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, C_GetSessionInfo(1, &info));
}

// Get Operation State Tests
class TestGetOperationState : public ::testing::Test {
 protected:
  void SetUp() override {
    uint8_t tmp[3] = {1, 2, 3};
    buffer_ = vector<uint8_t>(&tmp[0], &tmp[3]);
  }
  vector<uint8_t> buffer_;
};

TEST_F(TestGetOperationState, GetOperationStateOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetOperationState(_, 1, _))
      .WillOnce(DoAll(SetArgPointee<2>(buffer_), Return(CKR_OK)));
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_OK, C_GetOperationState(1, buffer, &size));
  EXPECT_EQ(size, buffer_.size());
  EXPECT_EQ(buffer[0], buffer_[0]);
  EXPECT_EQ(buffer[1], buffer_[1]);
  EXPECT_EQ(buffer[2], buffer_[2]);
}

TEST_F(TestGetOperationState, GetOperationStateNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetOperationState(CK_FALSE, NULL, NULL));
}

TEST_F(TestGetOperationState, GetOperationStateNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_GetOperationState(1, buffer, &size));
}

TEST_F(TestGetOperationState, GetOperationStateNoBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetOperationState(_, 1, _))
      .WillOnce(DoAll(SetArgPointee<2>(buffer_), Return(CKR_OK)));
  CK_ULONG size = 17;
  EXPECT_EQ(CKR_OK, C_GetOperationState(1, NULL, &size));
  EXPECT_EQ(size, buffer_.size());
}

TEST_F(TestGetOperationState, GetOperationStateSmallBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetOperationState(_, 1, _))
      .WillOnce(DoAll(SetArgPointee<2>(buffer_), Return(CKR_OK)));
  CK_BYTE buffer[2];
  CK_ULONG size = 2;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL, C_GetOperationState(1, buffer, &size));
  EXPECT_EQ(size, buffer_.size());
}

TEST_F(TestGetOperationState, GetOperationStateLargeBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetOperationState(_, 1, _))
      .WillOnce(DoAll(SetArgPointee<2>(buffer_), Return(CKR_OK)));
  CK_BYTE buffer[4];
  CK_ULONG size = 4;
  EXPECT_EQ(CKR_OK, C_GetOperationState(1, buffer, &size));
  EXPECT_EQ(size, buffer_.size());
  EXPECT_EQ(buffer[0], buffer_[0]);
  EXPECT_EQ(buffer[1], buffer_[1]);
  EXPECT_EQ(buffer[2], buffer_[2]);
}

TEST_F(TestGetOperationState, GetOperationStateFailure) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetOperationState(_, 1, _))
      .WillOnce(Return(CKR_STATE_UNSAVEABLE));
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_STATE_UNSAVEABLE, C_GetOperationState(1, buffer, &size));
}

// Set Operation State Tests
TEST(TestSetOperationState, SetOperationStateOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetOperationState(_, 1, _, 2, 3)).WillOnce(Return(CKR_OK));
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_OK, C_SetOperationState(1, buffer, size, 2, 3));
}

TEST(TestSetOperationState, SetOperationStateNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_SetOperationState(1, buffer, size, 2, 3));
}

TEST(TestSetOperationState, SetOperationStateNull) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SetOperationState(1, NULL, 0, 2, 3));
}

TEST(TestSetOperationState, SetOperationStateFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetOperationState(_, 1, _, 2, 3))
      .WillOnce(Return(CKR_SESSION_HANDLE_INVALID));
  CK_BYTE buffer[3];
  CK_ULONG size = 3;
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID,
            C_SetOperationState(1, buffer, size, 2, 3));
}

// Login Tests
TEST(TestLogin, LoginOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Login(_, 1, CKU_USER, _)).WillOnce(Return(CKR_OK));
  CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR) "test";
  EXPECT_EQ(CKR_OK, C_Login(1, CKU_USER, pin, 4));
}

TEST(TestLogin, LoginNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Login(1, CKU_USER, NULL, 0));
}

TEST(TestLogin, LoginNULLPin) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Login(_, 1, CKU_USER, _)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_Login(1, CKU_USER, NULL, 0));
}

TEST(TestLogin, LoginFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Login(_, 1, CKU_USER, _))
      .WillOnce(Return(CKR_PIN_INVALID));
  EXPECT_EQ(CKR_PIN_INVALID, C_Login(1, CKU_USER, NULL, 0));
}

TEST(TestLogin, LoginNoPrivateWait) {
  ChapsProxyMock proxy(true);
  SetRetryTimeParameters(1500 /* timeout_ms */, 0 /* delay_ms */);
  EXPECT_CALL(proxy, Login(_, _, _, _))
      .WillOnce(Return(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS))
      .WillRepeatedly(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_Login(1, CKU_USER, NULL, 0));
}

TEST(TestLogin, LoginNoPrivateTimeout) {
  ChapsProxyMock proxy(true);
  SetRetryTimeParameters(5 /* timeout_ms */, 0 /* delay_ms */);
  EXPECT_CALL(proxy, Login(_, _, _, _))
      .WillRepeatedly(Return(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS));
  EXPECT_EQ(CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS, C_Login(1, CKU_USER, NULL, 0));
}

// Logout Tests
TEST(TestLogout, LogoutOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Logout(_, 1)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_Logout(1));
}

TEST(TestLogout, LogoutNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Logout(1));
}

TEST(TestLogout, LogoutFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Logout(_, 1)).WillOnce(Return(CKR_SESSION_HANDLE_INVALID));
  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, C_Logout(1));
}

// CreateObject Tests
class TestAttributes : public ::testing::Test {
 protected:
  void SetUp() override {
    attribute_template_[0].type = CKA_ID;
    attribute_template_[0].ulValueLen = 4;
    attribute_template_[0].pValue = const_cast<char*>("test");
    attribute_template_[1].type = CKA_AC_ISSUER;
    attribute_template_[1].ulValueLen = 5;
    attribute_template_[1].pValue = const_cast<char*>("test2");
    attribute_template2_[0].type = CKA_ID;
    attribute_template2_[0].ulValueLen = 4;
    attribute_template2_[0].pValue = buf_[0];
    attribute_template2_[1].type = CKA_AC_ISSUER;
    attribute_template2_[1].ulValueLen = 5;
    attribute_template2_[1].pValue = buf_[1];
    attribute_template3_[0].type = CKA_ID;
    attribute_template3_[0].ulValueLen = 4;
    attribute_template3_[0].pValue = NULL;
    attribute_template3_[1].type = CKA_AC_ISSUER;
    attribute_template3_[1].ulValueLen = 5;
    attribute_template3_[1].pValue = NULL;
    ASSERT_TRUE(SerializeAttributes(attribute_template_, 2, &attributes_));
    ASSERT_TRUE(SerializeAttributes(attribute_template2_, 2, &attributes2_));
    ASSERT_TRUE(SerializeAttributes(attribute_template3_, 2, &attributes3_));
  }

  bool CompareAttributes(CK_ATTRIBUTE_PTR a1, CK_ATTRIBUTE_PTR a2, int size) {
    if (!a1 || !a2)
      return false;
    for (int i = 0; i < size; ++i) {
      if (a1[i].type != a2[i].type || a1[i].ulValueLen != a2[i].ulValueLen ||
          !a1[i].pValue != !a2[i].pValue)
        return false;
      if (!a1[i].pValue)
        continue;
      if (0 != memcmp(a1[i].pValue, a2[i].pValue, a1[i].ulValueLen))
        return false;
    }
    return true;
  }

  vector<uint8_t> attributes_;
  vector<uint8_t> attributes2_;
  vector<uint8_t> attributes3_;
  CK_ATTRIBUTE attribute_template_[2];
  char buf_[2][10];
  CK_ATTRIBUTE attribute_template2_[2];
  CK_ATTRIBUTE attribute_template3_[2];
};

TEST_F(TestAttributes, CreateObjectOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CreateObject(_, 1, attributes_, _))
      .WillOnce(DoAll(SetArgPointee<3>(3), Return(CKR_OK)));
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_OK, C_CreateObject(1, attribute_template_, 2, &object_handle));
  EXPECT_EQ(3, object_handle);
}

TEST_F(TestAttributes, CreateObjectNotInit) {
  ChapsProxyMock proxy(false);
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_CreateObject(1, attribute_template_, 2, &object_handle));
}

TEST_F(TestAttributes, CreateObjectNULLHandle) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_CreateObject(1, attribute_template_, 2, NULL));
}

TEST_F(TestAttributes, CreateObjectFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CreateObject(_, 1, attributes_, _))
      .WillOnce(Return(CKR_ATTRIBUTE_TYPE_INVALID));
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_ATTRIBUTE_TYPE_INVALID,
            C_CreateObject(1, attribute_template_, 2, &object_handle));
}

// CopyObject Tests
TEST_F(TestAttributes, CopyObjectOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CopyObject(_, 1, 2, attributes_, _))
      .WillOnce(DoAll(SetArgPointee<4>(3), Return(CKR_OK)));
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_OK, C_CopyObject(1, 2, attribute_template_, 2, &object_handle));
  EXPECT_EQ(3, object_handle);
}

TEST_F(TestAttributes, CopyObjectNotInit) {
  ChapsProxyMock proxy(false);
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_CopyObject(1, 2, attribute_template_, 2, &object_handle));
}

TEST_F(TestAttributes, CopyObjectNULLHandle) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_CopyObject(1, 2, attribute_template_, 2, NULL));
}

TEST_F(TestAttributes, CopyObjectFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, CopyObject(_, 1, 2, attributes_, _))
      .WillOnce(Return(CKR_ATTRIBUTE_TYPE_INVALID));
  CK_OBJECT_HANDLE object_handle = 0;
  EXPECT_EQ(CKR_ATTRIBUTE_TYPE_INVALID,
            C_CopyObject(1, 2, attribute_template_, 2, &object_handle));
}

// Attribute Serialization Tests
TEST_F(TestAttributes, TestAttributesSerialize) {
  vector<uint8_t> serialized;
  EXPECT_TRUE(SerializeAttributes(attribute_template_, 2, &serialized));
  EXPECT_TRUE(serialized == attributes_);
  Attributes tmp;
  EXPECT_TRUE(tmp.Parse(attributes_));
  EXPECT_TRUE(CompareAttributes(tmp.attributes(), attribute_template_, 2));
  vector<uint8_t> serialized2;
  EXPECT_TRUE(SerializeAttributes(tmp.attributes(), 2, &serialized2));
  EXPECT_TRUE(attributes_ == serialized2);
  EXPECT_TRUE(tmp.Parse(serialized));
  EXPECT_TRUE(CompareAttributes(attribute_template_, tmp.attributes(), 2));
}

TEST_F(TestAttributes, TestAttributesFill) {
  char buf1[10];
  char buf2[10];
  CK_ATTRIBUTE tmp_array[] = {{CKA_ID, buf1, 10}, {CKA_AC_ISSUER, buf2, 10}};
  EXPECT_TRUE(ParseAndFillAttributes(attributes_, tmp_array, 2));
  EXPECT_TRUE(CompareAttributes(attribute_template_, tmp_array, 2));
  EXPECT_FALSE(ParseAndFillAttributes(attributes_, NULL, 2));
  EXPECT_FALSE(ParseAndFillAttributes(vector<uint8_t>(20, 0), tmp_array, 2));
  EXPECT_FALSE(ParseAndFillAttributes(attributes_, tmp_array, 1));
  EXPECT_FALSE(ParseAndFillAttributes(attributes_, tmp_array, 3));
  tmp_array[0].pValue = NULL;
  EXPECT_FALSE(ParseAndFillAttributes(attributes_, tmp_array, 2));
  tmp_array[0].pValue = buf1;
  tmp_array[0].ulValueLen = 1;
  EXPECT_FALSE(ParseAndFillAttributes(attributes_, tmp_array, 2));
}

TEST_F(TestAttributes, TestAttributesNested) {
  char id[] = "myid";
  char issuer[] = "myissuer";
  CK_BBOOL true_val = CK_TRUE;
  CK_ATTRIBUTE tmp_array_inner[] = {{CKA_ENCRYPT, &true_val, sizeof(CK_BBOOL)},
                                    {CKA_SIGN, &true_val, sizeof(CK_BBOOL)}};
  CK_ATTRIBUTE tmp_array[] = {
      {CKA_ID, id, 4},
      {CKA_AC_ISSUER, issuer, 8},
      {CKA_WRAP_TEMPLATE, tmp_array_inner, sizeof(tmp_array_inner)}};
  vector<uint8_t> serialized;
  EXPECT_TRUE(SerializeAttributes(tmp_array, 3, &serialized));
  Attributes parsed;
  EXPECT_TRUE(parsed.Parse(serialized));
  EXPECT_TRUE(CompareAttributes(parsed.attributes(), tmp_array, 2));
  EXPECT_TRUE(CompareAttributes((CK_ATTRIBUTE_PTR)parsed.attributes()[2].pValue,
                                tmp_array_inner, 2));
  // Test a nested parse-and-fill.
  CK_BBOOL val1, val2;
  char buf1[10];
  char buf2[10];
  CK_ATTRIBUTE tmp_array_inner2[] = {{CKA_ENCRYPT, &val1, sizeof(CK_BBOOL)},
                                     {CKA_SIGN, &val2, sizeof(CK_BBOOL)}};
  CK_ATTRIBUTE tmp_array2[] = {
      {CKA_ID, buf1, 10},
      {CKA_AC_ISSUER, buf2, 10},
      {CKA_WRAP_TEMPLATE, tmp_array_inner2, sizeof(tmp_array_inner2)}};
  EXPECT_TRUE(ParseAndFillAttributes(serialized, tmp_array2, 3));
  EXPECT_TRUE(CompareAttributes(tmp_array2, tmp_array, 2));
  EXPECT_TRUE(CompareAttributes(tmp_array_inner2, tmp_array_inner, 2));
  // Test circular nesting.
  tmp_array[2].pValue = tmp_array;
  tmp_array[2].ulValueLen = sizeof(tmp_array);
  EXPECT_FALSE(SerializeAttributes(tmp_array, 3, &serialized));
}

// DestroyObject Tests
TEST(TestDestroyObject, DestroyObjectOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DestroyObject(_, 1, 2)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_DestroyObject(1, 2));
}

TEST(TestDestroyObject, DestroyObjectNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DestroyObject(1, 2));
}

TEST(TestDestroyObject, DestroyObjectFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DestroyObject(_, 1, 2))
      .WillOnce(Return(CKR_OBJECT_HANDLE_INVALID));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID, C_DestroyObject(1, 2));
}

// GetObjectSize Tests
TEST(TestObjectSize, ObjectSizeOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetObjectSize(_, 1, 2, _))
      .WillOnce(DoAll(SetArgPointee<3>(20), Return(CKR_OK)));
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_OK, C_GetObjectSize(1, 2, &size));
  EXPECT_EQ(size, 20);
}

TEST(TestObjectSize, ObjectSizeNULL) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetObjectSize(1, 2, NULL));
}

TEST(TestObjectSize, ObjectSizeNotInit) {
  ChapsProxyMock proxy(false);
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GetObjectSize(1, 2, &size));
}

TEST(TestObjectSize, ObjectSizeFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetObjectSize(_, 1, 2, _))
      .WillOnce(Return(CKR_OBJECT_HANDLE_INVALID));
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID, C_GetObjectSize(1, 2, &size));
}

// GetAttributeValue Tests
TEST_F(TestAttributes, GetAttributeValueOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetAttributeValue(_, 1, 2, attributes2_, _))
      .WillOnce(DoAll(SetArgPointee<4>(attributes_), Return(CKR_OK)));
  EXPECT_EQ(CKR_OK, C_GetAttributeValue(1, 2, attribute_template2_, 2));
  EXPECT_TRUE(CompareAttributes(attribute_template2_, attribute_template_, 2));
}

TEST_F(TestAttributes, GetAttributeValueSizeOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetAttributeValue(_, 1, 2, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(attributes3_), Return(CKR_OK)));
  attribute_template3_[0].ulValueLen = 0;
  attribute_template3_[1].ulValueLen = 0;
  EXPECT_EQ(CKR_OK, C_GetAttributeValue(1, 2, attribute_template3_, 2));
  EXPECT_EQ(4, attribute_template3_[0].ulValueLen);
  EXPECT_EQ(5, attribute_template3_[1].ulValueLen);
}

TEST_F(TestAttributes, GetAttributeValueOKWithError) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetAttributeValue(_, 1, 2, attributes2_, _))
      .WillOnce(DoAll(SetArgPointee<4>(attributes_),
                      Return(CKR_ATTRIBUTE_SENSITIVE)));
  EXPECT_EQ(CKR_ATTRIBUTE_SENSITIVE,
            C_GetAttributeValue(1, 2, attribute_template2_, 2));
  EXPECT_TRUE(CompareAttributes(attribute_template2_, attribute_template_, 2));
}

TEST_F(TestAttributes, GetAttributeValueNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_GetAttributeValue(1, 2, attribute_template3_, 2));
}

TEST_F(TestAttributes, GetAttributeValueNULL) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GetAttributeValue(1, 2, NULL, 2));
}

TEST_F(TestAttributes, GetAttributeValueFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GetAttributeValue(_, 1, 2, _, _))
      .WillOnce(Return(CKR_OBJECT_HANDLE_INVALID));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            C_GetAttributeValue(1, 2, attribute_template2_, 2));
}

TEST(GetAttributeValueDeathTest, GetAttributeValueFailFatal) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> invalid(20, 0);
  EXPECT_CALL(proxy, GetAttributeValue(_, 1, 2, _, _))
      .WillRepeatedly(DoAll(SetArgPointee<4>(invalid), Return(CKR_OK)));
  CK_ATTRIBUTE tmp;
  memset(&tmp, 0, sizeof(tmp));
  EXPECT_DEATH_IF_SUPPORTED(C_GetAttributeValue(1, 2, &tmp, 1), "Check failed");
}

// SetAttributeValue Tests
TEST_F(TestAttributes, SetAttributeValueOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetAttributeValue(_, 1, 2, attributes_))
      .WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_SetAttributeValue(1, 2, attribute_template_, 2));
}

TEST_F(TestAttributes, SetAttributeValueNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_SetAttributeValue(1, 2, attribute_template_, 2));
}

TEST_F(TestAttributes, SetAttributeValueNULL) {
  ChapsProxyMock proxy(true);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SetAttributeValue(1, 2, NULL, 2));
}

TEST_F(TestAttributes, SetAttributeValueFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SetAttributeValue(_, 1, 2, _))
      .WillOnce(Return(CKR_OBJECT_HANDLE_INVALID));
  EXPECT_EQ(CKR_OBJECT_HANDLE_INVALID,
            C_SetAttributeValue(1, 2, attribute_template2_, 2));
}

// FindObjects Tests
TEST_F(TestAttributes, FindObjectsInitOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, FindObjectsInit(_, 1, attributes_))
      .WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_FindObjectsInit(1, attribute_template_, 2));
}

TEST(TestFindObjects, FindObjectsInitNULL) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> empty;
  EXPECT_CALL(proxy, FindObjectsInit(_, 1, empty)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_FindObjectsInit(1, NULL, 1));
  EXPECT_EQ(CKR_OK, C_FindObjectsInit(1, NULL, 0));
}

TEST(TestFindObjects, FindObjectsInitNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_FindObjectsInit(1, NULL, 0));
}

TEST(TestFindObjects, FindObjectsInitFail) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> empty;
  EXPECT_CALL(proxy, FindObjectsInit(_, 1, empty))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_FindObjectsInit(1, NULL, 0));
}

TEST(TestFindObjects, FindObjectsOK) {
  ChapsProxyMock proxy(true);
  vector<uint64_t> object_list;
  object_list.push_back(20);
  object_list.push_back(21);
  EXPECT_CALL(proxy, FindObjects(_, 1, 7, _))
      .WillOnce(DoAll(SetArgPointee<3>(object_list), Return(CKR_OK)));
  CK_OBJECT_HANDLE object_array[7];
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_OK, C_FindObjects(1, object_array, 7, &size));
  EXPECT_EQ(size, 2);
  EXPECT_EQ(object_array[0], object_list[0]);
  EXPECT_EQ(object_array[1], object_list[1]);
}

TEST(TestFindObjects, FindObjectsNULL) {
  ChapsProxyMock proxy(true);
  CK_OBJECT_HANDLE object_array[7];
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_FindObjects(1, NULL, 7, &size));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_FindObjects(1, object_array, 7, NULL));
}

TEST(TestFindObjects, FindObjectsOverflow) {
  ChapsProxyMock proxy(true);
  vector<uint64_t> object_list(8, 20);
  EXPECT_CALL(proxy, FindObjects(_, 1, 7, _))
      .WillOnce(DoAll(SetArgPointee<3>(object_list), Return(CKR_OK)));
  CK_OBJECT_HANDLE object_array[7];
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_FindObjects(1, object_array, 7, &size));
}

TEST(TestFindObjects, FindObjectsNotInit) {
  ChapsProxyMock proxy(false);
  CK_OBJECT_HANDLE object_array[7];
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_FindObjects(1, object_array, 7, &size));
}

TEST(TestFindObjects, FindObjectsFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, FindObjects(_, 1, 7, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  CK_OBJECT_HANDLE object_array[7];
  CK_ULONG size = 0;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_FindObjects(1, object_array, 7, &size));
}

TEST(TestFindObjects, FindObjectsFinalOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, FindObjectsFinal(_, 1)).WillOnce(Return(CKR_OK));
  EXPECT_EQ(CKR_OK, C_FindObjectsFinal(1));
}

TEST(TestFindObjects, FindObjectsFinalNotInit) {
  ChapsProxyMock proxy(false);
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_FindObjectsFinal(1));
}

TEST(TestFindObjects, FindObjectsFinalFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, FindObjectsFinal(_, 1))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_FindObjectsFinal(1));
}

class TestEncrypt : public ::testing::Test {
 protected:
  void SetUp() {
    data_in_ = vector<uint8_t>(10, 1);
    data_out_ = vector<uint8_t>(10, 2);
    parameter_ = vector<uint8_t>(12, 0xAA);
    CK_MECHANISM mechanism = {2, parameter_.data(), parameter_.size()};
    mechanism_ = mechanism;
    buffer_in_ = reinterpret_cast<CK_BYTE_PTR>(data_in_.data());
    length_in_ = data_in_.size();
    length_out_max_ = 20;
    buffer_out_expected_ = reinterpret_cast<CK_BYTE_PTR>(data_out_.data());
    length_out_expected_ = data_out_.size();
  }
  vector<uint8_t> data_in_;
  vector<uint8_t> data_out_;
  vector<uint8_t> parameter_;
  CK_MECHANISM mechanism_;
  CK_BYTE_PTR buffer_in_;
  CK_ULONG length_in_;
  CK_BYTE buffer_out_[20];
  CK_ULONG length_out_max_;
  CK_ULONG length_out_;
  CK_BYTE_PTR buffer_out_expected_;
  CK_ULONG length_out_expected_;
};

// Encrypt / Decrypt Tests
TEST_F(TestEncrypt, EncryptOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, EncryptInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, DecryptInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, Encrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Decrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_),
                      SetArgPointee<4>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_),
                      SetArgPointee<4>(data_out_), Return(CKR_OK)));

  EXPECT_EQ(CKR_OK, C_EncryptInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_OK, C_DecryptInit(1, &mechanism_, 3));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK,
            C_Encrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK,
            C_Decrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_EncryptUpdate(1, buffer_in_, length_in_, buffer_out_,
                                    &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DecryptUpdate(1, buffer_in_, length_in_, buffer_out_,
                                    &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_EncryptFinal(1, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DecryptFinal(1, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
}

TEST_F(TestEncrypt, EncryptBadOutput) {
  ChapsProxyMock proxy(true);
  // This should trigger an error because length_out_expected_ is still 10.
  length_out_max_ = 8;
  EXPECT_CALL(proxy, Encrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Decrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_),
                      SetArgPointee<4>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_),
                      SetArgPointee<4>(data_out_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_Encrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_Decrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_EncryptUpdate(1, buffer_in_, length_in_,
                                               buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_DecryptUpdate(1, buffer_in_, length_in_,
                                               buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_EncryptFinal(1, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_DecryptFinal(1, buffer_out_, &length_out_));
}

TEST_F(TestEncrypt, EncryptFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, EncryptInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DecryptInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, Encrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, Decrypt(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, EncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DecryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, EncryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DecryptFinal(_, 1, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));

  EXPECT_EQ(CKR_SESSION_CLOSED, C_EncryptInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DecryptInit(1, &mechanism_, 3));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_Encrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_Decrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_EncryptUpdate(1, buffer_in_, length_in_,
                                                buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DecryptUpdate(1, buffer_in_, length_in_,
                                                buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_EncryptFinal(1, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DecryptFinal(1, buffer_out_, &length_out_));
}

TEST_F(TestEncrypt, EncryptSmallBuffer) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Encrypt(_, 1, data_in_, 1, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      Return(CKR_BUFFER_TOO_SMALL)));
  EXPECT_CALL(proxy, Decrypt(_, 1, data_in_, 1, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      Return(CKR_BUFFER_TOO_SMALL)));
  length_out_ = 1;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            C_Encrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 1;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL,
            C_Decrypt(1, buffer_in_, length_in_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
}

TEST_F(TestEncrypt, EncryptLengthOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Encrypt(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Decrypt(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, EncryptFinal(_, 1, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptFinal(_, 1, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(length_out_expected_), Return(CKR_OK)));

  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_Encrypt(1, buffer_in_, length_in_, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_Decrypt(1, buffer_in_, length_in_, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK,
            C_EncryptUpdate(1, buffer_in_, length_in_, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK,
            C_DecryptUpdate(1, buffer_in_, length_in_, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_EncryptFinal(1, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_DecryptFinal(1, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
}

TEST_F(TestEncrypt, EncryptNoInput) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> empty;
  EXPECT_CALL(proxy, Encrypt(_, 1, empty, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Decrypt(_, 1, empty, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_Encrypt(1, NULL, 0, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_Decrypt(1, NULL, 0, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
}

TEST_F(TestEncrypt, EncryptBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_EncryptInit(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptInit(1, NULL, 3));

  // All of the following failures should trigger an attempt to cancel the
  // operation in progress.
  EXPECT_CALL(proxy, EncryptCancel(_, 1)).Times(5);
  EXPECT_CALL(proxy, DecryptCancel(_, 1)).Times(5);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Encrypt(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Decrypt(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Encrypt(1, NULL, 3, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Decrypt(1, NULL, 3, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_EncryptUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_EncryptUpdate(1, NULL, 0, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptUpdate(1, NULL, 0, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_EncryptFinal(1, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptFinal(1, p, NULL));
}

TEST_F(TestEncrypt, EncryptNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_EncryptInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DecryptInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Encrypt(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Decrypt(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_EncryptUpdate(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DecryptUpdate(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_EncryptFinal(1, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DecryptFinal(1, p, ul));
}

class TestDigest : public ::testing::Test {
 protected:
  void SetUp() {
    data_ = vector<uint8_t>(10, 1);
    digest_ = vector<uint8_t>(10, 2);
    parameter_ = vector<uint8_t>(12, 0xAA);
    CK_MECHANISM mechanism = {2, parameter_.data(), parameter_.size()};
    mechanism_ = mechanism;
    data_buffer_ = reinterpret_cast<CK_BYTE_PTR>(data_.data());
    digest_buffer_ = reinterpret_cast<CK_BYTE_PTR>(digest_.data());
    data_length_ = data_.size();
    digest_length_ = digest_.size();
    length_out_max_ = 20;
  }
  vector<uint8_t> data_;
  vector<uint8_t> digest_;
  vector<uint8_t> parameter_;
  CK_MECHANISM mechanism_;
  CK_BYTE_PTR data_buffer_;
  CK_ULONG data_length_;
  CK_BYTE buffer_out_[20];
  CK_ULONG length_out_max_;
  CK_ULONG length_out_;
  CK_BYTE_PTR digest_buffer_;
  CK_ULONG digest_length_;
};

// Digest Tests
TEST_F(TestDigest, DigestOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DigestInit(_, 1, 2, parameter_)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, Digest(_, 1, data_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(digest_length_),
                      SetArgPointee<5>(digest_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DigestUpdate(_, 1, data_)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, DigestKey(_, 1, 2)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, DigestFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(digest_length_),
                      SetArgPointee<4>(digest_), Return(CKR_OK)));

  EXPECT_EQ(CKR_OK, C_DigestInit(1, &mechanism_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK,
            C_Digest(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, digest_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, digest_buffer_, digest_length_));
  EXPECT_EQ(CKR_OK, C_DigestUpdate(1, data_buffer_, data_length_));
  EXPECT_EQ(CKR_OK, C_DigestKey(1, 2));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DigestFinal(1, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, digest_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, digest_buffer_, digest_length_));
}

TEST_F(TestDigest, DigestBadOutput) {
  ChapsProxyMock proxy(true);
  // This should trigger an error because digest_length_ is still 10.
  length_out_max_ = 8;
  EXPECT_CALL(proxy, Digest(_, 1, data_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(digest_length_),
                      SetArgPointee<5>(digest_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DigestFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(digest_length_),
                      SetArgPointee<4>(digest_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_Digest(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_DigestFinal(1, buffer_out_, &length_out_));
}

TEST_F(TestDigest, DigestFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DigestInit(_, 1, 2, parameter_))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, Digest(_, 1, data_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DigestUpdate(_, 1, data_))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DigestKey(_, 1, 2)).WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DigestFinal(_, 1, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));

  EXPECT_EQ(CKR_SESSION_CLOSED, C_DigestInit(1, &mechanism_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_Digest(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DigestUpdate(1, data_buffer_, data_length_));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DigestKey(1, 2));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_DigestFinal(1, buffer_out_, &length_out_));
}

TEST_F(TestDigest, DigestLengthOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Digest(_, 1, data_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(digest_length_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DigestFinal(_, 1, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(digest_length_), Return(CKR_OK)));

  length_out_ = 0;
  EXPECT_EQ(CKR_OK,
            C_Digest(1, data_buffer_, data_length_, NULL, &length_out_));
  EXPECT_EQ(length_out_, digest_length_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_DigestFinal(1, NULL, &length_out_));
  EXPECT_EQ(length_out_, digest_length_);
}

TEST_F(TestDigest, DigestNoInput) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> empty;
  EXPECT_CALL(proxy, Digest(_, 1, empty, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(digest_length_),
                      SetArgPointee<5>(digest_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_Digest(1, NULL, 0, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, digest_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, digest_buffer_, digest_length_));
}

TEST_F(TestDigest, DigestBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestInit(1, NULL));

  // All of the following failures should trigger an attempt to cancel the
  // operation in progress.
  EXPECT_CALL(proxy, DigestCancel(_, 1)).Times(5);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Digest(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Digest(1, NULL, 3, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestUpdate(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestUpdate(1, NULL, 0));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestFinal(1, p, NULL));
}

TEST_F(TestDigest, DigestNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DigestInit(1, &mechanism_));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Digest(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DigestUpdate(1, p, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DigestKey(1, 2));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_DigestFinal(1, p, ul));
}

class TestSign : public ::testing::Test {
 protected:
  void SetUp() {
    data_ = vector<uint8_t>(10, 1);
    signature_ = vector<uint8_t>(10, 2);
    parameter_ = vector<uint8_t>(12, 0xAA);
    CK_MECHANISM mechanism = {2, parameter_.data(), parameter_.size()};
    mechanism_ = mechanism;
    data_buffer_ = reinterpret_cast<CK_BYTE_PTR>(data_.data());
    signature_buffer_ = reinterpret_cast<CK_BYTE_PTR>(signature_.data());
    data_length_ = data_.size();
    signature_length_ = signature_.size();
    length_out_max_ = 20;
  }
  vector<uint8_t> data_;
  vector<uint8_t> signature_;
  vector<uint8_t> parameter_;
  CK_MECHANISM mechanism_;
  CK_BYTE_PTR data_buffer_;
  CK_ULONG data_length_;
  CK_BYTE buffer_out_[20];
  CK_ULONG length_out_max_;
  CK_ULONG length_out_;
  CK_BYTE_PTR signature_buffer_;
  CK_ULONG signature_length_;
};

// Sign / Verify Tests
TEST_F(TestSign, SignOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SignInit(_, 1, 2, parameter_, 3)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, VerifyInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, Sign(_, 1, data_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(signature_length_),
                      SetArgPointee<5>(signature_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Verify(_, 1, data_, signature_)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, SignUpdate(_, 1, data_)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, VerifyUpdate(_, 1, data_)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, SignFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(signature_length_),
                      SetArgPointee<4>(signature_), Return(CKR_OK)));
  EXPECT_CALL(proxy, VerifyFinal(_, 1, signature_)).WillOnce(Return(CKR_OK));

  EXPECT_EQ(CKR_OK, C_SignInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_OK, C_VerifyInit(1, &mechanism_, 3));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK,
            C_Sign(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, signature_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, signature_buffer_, signature_length_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_Verify(1, data_buffer_, data_length_, signature_buffer_,
                             signature_length_));
  EXPECT_EQ(CKR_OK, C_SignUpdate(1, data_buffer_, data_length_));
  EXPECT_EQ(CKR_OK, C_VerifyUpdate(1, data_buffer_, data_length_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_SignFinal(1, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, signature_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, signature_buffer_, signature_length_));
  EXPECT_EQ(CKR_OK, C_VerifyFinal(1, signature_buffer_, signature_length_));
}

TEST_F(TestSign, SignBadOutput) {
  ChapsProxyMock proxy(true);
  // This should trigger an error because signature_length_ is still 10.
  length_out_max_ = 8;
  EXPECT_CALL(proxy, Sign(_, 1, data_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(signature_length_),
                      SetArgPointee<5>(signature_), Return(CKR_OK)));
  EXPECT_CALL(proxy, SignFinal(_, 1, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(signature_length_),
                      SetArgPointee<4>(signature_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_Sign(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_SignFinal(1, buffer_out_, &length_out_));
}

TEST_F(TestSign, SignFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, SignInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, VerifyInit(_, 1, 2, parameter_, 3))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, Sign(_, 1, data_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, Verify(_, 1, data_, signature_))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, SignUpdate(_, 1, data_))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, VerifyUpdate(_, 1, data_))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, SignFinal(_, 1, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, VerifyFinal(_, 1, signature_))
      .WillOnce(Return(CKR_SESSION_CLOSED));

  EXPECT_EQ(CKR_SESSION_CLOSED, C_SignInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_VerifyInit(1, &mechanism_, 3));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_Sign(1, data_buffer_, data_length_, buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_Verify(1, data_buffer_, data_length_,
                                         signature_buffer_, signature_length_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_SignUpdate(1, data_buffer_, data_length_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_VerifyUpdate(1, data_buffer_, data_length_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_SignFinal(1, buffer_out_, &length_out_));
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_VerifyFinal(1, signature_buffer_, signature_length_));
}

TEST_F(TestSign, SignLengthOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, Sign(_, 1, data_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(signature_length_), Return(CKR_OK)));
  EXPECT_CALL(proxy, SignFinal(_, 1, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(signature_length_), Return(CKR_OK)));

  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_Sign(1, data_buffer_, data_length_, NULL, &length_out_));
  EXPECT_EQ(length_out_, signature_length_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_SignFinal(1, NULL, &length_out_));
  EXPECT_EQ(length_out_, signature_length_);
}

TEST_F(TestSign, SignNoInput) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> empty;
  EXPECT_CALL(proxy, Sign(_, 1, empty, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(signature_length_),
                      SetArgPointee<5>(signature_), Return(CKR_OK)));
  EXPECT_CALL(proxy, Verify(_, 1, empty, signature_)).WillOnce(Return(CKR_OK));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_Sign(1, NULL, 0, buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, signature_length_);
  EXPECT_EQ(0, memcmp(buffer_out_, signature_buffer_, signature_length_));
  EXPECT_EQ(CKR_OK, C_Verify(1, NULL, 0, signature_buffer_, signature_length_));
}

TEST_F(TestSign, SignBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignInit(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_VerifyInit(1, NULL, 3));

  // All of the following failures should trigger an attempt to cancel the
  // operation in progress.
  EXPECT_CALL(proxy, SignCancel(_, 1)).Times(5);
  EXPECT_CALL(proxy, VerifyCancel(_, 1)).Times(7);
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Sign(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Sign(1, NULL, 3, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Verify(1, NULL, 3, p, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Verify(1, p, 3, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_Verify(1, p, 3, NULL, 0));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignUpdate(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignUpdate(1, NULL, 0));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_VerifyUpdate(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_VerifyUpdate(1, NULL, 0));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignFinal(1, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_VerifyFinal(1, NULL, 3));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_VerifyFinal(1, NULL, 0));
}

TEST_F(TestSign, SignNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SignInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_VerifyInit(1, &mechanism_, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Sign(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_Verify(1, p, 3, p, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SignUpdate(1, p, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_VerifyUpdate(1, p, 3));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SignFinal(1, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_VerifyFinal(1, p, 3));
}

// Dual-Function Tests
TEST_F(TestEncrypt, DualOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DigestEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptDigestUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, SignEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptVerifyUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DigestEncryptUpdate(1, buffer_in_, length_in_,
                                          buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DecryptDigestUpdate(1, buffer_in_, length_in_,
                                          buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_SignEncryptUpdate(1, buffer_in_, length_in_, buffer_out_,
                                        &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_OK, C_DecryptVerifyUpdate(1, buffer_in_, length_in_,
                                          buffer_out_, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  EXPECT_EQ(0, memcmp(buffer_out_, buffer_out_expected_, length_out_expected_));
}

TEST_F(TestEncrypt, DualBadOutput) {
  ChapsProxyMock proxy(true);
  // This should trigger an error because length_out_expected_ is still 10.
  length_out_max_ = 8;
  EXPECT_CALL(proxy, DigestEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptDigestUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, SignEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptVerifyUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_),
                      SetArgPointee<5>(data_out_), Return(CKR_OK)));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_DigestEncryptUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_DecryptDigestUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR, C_SignEncryptUpdate(1, buffer_in_, length_in_,
                                                   buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_GENERAL_ERROR,
            C_DecryptVerifyUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
}

TEST_F(TestEncrypt, DualFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DigestEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DecryptDigestUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, SignEncryptUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DecryptVerifyUpdate(_, 1, data_in_, length_out_max_, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));

  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_DigestEncryptUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_DecryptDigestUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED, C_SignEncryptUpdate(1, buffer_in_, length_in_,
                                                    buffer_out_, &length_out_));
  length_out_ = length_out_max_;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_DecryptVerifyUpdate(1, buffer_in_, length_in_, buffer_out_,
                                  &length_out_));
}

TEST_F(TestEncrypt, DualLengthOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, DigestEncryptUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptDigestUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, SignEncryptUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));
  EXPECT_CALL(proxy, DecryptVerifyUpdate(_, 1, data_in_, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(length_out_expected_), Return(CKR_OK)));

  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_DigestEncryptUpdate(1, buffer_in_, length_in_, NULL,
                                          &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_DecryptDigestUpdate(1, buffer_in_, length_in_, NULL,
                                          &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK,
            C_SignEncryptUpdate(1, buffer_in_, length_in_, NULL, &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
  length_out_ = 0;
  EXPECT_EQ(CKR_OK, C_DecryptVerifyUpdate(1, buffer_in_, length_in_, NULL,
                                          &length_out_));
  EXPECT_EQ(length_out_, length_out_expected_);
}

TEST_F(TestEncrypt, DualBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestEncryptUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DigestEncryptUpdate(1, NULL, 0, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptDigestUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptDigestUpdate(1, NULL, 0, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignEncryptUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SignEncryptUpdate(1, NULL, 0, p, ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptVerifyUpdate(1, p, 3, p, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DecryptVerifyUpdate(1, NULL, 0, p, ul));
}

TEST_F(TestEncrypt, DualNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE_PTR p = (CK_BYTE_PTR)0x1234;
  CK_ULONG_PTR ul = (CK_ULONG_PTR)0x1234;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_DigestEncryptUpdate(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_DecryptDigestUpdate(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SignEncryptUpdate(1, p, 3, p, ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_DecryptVerifyUpdate(1, p, 3, p, ul));
}

// Generate Key Tests
class TestGenKey : public TestAttributes {
 protected:
  void SetUp() {
    TestAttributes::SetUp();
    parameter_ = vector<uint8_t>(12, 0xAA);
    CK_MECHANISM mechanism = {2, parameter_.data(), parameter_.size()};
    mechanism_ = mechanism;
  }
  void TearDown() { TestAttributes::TearDown(); }
  vector<uint8_t> parameter_;
  CK_MECHANISM mechanism_;
};

TEST_F(TestGenKey, GenKeyOK) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GenerateKey(_, 1, 2, parameter_, attributes_, _))
      .WillOnce(DoAll(SetArgPointee<5>(1), Return(CKR_OK)));
  EXPECT_CALL(proxy, GenerateKeyPair(_, 2, 2, parameter_, attributes2_,
                                     attributes3_, _, _))
      .WillOnce(
          DoAll(SetArgPointee<6>(2), SetArgPointee<7>(3), Return(CKR_OK)));

  CK_OBJECT_HANDLE key;
  EXPECT_EQ(CKR_OK,
            C_GenerateKey(1, &mechanism_, attribute_template_, 2, &key));
  EXPECT_EQ(key, 1);
  CK_OBJECT_HANDLE keypair[2];
  EXPECT_EQ(CKR_OK, C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2,
                                      attribute_template3_, 2, &keypair[0],
                                      &keypair[1]));
  EXPECT_EQ(keypair[0], 2);
  EXPECT_EQ(keypair[1], 3);
}

TEST_F(TestGenKey, GenKeyFail) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, GenerateKey(_, 1, 2, parameter_, attributes_, _))
      .WillOnce(Return(CKR_MECHANISM_INVALID));
  EXPECT_CALL(proxy, GenerateKeyPair(_, 2, 2, parameter_, attributes2_,
                                     attributes3_, _, _))
      .WillOnce(Return(CKR_MECHANISM_INVALID));

  CK_OBJECT_HANDLE key;
  EXPECT_EQ(CKR_MECHANISM_INVALID,
            C_GenerateKey(1, &mechanism_, attribute_template_, 2, &key));
  CK_OBJECT_HANDLE keypair[2];
  EXPECT_EQ(
      CKR_MECHANISM_INVALID,
      C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2,
                        attribute_template3_, 2, &keypair[0], &keypair[1]));
}

TEST_F(TestGenKey, GenKeyBadArgs) {
  ChapsProxyMock proxy(true);
  CK_OBJECT_HANDLE key;
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKey(1, NULL, attribute_template_, 2, &key));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GenerateKey(1, &mechanism_, NULL, 2, &key));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKey(1, &mechanism_, attribute_template_, 2, NULL));
  CK_OBJECT_HANDLE keypair[2];
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GenerateKeyPair(2, NULL, attribute_template2_,
                                                 2, attribute_template3_, 2,
                                                 &keypair[0], &keypair[1]));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKeyPair(2, &mechanism_, NULL, 2, attribute_template3_, 2,
                              &keypair[0], &keypair[1]));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2, NULL, 2,
                              &keypair[0], &keypair[1]));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2,
                              attribute_template3_, 2, NULL, &keypair[1]));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2,
                              attribute_template3_, 2, &keypair[0], NULL));
}

TEST_F(TestGenKey, GenKeyNotInit) {
  ChapsProxyMock proxy(false);
  CK_OBJECT_HANDLE key;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_GenerateKey(1, &mechanism_, attribute_template_, 2, &key));
  CK_OBJECT_HANDLE keypair[2];
  EXPECT_EQ(
      CKR_CRYPTOKI_NOT_INITIALIZED,
      C_GenerateKeyPair(2, &mechanism_, attribute_template2_, 2,
                        attribute_template3_, 2, &keypair[0], &keypair[1]));
}

// Wrap / Derive Key Tests
TEST_F(TestGenKey, WrapKeyOK) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> wrapped(10, 0xAA);
  EXPECT_CALL(proxy, WrapKey(_, 1, 2, parameter_, 3, 4, 10, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(10), SetArgPointee<8>(wrapped),
                      Return(CKR_OK)));
  EXPECT_CALL(proxy, UnwrapKey(_, 1, 2, parameter_, 3, wrapped, attributes_, _))
      .WillOnce(DoAll(SetArgPointee<7>(10), Return(CKR_OK)));
  EXPECT_CALL(proxy, DeriveKey(_, 1, 2, parameter_, 3, attributes_, _))
      .WillOnce(DoAll(SetArgPointee<6>(11), Return(CKR_OK)));
  CK_BYTE buffer[10];
  CK_ULONG length = 10;
  EXPECT_EQ(CKR_OK, C_WrapKey(1, &mechanism_, 3, 4, buffer, &length));
  EXPECT_EQ(length, wrapped.size());
  EXPECT_EQ(0, memcmp(buffer, wrapped.data(), length));
  CK_OBJECT_HANDLE key = 0;
  EXPECT_EQ(CKR_OK, C_UnwrapKey(1, &mechanism_, 3, wrapped.data(),
                                wrapped.size(), attribute_template_, 2, &key));
  EXPECT_EQ(key, 10);
  EXPECT_EQ(CKR_OK,
            C_DeriveKey(1, &mechanism_, 3, attribute_template_, 2, &key));
  EXPECT_EQ(key, 11);
}

TEST_F(TestGenKey, WrapKeyFail) {
  ChapsProxyMock proxy(true);
  vector<uint8_t> wrapped(10, 0xAA);
  EXPECT_CALL(proxy, WrapKey(_, 1, 2, parameter_, 3, 4, 10, _, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, UnwrapKey(_, 1, 2, parameter_, 3, wrapped, attributes_, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, DeriveKey(_, 1, 2, parameter_, 3, attributes_, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  CK_BYTE buffer[10];
  CK_ULONG length = 10;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_WrapKey(1, &mechanism_, 3, 4, buffer, &length));
  CK_OBJECT_HANDLE key = 0;
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_UnwrapKey(1, &mechanism_, 3, wrapped.data(), wrapped.size(),
                        attribute_template_, 2, &key));
  EXPECT_EQ(CKR_SESSION_CLOSED,
            C_DeriveKey(1, &mechanism_, 3, attribute_template_, 2, &key));
}

TEST_F(TestGenKey, WrapKeyLengthOnly) {
  ChapsProxyMock proxy(true);
  EXPECT_CALL(proxy, WrapKey(_, 1, 2, parameter_, 3, 4, 0, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(10), Return(CKR_OK)));
  CK_ULONG length = 5;
  EXPECT_EQ(CKR_OK, C_WrapKey(1, &mechanism_, 3, 4, NULL, &length));
  EXPECT_EQ(length, 10);
}

TEST_F(TestGenKey, WrapKeyBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE b = 0;
  CK_ULONG ul = 0;
  CK_OBJECT_HANDLE h = 0;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_WrapKey(1, NULL, 2, 3, NULL, &ul));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_WrapKey(1, &mechanism_, 2, 3, NULL, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_UnwrapKey(1, NULL, 2, &b, 3, NULL, 0, &h));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_UnwrapKey(1, &mechanism_, 2, NULL, 3, NULL, 0, &h));
  EXPECT_EQ(CKR_ARGUMENTS_BAD,
            C_UnwrapKey(1, &mechanism_, 2, &b, 3, NULL, 0, NULL));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DeriveKey(1, NULL, 2, NULL, 0, &h));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_DeriveKey(1, &mechanism_, 2, NULL, 0, NULL));
}

TEST_F(TestGenKey, WrapKeyNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE b = 0;
  CK_ULONG ul = 0;
  CK_OBJECT_HANDLE h = 0;
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_WrapKey(1, &mechanism_, 2, 3, NULL, &ul));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_UnwrapKey(1, &mechanism_, 2, &b, 3, NULL, 0, &h));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED,
            C_DeriveKey(1, &mechanism_, 2, NULL, 0, &h));
}

TEST(TestRandom, RandomOK) {
  ChapsProxyMock proxy(true);
  CK_BYTE data_buffer[20];
  CK_BYTE data_buffer2[20];
  CK_ULONG data_length = 20;
  memset(data_buffer, 0xAA, 20);
  memset(data_buffer2, 0xBB, 20);
  vector<uint8_t> data(&data_buffer[0], &data_buffer[20]);
  EXPECT_CALL(proxy, SeedRandom(_, 1, data)).WillOnce(Return(CKR_OK));
  EXPECT_CALL(proxy, GenerateRandom(_, 1, data_length, _))
      .WillOnce(DoAll(SetArgPointee<3>(data), Return(CKR_OK)));
  EXPECT_EQ(CKR_OK, C_SeedRandom(1, data_buffer, data_length));
  EXPECT_EQ(CKR_OK, C_GenerateRandom(1, data_buffer2, data_length));
  EXPECT_EQ(0, memcmp(data_buffer, data_buffer2, data_length));
}

TEST(TestRandom, RandomFail) {
  ChapsProxyMock proxy(true);
  CK_BYTE data_buffer[20];
  CK_BYTE data_buffer2[20];
  CK_ULONG data_length = 20;
  memset(data_buffer, 0xAA, 20);
  memset(data_buffer2, 0xBB, 20);
  vector<uint8_t> data(&data_buffer[0], &data_buffer[20]);
  EXPECT_CALL(proxy, SeedRandom(_, 1, data))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_CALL(proxy, GenerateRandom(_, 1, data_length, _))
      .WillOnce(Return(CKR_SESSION_CLOSED));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_SeedRandom(1, data_buffer, data_length));
  EXPECT_EQ(CKR_SESSION_CLOSED, C_GenerateRandom(1, data_buffer2, data_length));
}

TEST(TestRandom, RandomBadArgs) {
  ChapsProxyMock proxy(true);
  CK_BYTE data_buffer[20] = {0};
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SeedRandom(1, NULL, 1));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_SeedRandom(1, data_buffer, 0));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GenerateRandom(1, NULL, 1));
  EXPECT_EQ(CKR_ARGUMENTS_BAD, C_GenerateRandom(1, data_buffer, 0));
}

TEST(TestRandom, RandomNotInit) {
  ChapsProxyMock proxy(false);
  CK_BYTE data_buffer[20] = {0};
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_SeedRandom(1, data_buffer, 1));
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, C_GenerateRandom(1, data_buffer, 1));
}

}  // namespace chaps
