// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/slot_manager_impl.h"

#include <iterator>
#include <map>
#include <memory>
#include <string>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/chaps/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <metrics/metrics_library_mock.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "chaps/chaps_factory_mock.h"
#include "chaps/chaps_utility.h"
#include "chaps/isolate.h"
#include "chaps/object_pool_mock.h"
#include "chaps/object_store_mock.h"
#include "chaps/session_mock.h"
#include "chaps/slot_policy_mock.h"

using base::FilePath;
using brillo::SecureBlob;
using hwsec::TPMError;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;
using std::string;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using TPMRetryAction = ::hwsec::TPMRetryAction;

namespace chaps {

namespace {

const char kAuthData[] = "000000";
const char kTokenLabel[] = "test_label";

const char kChapsTokenManagerLoadToken[] =
    "Platform.Chaps.TokenManager.LoadToken";
const char kChapsTokenManagerUnloadToken[] =
    "Platform.Chaps.TokenManager.UnloadToken";

SecureBlob MakeBlob(const char* auth_data_str) {
  return Sha1(SecureBlob(auth_data_str));
}

// Creates and sets default expectations on a ObjectPoolMock instance. Returns
// a pointer to the new object.
ObjectPool* CreateObjectPoolMock() {
  ObjectPoolMock* object_pool = new ObjectPoolMock();
  EXPECT_CALL(*object_pool, GetInternalBlob(kEncryptedAuthKey, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(string("auth_key_blob")), Return(true)));
  EXPECT_CALL(*object_pool, GetInternalBlob(kEncryptedRootKey, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(string("encrypted_root_key")), Return(true)));
  EXPECT_CALL(*object_pool, GetInternalBlob(kImportedTracker, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(string()), Return(false)));
  EXPECT_CALL(*object_pool, GetInternalBlob(kAuthDataHash, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(string("\x01\xCE")), Return(true)));
  EXPECT_CALL(*object_pool,
              SetInternalBlob(kEncryptedAuthKey, string("auth_key_blob")))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*object_pool,
              SetInternalBlob(kEncryptedAuthKey, string("new_auth_key_blob")))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*object_pool,
              SetInternalBlob(kEncryptedRootKey, string("encrypted_root_key")))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*object_pool, SetInternalBlob(kImportedTracker, string()))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*object_pool, SetInternalBlob(kAuthDataHash, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*object_pool, SetEncryptionKey(_)).WillRepeatedly(Return(true));
  return object_pool;
}

// Sets default expectations on a hwsec::MockChapsFrontend.
void ConfigureHwsec(hwsec::MockChapsFrontend* hwsec) {
  EXPECT_CALL(*hwsec, GetRandomBlob(_)).WillRepeatedly([](size_t size) {
    brillo::Blob blob(size);
    RAND_bytes(blob.data(), size);
    return blob;
  });
  EXPECT_CALL(*hwsec, GetRandomSecureBlob(_)).WillRepeatedly([](size_t size) {
    brillo::SecureBlob blob(size);
    RAND_bytes(blob.data(), size);
    return blob;
  });
  EXPECT_CALL(*hwsec, IsEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(*hwsec, IsReady()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(*hwsec, GetFamily()).WillRepeatedly(ReturnValue(0x322E3000));
  EXPECT_CALL(*hwsec, UnsealDataAsync(_, Sha1(MakeBlob(kAuthData)), _))
      .WillRepeatedly([](auto&&, auto&&, auto&& callback) {
        std::move(callback).Run(brillo::SecureBlob());
      });
  EXPECT_CALL(*hwsec, SealDataAsync(_, Sha1(MakeBlob(kAuthData)), _))
      .WillRepeatedly([](auto&&, auto&&, auto&& callback) {
        std::move(callback).Run(hwsec::ChapsSealedData{});
      });
}

// Creates and returns a mock Session instance.
Session* CreateNewSession() {
  return new SessionMock();
}

}  // namespace

// A test fixture for an initialized SlotManagerImpl instance.
class TestSlotManager : public ::testing::Test {
 public:
  TestSlotManager() {
    EXPECT_CALL(factory_, CreateSession(_, _, _, _, _))
        .WillRepeatedly(InvokeWithoutArgs(CreateNewSession));
    ObjectStore* null_store = nullptr;
    EXPECT_CALL(factory_, CreateObjectStore(_))
        .WillRepeatedly(Return(null_store));
    ic_ = IsolateCredentialManager::GetDefaultIsolateCredential();
  }
  void SetUp() {
    // The default style "fast" does not support multi-threaded death tests.
    testing::FLAGS_gtest_death_test_style = "threadsafe";

    EXPECT_CALL(factory_, CreateObjectPool(_, _, _))
        .WillRepeatedly(InvokeWithoutArgs(CreateObjectPoolMock));
    ConfigureHwsec(&hwsec_);
    chaps_metrics_.set_metrics_library_for_testing(&mock_metrics_library_);
    EXPECT_CALL(
        mock_metrics_library_,
        SendEnumToUMA(kTPMAvailability,
                      static_cast<int>(TPMAvailabilityStatus::kTPMAvailable),
                      static_cast<int>(TPMAvailabilityStatus::kMaxValue)))
        .WillOnce(Return(true));
    slot_manager_.reset(new SlotManagerImpl(&factory_, &hwsec_, false, nullptr,
                                            &chaps_metrics_));
    ASSERT_TRUE(slot_manager_->Init());
  }
  void TearDown() {
    // Destroy the slot manager before its dependencies.
    slot_manager_.reset();
  }

  int InsertToken() {
    int slot_id = 0;
    slot_manager_->LoadToken(ic_, FilePath("/var/lib/chaps"),
                             MakeBlob(kAuthData), kTokenLabel, &slot_id);
    return slot_id;
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  ChapsFactoryMock factory_;
  hwsec::MockChapsFrontend hwsec_;
  std::unique_ptr<SlotManagerImpl> slot_manager_;
  SecureBlob ic_;
  StrictMock<MetricsLibraryMock> mock_metrics_library_;
  ChapsMetrics chaps_metrics_;
};

typedef TestSlotManager TestSlotManager_DeathTest;
TEST(DeathTest, InvalidInit) {
  // The default style "fast" does not support multi-threaded death tests.
  testing::FLAGS_gtest_death_test_style = "threadsafe";

  hwsec::MockChapsFrontend hwsec;
  ConfigureHwsec(&hwsec);
  ChapsFactoryMock factory;
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_DEATH_IF_SUPPORTED(
      new SlotManagerImpl(&factory, nullptr, false, nullptr, &chaps_metrics),
      "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      new SlotManagerImpl(nullptr, &hwsec, false, nullptr, &chaps_metrics),
      "Check failed");
}

TEST_F(TestSlotManager_DeathTest, InvalidArgs) {
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->IsTokenPresent(ic_, 3),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetSlotInfo(ic_, 0, nullptr),
                            "Check failed");
  CK_SLOT_INFO slot_info;
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetSlotInfo(ic_, 3, &slot_info),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetTokenInfo(ic_, 0, nullptr),
                            "Check failed");
  CK_TOKEN_INFO token_info;
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetTokenInfo(ic_, 3, &token_info),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetMechanismInfo(ic_, 3),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->OpenSession(ic_, 3, false),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->CloseAllSessions(ic_, 3),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetSession(ic_, 0, nullptr),
                            "Check failed");
}

TEST_F(TestSlotManager_DeathTest, OutOfMemorySession) {
  Session* null_session = nullptr;
  EXPECT_CALL(factory_, CreateSession(_, _, _, _, _))
      .WillRepeatedly(Return(null_session));
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->OpenSession(ic_, 0, false),
                            "Check failed");
}

TEST_F(TestSlotManager_DeathTest, NoToken) {
  CK_TOKEN_INFO token_info;
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetTokenInfo(ic_, 1, &token_info),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetMechanismInfo(ic_, 1),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->OpenSession(ic_, 1, false),
                            "Check failed");
}

TEST_F(TestSlotManager, DefaultSlotSetup) {
  EXPECT_EQ(2, slot_manager_->GetSlotCount());
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 0));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 1));
}

TEST(DeathTest, OutOfMemoryInit) {
  // The default style "fast" does not support multi-threaded death tests.
  testing::FLAGS_gtest_death_test_style = "threadsafe";

  hwsec::MockChapsFrontend hwsec;
  ConfigureHwsec(&hwsec);
  ChapsFactoryMock factory;
  ObjectPool* null_pool = nullptr;
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(factory, CreateObjectPool(_, _, _))
      .WillRepeatedly(Return(null_pool));
  ObjectStore* null_store = nullptr;
  EXPECT_CALL(factory, CreateObjectStore(_)).WillRepeatedly(Return(null_store));
  SlotManagerImpl sm(&factory, &hwsec, false, nullptr, &chaps_metrics);
  EXPECT_CALL(
      mock_metrics_library,
      SendEnumToUMA(kTPMAvailability,
                    static_cast<int>(TPMAvailabilityStatus::kTPMAvailable),
                    static_cast<int>(TPMAvailabilityStatus::kMaxValue)))
      .WillOnce(Return(true));
  ASSERT_TRUE(sm.Init());
  int slot_id;
  EXPECT_DEATH_IF_SUPPORTED(
      sm.LoadToken(IsolateCredentialManager::GetDefaultIsolateCredential(),
                   FilePath("/var/lib/chaps"), MakeBlob(kAuthData), kTokenLabel,
                   &slot_id),
      "Check failed");
  LOG_CK_RV(CKR_OK);
}

TEST_F(TestSlotManager, QueryInfo) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InsertToken();
  CK_SLOT_INFO slot_info;
  memset(&slot_info, 0xEE, sizeof(slot_info));
  slot_manager_->GetSlotInfo(ic_, 0, &slot_info);
  // Check if all bytes have been set by the call.
  EXPECT_EQ(nullptr, memchr(&slot_info, 0xEE, sizeof(slot_info)));
  CK_TOKEN_INFO token_info;
  memset(&token_info, 0xEE, sizeof(token_info));
  slot_manager_->GetTokenInfo(ic_, 0, &token_info);
  EXPECT_EQ(nullptr, memchr(&token_info, 0xEE, sizeof(token_info)));
  string expected_label(kTokenLabel);
  expected_label.resize(std::size(token_info.label), ' ');
  string actual_label(reinterpret_cast<char*>(token_info.label),
                      std::size(token_info.label));
  EXPECT_EQ(expected_label, actual_label);
  const MechanismMap* mechanisms = slot_manager_->GetMechanismInfo(ic_, 0);
  ASSERT_TRUE(mechanisms != nullptr);
  // Sanity check - we don't want to be strict on the mechanism list.
  EXPECT_TRUE(mechanisms->end() != mechanisms->find(CKM_RSA_PKCS));
  EXPECT_TRUE(mechanisms->end() != mechanisms->find(CKM_AES_CBC));
}

TEST_F(TestSlotManager, TestSessions) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InsertToken();
  int id1 = slot_manager_->OpenSession(ic_, 0, false);
  int id2 = slot_manager_->OpenSession(ic_, 0, true);
  EXPECT_NE(id1, id2);
  Session* s1 = nullptr;
  EXPECT_TRUE(slot_manager_->GetSession(ic_, id1, &s1));
  EXPECT_TRUE(s1 != nullptr);
  Session* s2 = nullptr;
  EXPECT_TRUE(slot_manager_->GetSession(ic_, id2, &s2));
  EXPECT_TRUE(s2 != nullptr);
  EXPECT_NE(s1, s2);
  EXPECT_TRUE(slot_manager_->CloseSession(ic_, id1));
  EXPECT_FALSE(slot_manager_->CloseSession(ic_, id1));
  slot_manager_->CloseAllSessions(ic_, 0);
  EXPECT_FALSE(slot_manager_->CloseSession(ic_, id2));
}

TEST_F(TestSlotManager, TestLoadTokenEvents) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(4);
  InsertToken();
  int slot_id;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kLoadExistingToken),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(
      ic_, FilePath("some_path"), MakeBlob(kAuthData), kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenPresent(ic_, 1));
  // Load token with an existing path - should not result in a new slot.
  int slot_id2;
  EXPECT_TRUE(slot_manager_->LoadToken(
      ic_, FilePath("some_path"), MakeBlob(kAuthData), kTokenLabel, &slot_id2));
  EXPECT_EQ(slot_id, slot_id2);
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, FilePath("another_path"),
                                       MakeBlob(kAuthData), kTokenLabel,
                                       &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenPresent(ic_, 2));
  // Logout with an unknown path.
  EXPECT_CALL(mock_metrics_library_,
              SendEnumToUMA(kChapsTokenManagerUnloadToken,
                            static_cast<int>(TokenManagerStatus::kUnknownPath),
                            static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_FALSE(
      slot_manager_->UnloadToken(ic_, FilePath("still_yet_another_path")));
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(2);
  EXPECT_TRUE(slot_manager_->UnloadToken(ic_, FilePath("some_path")));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 1));
  EXPECT_TRUE(slot_manager_->IsTokenPresent(ic_, 2));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, FilePath("one_more_path"),
                                       MakeBlob(kAuthData), kTokenLabel,
                                       &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenPresent(ic_, 1));
  EXPECT_TRUE(slot_manager_->UnloadToken(ic_, FilePath("another_path")));
}

TEST_F(TestSlotManager, ManyLoadToken) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(101);
  InsertToken();
  for (int i = 0; i < 100; ++i) {
    string path = base::StringPrintf("test%d", i);
    int slot_id = 0;
    EXPECT_TRUE(slot_manager_->LoadToken(
        ic_, FilePath(path), MakeBlob(kAuthData), kTokenLabel, &slot_id));
  }
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(100);
  for (int i = 0; i < 100; ++i) {
    string path = base::StringPrintf("test%d", i);
    EXPECT_TRUE(slot_manager_->UnloadToken(ic_, FilePath(path)));
  }
}

TEST_F(TestSlotManager, TestDefaultIsolate) {
  // Check default isolate is there by default.
  SecureBlob defaultIsolate =
      IsolateCredentialManager::GetDefaultIsolateCredential();
  bool new_isolate = true;
  EXPECT_TRUE(slot_manager_->OpenIsolate(&defaultIsolate, &new_isolate));
  EXPECT_FALSE(new_isolate);
  EXPECT_EQ(IsolateCredentialManager::GetDefaultIsolateCredential(),
            defaultIsolate);
}

TEST_F(TestSlotManager, TestOpenIsolate) {
  EXPECT_CALL(hwsec_, GetRandomSecureBlob(_))
      .WillOnce(ReturnValue(brillo::SecureBlob(kIsolateCredentialBytes, 'A')));

  // Check that trying to open an invalid isolate creates new isolate.
  SecureBlob isolate("invalid");
  bool new_isolate_created = false;
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_TRUE(new_isolate_created);
  EXPECT_EQ(brillo::SecureBlob(kIsolateCredentialBytes, 'A'), isolate);

  // Check opening an existing isolate.
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_FALSE(new_isolate_created);
  EXPECT_EQ(brillo::SecureBlob(kIsolateCredentialBytes, 'A'), isolate);
}

TEST_F(TestSlotManager, TestCloseIsolate) {
  EXPECT_CALL(hwsec_, GetRandomSecureBlob(_))
      .WillOnce(ReturnValue(brillo::SecureBlob(kIsolateCredentialBytes, 'A')))
      .WillOnce(ReturnValue(brillo::SecureBlob(kIsolateCredentialBytes, 'B')));

  SecureBlob isolate;
  bool new_isolate_created;
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_TRUE(new_isolate_created);
  EXPECT_EQ(brillo::SecureBlob(kIsolateCredentialBytes, 'A'), isolate);
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_FALSE(new_isolate_created);
  EXPECT_EQ(brillo::SecureBlob(kIsolateCredentialBytes, 'A'), isolate);
  slot_manager_->CloseIsolate(isolate);
  slot_manager_->CloseIsolate(isolate);
  // Final logout, isolate should now be destroyed.
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_TRUE(new_isolate_created);
  EXPECT_EQ(brillo::SecureBlob(kIsolateCredentialBytes, 'B'), isolate);
}

TEST_F(TestSlotManager, TestCloseIsolateUnloadToken) {
  SecureBlob isolate;
  bool new_isolate_created;
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_TRUE(new_isolate_created);
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(isolate, 0));
  int slot_id;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(isolate, FilePath("some_path"),
                                       MakeBlob(kAuthData), kTokenLabel,
                                       &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenPresent(isolate, 0));
  // Token should be unloaded by CloseIsolate call.
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  slot_manager_->CloseIsolate(isolate);
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(isolate, 0));
}

TEST_F(TestSlotManager_DeathTest, TestIsolateTokens) {
  CK_SLOT_INFO slot_info;
  CK_TOKEN_INFO token_info;
  Session* session;
  SecureBlob new_isolate_0, new_isolate_1;
  SecureBlob defaultIsolate =
      IsolateCredentialManager::GetDefaultIsolateCredential();

  // Ensure different credentials are created for each isolate.
  EXPECT_CALL(hwsec_, GetRandomSecureBlob(_))
      .WillOnce(ReturnValue(brillo::SecureBlob(kIsolateCredentialBytes, 'A')))
      .WillOnce(ReturnValue(brillo::SecureBlob(kIsolateCredentialBytes, 'B')));

  bool new_isolate_created;
  int slot_id;
  ASSERT_TRUE(slot_manager_->OpenIsolate(&new_isolate_0, &new_isolate_created));
  ASSERT_TRUE(new_isolate_created);
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(2);
  ASSERT_TRUE(slot_manager_->LoadToken(new_isolate_0, FilePath("new_isolate"),
                                       MakeBlob(kAuthData), kTokenLabel,
                                       &slot_id));

  ASSERT_TRUE(slot_manager_->OpenIsolate(&new_isolate_1, &new_isolate_created));
  ASSERT_TRUE(new_isolate_created);
  ASSERT_TRUE(
      slot_manager_->LoadToken(new_isolate_1, FilePath("another_new_isolate"),
                               MakeBlob(kAuthData), kTokenLabel, &slot_id));
  // Ensure tokens are only accessible with the valid isolate cred.
  ASSERT_TRUE(slot_manager_->IsTokenAccessible(new_isolate_0, 0));
  ASSERT_TRUE(slot_manager_->IsTokenAccessible(new_isolate_1, 1));
  ASSERT_FALSE(slot_manager_->IsTokenAccessible(new_isolate_1, 0));
  ASSERT_FALSE(slot_manager_->IsTokenAccessible(new_isolate_0, 1));
  ASSERT_FALSE(slot_manager_->IsTokenAccessible(defaultIsolate, 0));
  ASSERT_FALSE(slot_manager_->IsTokenAccessible(defaultIsolate, 1));

  // Check all public methods perform isolate checks.
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->IsTokenPresent(new_isolate_0, 1),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      slot_manager_->GetSlotInfo(new_isolate_0, 1, &slot_info), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(
      slot_manager_->GetTokenInfo(new_isolate_0, 1, &token_info),
      "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->GetMechanismInfo(new_isolate_0, 1),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->OpenSession(new_isolate_0, 1, false),
                            "Check failed");
  int slot_1_session = slot_manager_->OpenSession(new_isolate_1, 1, false);
  EXPECT_TRUE(
      slot_manager_->GetSession(new_isolate_1, slot_1_session, &session));
  EXPECT_FALSE(
      slot_manager_->GetSession(new_isolate_0, slot_1_session, &session));
  EXPECT_FALSE(slot_manager_->CloseSession(new_isolate_0, slot_1_session));
  EXPECT_DEATH_IF_SUPPORTED(slot_manager_->CloseAllSessions(new_isolate_0, 1),
                            "Check failed");
}

TEST_F(TestSlotManager, HWSecNotReady) {
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));
  EXPECT_CALL(
      mock_metrics_library,
      SendEnumToUMA(kTPMAvailability,
                    static_cast<int>(TPMAvailabilityStatus::kTPMAvailable),
                    static_cast<int>(TPMAvailabilityStatus::kMaxValue)))
      .WillOnce(Return(true));
  slot_manager_.reset(
      new SlotManagerImpl(&factory_, &hwsec_, false, nullptr, &chaps_metrics));
  ASSERT_TRUE(slot_manager_->Init());

  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 0));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 1));
  int slot_id = 0;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(
      mock_metrics_library,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kInitStage2Failed),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_FALSE(slot_manager_->LoadToken(
      ic_, FilePath("test_token"), MakeBlob(kAuthData), kTokenLabel, &slot_id));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 0));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, 1));
}

TEST_F(TestSlotManager, DelayedHWSecReady) {
  StrictMock<MetricsLibraryMock> mock_metrics_library;
  ChapsMetrics chaps_metrics;
  chaps_metrics.set_metrics_library_for_testing(&mock_metrics_library);
  EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(true));
  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));
  EXPECT_CALL(
      mock_metrics_library,
      SendEnumToUMA(kTPMAvailability,
                    static_cast<int>(TPMAvailabilityStatus::kTPMAvailable),
                    static_cast<int>(TPMAvailabilityStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_CALL(
      mock_metrics_library,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  slot_manager_.reset(
      new SlotManagerImpl(&factory_, &hwsec_, false, nullptr, &chaps_metrics));
  ASSERT_TRUE(slot_manager_->Init());

  EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(true));
  int slot_id = 0;
  EXPECT_TRUE(slot_manager_->LoadToken(
      ic_, FilePath("test_token"), MakeBlob(kAuthData), kTokenLabel, &slot_id));
}

class SoftwareOnlyTest : public TestSlotManager {
 public:
  SoftwareOnlyTest()
      : kTestTokenPath("sw_test_token"),
        set_encryption_key_num_calls_(0),
        delete_all_num_calls_(0),
        pool_write_result_(true) {}
  ~SoftwareOnlyTest() override {}

  void SetUp() override {
    // The default style "fast" does not support multi-threaded death tests.
    testing::FLAGS_gtest_death_test_style = "threadsafe";

    // Use our own SlotPolicyFactory and ObjectPoolFactory.
    EXPECT_CALL(factory_, CreateSlotPolicy(false))
        .WillRepeatedly(
            InvokeWithoutArgs(this, &SoftwareOnlyTest::SlotPolicyFactory));
    EXPECT_CALL(factory_, CreateObjectPool(_, _, _))
        .WillRepeatedly(
            InvokeWithoutArgs(this, &SoftwareOnlyTest::ObjectPoolFactory));
    chaps_metrics_.set_metrics_library_for_testing(&mock_metrics_library_);
    EXPECT_CALL(hwsec_, IsEnabled()).WillRepeatedly(ReturnValue(false));
    EXPECT_CALL(hwsec_, IsReady()).WillRepeatedly(ReturnValue(false));
    EXPECT_CALL(hwsec_, GetFamily())
        .WillRepeatedly(
            ReturnError<TPMError>("Not supported", TPMRetryAction::kNoRetry));
    EXPECT_CALL(
        mock_metrics_library_,
        SendEnumToUMA(kTPMAvailability,
                      static_cast<int>(TPMAvailabilityStatus::kTPMUnavailable),
                      static_cast<int>(TPMAvailabilityStatus::kMaxValue)))
        .WillOnce(Return(true));
    slot_manager_.reset(new SlotManagerImpl(&factory_, &hwsec_, false, nullptr,
                                            &chaps_metrics_));
    ASSERT_TRUE(slot_manager_->Init());
  }

  void TearDown() override {
    // Destroy the slot manager before its dependencies.
    slot_manager_.reset();
  }

  SlotPolicyMock* SlotPolicyFactory() {
    // Redirect internal blob stuff to fake methods.
    SlotPolicyMock* slot_policy = new SlotPolicyMock();
    EXPECT_CALL(*slot_policy, IsObjectClassAllowedForNewObject(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*slot_policy, IsObjectClassAllowedForImportedObject(_))
        .WillRepeatedly(Return(true));
    return slot_policy;
  }

  ObjectPoolMock* ObjectPoolFactory() {
    // Redirect internal blob stuff to fake methods.
    ObjectPoolMock* object_pool = new ObjectPoolMock();
    EXPECT_CALL(*object_pool, GetInternalBlob(_, _))
        .WillRepeatedly(Invoke(this, &SoftwareOnlyTest::FakeGetInternalBlob));
    EXPECT_CALL(*object_pool, SetInternalBlob(_, _))
        .WillRepeatedly(Invoke(this, &SoftwareOnlyTest::FakeSetInternalBlob));
    EXPECT_CALL(*object_pool, SetEncryptionKey(_))
        .WillRepeatedly(Invoke(this, &SoftwareOnlyTest::FakeSetEncryptionKey));
    EXPECT_CALL(*object_pool, DeleteAll())
        .WillRepeatedly(Invoke(this, &SoftwareOnlyTest::FakeDeleteAll));
    return object_pool;
  }

  void InitializeObjectPoolBlobs() {
    // The easiest way is to load / unload a token and let the SlotManager do
    // the crypto.
    pool_blobs_.clear();
    int slot_id = 0;
    ASSERT_TRUE(slot_manager_->LoadToken(
        ic_, kTestTokenPath, MakeBlob(kAuthData), kTokenLabel, &slot_id));
    ASSERT_TRUE(slot_manager_->UnloadToken(ic_, kTestTokenPath));
    set_encryption_key_num_calls_ = 0;
    delete_all_num_calls_ = 0;
  }

  bool FakeGetInternalBlob(int blob_id, std::string* blob) {
    std::map<int, string>::iterator iter = pool_blobs_.find(blob_id);
    if (iter == pool_blobs_.end())
      return false;
    *blob = iter->second;
    return true;
  }

  bool FakeSetInternalBlob(int blob_id, const std::string& blob) {
    if (pool_write_result_) {
      pool_blobs_[blob_id] = blob;
    }
    return pool_write_result_;
  }

  bool FakeSetEncryptionKey(const brillo::SecureBlob& key) {
    set_encryption_key_num_calls_++;
    return pool_write_result_;
  }

  ObjectPool::Result FakeDeleteAll() {
    delete_all_num_calls_++;
    return pool_write_result_ ? ObjectPool::Result::Success
                              : ObjectPool::Result::Failure;
  }

 protected:
  const FilePath kTestTokenPath;
  // Strict so that we get an error if this gets called.
  hwsec::MockChapsFrontend hwsec_;
  std::map<int, string> pool_blobs_;
  int set_encryption_key_num_calls_;
  int delete_all_num_calls_;
  bool pool_write_result_;
};

TEST_F(SoftwareOnlyTest, CreateNew) {
  int slot_id = 0;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, kTestTokenPath, MakeBlob(kAuthData),
                                       kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  // Check that an encryption key gets set for a load.
  EXPECT_EQ(1, set_encryption_key_num_calls_);
  // Check that there was no attempt to destroy a previous token.
  EXPECT_EQ(0, delete_all_num_calls_);
}

TEST_F(SoftwareOnlyTest, CreateNewShared) {
  int slot_id = 0;
  EXPECT_CALL(factory_, CreateSlotPolicy(true))
      .WillOnce(InvokeWithoutArgs(this, &SoftwareOnlyTest::SlotPolicyFactory));
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, base::FilePath(kSystemTokenPath),
                                       MakeBlob(kAuthData), kTokenLabel,
                                       &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  // Check that an encryption key gets set for a load.
  EXPECT_EQ(1, set_encryption_key_num_calls_);
  // Check that there was no attempt to destroy a previous token.
  EXPECT_EQ(0, delete_all_num_calls_);
}

TEST_F(SoftwareOnlyTest, TestOpenIsolate) {
  // Check that trying to open an invalid isolate creates new isolate.
  SecureBlob isolate("invalid");
  bool new_isolate_created = false;
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_TRUE(new_isolate_created);

  // Check opening an existing isolate.
  EXPECT_TRUE(slot_manager_->OpenIsolate(&isolate, &new_isolate_created));
  EXPECT_FALSE(new_isolate_created);
}

TEST_F(SoftwareOnlyTest, LoadExisting) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(2);
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InitializeObjectPoolBlobs();
  int slot_id = 0;
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, kTestTokenPath, MakeBlob(kAuthData),
                                       kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  EXPECT_EQ(1, set_encryption_key_num_calls_);
  EXPECT_EQ(0, delete_all_num_calls_);
}

TEST_F(SoftwareOnlyTest, BadAuth) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(2);
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InitializeObjectPoolBlobs();
  // We expect the token to be successfully recreated with the new auth value.
  int slot_id = 0;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(
          kReinitializingToken,
          static_cast<int>(ReinitializingTokenStatus::kBadAuthorizationData),
          static_cast<int>(ReinitializingTokenStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, kTestTokenPath, MakeBlob("bad"),
                                       kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  EXPECT_EQ(1, set_encryption_key_num_calls_);
  EXPECT_EQ(1, delete_all_num_calls_);
}

TEST_F(SoftwareOnlyTest, CorruptRootKey) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .Times(2);
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InitializeObjectPoolBlobs();
  pool_blobs_[kEncryptedRootKey] = "bad";
  // We expect the token to be successfully recreated.
  int slot_id = 0;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(
          kReinitializingToken,
          static_cast<int>(ReinitializingTokenStatus::kFailedToDecryptRootKey),
          static_cast<int>(ReinitializingTokenStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, kTestTokenPath, MakeBlob(kAuthData),
                                       kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  EXPECT_EQ(1, set_encryption_key_num_calls_);
  EXPECT_EQ(1, delete_all_num_calls_);
}

TEST_F(SoftwareOnlyTest, CreateNewWriteFailure) {
  pool_write_result_ = false;
  int slot_id = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendEnumToUMA(kChapsTokenManagerLoadToken,
                            static_cast<int>(
                                TokenManagerStatus::kFailedToLoadSoftwareToken),
                            static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_FALSE(slot_manager_->LoadToken(
      ic_, kTestTokenPath, MakeBlob(kAuthData), kTokenLabel, &slot_id));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, slot_id));
}

TEST_F(SoftwareOnlyTest, LoadExistingWriteFailure) {
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  InitializeObjectPoolBlobs();
  pool_write_result_ = false;
  int slot_id = 0;
  EXPECT_CALL(mock_metrics_library_,
              SendEnumToUMA(kChapsTokenManagerLoadToken,
                            static_cast<int>(
                                TokenManagerStatus::kFailedToLoadSoftwareToken),
                            static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_FALSE(slot_manager_->LoadToken(
      ic_, kTestTokenPath, MakeBlob(kAuthData), kTokenLabel, &slot_id));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  EXPECT_EQ(1, set_encryption_key_num_calls_);
}

TEST_F(SoftwareOnlyTest, Unload) {
  int slot_id = 0;
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerLoadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->LoadToken(ic_, kTestTokenPath, MakeBlob(kAuthData),
                                       kTokenLabel, &slot_id));
  EXPECT_TRUE(slot_manager_->IsTokenAccessible(ic_, slot_id));
  EXPECT_CALL(
      mock_metrics_library_,
      SendEnumToUMA(kChapsTokenManagerUnloadToken,
                    static_cast<int>(TokenManagerStatus::kCommandSuccess),
                    static_cast<int>(TokenManagerStatus::kMaxValue)))
      .WillOnce(Return(true));
  EXPECT_TRUE(slot_manager_->UnloadToken(ic_, kTestTokenPath));
  EXPECT_FALSE(slot_manager_->IsTokenAccessible(ic_, slot_id));
}

}  // namespace chaps
