// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/user_policy_service.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ptr_util.h>
#include <base/run_loop.h>
#include <brillo/message_loops/fake_message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bindings/device_management_backend.pb.h"
#include "login_manager/blob_util.h"
#include "login_manager/matchers.h"
#include "login_manager/mock_policy_key.h"
#include "login_manager/mock_policy_service.h"
#include "login_manager/mock_policy_store.h"
#include "login_manager/policy_service.h"
#include "login_manager/system_utils_impl.h"

namespace em = enterprise_management;

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::Sequence;
using ::testing::StrictMock;

namespace login_manager {

namespace {

PolicyNamespace MakeExtensionPolicyNamespace() {
  return std::make_pair(POLICY_DOMAIN_EXTENSIONS,
                        "ababababcdcdcdcdefefefefghghghgh");
}

void InitPolicyFetchResponse(const std::string& policy_value_str,
                             em::PolicyData::AssociationState state,
                             const std::string& signature,
                             em::PolicyFetchResponse* policy_proto) {
  em::PolicyData policy_data;
  policy_data.set_state(state);
  policy_data.set_policy_value(policy_value_str);
  std::string policy_data_str;
  ASSERT_TRUE(policy_data.SerializeToString(&policy_data_str));

  policy_proto->Clear();
  policy_proto->set_policy_data(policy_data_str);
  if (!signature.empty())
    policy_proto->set_policy_data_signature(signature);
}

}  // namespace

class UserPolicyServiceTest : public ::testing::Test {
 public:
  UserPolicyServiceTest() = default;
  UserPolicyServiceTest(const UserPolicyServiceTest&) = delete;
  UserPolicyServiceTest& operator=(const UserPolicyServiceTest&) = delete;

  void SetUp() override {
    fake_loop_.SetAsCurrent();
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    key_copy_file_ = tmpdir_.GetPath().Append("hash/key_copy.pub");

    key_ = new StrictMock<MockPolicyKey>;
    store_ = new StrictMock<MockPolicyStore>;
    service_.reset(new UserPolicyService(tmpdir_.GetPath(),
                                         std::unique_ptr<PolicyKey>(key_),
                                         key_copy_file_, &system_utils_));
    service_->SetStoreForTesting(MakeChromePolicyNamespace(),
                                 std::unique_ptr<PolicyStore>(store_));
  }

  void InitPolicy(em::PolicyData::AssociationState state,
                  const std::string& signature) {
    ASSERT_NO_FATAL_FAILURE(InitPolicyFetchResponse(
        "" /* policy_value */, state, signature, &policy_proto_));
  }

  void ExpectStorePolicy(const Sequence& sequence) {
    EXPECT_CALL(*store_, Set(ProtoEq(policy_proto_))).InSequence(sequence);
    EXPECT_CALL(*store_, Persist()).InSequence(sequence).WillOnce(Return(true));
  }

 protected:
  SystemUtilsImpl system_utils_;
  base::ScopedTempDir tmpdir_;
  base::FilePath key_copy_file_;

  const std::string fake_signature_ = "fake_signature";

  // Various representations of the policy protobuf.
  em::PolicyFetchResponse policy_proto_;

  brillo::FakeMessageLoop fake_loop_{nullptr};

  // Use StrictMock to make sure that no unexpected policy or key mutations can
  // occur without the test failing.
  StrictMock<MockPolicyKey>* key_;
  StrictMock<MockPolicyStore>* store_;

  std::unique_ptr<UserPolicyService> service_;
};

TEST_F(UserPolicyServiceTest, StoreSignedPolicy) {
  InitPolicy(em::PolicyData::ACTIVE, fake_signature_);

  Sequence s1;
  EXPECT_CALL(*key_, Verify(_, _)).InSequence(s1).WillOnce(Return(true));
  ExpectStorePolicy(s1);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
}

TEST_F(UserPolicyServiceTest, StoreUnmanagedSigned) {
  InitPolicy(em::PolicyData::UNMANAGED, fake_signature_);

  Sequence s1;
  EXPECT_CALL(*key_, Verify(_, _)).InSequence(s1).WillOnce(Return(true));
  ExpectStorePolicy(s1);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
}

TEST_F(UserPolicyServiceTest, StoreUnmanagedKeyPresent) {
  InitPolicy(em::PolicyData::UNMANAGED, "");

  Sequence s1;
  ExpectStorePolicy(s1);
  std::vector<uint8_t> key_value;
  key_value.push_back(0x12);

  EXPECT_CALL(*key_, IsPopulated()).WillRepeatedly(Return(true));
  EXPECT_CALL(*key_, public_key_der()).WillRepeatedly(ReturnRef(key_value));

  Sequence s2;
  EXPECT_CALL(*key_, ClobberCompromisedKey(ElementsAre())).InSequence(s2);
  EXPECT_CALL(*key_, Persist()).InSequence(s2).WillOnce(Return(true));

  EXPECT_FALSE(base::PathExists(key_copy_file_));
  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();

  EXPECT_TRUE(base::PathExists(key_copy_file_));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(key_copy_file_, &content));
  ASSERT_EQ(1u, content.size());
  EXPECT_EQ(key_value[0], content[0]);
}

TEST_F(UserPolicyServiceTest, StoreUnmanagedNoKey) {
  InitPolicy(em::PolicyData::UNMANAGED, "");

  Sequence s1;
  ExpectStorePolicy(s1);

  EXPECT_CALL(*key_, IsPopulated()).WillRepeatedly(Return(false));

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
  EXPECT_FALSE(base::PathExists(key_copy_file_));
}

TEST_F(UserPolicyServiceTest, StoreInvalidSignature) {
  InitPolicy(em::PolicyData::ACTIVE, fake_signature_);

  InSequence s;
  EXPECT_CALL(*key_, Verify(_, _)).WillOnce(Return(false));

  EXPECT_FALSE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectFailureCallback()));

  fake_loop_.Run();
}

TEST_F(UserPolicyServiceTest, PersistKeyCopy) {
  std::vector<uint8_t> key_value;
  key_value.push_back(0x12);
  EXPECT_CALL(*key_, IsPopulated()).WillRepeatedly(Return(true));
  EXPECT_CALL(*key_, public_key_der()).WillOnce(ReturnRef(key_value));
  EXPECT_FALSE(base::PathExists(key_copy_file_));

  service_->PersistKeyCopy();
  EXPECT_TRUE(base::PathExists(key_copy_file_));
  std::string content;
  EXPECT_TRUE(base::ReadFileToString(key_copy_file_, &content));
  ASSERT_EQ(1u, content.size());
  EXPECT_EQ(key_value[0], content[0]);

  // Now persist an empty key, and verify that the copy is removed.
  EXPECT_CALL(*key_, IsPopulated()).WillRepeatedly(Return(false));
  service_->PersistKeyCopy();
  EXPECT_FALSE(base::PathExists(key_copy_file_));
}

TEST_F(UserPolicyServiceTest, PersistPolicyMultipleNamespaces) {
  // Set up store for extension policy.
  auto extension_store = new StrictMock<MockPolicyStore>;
  service_->SetStoreForTesting(MakeExtensionPolicyNamespace(),
                               base::WrapUnique(extension_store));

  // Set up user policy.
  InitPolicy(em::PolicyData::ACTIVE, fake_signature_);

  // Set up extension policy.
  em::PolicyFetchResponse extension_policy_proto;
  ASSERT_NO_FATAL_FAILURE(
      InitPolicyFetchResponse("fake_extension_policy", em::PolicyData::ACTIVE,
                              fake_signature_, &extension_policy_proto));

  // Store user policy.
  EXPECT_CALL(*key_, Verify(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*store_, Set(ProtoEq(policy_proto_)));
  EXPECT_CALL(*store_, Persist()).WillOnce(Return(true));
  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
  testing::Mock::VerifyAndClearExpectations(&key_);
  testing::Mock::VerifyAndClearExpectations(store_);

  // Store extension policy.
  EXPECT_CALL(*key_, Verify(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*extension_store, Set(ProtoEq(extension_policy_proto)));
  EXPECT_CALL(*extension_store, Persist()).WillOnce(Return(true));
  EXPECT_TRUE(service_->Store(
      MakeExtensionPolicyNamespace(), SerializeAsBlob(extension_policy_proto),
      PolicyService::KEY_NONE, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));
  fake_loop_.Run();
}

}  // namespace login_manager
