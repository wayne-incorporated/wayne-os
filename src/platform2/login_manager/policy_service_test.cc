// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_service.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/run_loop.h>
#include <base/threading/thread.h>
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

namespace em = enterprise_management;

using ::testing::_;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Mock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::Sequence;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

namespace {

constexpr char kPolicyValue1[] = "fake_policy1";
constexpr char kPolicyValue2[] = "fake_policy2";

}  // namespace

namespace login_manager {

class PolicyServiceTest : public testing::Test {
 public:
  PolicyServiceTest() = default;

  void SetUp() override {
    fake_loop_.SetAsCurrent();
    store_ = new StrictMock<MockPolicyStore>;
    service_ = std::make_unique<PolicyService>(base::FilePath(), &key_, nullptr,
                                               false);
    service_->SetStoreForTesting(MakeChromePolicyNamespace(),
                                 std::unique_ptr<PolicyStore>(store_));
    service_->set_delegate(&delegate_);
  }

  void InitPolicy(const std::vector<uint8_t>& data,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& key,
                  const std::vector<uint8_t>& key_signature) {
    policy_proto_.Clear();
    if (!data.empty())
      policy_proto_.set_policy_data(BlobToString(data));
    if (!signature.empty())
      policy_proto_.set_policy_data_signature(BlobToString(signature));
    if (!key.empty())
      policy_proto_.set_new_public_key(BlobToString(key));
    if (!key_signature.empty())
      policy_proto_.set_new_public_key_signature(BlobToString(key_signature));
  }

  void ExpectVerifyAndSetPolicy(Sequence* sequence) {
    EXPECT_CALL(key_, Verify(fake_data_, fake_sig_))
        .InSequence(*sequence)
        .WillOnce(Return(true));
    EXPECT_CALL(*store_, Set(ProtoEq(policy_proto_)))
        .Times(1)
        .InSequence(*sequence);
  }

  void ExpectSetPolicy(Sequence* sequence) {
    EXPECT_CALL(*store_, Set(ProtoEq(policy_proto_)))
        .Times(1)
        .InSequence(*sequence);
  }

  void ExpectPersistKey(Sequence* sequence) {
    EXPECT_CALL(key_, Persist()).InSequence(*sequence).WillOnce(Return(true));
    EXPECT_CALL(delegate_, OnKeyPersisted(true));
  }

  void ExpectPersistPolicy(Sequence* sequence) {
    EXPECT_CALL(*store_, Persist())
        .InSequence(*sequence)
        .WillOnce(Return(true));
    EXPECT_CALL(delegate_, OnPolicyPersisted(true));
  }

  void ExpectKeyEqualsFalse(Sequence* sequence) {
    EXPECT_CALL(key_, Equals(_))
        .InSequence(*sequence)
        .WillRepeatedly(Return(false));
  }

  void ExpectKeyPopulated(Sequence* sequence, bool return_value) {
    EXPECT_CALL(key_, IsPopulated())
        .InSequence(*sequence)
        .WillRepeatedly(Return(return_value));
  }

  void ExpectStoreFail(int flags,
                       SignatureCheck signature_check,
                       const std::string& code) {
    EXPECT_CALL(key_, Persist()).Times(0);
    EXPECT_CALL(*store_, Set(_)).Times(0);
    EXPECT_CALL(*store_, Persist()).Times(0);

    EXPECT_FALSE(service_->Store(
        MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), flags,
        signature_check, MockPolicyService::CreateExpectFailureCallback()));
    fake_loop_.Run();
  }

  static const int kAllKeyFlags;
  static const char kSignalSuccess[];
  static const char kSignalFailure[];

  const std::vector<uint8_t> fake_data_ = StringToBlob("fake_data");
  const std::vector<uint8_t> fake_sig_ = StringToBlob("fake_signature");
  const std::vector<uint8_t> fake_key_ = StringToBlob("fake_key");
  const std::vector<uint8_t> fake_key_sig_ = StringToBlob("fake_key_signature");

  const std::vector<uint8_t> empty_blob_;

  // Various representations of the policy protobuf.
  em::PolicyFetchResponse policy_proto_;

  brillo::FakeMessageLoop fake_loop_{nullptr};

  // Use StrictMock to make sure that no unexpected policy or key mutations can
  // occur without the test failing.
  StrictMock<MockPolicyKey> key_;
  StrictMock<MockPolicyStore>* store_;
  MockPolicyServiceDelegate delegate_;

  std::unique_ptr<PolicyService> service_;
};

const int PolicyServiceTest::kAllKeyFlags = PolicyService::KEY_ROTATE |
                                            PolicyService::KEY_INSTALL_NEW |
                                            PolicyService::KEY_CLOBBER;
const char PolicyServiceTest::kSignalSuccess[] = "success";
const char PolicyServiceTest::kSignalFailure[] = "failure";

TEST_F(PolicyServiceTest, Store) {
  InitPolicy(fake_data_, fake_sig_, empty_blob_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);
  EXPECT_CALL(key_, Verify(fake_data_, fake_sig_))
      .InSequence(s1, s2)
      .WillRepeatedly(Return(true));
  ExpectKeyPopulated(&s1, true);
  ExpectVerifyAndSetPolicy(&s2);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreUnsigned) {
  InitPolicy(fake_data_, empty_blob_, empty_blob_, empty_blob_);

  Sequence s1, s2;
  ExpectSetPolicy(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kDisabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreWrongSignature) {
  InitPolicy(fake_data_, fake_sig_, empty_blob_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);
  EXPECT_CALL(key_, Verify(fake_data_, fake_sig_))
      .InSequence(s1, s2)
      .WillRepeatedly(Return(false));

  ExpectStoreFail(kAllKeyFlags, SignatureCheck::kEnabled,
                  dbus_error::kVerifyFail);
}

TEST_F(PolicyServiceTest, StoreNoData) {
  InitPolicy(empty_blob_, empty_blob_, empty_blob_, empty_blob_);

  ExpectStoreFail(kAllKeyFlags, SignatureCheck::kEnabled,
                  dbus_error::kSigDecodeFail);
}

TEST_F(PolicyServiceTest, StoreNoSignature) {
  InitPolicy(fake_data_, empty_blob_, empty_blob_, empty_blob_);

  EXPECT_CALL(key_, Verify(fake_data_, std::vector<uint8_t>()))
      .WillOnce(Return(false));

  ExpectStoreFail(kAllKeyFlags, SignatureCheck::kEnabled,
                  dbus_error::kVerifyFail);
}

TEST_F(PolicyServiceTest, StoreNoKey) {
  InitPolicy(fake_data_, fake_sig_, empty_blob_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, false);
  EXPECT_CALL(key_, Verify(fake_data_, fake_sig_))
      .InSequence(s1, s2)
      .WillRepeatedly(Return(false));

  ExpectStoreFail(kAllKeyFlags, SignatureCheck::kEnabled,
                  dbus_error::kVerifyFail);
}

TEST_F(PolicyServiceTest, StoreNewKey) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, false);
  EXPECT_CALL(key_, PopulateFromBuffer(VectorEq(fake_key_)))
      .InSequence(s1, s2)
      .WillOnce(Return(true));
  ExpectKeyPopulated(&s1, true);
  ExpectVerifyAndSetPolicy(&s2);
  ExpectPersistKey(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreNewKeyClobber) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, false);
  EXPECT_CALL(key_, ClobberCompromisedKey(VectorEq(fake_key_)))
      .InSequence(s1, s2)
      .WillOnce(Return(true));
  ExpectKeyPopulated(&s1, true);
  ExpectVerifyAndSetPolicy(&s2);
  ExpectPersistKey(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_CLOBBER, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreNewKeySame) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, empty_blob_);

  Sequence s1, s2, s3;
  EXPECT_CALL(key_, Equals(BlobToString(fake_key_)))
      .InSequence(s1)
      .WillRepeatedly(Return(true));
  ExpectKeyPopulated(&s2, true);
  ExpectVerifyAndSetPolicy(&s3);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreNewKeyNotAllowed) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, false);

  ExpectStoreFail(PolicyService::KEY_NONE, SignatureCheck::kEnabled,
                  dbus_error::kPubkeySetIllegal);
}

TEST_F(PolicyServiceTest, StoreRotation) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, fake_key_sig_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);
  EXPECT_CALL(key_, Rotate(VectorEq(fake_key_), VectorEq(fake_key_sig_)))
      .InSequence(s1, s2)
      .WillOnce(Return(true));
  ExpectKeyPopulated(&s1, true);
  ExpectVerifyAndSetPolicy(&s2);
  ExpectPersistKey(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreRotationClobber) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, fake_key_sig_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, false);
  EXPECT_CALL(key_, ClobberCompromisedKey(VectorEq(fake_key_)))
      .InSequence(s1, s2)
      .WillOnce(Return(true));
  ExpectKeyPopulated(&s1, true);
  ExpectVerifyAndSetPolicy(&s2);
  ExpectPersistKey(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_),
      PolicyService::KEY_CLOBBER, SignatureCheck::kEnabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();
}

TEST_F(PolicyServiceTest, StoreRotationNoSignature) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, empty_blob_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);

  ExpectStoreFail(PolicyService::KEY_ROTATE, SignatureCheck::kEnabled,
                  dbus_error::kPubkeySetIllegal);
}

TEST_F(PolicyServiceTest, StoreRotationBadSignature) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, fake_key_sig_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);
  EXPECT_CALL(key_, Rotate(VectorEq(fake_key_), VectorEq(fake_key_sig_)))
      .InSequence(s1, s2)
      .WillOnce(Return(false));

  ExpectStoreFail(PolicyService::KEY_ROTATE, SignatureCheck::kEnabled,
                  dbus_error::kPubkeySetIllegal);
}

TEST_F(PolicyServiceTest, StoreRotationNotAllowed) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, fake_key_sig_);

  Sequence s1, s2;
  ExpectKeyEqualsFalse(&s1);
  ExpectKeyPopulated(&s2, true);

  ExpectStoreFail(PolicyService::KEY_NONE, SignatureCheck::kEnabled,
                  dbus_error::kPubkeySetIllegal);
}

TEST_F(PolicyServiceTest, Retrieve) {
  InitPolicy(fake_data_, fake_sig_, fake_key_, fake_key_sig_);

  EXPECT_CALL(*store_, Get()).WillOnce(ReturnRef(policy_proto_));

  std::vector<uint8_t> out_policy_blob;
  EXPECT_TRUE(
      service_->Retrieve(MakeChromePolicyNamespace(), &out_policy_blob));
  EXPECT_EQ(SerializeAsBlob(policy_proto_), out_policy_blob);
}

// Makes sure ListComponentIds doesn't return anything if POLICY_DOMAIN_CHROME
// is passed, even if policy is stored.
TEST_F(PolicyServiceTest, ListEmpty) {
  InitPolicy(fake_data_, empty_blob_, empty_blob_, empty_blob_);

  Sequence s1, s2;
  ExpectSetPolicy(&s1);
  ExpectPersistPolicy(&s2);

  EXPECT_TRUE(service_->Store(
      MakeChromePolicyNamespace(), SerializeAsBlob(policy_proto_), kAllKeyFlags,
      SignatureCheck::kDisabled,
      MockPolicyService::CreateExpectSuccessCallback()));

  fake_loop_.Run();

  EXPECT_TRUE(service_->ListComponentIds(POLICY_DOMAIN_CHROME).empty());
}

TEST_F(PolicyServiceTest, PersistPolicySuccess) {
  EXPECT_CALL(*store_, Persist()).WillOnce(Return(true));
  EXPECT_CALL(delegate_, OnPolicyPersisted(true)).Times(1);
  service_->PersistPolicy(MakeChromePolicyNamespace(),
                          PolicyService::Completion());
}

TEST_F(PolicyServiceTest, PersistPolicyFailure) {
  EXPECT_CALL(*store_, Persist()).WillOnce(Return(false));
  EXPECT_CALL(delegate_, OnPolicyPersisted(false)).Times(1);
  service_->PersistPolicy(MakeChromePolicyNamespace(),
                          PolicyService::Completion());
}

// Tests PolicyService with multiple namespace and a real PolicyStore.
class PolicyServiceNamespaceTest : public testing::Test {
 public:
  PolicyServiceNamespaceTest() = default;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    fake_loop_.SetAsCurrent();
    service_ = std::make_unique<PolicyService>(temp_dir_.GetPath(), nullptr,
                                               nullptr, false);

    const std::string kExtensionId1 = "abcdefghijklmnopabcdefghijklmnop";
    ns1_ = PolicyNamespace(POLICY_DOMAIN_CHROME, "");
    ns2_ = PolicyNamespace(POLICY_DOMAIN_EXTENSIONS, kExtensionId1);

    policy_path1_ =
        temp_dir_.GetPath().Append(PolicyService::kChromePolicyFileName);
    policy_path2_ = temp_dir_.GetPath().Append(
        PolicyService::kExtensionsPolicyFileNamePrefix + kExtensionId1);
  }

 protected:
  std::vector<uint8_t> PolicyValueToBlob(const std::string& policy_value) {
    em::PolicyFetchResponse policy_response;
    em::PolicyData policy_data;
    policy_data.set_policy_value(policy_value);
    EXPECT_TRUE(
        policy_data.SerializeToString(policy_response.mutable_policy_data()));
    return StringToBlob(policy_response.SerializeAsString());
  }

  std::string BlobToPolicyValue(const std::vector<uint8_t>& policy_blob) {
    em::PolicyFetchResponse policy_response;
    em::PolicyData policy_data;
    EXPECT_TRUE(
        policy_response.ParseFromArray(policy_blob.data(), policy_blob.size()));
    EXPECT_TRUE(policy_data.ParseFromString(policy_response.policy_data()));
    return policy_data.policy_value();
  }

  // Stores policy with value |policy_value| in the namespace |ns|.
  void StorePolicy(const std::string& policy_value, const PolicyNamespace& ns) {
    const std::vector<uint8_t> policy_blob = PolicyValueToBlob(policy_value);
    EXPECT_TRUE(service_->Store(
        ns, policy_blob, PolicyService::KEY_NONE, SignatureCheck::kDisabled,
        MockPolicyService::CreateExpectSuccessCallback()));
  }

  // Retrieves the policy value from namespace |ns|. Returns an empty string on
  // error.
  std::string RetrievePolicy(const PolicyNamespace& ns) {
    std::vector<uint8_t> policy_blob;
    if (!service_->Retrieve(ns, &policy_blob))
      return std::string();
    return BlobToPolicyValue(policy_blob);
  }

  // Loads a policy value from disk and returns the policy value string. Returns
  // an empty string on error.
  std::string LoadPolicyFromFile(const base::FilePath& policy_path) {
    std::string policy_blob;
    if (!base::ReadFileToString(policy_path, &policy_blob))
      return std::string();
    return BlobToPolicyValue(StringToBlob(policy_blob));
  }

  // Saves a policy value to disk embedded in a PolicyFetchResponse.
  void SavePolicyToFile(const base::FilePath& policy_path,
                        const std::string& policy_value) {
    EXPECT_TRUE(WriteBlobToFile(policy_path, PolicyValueToBlob(policy_value)));
  }

  brillo::FakeMessageLoop fake_loop_{nullptr};
  std::unique_ptr<PolicyService> service_;
  base::ScopedTempDir temp_dir_;
  PolicyNamespace ns1_;
  PolicyNamespace ns2_;
  base::FilePath policy_path1_;
  base::FilePath policy_path2_;
};

TEST_F(PolicyServiceNamespaceTest, Store) {
  EXPECT_FALSE(base::PathExists(policy_path1_));
  StorePolicy(kPolicyValue1, ns1_);
  // The file is stored in a "background" task.
  fake_loop_.Run();
  EXPECT_TRUE(base::PathExists(policy_path1_));
  std::string actual_value = LoadPolicyFromFile(policy_path1_);
  EXPECT_EQ(kPolicyValue1, actual_value);
}

TEST_F(PolicyServiceNamespaceTest, StoreMultiple) {
  EXPECT_FALSE(base::PathExists(policy_path1_));
  StorePolicy(kPolicyValue1, ns1_);
  fake_loop_.Run();
  EXPECT_TRUE(base::PathExists(policy_path1_));

  EXPECT_FALSE(base::PathExists(policy_path2_));
  StorePolicy(kPolicyValue2, ns2_);
  fake_loop_.Run();
  EXPECT_TRUE(base::PathExists(policy_path2_));

  std::string actual_value1 = LoadPolicyFromFile(policy_path1_);
  std::string actual_value2 = LoadPolicyFromFile(policy_path2_);

  EXPECT_EQ(kPolicyValue1, actual_value1);
  EXPECT_EQ(kPolicyValue2, actual_value2);
}

TEST_F(PolicyServiceNamespaceTest, StoreRetrieveMultiple) {
  EXPECT_FALSE(base::PathExists(policy_path1_));
  EXPECT_FALSE(base::PathExists(policy_path2_));

  StorePolicy(kPolicyValue1, ns1_);
  StorePolicy(kPolicyValue2, ns2_);

  std::string actual_value1 = RetrievePolicy(ns1_);
  std::string actual_value2 = RetrievePolicy(ns2_);

  EXPECT_EQ(kPolicyValue1, actual_value1);
  EXPECT_EQ(kPolicyValue2, actual_value2);

  // The files are stored in a "background" task.
  fake_loop_.Run();

  EXPECT_TRUE(base::PathExists(policy_path1_));
  EXPECT_TRUE(base::PathExists(policy_path2_));
}

TEST_F(PolicyServiceNamespaceTest, LoadPolicyFromDisk) {
  // Makes sure that policy is loaded from disk on first access.
  SavePolicyToFile(policy_path1_, kPolicyValue1);
  const std::string actual_value = RetrievePolicy(ns1_);
  EXPECT_EQ(kPolicyValue1, actual_value);
}

// ListComponentIds returns the expected component id(s) after a StorePolicy()
// call.
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsFromPolicyInStore) {
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  StorePolicy(kPolicyValue2, ns2_);
  EXPECT_FALSE(base::PathExists(policy_path2_));
  EXPECT_EQ(service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS),
            std::vector<std::string>({ns2_.second}));
  // Make expectations happy.
  fake_loop_.Run();
}

// ListComponentIds returns the expected component id(s) from policy stored on
// disk (and no PolicyStore instance in the service).
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsFromPolicyOnDisk) {
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  SavePolicyToFile(policy_path2_, "good");
  EXPECT_EQ(service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS),
            std::vector<std::string>({ns2_.second}));
}

// ListComponentIds returns no duplicates if a policy exists on disk and the
// store exists as well.
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsHasNoDuplicates) {
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  StorePolicy(kPolicyValue2, ns2_);
  fake_loop_.Run();
  EXPECT_TRUE(base::PathExists(policy_path2_));
  EXPECT_EQ(service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS),
            std::vector<std::string>({ns2_.second}));
}

// ListComponentIds does not return stores with empty policy.
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsDoesNotReturnEmptyStores) {
  // Note that RetrievePolicy actually creates a PolicyStore instance.
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  EXPECT_TRUE(RetrievePolicy(ns2_).empty());
  EXPECT_FALSE(base::PathExists(policy_path2_));
  EXPECT_TRUE(service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS).empty());
}

// Policy files with bad component ids are ignored.
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsIgnoresBadIds) {
  // Invalidate component id.
  ns2_.second = "deadl0ccfail3db19";
  policy_path2_ = temp_dir_.GetPath().Append(
      PolicyService::kExtensionsPolicyFileNamePrefix + ns2_.second);

  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  SavePolicyToFile(policy_path2_, "bad");
  EXPECT_EQ(service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS),
            std::vector<std::string>());
}

// Make sure the list command doesn't leak component ids across domains.
TEST_F(PolicyServiceNamespaceTest, ListComponentIdsDoesntLeakAcrossDomains) {
  // Write
  //   - 2 extension policies,
  //   - 1 signin extension policy,
  //   - 1 Chrome policy.
  const std::string kExtensionId1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const std::string kExtensionId2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const std::string kSigninExtensionId = "cccccccccccccccccccccccccccccccc";

  const base::FilePath kExtensionPath1 = temp_dir_.GetPath().Append(
      PolicyService::kExtensionsPolicyFileNamePrefix + kExtensionId1);
  const base::FilePath kExtensionPath2 = temp_dir_.GetPath().Append(
      PolicyService::kExtensionsPolicyFileNamePrefix + kExtensionId2);
  const base::FilePath kSigninExtensionPath = temp_dir_.GetPath().Append(
      PolicyService::kSignInExtensionsPolicyFileNamePrefix +
      kSigninExtensionId);
  const base::FilePath kChromePath =
      temp_dir_.GetPath().Append(PolicyService::kChromePolicyFileName);

  SavePolicyToFile(kExtensionPath1, "Extension policy 1");
  SavePolicyToFile(kExtensionPath2, "Extension policy 2");
  SavePolicyToFile(kSigninExtensionPath, "Signin extension policy");
  SavePolicyToFile(kChromePath, "Chrome policy");

  EXPECT_EQ(std::vector<std::string>({kExtensionId1, kExtensionId2}),
            service_->ListComponentIds(POLICY_DOMAIN_EXTENSIONS));
  EXPECT_EQ(std::vector<std::string>({kSigninExtensionId}),
            service_->ListComponentIds(POLICY_DOMAIN_SIGNIN_EXTENSIONS));
  EXPECT_EQ(std::vector<std::string>(),
            service_->ListComponentIds(POLICY_DOMAIN_CHROME));
}

TEST_F(PolicyServiceNamespaceTest, DeleteFailsForChromeNamespace) {
  EXPECT_EQ(ns1_.first, POLICY_DOMAIN_CHROME);
  EXPECT_FALSE(service_->Delete(ns1_, SignatureCheck::kDisabled));
}

TEST_F(PolicyServiceNamespaceTest, DeleteFailsForEnabledSignatureCheck) {
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  EXPECT_FALSE(service_->Delete(ns2_, SignatureCheck::kEnabled));
}

TEST_F(PolicyServiceNamespaceTest, DeleteSucceeds) {
  EXPECT_EQ(ns2_.first, POLICY_DOMAIN_EXTENSIONS);
  EXPECT_TRUE(service_->Delete(ns2_, SignatureCheck::kDisabled));
}

}  // namespace login_manager
