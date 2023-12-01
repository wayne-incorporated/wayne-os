// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/object_mock.h"
#include "chaps/object_policy_cert.h"
#include "chaps/object_policy_data.h"
#include "chaps/object_policy_secret_key.h"

using std::string;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace chaps {

// Test fixture for an initialized ObjectImpl instance.
class TestObjectPolicy : public ::testing::Test {
 public:
  TestObjectPolicy() {
    object_.SetupFake();
    EXPECT_CALL(object_, GetObjectClass()).Times(AnyNumber());
    EXPECT_CALL(object_, GetAttributeBool(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, SetAttributeBool(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, GetAttributeInt(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, SetAttributeInt(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, GetAttributeString(_)).Times(AnyNumber());
    EXPECT_CALL(object_, SetAttributeString(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, SetAttributes(_, _)).Times(AnyNumber());
    EXPECT_CALL(object_, IsAttributePresent(_)).Times(AnyNumber());
    EXPECT_CALL(object_, RemoveAttribute(_)).Times(AnyNumber());
    EXPECT_CALL(object_, GetStage()).WillRepeatedly(Return(kCreate));
  }

  ObjectMock object_;
};

TEST(DeathTest, NotInit) {
  ObjectPolicyData policy;
  EXPECT_DEATH_IF_SUPPORTED(policy.IsReadAllowed(CKA_CLASS), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(policy.IsModifyAllowed(CKA_CLASS, ""),
                            "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(policy.IsObjectComplete(), "Check failed");
  EXPECT_DEATH_IF_SUPPORTED(policy.SetDefaultAttributes(), "Check failed");
}

TEST_F(TestObjectPolicy, IsReadAllowed) {
  ObjectPolicySecretKey policy;
  policy.Init(&object_);
  EXPECT_TRUE(policy.IsReadAllowed(CKA_CLASS));
  EXPECT_TRUE(policy.IsReadAllowed(CKA_DEFAULT_CMS_ATTRIBUTES));
  EXPECT_FALSE(policy.IsReadAllowed(CKA_VALUE));
  object_.SetAttributeBool(CKA_SENSITIVE, true);
  object_.SetAttributeBool(CKA_EXTRACTABLE, false);
  EXPECT_FALSE(policy.IsReadAllowed(CKA_VALUE));
  object_.SetAttributeBool(CKA_SENSITIVE, false);
  object_.SetAttributeBool(CKA_EXTRACTABLE, true);
  EXPECT_TRUE(policy.IsReadAllowed(CKA_VALUE));
}

TEST_F(TestObjectPolicy, IsModifyAllowed) {
  ObjectPolicySecretKey policy;
  policy.Init(&object_);
  // Create stage.
  EXPECT_CALL(object_, GetStage()).WillRepeatedly(Return(kCreate));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_LABEL, ""));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_PRIVATE, ""));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_TOKEN, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_LOCAL, ""));
  // Copy stage.
  EXPECT_CALL(object_, GetStage()).WillRepeatedly(Return(kCopy));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_LABEL, ""));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_PRIVATE, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_TOKEN, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_LOCAL, ""));
  // Modify stage.
  EXPECT_CALL(object_, GetStage()).WillRepeatedly(Return(kModify));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_LABEL, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_PRIVATE, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_TOKEN, ""));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_LOCAL, ""));
  // Special cases.
  string false_str(1, 0);
  string true_str(1, 1);
  object_.SetAttributeBool(CKA_SENSITIVE, false);
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_SENSITIVE, false_str));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_SENSITIVE, true_str));
  object_.SetAttributeBool(CKA_SENSITIVE, true);
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_SENSITIVE, false_str));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_SENSITIVE, true_str));
  object_.SetAttributeBool(CKA_EXTRACTABLE, true);
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_EXTRACTABLE, false_str));
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_EXTRACTABLE, true_str));
  object_.SetAttributeBool(CKA_EXTRACTABLE, false);
  EXPECT_TRUE(policy.IsModifyAllowed(CKA_EXTRACTABLE, false_str));
  EXPECT_FALSE(policy.IsModifyAllowed(CKA_EXTRACTABLE, true_str));
}

TEST_F(TestObjectPolicy, IsObjectComplete) {
  ObjectPolicyCert policy;
  policy.Init(&object_);
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeInt(CKA_CLASS, CKO_CERTIFICATE);
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_VALUE, "");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeInt(CKA_CERTIFICATE_TYPE, CKC_X_509_ATTR_CERT);
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_OWNER, "");
  EXPECT_TRUE(policy.IsObjectComplete());
  object_.SetAttributeInt(CKA_CERTIFICATE_TYPE, CKC_X_509);
  object_.SetAttributeString(CKA_SUBJECT, "");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_VALUE, "123");
  EXPECT_TRUE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_VALUE, "");
  object_.SetAttributeString(CKA_URL, "");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_URL, "123");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_HASH_OF_ISSUER_PUBLIC_KEY, "");
  object_.SetAttributeString(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "123");
  EXPECT_FALSE(policy.IsObjectComplete());
  object_.SetAttributeString(CKA_HASH_OF_ISSUER_PUBLIC_KEY, "123");
  EXPECT_TRUE(policy.IsObjectComplete());
  object_.RemoveAttribute(CKA_VALUE);
  EXPECT_FALSE(policy.IsObjectComplete());
}

TEST_F(TestObjectPolicy, SetDefaultAttributes) {
  ObjectPolicySecretKey policy;
  policy.Init(&object_);
  object_.SetAttributeBool(CKA_ENCRYPT, true);
  policy.SetDefaultAttributes();
  EXPECT_TRUE(object_.GetAttributeBool(CKA_ENCRYPT, false));
  EXPECT_FALSE(object_.GetAttributeBool(CKA_DECRYPT, true));
}

TEST_F(TestObjectPolicy, LatchingAttributes) {
  for (bool keygen_known : {false, true}) {
    for (bool extractable : {false, true}) {
      for (bool sensitive : {false, true}) {
        ObjectPolicySecretKey policy;
        policy.Init(&object_);
        if (keygen_known) {
          object_.SetAttributeInt(CKA_KEY_GEN_MECHANISM, CKM_DES3_KEY_GEN);
        } else {
          object_.RemoveAttribute(CKA_KEY_GEN_MECHANISM);
        }
        object_.SetAttributeBool(CKA_EXTRACTABLE, extractable);
        object_.SetAttributeBool(CKA_SENSITIVE, sensitive);
        policy.SetDefaultAttributes();

        if (!keygen_known) {
          // Can't claim the key was never extractable or always sensitive
          // if we don't know how it was generated.
          EXPECT_FALSE(object_.GetAttributeBool(CKA_ALWAYS_SENSITIVE, true));
          EXPECT_FALSE(object_.GetAttributeBool(CKA_NEVER_EXTRACTABLE, true));
          EXPECT_EQ(
              static_cast<int>(CK_UNAVAILABLE_INFORMATION),
              object_.GetAttributeInt(CKA_KEY_GEN_MECHANISM, CKM_DES3_KEY_GEN));
        } else {
          EXPECT_EQ(sensitive,
                    object_.GetAttributeBool(CKA_ALWAYS_SENSITIVE, !sensitive));
          EXPECT_EQ(!extractable, object_.GetAttributeBool(
                                      CKA_NEVER_EXTRACTABLE, extractable));
          EXPECT_EQ(
              CKM_DES3_KEY_GEN,
              object_.GetAttributeInt(CKA_KEY_GEN_MECHANISM, CKM_AES_KEY_GEN));
        }
      }
    }
  }
}

}  // namespace chaps
