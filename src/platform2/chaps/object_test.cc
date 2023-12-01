// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_impl.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/chaps_factory_mock.h"
#include "chaps/object_policy_mock.h"

using std::string;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace chaps {

// Test fixture for an initialized ObjectImpl instance.
class TestObject : public ::testing::Test {
 public:
  TestObject() {
    scoped_policy_.reset(CreatePolicy());
    next_policy_ = scoped_policy_.get();
    policy_ = NULL;
    EXPECT_CALL(factory_, CreateObjectPolicy(_))
        .WillRepeatedly(InvokeWithoutArgs(this, &TestObject::GetPolicy));
    object_.reset(new ObjectImpl(&factory_));
  }

 protected:
  ObjectPolicyMock* CreatePolicy() {
    ObjectPolicyMock* policy = new ObjectPolicyMock();
    EXPECT_CALL(*policy, Init(_)).Times(AnyNumber());
    EXPECT_CALL(*policy, IsReadAllowed(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*policy, IsModifyAllowed(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*policy, IsObjectComplete()).WillRepeatedly(Return(true));
    EXPECT_CALL(*policy, SetDefaultAttributes()).Times(AnyNumber());
    return policy;
  }
  ObjectPolicy* GetPolicy() {
    policy_ = scoped_policy_.release();
    scoped_policy_.reset(CreatePolicy());
    next_policy_ = scoped_policy_.get();
    return policy_;
  }
  ChapsFactoryMock factory_;
  ObjectPolicyMock* policy_;       // The policy in use (if any).
  ObjectPolicyMock* next_policy_;  // The policy to be used next.
  // Owns next_policy_ until used.
  std::unique_ptr<ObjectPolicyMock> scoped_policy_;
  std::unique_ptr<ObjectImpl> object_;
};

// Test that the Object class asserts when ChapsFactory fails.
TEST(DeathTest, FactoryFailure) {
  ChapsFactoryMock factory;
  ObjectPolicy* null_policy = NULL;
  EXPECT_CALL(factory, CreateObjectPolicy(1))
      .WillRepeatedly(Return(null_policy));
  ObjectImpl obj(&factory);
  obj.SetAttributeInt(CKA_CLASS, 1);
  EXPECT_DEATH_IF_SUPPORTED(obj.FinalizeNewObject(), "Check failed");
}

// Test object lifecycle management.
TEST_F(TestObject, GetStage) {
  EXPECT_EQ(kCreate, object_->GetStage());
  ObjectImpl object2(&factory_);
  object2.SetAttributeInt(CKA_CLASS, CKO_PUBLIC_KEY);
  EXPECT_EQ(CKR_OK, object_->Copy(&object2));
  EXPECT_EQ(kCopy, object_->GetStage());
  EXPECT_EQ(CKR_OK, object_->FinalizeNewObject());
  EXPECT_EQ(kModify, object_->GetStage());
}

// Perform a sanity check for object size.
TEST_F(TestObject, GetSize) {
  EXPECT_EQ(0, object_->GetSize());
  object_->SetAttributeString(1, string(20, 'a'));
  EXPECT_LT(20, object_->GetSize());
}

// Test the convenience methods for common attributes.
TEST_F(TestObject, BuiltInAttributes) {
  object_->SetAttributeInt(CKA_CLASS, CKO_PUBLIC_KEY);
  object_->SetAttributeBool(CKA_TOKEN, true);
  object_->SetAttributeBool(CKA_MODIFIABLE, true);
  object_->SetAttributeBool(CKA_PRIVATE, false);
  EXPECT_EQ(CKO_PUBLIC_KEY, object_->GetObjectClass());
  EXPECT_TRUE(object_->IsTokenObject());
  EXPECT_TRUE(object_->IsModifiable());
  EXPECT_FALSE(object_->IsPrivate());
}

// Test basic consistency for attribute manipulation.
TEST_F(TestObject, AttributeConsistency) {
  // [G|S]etAttributeInt
  EXPECT_FALSE(object_->IsAttributePresent(1));
  EXPECT_EQ(0, object_->GetAttributeInt(1, 0));
  object_->SetAttributeInt(1, 2);
  EXPECT_TRUE(object_->IsAttributePresent(1));
  EXPECT_EQ(2, object_->GetAttributeInt(1, 0));
  object_->SetAttributeString(1, string(1, 0xA));
  EXPECT_EQ(0xA, object_->GetAttributeInt(1, 0));
  object_->SetAttributeString(1, string(2, 0xA));
  EXPECT_EQ(0xA0A, object_->GetAttributeInt(1, 0));
  object_->SetAttributeString(1, string(3, 0xA));
  EXPECT_EQ(0, object_->GetAttributeInt(1, 0));
  object_->SetAttributeString(1, string(4, 0xA));
  EXPECT_EQ(0xA0A0A0A, object_->GetAttributeInt(1, 0));
  // [G|S]etAttributeBool
  EXPECT_FALSE(object_->IsAttributePresent(2));
  EXPECT_FALSE(object_->GetAttributeBool(2, false));
  object_->SetAttributeBool(2, true);
  EXPECT_TRUE(object_->IsAttributePresent(2));
  EXPECT_TRUE(object_->GetAttributeBool(2, false));
  // [G|S]etAttributeString
  EXPECT_FALSE(object_->IsAttributePresent(3));
  EXPECT_EQ("", object_->GetAttributeString(3));
  object_->SetAttributeString(3, "test");
  EXPECT_TRUE(object_->IsAttributePresent(3));
  EXPECT_EQ("test", object_->GetAttributeString(3));
  // RemoveAttribute
  object_->RemoveAttribute(3);
  EXPECT_FALSE(object_->IsAttributePresent(3));
  // [G|S]etAttributes
  CK_ULONG val = 0x1234;
  CK_ATTRIBUTE templ[] = {{1, &val, sizeof(CK_ULONG)}};
  EXPECT_EQ(CKR_OK, object_->SetAttributes(templ, 1));
  EXPECT_EQ(0x1234, object_->GetAttributeInt(1, 0));
  CK_ULONG val2 = 0;
  CK_ATTRIBUTE templ2[] = {{1, &val2, 17}};
  EXPECT_EQ(CKR_OK, object_->GetAttributes(templ2, 1));
  EXPECT_EQ(sizeof(CK_ULONG), templ2[0].ulValueLen);
  EXPECT_EQ(0x1234, val2);
}

// Test object policy assignment and validation when finalizing.
TEST_F(TestObject, FinalizeNewObject) {
  // Finalize before setting object class.
  EXPECT_EQ(CKR_TEMPLATE_INCOMPLETE, object_->FinalizeNewObject());
  // Finalize after setting read-only attribute.
  EXPECT_CALL(*next_policy_, IsModifyAllowed(1, "test"))
      .WillRepeatedly(Return(false));
  CK_OBJECT_CLASS classval = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE attr[] = {{CKA_CLASS, &classval, sizeof(classval)},
                         {1, const_cast<char*>("test"), 4},
                         {2, const_cast<char*>("test2"), 5}};
  object_->SetAttributes(attr, 3);
  EXPECT_EQ(CKR_ATTRIBUTE_READ_ONLY, object_->FinalizeNewObject());
  // Finalize before object is complete.
  EXPECT_CALL(*next_policy_, IsModifyAllowed(1, "test"))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*next_policy_, IsObjectComplete())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  CK_ATTRIBUTE attr2[] = {{1, const_cast<char*>("test3"), 5}};
  object_->SetAttributes(attr2, 1);
  EXPECT_EQ(CKR_TEMPLATE_INCOMPLETE, object_->FinalizeNewObject());
  EXPECT_EQ(CKR_OK, object_->FinalizeNewObject());
}

// Test GetAttributes in more detail.
TEST_F(TestObject, GetAttributes) {
  EXPECT_CALL(*next_policy_, IsReadAllowed(CKA_CLASS))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  // Attempt to read an attribute before it has been set.
  CK_ATTRIBUTE templ[] = {{CKA_CLASS, NULL, 0}};
  EXPECT_EQ(CKR_ATTRIBUTE_TYPE_INVALID, object_->GetAttributes(templ, 1));
  EXPECT_EQ(-1, templ[0].ulValueLen);
  // Attempt to read a read-only attribute (IsReadAllowed returns false once).
  object_->SetAttributeInt(CKA_CLASS, CKO_PUBLIC_KEY);
  object_->FinalizeNewObject();
  EXPECT_EQ(CKR_ATTRIBUTE_SENSITIVE, object_->GetAttributes(templ, 1));
  EXPECT_EQ(-1, templ[0].ulValueLen);
  // Read an attribute's length (pValue == NULL) successfully.
  EXPECT_EQ(CKR_OK, object_->GetAttributes(templ, 1));
  EXPECT_EQ(sizeof(CK_ULONG), templ[0].ulValueLen);
  // Read an attribute with not enough buffer.
  CK_ULONG val = 0;
  templ[0].ulValueLen = 1;
  templ[0].pValue = &val;
  EXPECT_EQ(CKR_BUFFER_TOO_SMALL, object_->GetAttributes(templ, 1));
  EXPECT_EQ(-1, templ[0].ulValueLen);
  // Read an attribute successfully.
  templ[0].ulValueLen = sizeof(CK_ULONG);
  EXPECT_EQ(CKR_OK, object_->GetAttributes(templ, 1));
  EXPECT_EQ(CKO_PUBLIC_KEY, val);
}

// Test SetAttributes in more detail.
TEST_F(TestObject, SetAttributes) {
  CK_ULONG val = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE templ[] = {{CKA_CLASS, &val, sizeof(CK_ULONG)}};
  // Modify attributes before finalizing (object creation stage).
  EXPECT_EQ(CKR_OK, object_->SetAttributes(templ, 1));
  EXPECT_EQ(CKR_OK, object_->FinalizeNewObject());
  // Attempt to modify read-only attributes.
  EXPECT_CALL(*policy_, IsModifyAllowed(_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_EQ(CKR_ATTRIBUTE_READ_ONLY, object_->SetAttributes(templ, 1));
  // Modify attributes successfully.
  EXPECT_EQ(CKR_OK, object_->SetAttributes(templ, 1));
  EXPECT_EQ(CKO_PUBLIC_KEY, object_->GetObjectClass());
  // Attempt to set with invalid length; specifically, with the length value
  // that is used to indicate an error on C_GetAttributeValue (so if an
  // application re-used the CK_ATTRIBUTE template without checking/updating
  // the length, this is what arrives).
  CK_BYTE label[] = "label";
  CK_ATTRIBUTE invalid[] = {{CKA_LABEL, &label, (CK_ULONG)-1}};
  EXPECT_EQ(CKR_ATTRIBUTE_VALUE_INVALID, object_->SetAttributes(invalid, 1));
}

}  // namespace chaps
