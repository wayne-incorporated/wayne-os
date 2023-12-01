// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_pool_impl.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/chaps_factory_mock.h"
#include "chaps/handle_generator_mock.h"
#include "chaps/object_mock.h"
#include "chaps/object_store_mock.h"
#include "chaps/proto_bindings/attributes.pb.h"
#include "chaps/slot_policy_mock.h"

using brillo::SecureBlob;
using std::map;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::SetArgPointee;
using Result = chaps::ObjectPool::Result;

namespace chaps {

namespace {

ObjectMock* CreateObjectMock() {
  ObjectMock* o = new ObjectMock();
  o->SetupFake();
  EXPECT_CALL(*o, GetObjectClass()).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributes(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, FinalizeNewObject()).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(*o, Copy(_)).WillRepeatedly(Return(CKR_OK));
  EXPECT_CALL(*o, IsTokenObject()).Times(AnyNumber());
  EXPECT_CALL(*o, IsPrivate()).Times(AnyNumber());
  EXPECT_CALL(*o, IsAttributePresent(_)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeString(_)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeInt(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeBool(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeString(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeInt(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, SetAttributeBool(_, _)).Times(AnyNumber());
  EXPECT_CALL(*o, GetAttributeMap()).Times(AnyNumber());
  EXPECT_CALL(*o, set_handle(_)).Times(AnyNumber());
  EXPECT_CALL(*o, set_store_id(_)).Times(AnyNumber());
  EXPECT_CALL(*o, handle()).Times(AnyNumber());
  EXPECT_CALL(*o, store_id()).Times(AnyNumber());
  return o;
}

Object* CreateObjectMockWithClass(CK_OBJECT_CLASS object_class) {
  ObjectMock* object = CreateObjectMock();
  EXPECT_CALL(*object, GetObjectClass())
      .Times(AnyNumber())
      .WillRepeatedly(Return(object_class));
  return object;
}

int CreateHandle() {
  static int last_handle = 0;
  return ++last_handle;
}

}  // namespace

// A test fixture for object pools.
class TestObjectPool : public ::testing::Test {
 public:
  TestObjectPool() {
    // Setup the factory to return functional fake objects.
    EXPECT_CALL(factory_, CreateObject())
        .WillRepeatedly(Invoke(CreateObjectMock));
    EXPECT_CALL(handle_generator_, CreateHandle())
        .WillRepeatedly(Invoke(CreateHandle));
    // Setup the slot policy to allow all objects.
    EXPECT_CALL(slot_policy_, IsObjectClassAllowedForNewObject(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(slot_policy_, IsObjectClassAllowedForImportedObject(_))
        .WillRepeatedly(Return(true));
    // Create object pools to test with.
    store_ = new ObjectStoreMock();
    pool_.reset(new ObjectPoolImpl(&factory_, &handle_generator_, &slot_policy_,
                                   store_));
    pool2_.reset(
        new ObjectPoolImpl(&factory_, &handle_generator_, &slot_policy_, NULL));
  }

  // Initialize and load private objects.
  void PreparePools() {
    EXPECT_CALL(*store_, SetEncryptionKey(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*store_, LoadPublicObjectBlobs(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*store_, LoadPrivateObjectBlobs(_))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*store_, GetInternalBlob(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*store_, SetInternalBlob(_, _)).WillRepeatedly(Return(true));

    EXPECT_TRUE(pool_->Init());
    EXPECT_TRUE(pool_->SetEncryptionKey(SecureBlob()));
    EXPECT_TRUE(pool_->IsPrivateLoaded());

    EXPECT_TRUE(pool2_->Init());
    EXPECT_TRUE(pool2_->IsPrivateLoaded());

    testing::Mock::VerifyAndClearExpectations(store_);
  }

  ChapsFactoryMock factory_;
  ObjectStoreMock* store_;
  HandleGeneratorMock handle_generator_;
  SlotPolicyMock slot_policy_;

  std::unique_ptr<ObjectPoolImpl> pool_;
  std::unique_ptr<ObjectPoolImpl> pool2_;
};

// Test object pool initialization when using an object store.
TEST_F(TestObjectPool, Init) {
  // Create some fake persistent objects for the mock store to return.
  map<int, ObjectBlob> persistent_objects;
  AttributeList l;
  Attribute* a = l.add_attribute();
  a->set_type(CKA_ID);
  a->set_value("value");
  string s;
  l.SerializeToString(&s);
  persistent_objects[1].blob = s;
  persistent_objects[1].is_private = true;
  persistent_objects[2].blob = "not_valid_protobuf";
  persistent_objects[2].is_private = false;
  string tmp(32, 'A');
  SecureBlob key(tmp.begin(), tmp.end());
  EXPECT_CALL(*store_, GetInternalBlob(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(*store_, SetInternalBlob(_, _)).WillRepeatedly(Return(true));
  EXPECT_CALL(*store_, SetEncryptionKey(key))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*store_, LoadPublicObjectBlobs(_))
      .WillOnce(Return(false))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(persistent_objects), Return(true)));
  EXPECT_CALL(*store_, LoadPrivateObjectBlobs(_))
      .WillOnce(Return(false))
      .WillRepeatedly(
          DoAll(SetArgPointee<0>(persistent_objects), Return(true)));
  // Loading of public objects happens when the pool is initialized.
  EXPECT_TRUE(pool2_->Init());
  EXPECT_FALSE(pool_->Init());
  EXPECT_TRUE(pool_->Init());
  EXPECT_TRUE(pool_->Init());
  // Loading of private objects happens when the encryption key is set.
  EXPECT_FALSE(pool_->IsPrivateLoaded());
  EXPECT_TRUE(pool2_->SetEncryptionKey(key));
  EXPECT_FALSE(pool_->SetEncryptionKey(key));
  EXPECT_TRUE(pool_->SetEncryptionKey(key));
  EXPECT_TRUE(pool_->SetEncryptionKey(key));
  EXPECT_TRUE(pool_->IsPrivateLoaded());
  vector<const Object*> v;
  std::unique_ptr<Object> find_all(CreateObjectMock());
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  ASSERT_EQ(3, v.size());
  EXPECT_TRUE(v[0]->GetAttributeString(CKA_ID) == string("value"));
  EXPECT_TRUE(v[1]->GetAttributeString(CKA_ID) == string("value"));
  EXPECT_TRUE(v[2]->GetAttributeString(CKA_ID) == string("value"));
}

// Test the methods that should just pass through to the object store.
TEST_F(TestObjectPool, StorePassThrough) {
  string s("test");
  SecureBlob blob("test");
  EXPECT_CALL(*store_, GetInternalBlob(1, _))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_CALL(*store_, SetInternalBlob(1, s))
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_CALL(*store_, LoadPublicObjectBlobs(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*store_, LoadPrivateObjectBlobs(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*store_, SetEncryptionKey(blob))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_FALSE(pool2_->GetInternalBlob(1, &s));
  EXPECT_FALSE(pool2_->SetInternalBlob(1, s));
  EXPECT_TRUE(pool2_->SetEncryptionKey(blob));
  EXPECT_FALSE(pool_->GetInternalBlob(1, &s));
  EXPECT_TRUE(pool_->GetInternalBlob(1, &s));
  EXPECT_FALSE(pool_->SetInternalBlob(1, s));
  EXPECT_TRUE(pool_->SetInternalBlob(1, s));
  EXPECT_FALSE(pool_->SetEncryptionKey(blob));
  EXPECT_TRUE(pool_->SetEncryptionKey(blob));
}

// Test basic object management operations.
TEST_F(TestObjectPool, InsertFindUpdateDelete) {
  PreparePools();
  EXPECT_CALL(*store_, InsertObjectBlob(_, _))
      .WillOnce(Return(false))
      .WillRepeatedly(DoAll(SetArgPointee<1>(3), Return(true)));
  EXPECT_CALL(*store_, UpdateObjectBlob(3, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*store_, DeleteObjectBlob(3))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  vector<const Object*> v;
  std::unique_ptr<Object> find_all(CreateObjectMock());
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  ASSERT_EQ(2, v.size());
  Object* o = pool2_->GetModifiableObject(v[0]);
  EXPECT_EQ(Result::Success, pool2_->Flush(o));
  EXPECT_EQ(Result::Success, pool2_->Delete(v[0]));
  EXPECT_EQ(Result::Success, pool2_->Delete(v[1]));
  v.clear();
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
  // Now with the persistent pool.
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
  Object* tmp = CreateObjectMock();
  EXPECT_NE(Result::Success, pool_->Insert(tmp));
  EXPECT_EQ(Result::Success, pool_->Insert(tmp));
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  ASSERT_EQ(1, v.size());
  o = pool_->GetModifiableObject(v[0]);
  EXPECT_NE(Result::Success, pool_->Flush(o));
  EXPECT_EQ(Result::Success, pool_->Flush(o));
  EXPECT_NE(Result::Success, pool_->Delete(v[0]));
  EXPECT_EQ(Result::Success, pool_->Delete(v[0]));
  v.clear();
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
}

// Test handling of an invalid object pointer.
TEST_F(TestObjectPool, UnknownObject) {
  PreparePools();
  std::unique_ptr<Object> o(CreateObjectMock());
  EXPECT_NE(Result::Success, pool_->Flush(o.get()));
  EXPECT_NE(Result::Success, pool_->Delete(o.get()));
  EXPECT_NE(Result::Success, pool2_->Flush(o.get()));
  EXPECT_NE(Result::Success, pool2_->Delete(o.get()));
}

// Test multiple insertion of the same object pointer.
TEST_F(TestObjectPool, DuplicateObject) {
  PreparePools();
  Object* o = CreateObjectMock();
  EXPECT_CALL(*store_, InsertObjectBlob(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(3), Return(true)));
  EXPECT_EQ(Result::Success, pool_->Insert(o));
  EXPECT_NE(Result::Success, pool_->Insert(o));
  Object* o2 = CreateObjectMock();
  EXPECT_EQ(Result::Success, pool2_->Insert(o2));
  EXPECT_NE(Result::Success, pool2_->Insert(o2));
}

TEST_F(TestObjectPool, DeleteAll) {
  PreparePools();
  EXPECT_CALL(*store_, InsertObjectBlob(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(3), Return(true)));
  EXPECT_CALL(*store_, DeleteAllObjectBlobs())
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  vector<const Object*> v;
  std::unique_ptr<Object> find_all(CreateObjectMock());
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  EXPECT_EQ(3, v.size());
  // Test the store failure is passed back but cached objects are still deleted.
  EXPECT_NE(Result::Success, pool_->DeleteAll());
  v.clear();
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool_->Insert(CreateObjectMock()));
  // Test with store success.
  EXPECT_EQ(Result::Success, pool_->DeleteAll());
  v.clear();
  EXPECT_EQ(Result::Success, pool_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
  // Test with session pool.
  EXPECT_CALL(*store_, InsertObjectBlob(_, _)).Times(0);
  EXPECT_CALL(*store_, DeleteAllObjectBlobs()).Times(0);
  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));
  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));
  v.clear();
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  EXPECT_EQ(3, v.size());
  EXPECT_EQ(Result::Success, pool2_->DeleteAll());
  v.clear();
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
}

// Test pool with unloaded private objects
TEST_F(TestObjectPool, UnloadedPrivateObjects) {
  EXPECT_FALSE(pool_->IsPrivateLoaded());

  // ObjectPool::Find behavior.
  std::unique_ptr<Object> public_template(CreateObjectMock());
  public_template->SetAttributeBool(CKA_PRIVATE, false);
  std::unique_ptr<Object> private_template(CreateObjectMock());
  private_template->SetAttributeBool(CKA_PRIVATE, true);
  std::unique_ptr<Object> private_keys_template(CreateObjectMock());
  private_keys_template->SetAttributeInt(CKA_CLASS, CKO_PRIVATE_KEY);

  vector<const Object*> v;
  EXPECT_EQ(Result::WaitForPrivateObjects,
            pool_->Find(private_template.get(), &v));
  EXPECT_EQ(Result::WaitForPrivateObjects,
            pool_->Find(private_keys_template.get(), &v));
  EXPECT_EQ(Result::Success, pool_->Find(public_template.get(), &v));

  // ObjectPool::Insert behavior.
  std::unique_ptr<Object> default_obj(CreateObjectMock());
  std::unique_ptr<Object> private_obj(CreateObjectMock());
  private_obj->SetAttributeBool(CKA_PRIVATE, true);
  EXPECT_EQ(Result::WaitForPrivateObjects, pool_->Insert(private_obj.get()));
  EXPECT_EQ(Result::WaitForPrivateObjects, pool_->Insert(default_obj.get()));

  Object* public_obj = CreateObjectMock();
  public_obj->SetAttributeBool(CKA_PRIVATE, false);
  EXPECT_CALL(*store_, InsertObjectBlob(_, _))
      .WillRepeatedly(DoAll(SetArgPointee<1>(117), Return(true)));
  EXPECT_EQ(Result::Success, pool_->Insert(public_obj));
}

// Test that Insert() respects the slot policy for new objects.
TEST_F(TestObjectPool, InsertRespectsSlotPolicy) {
  EXPECT_CALL(slot_policy_, IsObjectClassAllowedForNewObject(CKO_PRIVATE_KEY))
      .WillOnce(Return(false));
  PreparePools();

  Object* object = CreateObjectMockWithClass(CKO_PRIVATE_KEY);
  ASSERT_EQ(Result::Failure, pool2_->Insert(object));
  // ObjectPool::Insert does not take ownership of |object| on failure.
  delete object;

  std::unique_ptr<Object> find_all(CreateObjectMock());
  vector<const Object*> v;
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  EXPECT_EQ(0, v.size());
}

TEST_F(TestObjectPool, NullSlotPolicyMeansAcceptEverything) {
  std::unique_ptr<ObjectPool> pool_without_slot_policy =
      std::make_unique<ObjectPoolImpl>(&factory_, &handle_generator_, nullptr,
                                       nullptr);
  EXPECT_TRUE(pool2_->Init());
  EXPECT_TRUE(pool2_->IsPrivateLoaded());

  EXPECT_EQ(Result::Success, pool2_->Insert(CreateObjectMock()));

  std::unique_ptr<Object> find_all(CreateObjectMock());
  vector<const Object*> v;
  EXPECT_EQ(Result::Success, pool2_->Find(find_all.get(), &v));
  ASSERT_EQ(1, v.size());
}

}  // namespace chaps
