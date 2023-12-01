// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_MOCK_H_
#define CHAPS_OBJECT_MOCK_H_

#include "chaps/object.h"

#include <string>

#include <base/notreached.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chaps/attributes.h"
#include "chaps/chaps_utility.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

class ObjectMock : public Object {
 public:
  ObjectMock();
  ObjectMock(const ObjectMock&) = delete;
  ObjectMock& operator=(const ObjectMock&) = delete;

  ~ObjectMock() override;
  MOCK_CONST_METHOD0(GetStage, ObjectStage());
  MOCK_CONST_METHOD0(GetObjectClass, CK_OBJECT_CLASS());
  MOCK_CONST_METHOD0(IsTokenObject, bool());
  MOCK_CONST_METHOD0(IsModifiable, bool());
  MOCK_CONST_METHOD0(IsPrivate, bool());
  MOCK_CONST_METHOD0(GetSize, int());
  MOCK_METHOD0(FinalizeNewObject, CK_RV());
  MOCK_METHOD0(FinalizeCopyObject, CK_RV());
  MOCK_METHOD1(Copy, CK_RV(const Object*));
  MOCK_CONST_METHOD2(GetAttributes, CK_RV(CK_ATTRIBUTE_PTR, int));
  MOCK_METHOD2(SetAttributes, CK_RV(const CK_ATTRIBUTE_PTR, int));
  MOCK_CONST_METHOD1(IsAttributePresent, bool(CK_ATTRIBUTE_TYPE));
  MOCK_CONST_METHOD2(GetAttributeBool, bool(CK_ATTRIBUTE_TYPE, bool));
  MOCK_METHOD2(SetAttributeBool, void(CK_ATTRIBUTE_TYPE, bool));
  MOCK_CONST_METHOD2(GetAttributeInt, CK_ULONG(CK_ATTRIBUTE_TYPE, CK_ULONG));
  MOCK_METHOD2(SetAttributeInt, void(CK_ATTRIBUTE_TYPE, CK_ULONG));
  MOCK_CONST_METHOD1(GetAttributeString, std::string(CK_ATTRIBUTE_TYPE));
  MOCK_METHOD2(SetAttributeString, void(CK_ATTRIBUTE_TYPE, const std::string&));
  MOCK_METHOD1(RemoveAttribute, void(CK_ATTRIBUTE_TYPE));
  MOCK_CONST_METHOD0(GetAttributeMap, const AttributeMap*());
  MOCK_METHOD0(OnLoad, bool());
  MOCK_CONST_METHOD0(handle, int());
  MOCK_METHOD1(set_handle, void(int));
  MOCK_CONST_METHOD0(store_id, int());
  MOCK_METHOD1(set_store_id, void(int));

  void SetupFake() {
    handle_ = 0;
    store_id_ = 0;
    ON_CALL(*this, GetObjectClass())
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeGetObjectClass));
    ON_CALL(*this, IsTokenObject())
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeIsTokenObject));
    ON_CALL(*this, IsPrivate())
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeIsPrivate));
    ON_CALL(*this, SetAttributes(testing::_, testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeSetAttributes));
    ON_CALL(*this, IsAttributePresent(testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectMock::FakeIsAttributePresent));
    ON_CALL(*this, GetAttributeBool(testing::_, testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectMock::FakeGetAttributeBool));
    ON_CALL(*this, GetAttributeString(testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectMock::FakeGetAttributeString));
    ON_CALL(*this, GetAttributeInt(testing::_, testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeGetAttributeInt));
    ON_CALL(*this, SetAttributeBool(testing::_, testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectMock::FakeSetAttributeBool));
    ON_CALL(*this, SetAttributeInt(testing::_, testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeSetAttributeInt));
    ON_CALL(*this, SetAttributeString(testing::_, testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectMock::FakeSetAttributeString));
    ON_CALL(*this, RemoveAttribute(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeRemoveAttribute));
    ON_CALL(*this, GetAttributeMap())
        .WillByDefault(testing::Return(&attributes_));
    ON_CALL(*this, OnLoad()).WillByDefault(testing::Return(true));
    ON_CALL(*this, set_handle(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeSetHandle));
    ON_CALL(*this, set_store_id(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeSetStoreID));
    ON_CALL(*this, handle())
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeGetHandle));
    ON_CALL(*this, store_id())
        .WillByDefault(testing::Invoke(this, &ObjectMock::FakeGetStoreID));
  }

 private:
  AttributeMap attributes_;
  int handle_;
  int store_id_;

  CK_OBJECT_CLASS FakeGetObjectClass() {
    return FakeGetAttributeInt(CKA_CLASS, 0);
  }
  bool FakeIsTokenObject() { return FakeGetAttributeBool(CKA_TOKEN, true); }
  bool FakeIsPrivate() { return FakeGetAttributeBool(CKA_PRIVATE, true); }
  bool FakeIsAttributePresent(CK_ATTRIBUTE_TYPE type) {
    return (attributes_.find(type) != attributes_.end());
  }
  bool FakeSetAttributes(const CK_ATTRIBUTE_PTR attr, int num_attr) {
    for (int i = 0; i < num_attr; ++i) {
      attributes_[attr[i].type] = std::string(
          reinterpret_cast<const char*>(attr[i].pValue), attr[i].ulValueLen);
    }
    return CKR_OK;
  }
  bool FakeGetAttributeBool(CK_ATTRIBUTE_TYPE type, bool default_value) {
    std::string s = FakeGetAttributeString(type);
    if (s.empty())
      return default_value;
    return (0 != s[0]);
  }
  CK_ULONG FakeGetAttributeInt(CK_ATTRIBUTE_TYPE type, CK_ULONG default_value) {
    std::string s = FakeGetAttributeString(type);
    if (s.empty())
      return default_value;
    switch (s.length()) {
      case 1:
        return ExtractFromByteString<uint8_t>(s);
      case 2:
        return ExtractFromByteString<uint16_t>(s);
      case 4:
        return ExtractFromByteString<uint32_t>(s);
      case 8:
        return ExtractFromByteString<uint64_t>(s);
      default:
        NOTREACHED();
    }
    return default_value;
  }
  std::string FakeGetAttributeString(CK_ATTRIBUTE_TYPE type) {
    std::string s;
    AttributeMap::iterator it = attributes_.find(type);
    if (it != attributes_.end())
      s = it->second;
    return s;
  }
  void FakeSetAttributeBool(CK_ATTRIBUTE_TYPE type, bool value) {
    attributes_[type] = std::string(1, value ? 1 : 0);
  }
  void FakeSetAttributeInt(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    attributes_[type] =
        std::string(reinterpret_cast<const char*>(&value), sizeof(value));
  }
  void FakeSetAttributeString(CK_ATTRIBUTE_TYPE type,
                              const std::string& value) {
    attributes_[type] = value;
  }
  void FakeRemoveAttribute(CK_ATTRIBUTE_TYPE type) { attributes_.erase(type); }

  void FakeSetHandle(int handle) { handle_ = handle; }

  void FakeSetStoreID(int id) { store_id_ = id; }

  int FakeGetHandle() { return handle_; }

  int FakeGetStoreID() { return store_id_; }
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_MOCK_H_
