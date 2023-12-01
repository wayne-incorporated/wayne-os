// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POOL_MOCK_H_
#define CHAPS_OBJECT_POOL_MOCK_H_

#include "chaps/object_pool.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "chaps/object.h"

namespace chaps {

class ObjectPoolMock : public ObjectPool {
 public:
  ObjectPoolMock();
  ObjectPoolMock(const ObjectPoolMock&) = delete;
  ObjectPoolMock& operator=(const ObjectPoolMock&) = delete;

  ~ObjectPoolMock() override;

  MOCK_METHOD2(GetInternalBlob, bool(int, std::string*));
  MOCK_METHOD2(SetInternalBlob, bool(int, const std::string&));
  MOCK_METHOD1(SetEncryptionKey, bool(const brillo::SecureBlob&));
  MOCK_METHOD1(Insert, ObjectPool::Result(Object*));
  MOCK_METHOD1(Import, ObjectPool::Result(Object*));
  MOCK_METHOD1(Delete, ObjectPool::Result(const Object*));
  MOCK_METHOD0(DeleteAll, ObjectPool::Result());
  MOCK_METHOD2(Find,
               ObjectPool::Result(const Object*, std::vector<const Object*>*));
  MOCK_METHOD2(FindByHandle, ObjectPool::Result(int, const Object**));
  MOCK_METHOD1(GetModifiableObject, Object*(const Object*));
  MOCK_METHOD1(Flush, ObjectPool::Result(const Object*));
  MOCK_METHOD0(IsPrivateLoaded, bool());
  void SetupFake(int handle_base) {
    last_handle_ = handle_base;
    ON_CALL(*this, Insert(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectPoolMock::FakeInsert));
    ON_CALL(*this, Import(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectPoolMock::FakeInsert));
    ON_CALL(*this, Delete(testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectPoolMock::FakeDelete));
    ON_CALL(*this, Find(testing::_, testing::_))
        .WillByDefault(testing::Invoke(this, &ObjectPoolMock::FakeFind));
    ON_CALL(*this, FindByHandle(testing::_, testing::_))
        .WillByDefault(
            testing::Invoke(this, &ObjectPoolMock::FakeFindByHandle));
    ON_CALL(*this, IsPrivateLoaded()).WillByDefault(testing::Return(true));
  }

 private:
  ObjectPool::Result FakeInsert(Object* o) {
    v_.push_back(o);
    o->set_handle(++last_handle_);
    return ObjectPool::Result::Success;
  }
  ObjectPool::Result FakeDelete(const Object* o) {
    for (size_t i = 0; i < v_.size(); ++i) {
      if (o == v_[i]) {
        delete v_[i];
        v_.erase(v_.begin() + i);
        return ObjectPool::Result::Success;
      }
    }
    return ObjectPool::Result::Failure;
  }
  ObjectPool::Result FakeFind(const Object* o, std::vector<const Object*>* v) {
    for (size_t i = 0; i < v_.size(); ++i)
      v->push_back(v_[i]);
    return ObjectPool::Result::Success;
  }
  ObjectPool::Result FakeFindByHandle(int handle, const Object** o) {
    for (size_t i = 0; i < v_.size(); ++i) {
      if (handle == v_[i]->handle()) {
        *o = v_[i];
        return ObjectPool::Result::Success;
      }
    }
    return ObjectPool::Result::Failure;
  }
  std::vector<const Object*> v_;
  int last_handle_;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POOL_MOCK_H_
