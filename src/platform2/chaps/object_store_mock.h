// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_STORE_MOCK_H_
#define CHAPS_OBJECT_STORE_MOCK_H_

#include "chaps/object_store.h"

#include <map>
#include <string>

#include <gmock/gmock.h>

namespace chaps {

class ObjectStoreMock : public ObjectStore {
 public:
  ObjectStoreMock();
  ~ObjectStoreMock() override;
  MOCK_METHOD2(GetInternalBlob, bool(int blob_id, std::string* blob));
  MOCK_METHOD2(SetInternalBlob, bool(int blob_id, const std::string& blob));
  MOCK_METHOD1(SetEncryptionKey, bool(const brillo::SecureBlob& key));
  MOCK_METHOD2(InsertObjectBlob, bool(const ObjectBlob& blob, int* blob_id));
  MOCK_METHOD1(DeleteObjectBlob, bool(int blob_id));
  MOCK_METHOD0(DeleteAllObjectBlobs, bool());
  MOCK_METHOD2(UpdateObjectBlob, bool(int blob_id, const ObjectBlob& blob));
  MOCK_METHOD1(LoadPublicObjectBlobs, bool(std::map<int, ObjectBlob>* blobs));
  MOCK_METHOD1(LoadPrivateObjectBlobs, bool(std::map<int, ObjectBlob>* blobs));
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_STORE_MOCK_H_
