// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_STORE_FAKE_H_
#define CHAPS_OBJECT_STORE_FAKE_H_

#include "chaps/object_store.h"

#include <map>
#include <string>

namespace chaps {

// A fake object store implementation which just stores blobs in memory.
class ObjectStoreFake : public ObjectStore {
 public:
  ObjectStoreFake() : last_handle_(0) {}
  ~ObjectStoreFake() override {}
  bool GetInternalBlob(int blob_id, std::string* blob) override {
    if (internal_blobs_.find(blob_id) == internal_blobs_.end())
      return false;
    *blob = internal_blobs_[blob_id];
    return true;
  }
  bool SetInternalBlob(int blob_id, const std::string& blob) override {
    internal_blobs_[blob_id] = blob;
    return true;
  }
  bool SetEncryptionKey(const brillo::SecureBlob& key) override { return true; }
  bool InsertObjectBlob(const ObjectBlob& blob, int* handle) override {
    *handle = ++last_handle_;
    object_blobs_[*handle] = blob;
    return true;
  }
  bool DeleteObjectBlob(int handle) override {
    object_blobs_.erase(handle);
    return true;
  }
  bool DeleteAllObjectBlobs() override {
    object_blobs_.clear();
    return true;
  }
  bool UpdateObjectBlob(int handle, const ObjectBlob& blob) override {
    object_blobs_[handle] = blob;
    return true;
  }
  bool LoadPublicObjectBlobs(std::map<int, ObjectBlob>* blobs) override {
    *blobs = object_blobs_;
    return true;
  }
  bool LoadPrivateObjectBlobs(std::map<int, ObjectBlob>* blobs) override {
    return true;
  }

 private:
  int last_handle_;
  std::map<int, std::string> internal_blobs_;
  std::map<int, ObjectBlob> object_blobs_;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_STORE_FAKE_H_
