// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_POOL_IMPL_H_
#define CHAPS_OBJECT_POOL_IMPL_H_

#include "chaps/object_pool.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "chaps/object_store.h"

namespace chaps {

class ChapsFactory;
class HandleGenerator;
class SlotPolicy;

// Key: Object handle.
// Value: Object shared pointer.
typedef std::map<int, std::shared_ptr<const Object>> HandleObjectMap;
typedef std::set<const Object*> ObjectSet;

class ObjectPoolImpl : public ObjectPool {
 public:
  // The 'factory', 'handle_generator' and 'slot_policy' pointers are not owned
  // by the object pool. They must remain valid for the entire life of the
  // ObjectPoolImpl instance. If the object pool is not persistent, 'store'
  // should be NULL. Otherwise, 'store' will be owned by (and later deleted by)
  // the object pool.
  // If 'slot_policy' is nullptr, it means that all objects are allowed.
  ObjectPoolImpl(ChapsFactory* factory,
                 HandleGenerator* handle_generator,
                 SlotPolicy* slot_policy,
                 ObjectStore* store);
  ObjectPoolImpl(const ObjectPoolImpl&) = delete;
  ObjectPoolImpl& operator=(const ObjectPoolImpl&) = delete;

  ~ObjectPoolImpl() override;
  virtual bool Init();
  bool GetInternalBlob(int blob_id, std::string* blob) override;
  bool SetInternalBlob(int blob_id, const std::string& blob) override;
  bool SetEncryptionKey(const brillo::SecureBlob& key) override;
  Result Insert(Object* object) override;
  Result Import(Object* object) override;
  Result Delete(const Object* object) override;
  Result DeleteAll() override;
  Result Find(const Object* search_template,
              std::vector<const Object*>* matching_objects) override;
  Result FindByHandle(int handle, const Object** object) override;
  Object* GetModifiableObject(const Object* object) override;
  Result Flush(const Object* object) override;
  bool IsPrivateLoaded() override;

 private:
  Result AddObject(Object* object, bool from_external_source);
  // An object matches a template when it holds values for all template
  // attributes and those values match the template values. This function
  // returns true if the given object matches the given template.
  bool Matches(const Object* object_template, const Object* object);
  bool Parse(const ObjectBlob& object_blob, Object* object);
  bool Serialize(const Object* object, ObjectBlob* serialized);
  bool LoadBlobs(const std::map<int, ObjectBlob>& object_blobs);
  bool LoadPublicObjects();
  bool LoadPrivateObjects();

  // Allows us to quickly check whether an object exists in the pool.
  ObjectSet objects_;
  HandleObjectMap handle_object_map_;
  ChapsFactory* factory_;
  HandleGenerator* handle_generator_;
  SlotPolicy* slot_policy_;
  std::unique_ptr<ObjectStore> store_;
  bool is_private_loaded_;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_POOL_IMPL_H_
