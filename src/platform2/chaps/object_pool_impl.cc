// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/object_pool_impl.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>

#include "chaps/chaps.h"
#include "chaps/chaps_factory.h"
#include "chaps/chaps_utility.h"
#include "chaps/handle_generator.h"
#include "chaps/object.h"
#include "chaps/object_store.h"
#include "chaps/proto_bindings/attributes.pb.h"
#include "chaps/slot_policy.h"

using brillo::SecureBlob;
using std::map;
using std::shared_ptr;
using std::string;
using std::vector;
using Result = chaps::ObjectPool::Result;

namespace chaps {

ObjectPoolImpl::ObjectPoolImpl(ChapsFactory* factory,
                               HandleGenerator* handle_generator,
                               SlotPolicy* slot_policy,
                               ObjectStore* store)
    : factory_(factory),
      handle_generator_(handle_generator),
      slot_policy_(slot_policy),
      store_(store),
      is_private_loaded_(false) {}

ObjectPoolImpl::~ObjectPoolImpl() {}

bool ObjectPoolImpl::Init() {
  if (store_.get()) {
    if (!LoadPublicObjects())
      return false;
  } else {
    // There are no objects to load.
    is_private_loaded_ = true;
  }
  return true;
}

bool ObjectPoolImpl::GetInternalBlob(int blob_id, string* blob) {
  if (store_.get())
    return store_->GetInternalBlob(blob_id, blob);
  return false;
}

bool ObjectPoolImpl::SetInternalBlob(int blob_id, const string& blob) {
  if (store_.get())
    return store_->SetInternalBlob(blob_id, blob);
  return false;
}

bool ObjectPoolImpl::SetEncryptionKey(const SecureBlob& key) {
  if (key.empty())
    LOG(WARNING) << "WARNING: Private object services will not be available.";
  if (store_.get() && !key.empty()) {
    if (!store_->SetEncryptionKey(key))
      return false;
    // Once we have the encryption key we can load private objects.
    if (!LoadPrivateObjects())
      LOG(WARNING) << "Failed to load private objects.";
  }
  // Signal any callers waiting for private objects that they're ready.
  is_private_loaded_ = true;
  return true;
}

Result ObjectPoolImpl::Insert(Object* object) {
  // If it's a private object we need to wait until private objects have been
  // loaded.
  if (object->IsPrivate() && !is_private_loaded_) {
    return Result::WaitForPrivateObjects;
  }
  return AddObject(object, /*from_external_source=*/false);
}

Result ObjectPoolImpl::Import(Object* object) {
  return AddObject(object, /*from_external_source=*/true);
}

Result ObjectPoolImpl::AddObject(Object* object, bool from_external_source) {
  const CK_OBJECT_CLASS object_class = object->GetObjectClass();
  const bool allowed =
      !slot_policy_ ||
      (from_external_source
           ? slot_policy_->IsObjectClassAllowedForImportedObject(object_class)
           : slot_policy_->IsObjectClassAllowedForNewObject(object_class));
  if (!allowed) {
    return Result::Failure;
  }

  if (objects_.find(object) != objects_.end())
    return Result::Failure;
  if (store_.get()) {
    ObjectBlob serialized;
    if (!Serialize(object, &serialized))
      return Result::Failure;
    // Parsing the serialized blob will normalize the object attribute values.
    // e.g. If the caller specified 32-bits for a CK_ULONG on a 64-bit system,
    // the value will be resized correctly.
    if (!Parse(serialized, object))
      return Result::Failure;
    int store_id;
    if (!store_->InsertObjectBlob(serialized, &store_id))
      return Result::Failure;
    object->set_store_id(store_id);
  }
  object->set_handle(handle_generator_->CreateHandle());
  objects_.insert(object);
  handle_object_map_[object->handle()] = shared_ptr<const Object>(object);
  return Result::Success;
}

Result ObjectPoolImpl::Delete(const Object* object) {
  if (objects_.find(object) == objects_.end())
    return Result::Failure;
  if (store_.get()) {
    // If it's a private object we need to wait until private objects have been
    // loaded.
    if (object->IsPrivate() && !is_private_loaded_)
      return Result::WaitForPrivateObjects;
    if (!store_->DeleteObjectBlob(object->store_id()))
      return Result::Failure;
  }
  handle_object_map_.erase(object->handle());
  objects_.erase(object);
  return Result::Success;
}

Result ObjectPoolImpl::DeleteAll() {
  objects_.clear();
  handle_object_map_.clear();
  if (store_.get())
    return store_->DeleteAllObjectBlobs() ? Result::Success : Result::Failure;
  return Result::Success;
}

Result ObjectPoolImpl::Find(const Object* search_template,
                            vector<const Object*>* matching_objects) {
  // If we're looking for private objects we need to wait until private objects
  // have been loaded.
  if (((search_template->IsAttributePresent(CKA_PRIVATE) &&
        search_template->IsPrivate()) ||
       (search_template->IsAttributePresent(CKA_CLASS) &&
        search_template->GetObjectClass() == CKO_PRIVATE_KEY)) &&
      !is_private_loaded_)
    return Result::WaitForPrivateObjects;
  for (ObjectSet::iterator it = objects_.begin(); it != objects_.end(); ++it) {
    if (Matches(search_template, *it))
      matching_objects->push_back(*it);
  }
  return Result::Success;
}

Result ObjectPoolImpl::FindByHandle(int handle, const Object** object) {
  CHECK(object);
  HandleObjectMap::iterator it = handle_object_map_.find(handle);
  if (it == handle_object_map_.end())
    return Result::Failure;
  *object = it->second.get();
  return Result::Success;
}

Object* ObjectPoolImpl::GetModifiableObject(const Object* object) {
  return const_cast<Object*>(object);
}

Result ObjectPoolImpl::Flush(const Object* object) {
  if (objects_.find(object) == objects_.end())
    return Result::Failure;
  if (store_.get()) {
    ObjectBlob serialized;
    if (!Serialize(object, &serialized))
      return Result::Failure;
    // If it's a private object we need to wait until private objects have been
    // loaded.
    if (object->IsPrivate() && !is_private_loaded_)
      return Result::WaitForPrivateObjects;
    if (!store_->UpdateObjectBlob(object->store_id(), serialized))
      return Result::Failure;
  }
  return Result::Success;
}

bool ObjectPoolImpl::IsPrivateLoaded() {
  return is_private_loaded_;
}

bool ObjectPoolImpl::Matches(const Object* object_template,
                             const Object* object) {
  const AttributeMap* attributes = object_template->GetAttributeMap();
  AttributeMap::const_iterator it;
  for (it = attributes->begin(); it != attributes->end(); ++it) {
    if (!object->IsAttributePresent(it->first))
      return false;
    if (it->second != object->GetAttributeString(it->first))
      return false;
  }
  return true;
}

bool ObjectPoolImpl::Parse(const ObjectBlob& object_blob, Object* object) {
  AttributeList attribute_list;
  if (!attribute_list.ParseFromString(object_blob.blob)) {
    LOG(ERROR) << "Failed to parse proto-buffer.";
    return false;
  }
  for (int i = 0; i < attribute_list.attribute_size(); ++i) {
    const Attribute& attribute = attribute_list.attribute(i);
    if (!attribute.has_value()) {
      LOG(WARNING) << "No value found for attribute: " << attribute.type();
      continue;
    }
    object->SetAttributeString(attribute.type(), attribute.value());
    // Correct the length of integral attributes since they may have been
    // serialized with a different sizeof(CK_ULONG).
    if (IsIntegralAttribute(attribute.type()) &&
        attribute.value().length() != sizeof(CK_ULONG)) {
      CK_ULONG int_value = object->GetAttributeInt(attribute.type(), 0);
      object->SetAttributeInt(attribute.type(), int_value);
    }
    if (attribute.type() == CKA_PRIVATE &&
        object->IsPrivate() != object_blob.is_private) {
      // Assume this object has been tampered with.
      LOG(ERROR) << "Privacy attribute mismatch.";
      return false;
    }
  }

  if (!object->OnLoad()) {
    LOG(ERROR) << "Object's OnLoad failed.";
    return false;
  }

  return true;
}

bool ObjectPoolImpl::Serialize(const Object* object, ObjectBlob* serialized) {
  const AttributeMap* attribute_map = object->GetAttributeMap();
  AttributeMap::const_iterator it;
  AttributeList attribute_list;
  for (it = attribute_map->begin(); it != attribute_map->end(); ++it) {
    Attribute* next = attribute_list.add_attribute();
    next->set_type(it->first);
    next->set_length(it->second.length());
    next->set_value(it->second);
  }
  if (!attribute_list.SerializeToString(&serialized->blob)) {
    LOG(ERROR) << "Failed to serialize object.";
    return false;
  }
  serialized->is_private = object->IsPrivate();
  return true;
}

bool ObjectPoolImpl::LoadBlobs(const map<int, ObjectBlob>& object_blobs) {
  map<int, ObjectBlob>::const_iterator it;
  for (it = object_blobs.begin(); it != object_blobs.end(); ++it) {
    shared_ptr<Object> object(factory_->CreateObject());
    // An object that is not parsable will be ignored.
    if (Parse(it->second, object.get())) {
      object->set_handle(handle_generator_->CreateHandle());
      object->set_store_id(it->first);
      objects_.insert(object.get());
      handle_object_map_[object->handle()] = object;
    } else {
      LOG(WARNING) << "Object not parsable: " << it->first;
    }
  }
  return true;
}

bool ObjectPoolImpl::LoadPublicObjects() {
  CHECK(store_.get());
  map<int, ObjectBlob> object_blobs;
  if (!store_->LoadPublicObjectBlobs(&object_blobs))
    return false;
  return LoadBlobs(object_blobs);
}

bool ObjectPoolImpl::LoadPrivateObjects() {
  CHECK(store_.get());
  map<int, ObjectBlob> object_blobs;
  if (!store_->LoadPrivateObjectBlobs(&object_blobs))
    return false;
  return LoadBlobs(object_blobs);
}

}  // namespace chaps
