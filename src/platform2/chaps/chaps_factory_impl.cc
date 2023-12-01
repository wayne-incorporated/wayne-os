// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/chaps_factory_impl.h"

#include <memory>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <libhwsec/frontend/chaps/frontend.h>

#include "chaps/object_impl.h"
#include "chaps/object_policy_cert.h"
#include "chaps/object_policy_common.h"
#include "chaps/object_policy_data.h"
#include "chaps/object_policy_private_key.h"
#include "chaps/object_policy_public_key.h"
#include "chaps/object_policy_secret_key.h"
#include "chaps/object_pool_impl.h"
#include "chaps/object_store_fake.h"
#include "chaps/object_store_impl.h"
#include "chaps/session_impl.h"
#include "chaps/slot_policy_default.h"
#include "chaps/slot_policy_shared_slot.h"

using base::FilePath;
using std::string;

namespace chaps {

ChapsFactoryImpl::ChapsFactoryImpl(ChapsMetrics* chaps_metrics)
    : chaps_metrics_(chaps_metrics) {
  CHECK(chaps_metrics_);
}

Session* ChapsFactoryImpl::CreateSession(int slot_id,
                                         ObjectPool* token_object_pool,
                                         const hwsec::ChapsFrontend* hwsec,
                                         HandleGenerator* handle_generator,
                                         bool is_read_only) {
  return new SessionImpl(slot_id, token_object_pool, hwsec, this,
                         handle_generator, is_read_only, chaps_metrics_);
}

ObjectPool* ChapsFactoryImpl::CreateObjectPool(
    HandleGenerator* handle_generator,
    SlotPolicy* slot_policy,
    ObjectStore* object_store) {
  std::unique_ptr<ObjectPoolImpl> pool(
      new ObjectPoolImpl(this, handle_generator, slot_policy, object_store));
  CHECK(pool.get());
  if (!pool->Init())
    return NULL;
  return pool.release();
}

ObjectStore* ChapsFactoryImpl::CreateObjectStore(const FilePath& file_name) {
  std::unique_ptr<ObjectStoreImpl> store(new ObjectStoreImpl());
  if (!store->Init(file_name, chaps_metrics_)) {
    // The approach here is to limp along without a persistent object store so
    // crypto services do not become unavailable. The side-effect is that all
    // objects will disappear when the token is removed (e.g. at logout).
    LOG(WARNING)
        << "Object store initialization failed, proceeding with fake store.";
    return new ObjectStoreFake();
  }
  return store.release();
}

Object* ChapsFactoryImpl::CreateObject() {
  return new ObjectImpl(this);
}

ObjectPolicy* ChapsFactoryImpl::CreateObjectPolicy(CK_OBJECT_CLASS type) {
  return ChapsFactoryImpl::GetObjectPolicyForType(type);
}

SlotPolicy* ChapsFactoryImpl::CreateSlotPolicy(bool is_shared_slot) {
  if (is_shared_slot) {
    return new SlotPolicySharedSlot();
  }
  return new SlotPolicyDefault();
}

ObjectPolicy* ChapsFactoryImpl::GetObjectPolicyForType(CK_OBJECT_CLASS type) {
  switch (type) {
    case CKO_DATA:
      return new ObjectPolicyData();
    case CKO_CERTIFICATE:
      return new ObjectPolicyCert();
    case CKO_PUBLIC_KEY:
      return new ObjectPolicyPublicKey();
    case CKO_PRIVATE_KEY:
      return new ObjectPolicyPrivateKey();
    case CKO_SECRET_KEY:
      return new ObjectPolicySecretKey();
  }
  return new ObjectPolicyCommon();
}

}  // namespace chaps
