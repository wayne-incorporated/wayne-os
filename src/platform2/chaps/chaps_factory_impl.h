// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_FACTORY_IMPL_H_
#define CHAPS_CHAPS_FACTORY_IMPL_H_

#include "chaps/chaps_factory.h"

#include <libhwsec/frontend/chaps/frontend.h>

#include "chaps/chaps_metrics.h"

namespace chaps {

class ChapsFactoryImpl : public ChapsFactory {
 public:
  explicit ChapsFactoryImpl(ChapsMetrics* chaps_metrics);
  ChapsFactoryImpl(const ChapsFactoryImpl&) = delete;
  ChapsFactoryImpl& operator=(const ChapsFactoryImpl&) = delete;
  ~ChapsFactoryImpl() override {}

  Session* CreateSession(int slot_id,
                         ObjectPool* token_object_pool,
                         const hwsec::ChapsFrontend* chaps,
                         HandleGenerator* handle_generator,
                         bool is_read_only) override;
  ObjectPool* CreateObjectPool(HandleGenerator* handle_generator,
                               SlotPolicy* slot_policy,
                               ObjectStore* store) override;
  ObjectStore* CreateObjectStore(const base::FilePath& file_name) override;
  Object* CreateObject() override;
  ObjectPolicy* CreateObjectPolicy(CK_OBJECT_CLASS type) override;
  SlotPolicy* CreateSlotPolicy(bool is_shared_slot) override;

  static ObjectPolicy* GetObjectPolicyForType(CK_OBJECT_CLASS type);

 private:
  ChapsMetrics* chaps_metrics_;
};

}  // namespace chaps

#endif  // CHAPS_CHAPS_FACTORY_IMPL_H_
