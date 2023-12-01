// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_FUZZERS_FUZZED_CHAPS_FACTORY_H_
#define CHAPS_FUZZERS_FUZZED_CHAPS_FACTORY_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "chaps/chaps_factory.h"

namespace chaps {

class FuzzedChapsFactory : public ChapsFactory {
 public:
  explicit FuzzedChapsFactory(FuzzedDataProvider* data_provider);
  FuzzedChapsFactory(const FuzzedChapsFactory&) = delete;
  FuzzedChapsFactory& operator=(const FuzzedChapsFactory&) = delete;
  ~FuzzedChapsFactory() override {}

  Session* CreateSession(int slot_id,
                         ObjectPool* token_object_pool,
                         const hwsec::ChapsFrontend* hwsec,
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
  FuzzedDataProvider* data_provider_;
};

}  // namespace chaps

#endif  // CHAPS_FUZZERS_FUZZED_CHAPS_FACTORY_H_
