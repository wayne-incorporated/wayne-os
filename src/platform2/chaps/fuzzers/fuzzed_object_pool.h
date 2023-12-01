// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_FUZZERS_FUZZED_OBJECT_POOL_H_
#define CHAPS_FUZZERS_FUZZED_OBJECT_POOL_H_

#include <absl/container/flat_hash_map.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#include "chaps/object.h"
#include "chaps/object_pool.h"

namespace chaps {

class FuzzedObjectPool : public ObjectPool {
 public:
  explicit FuzzedObjectPool(FuzzedDataProvider* data_provider);
  FuzzedObjectPool(const FuzzedObjectPool&) = delete;
  FuzzedObjectPool& operator=(const FuzzedObjectPool&) = delete;

  ~FuzzedObjectPool() override {}

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
  // Returns fuzzed bool, which is true with probability |probability| %.
  bool ConsumeBoolWithProbability(uint32_t probability);
  std::string ConsumeLowEntropyRandomLengthString(int len);
  std::string ConsumeRandomMessage();
  Result ConsumeResult();

  FuzzedDataProvider* data_provider_;
  absl::flat_hash_map<int, std::string> blobs_;
};

}  // namespace chaps

#endif  // CHAPS_FUZZERS_FUZZED_OBJECT_POOL_H_
