// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/fuzzers/fuzzed_object_pool.h"

#include <absl/container/flat_hash_map.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#include "chaps/object.h"
#include "chaps/object_pool.h"

namespace {
const int kMaxMessageSize = 10;
const int kSuccessProbability = 90;
}  // namespace

namespace chaps {

using Result = ObjectPool::Result;

FuzzedObjectPool::FuzzedObjectPool(FuzzedDataProvider* data_provider)
    : data_provider_(data_provider) {}

bool FuzzedObjectPool::GetInternalBlob(int blob_id, std::string* blob) {
  if (data_provider_->ConsumeBool()) {
    auto it = blobs_.find(blob_id);
    if (it != blobs_.end()) {
      *blob = it->second;
    }
    return true;
  }
  if (data_provider_->ConsumeBool()) {
    *blob = ConsumeRandomMessage();
    return true;
  } else if (data_provider_->ConsumeBool()) {
    *blob = std::string(
        data_provider_->ConsumeIntegralInRange(0, kMaxMessageSize), 'a');
    return true;
  }
  return false;
}

bool FuzzedObjectPool::SetInternalBlob(int blob_id, const std::string& blob) {
  if (data_provider_->ConsumeBool()) {
    blobs_.insert({blob_id, blob});
  }
  return ConsumeBoolWithProbability(kSuccessProbability);
}

bool FuzzedObjectPool::SetEncryptionKey(const brillo::SecureBlob& key) {
  return ConsumeBoolWithProbability(kSuccessProbability);
}

Result FuzzedObjectPool::Insert(Object* object) {
  return ConsumeResult();
}

Result FuzzedObjectPool::Import(Object* object) {
  return ConsumeResult();
}

Result FuzzedObjectPool::Delete(const Object* object) {
  return ConsumeResult();
}

Result FuzzedObjectPool::DeleteAll() {
  return ConsumeResult();
}

Result FuzzedObjectPool::Find(const Object* search_template,
                              std::vector<const Object*>* matching_objects) {
  // Not used yet.
  return Result::Failure;
}

Result FuzzedObjectPool::FindByHandle(int handle, const Object** object) {
  // Not used yet.
  return Result::Failure;
}

Object* FuzzedObjectPool::GetModifiableObject(const Object* object) {
  return const_cast<Object*>(object);
}

Result FuzzedObjectPool::Flush(const Object* object) {
  return ConsumeResult();
}

bool FuzzedObjectPool::IsPrivateLoaded() {
  return ConsumeBoolWithProbability(kSuccessProbability);
}

bool FuzzedObjectPool::ConsumeBoolWithProbability(uint32_t probability) {
  return data_provider_->ConsumeIntegralInRange<uint32_t>(0, 9) * 10 <
         probability;
}

std::string FuzzedObjectPool::ConsumeRandomMessage() {
  return data_provider_->ConsumeRandomLengthString(kMaxMessageSize);
}

std::string FuzzedObjectPool::ConsumeLowEntropyRandomLengthString(int len) {
  return std::string(data_provider_->ConsumeIntegralInRange<size_t>(0, len - 1),
                     '0') +
         data_provider_->ConsumeBytesAsString(1);
}

Result FuzzedObjectPool::ConsumeResult() {
  return static_cast<Result>(
      data_provider_->ConsumeIntegralInRange<uint32_t>(0, 2));
}

}  // namespace chaps
