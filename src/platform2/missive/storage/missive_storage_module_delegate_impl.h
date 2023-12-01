// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_STORAGE_MISSIVE_STORAGE_MODULE_DELEGATE_IMPL_H_
#define MISSIVE_STORAGE_MISSIVE_STORAGE_MODULE_DELEGATE_IMPL_H_

#include <base/functional/callback.h>

#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/storage/missive_storage_module.h"
#include "missive/util/status.h"

namespace reporting {

// Provides a delegate that sends all requests to callbacks.
class MissiveStorageModuleDelegateImpl
    : public MissiveStorageModule::MissiveStorageModuleDelegateInterface {
 public:
  using AddRecordCallback = base::RepeatingCallback<void(
      Priority, Record, MissiveStorageModule::EnqueueCallback)>;
  using FlushCallback = base::RepeatingCallback<void(
      Priority, MissiveStorageModule::FlushCallback)>;

  MissiveStorageModuleDelegateImpl(AddRecordCallback add_record,
                                   FlushCallback flush);
  ~MissiveStorageModuleDelegateImpl() override;

  void AddRecord(Priority priority,
                 Record record,
                 MissiveStorageModule::EnqueueCallback callback) override;

  void Flush(Priority priority,
             MissiveStorageModule::FlushCallback callback) override;

 private:
  const AddRecordCallback add_record_;
  const FlushCallback flush_;
};

}  // namespace reporting

#endif  // MISSIVE_STORAGE_MISSIVE_STORAGE_MODULE_DELEGATE_IMPL_H_
