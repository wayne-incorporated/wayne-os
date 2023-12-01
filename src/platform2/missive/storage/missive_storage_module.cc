// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/missive_storage_module.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>

#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"

namespace reporting {

using MissiveStorageModuleDelegateInterface =
    MissiveStorageModule::MissiveStorageModuleDelegateInterface;

MissiveStorageModuleDelegateInterface::MissiveStorageModuleDelegateInterface() =
    default;
MissiveStorageModuleDelegateInterface::
    ~MissiveStorageModuleDelegateInterface() = default;

MissiveStorageModule::MissiveStorageModule(
    std::unique_ptr<MissiveStorageModuleDelegateInterface> delegate)
    : delegate_(std::move(delegate)) {}

MissiveStorageModule::~MissiveStorageModule() = default;

// static
scoped_refptr<MissiveStorageModule> MissiveStorageModule::Create(
    std::unique_ptr<MissiveStorageModuleDelegateInterface> delegate) {
  return base::WrapRefCounted(new MissiveStorageModule(std::move(delegate)));
}

void MissiveStorageModule::AddRecord(Priority priority,
                                     Record record,
                                     EnqueueCallback callback) {
  delegate_->AddRecord(priority, std::move(record), std::move(callback));
}

void MissiveStorageModule::Flush(Priority priority, FlushCallback callback) {
  delegate_->Flush(priority, std::move(callback));
}
}  // namespace reporting
