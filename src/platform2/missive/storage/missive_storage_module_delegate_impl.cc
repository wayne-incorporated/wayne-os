// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/missive_storage_module_delegate_impl.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>

#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/util/status.h"

namespace reporting {

MissiveStorageModuleDelegateImpl::MissiveStorageModuleDelegateImpl(
    AddRecordCallback add_record, FlushCallback flush)
    : add_record_(std::move(add_record)), flush_(std::move(flush)) {}

MissiveStorageModuleDelegateImpl::~MissiveStorageModuleDelegateImpl() = default;

void MissiveStorageModuleDelegateImpl::AddRecord(
    Priority priority,
    Record record,
    MissiveStorageModule::EnqueueCallback callback) {
  add_record_.Run(priority, std::move(record), std::move(callback));
}

void MissiveStorageModuleDelegateImpl::Flush(
    Priority priority, MissiveStorageModule::FlushCallback callback) {
  flush_.Run(priority, std::move(callback));
}
}  // namespace reporting
