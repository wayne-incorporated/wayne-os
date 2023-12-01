// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iterator>
#include <utility>

#include "runtime_probe/functions/generic_storage.h"

namespace runtime_probe {
namespace {

void ConcatenateDataType(GenericStorageFunction::DataType* dest,
                         GenericStorageFunction::DataType&& src) {
  for (auto& value : src) {
    dest->Append(std::move(value));
  }
}
}  // namespace

bool GenericStorageFunction::PostParseArguments() {
  ata_prober_ = CreateProbeFunction<AtaStorageFunction>(base::Value::Dict{});
  mmc_prober_ = CreateProbeFunction<MmcStorageFunction>(base::Value::Dict{});
  nvme_prober_ = CreateProbeFunction<NvmeStorageFunction>(base::Value::Dict{});
  ufs_prober_ = CreateProbeFunction<UfsStorageFunction>(base::Value::Dict{});

  return ata_prober_ && mmc_prober_ && nvme_prober_ && ufs_prober_;
}

GenericStorageFunction::DataType GenericStorageFunction::EvalImpl() const {
  DataType result{};
  ConcatenateDataType(&result, ata_prober_->Eval());
  ConcatenateDataType(&result, mmc_prober_->Eval());
  ConcatenateDataType(&result, nvme_prober_->Eval());
  ConcatenateDataType(&result, ufs_prober_->Eval());
  return result;
}

}  // namespace runtime_probe
