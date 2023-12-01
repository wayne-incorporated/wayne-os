// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/enrollment_queue.h"

#include <memory>
#include <utility>

#include <base/check_op.h>

namespace attestation {

EnrollmentQueue::EnrollmentQueue(size_t size_limit) : size_limit_(size_limit) {}

bool EnrollmentQueue::Push(const std::shared_ptr<AttestationFlowData>& data) {
  DCHECK_LE(data->aca_type(), ACAType_ARRAYSIZE);
  if (entries_[data->aca_type()].size() >= size_limit_) {
    return false;
  }
  entries_[data->aca_type()].push_back(data);
  return true;
}

std::vector<std::shared_ptr<AttestationFlowData>> EnrollmentQueue::PopAll(
    ACAType aca_type) {
  DCHECK_LE(aca_type, ACAType_ARRAYSIZE);
  auto result = std::move(entries_[aca_type]);
  return result;
}

}  // namespace attestation
