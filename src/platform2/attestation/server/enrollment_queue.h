// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_ENROLLMENT_QUEUE_H_
#define ATTESTATION_SERVER_ENROLLMENT_QUEUE_H_

#include <memory>
#include <vector>

#include "attestation/server/attestation_flow.h"

namespace attestation {

// This class maintains the coming attestation flow entry when the enrollment is
// in progress.
class EnrollmentQueue {
 public:
  explicit EnrollmentQueue(size_t size_limit);
  ~EnrollmentQueue() = default;

  // Enqueues |data| if the size limit is not reached yet for
  // |data->aca_type()|.
  bool Push(const std::shared_ptr<AttestationFlowData>& data);

  // Pops and returns all stored |AttestationFlowData| with |aca_type|.
  std::vector<std::shared_ptr<AttestationFlowData>> PopAll(ACAType aca_type);

 private:
  // Size limit for each ACA type.
  const size_t size_limit_;
  // Constainer instances for each ACA type.
  std::vector<std::shared_ptr<AttestationFlowData>> entries_[ACAType_ARRAYSIZE];
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_ENROLLMENT_QUEUE_H_
