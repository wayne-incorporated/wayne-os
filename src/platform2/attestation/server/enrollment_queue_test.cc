// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/enrollment_queue.h"

#include <base/functional/callback_helpers.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "attestation/common/attestation_interface.h"
#include "attestation/server/attestation_flow.h"

namespace attestation {

namespace {

using ::testing::ElementsAreArray;

constexpr size_t kTotalLimit = 10;

}  // namespace

class EnrollmentQueueTest : public testing::TestWithParam<ACAType> {
 protected:
  ACAType aca_type() { return GetParam(); }

  std::shared_ptr<AttestationFlowData> MakeAttestationFlowDataForTesting() {
    GetCertificateRequest request;
    request.set_aca_type(GetParam());
    return std::make_shared<AttestationFlowData>(request, base::DoNothing());
  }
};

TEST_P(EnrollmentQueueTest, ClosedLoopTesting) {
  EnrollmentQueue enrollment_queue(kTotalLimit);
  std::vector<std::shared_ptr<AttestationFlowData>> entries;
  for (int i = 0; i < kTotalLimit; ++i) {
    entries.push_back(MakeAttestationFlowDataForTesting());
    EXPECT_TRUE(enrollment_queue.Push(entries.back()));
  }
  // Reached the size limit; the push operation should fail.
  EXPECT_FALSE(enrollment_queue.Push(MakeAttestationFlowDataForTesting()));
  // Popped items should match the entries we push into the queue.
  EXPECT_THAT(enrollment_queue.PopAll(aca_type()), ElementsAreArray(entries));
  // Makes sure after popping the entries, the queue is empty.
  EXPECT_TRUE(enrollment_queue.PopAll(aca_type()).empty());
}

INSTANTIATE_TEST_SUITE_P(AcaType,
                         EnrollmentQueueTest,
                         testing::Values(DEFAULT_ACA, TEST_ACA));

}  // namespace attestation
