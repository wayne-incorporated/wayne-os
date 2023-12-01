// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_TEST_MOCK_BPF_SKELETON_H_
#define SECAGENTD_TEST_MOCK_BPF_SKELETON_H_

#include <memory>
#include <utility>

#include "gmock/gmock.h"  // IWYU pragma: keep
#include "secagentd/bpf_skeleton_wrappers.h"

namespace secagentd {

MATCHER_P(BPF_CBS_EQ, cbs, "BpfCallbacks are equal.") {
  if (arg.ring_buffer_event_callback == cbs.ring_buffer_event_callback &&
      arg.ring_buffer_read_ready_callback ==
          cbs.ring_buffer_read_ready_callback) {
    return true;
  }
  return false;
}

class MockBpfSkeleton : public BpfSkeletonInterface {
 public:
  MOCK_METHOD((std::pair<absl::Status, metrics::BpfAttachResult>),
              LoadAndAttach,
              (),
              (override));
  MOCK_METHOD(void, RegisterCallbacks, (BpfCallbacks cbs), (override));
  MOCK_METHOD(int, ConsumeEvent, (), (override));
};

class MockSkeletonFactory : public BpfSkeletonFactoryInterface {
 public:
  MOCK_METHOD(std::unique_ptr<BpfSkeletonInterface>,
              Create,
              (Types::BpfSkeleton type,
               BpfCallbacks cbs,
               uint32_t batch_interval_s),
              (override));
};
}  // namespace secagentd

#endif  // SECAGENTD_TEST_MOCK_BPF_SKELETON_H_
