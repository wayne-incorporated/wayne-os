// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "base/memory/scoped_refptr.h"
#include "gtest/gtest.h"
#include "secagentd/bpf_skeleton_wrappers.h"
#include "secagentd/common.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/test/mock_bpf_skeleton.h"

namespace secagentd {

using ::testing::_;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::TestWithParam;

class BpfSkeletonFactoryTestFixture
    : public ::testing::TestWithParam<Types::BpfSkeleton> {
 public:
  void SetUp() override {
    type = GetParam();
    auto mock_process_skel = std::make_unique<MockBpfSkeleton>();
    auto mock_network_skel = std::make_unique<MockBpfSkeleton>();
    switch (type) {
      case Types::BpfSkeleton::kProcess:
        active_skeleton = mock_process_skel.get();
        break;
      case Types::BpfSkeleton::kNetwork:
        active_skeleton = mock_network_skel.get();
        break;
    }

    skel_factory = base::MakeRefCounted<BpfSkeletonFactory>(
        BpfSkeletonFactory::SkeletonInjections(
            {.process = std::move(mock_process_skel),
             .network = std::move(mock_network_skel)}));
    cbs.ring_buffer_event_callback =
        base::BindRepeating([](const bpf::cros_event&) {});
    cbs.ring_buffer_read_ready_callback = base::BindRepeating([]() {});
  }
  BpfCallbacks cbs;
  Types::BpfSkeleton type;
  scoped_refptr<BpfSkeletonFactory> skel_factory;
  MockBpfSkeleton* active_skeleton;
};

TEST_P(BpfSkeletonFactoryTestFixture, TestSuccessfulBPFAttach) {
  {
    InSequence seq;
    EXPECT_CALL(*active_skeleton, RegisterCallbacks(BPF_CBS_EQ(cbs))).Times(1);
    EXPECT_CALL(*active_skeleton, LoadAndAttach())
        .WillOnce(Return(std::make_pair(absl::OkStatus(),
                                        metrics::BpfAttachResult::kSuccess)));
  }
  EXPECT_TRUE(skel_factory->Create(type, cbs, 0));
}

TEST_P(BpfSkeletonFactoryTestFixture, TestFailedBPFAttach) {
  {
    InSequence seq;
    EXPECT_CALL(*active_skeleton, RegisterCallbacks(BPF_CBS_EQ(cbs))).Times(1);
    EXPECT_CALL(*active_skeleton, LoadAndAttach())
        .WillOnce(
            Return(std::make_pair(absl::InternalError("Load and Attach Failed"),
                                  metrics::BpfAttachResult::kErrorAttach)));
  }
  EXPECT_EQ(skel_factory->Create(type, cbs, 0), nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    BpfSkeletonFactoryTest,
    BpfSkeletonFactoryTestFixture,
    ::testing::ValuesIn<Types::BpfSkeleton>({Types::BpfSkeleton::kProcess,
                                             Types::BpfSkeleton::kNetwork}),
    [](const ::testing::TestParamInfo<BpfSkeletonFactoryTestFixture::ParamType>&
           info) { return absl::StrFormat("%s", info.param); });

}  // namespace secagentd
