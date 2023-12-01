// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iterator>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "base/memory/scoped_refptr.h"
#include "base/test/task_environment.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "google/protobuf/message_lite.h"
#include "google/protobuf/stubs/casts.h"
#include "gtest/gtest.h"
#include "missive/proto/record_constants.pb.h"
#include "secagentd/batch_sender.h"
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/bpf_skeleton_wrappers.h"
#include "secagentd/plugins.h"
#include "secagentd/policies_features_broker.h"
#include "secagentd/proto/security_xdr_events.pb.h"
#include "secagentd/test/mock_batch_sender.h"
#include "secagentd/test/mock_bpf_skeleton.h"
#include "secagentd/test/mock_device_user.h"
#include "secagentd/test/mock_message_sender.h"
#include "secagentd/test/mock_policies_features_broker.h"
#include "secagentd/test/mock_process_cache.h"

namespace secagentd::testing {

namespace pb = cros_xdr::reporting;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

constexpr char kDeviceUser[] = "deviceUser@email.com";

class ProcessPluginTestFixture : public ::testing::Test {
 protected:
  ProcessPluginTestFixture()
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  using BatchSenderType =
      StrictMock<MockBatchSender<std::string,
                                 pb::XdrProcessEvent,
                                 pb::ProcessEventAtomicVariant>>;

  static constexpr uint32_t kBatchInterval = 10;

  static void SetPluginBatchSenderForTesting(
      PluginInterface* plugin, std::unique_ptr<BatchSenderType> batch_sender) {
    // This downcast here is very unfortunate but it avoids a lot of templating
    // in the plugin interface and the plugin factory. The factory generally
    // requires future cleanup to cleanly accommodate plugin specific dependency
    // injections.
    google::protobuf::down_cast<ProcessPlugin*>(plugin)
        ->SetBatchSenderForTesting(std::move(batch_sender));
  }

  void SetUp() override {
    bpf_skeleton_ = std::make_unique<MockBpfSkeleton>();
    bpf_skeleton_ref_ = bpf_skeleton_.get();
    skel_factory_ = base::MakeRefCounted<MockSkeletonFactory>();
    message_sender_ = base::MakeRefCounted<MockMessageSender>();
    process_cache_ = base::MakeRefCounted<MockProcessCache>();
    policies_features_broker_ =
        base::MakeRefCounted<MockPoliciesFeaturesBroker>();
    device_user_ = base::MakeRefCounted<MockDeviceUser>();
    auto batch_sender = std::make_unique<BatchSenderType>();
    batch_sender_ = batch_sender.get();
    plugin_factory_ = std::make_unique<PluginFactory>(skel_factory_);

    plugin_ = plugin_factory_->Create(Types::Plugin::kProcess, message_sender_,
                                      process_cache_, policies_features_broker_,
                                      device_user_, kBatchInterval);
    EXPECT_NE(nullptr, plugin_);
    SetPluginBatchSenderForTesting(plugin_.get(), std::move(batch_sender));

    EXPECT_CALL(*skel_factory_, Create(Types::BpfSkeleton::kProcess, _, _))
        .WillOnce(
            DoAll(SaveArg<1>(&cbs_), Return(ByMove(std::move(bpf_skeleton_)))));
    EXPECT_CALL(*batch_sender_, Start());
    EXPECT_OK(plugin_->Activate());

    ON_CALL(*policies_features_broker_,
            GetFeature(PoliciesFeaturesBroker::Feature::
                           kCrOSLateBootSecagentdCoalesceTerminates))
        .WillByDefault(Return(false));
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<MockSkeletonFactory> skel_factory_;
  scoped_refptr<MockMessageSender> message_sender_;
  scoped_refptr<MockProcessCache> process_cache_;
  scoped_refptr<MockPoliciesFeaturesBroker> policies_features_broker_;
  scoped_refptr<MockDeviceUser> device_user_;
  BatchSenderType* batch_sender_;
  std::unique_ptr<PluginFactory> plugin_factory_;
  std::unique_ptr<MockBpfSkeleton> bpf_skeleton_;
  MockBpfSkeleton* bpf_skeleton_ref_;
  std::unique_ptr<PluginInterface> plugin_;
  BpfCallbacks cbs_;
};

TEST_F(ProcessPluginTestFixture, TestActivationFailureBadSkeleton) {
  auto plugin = plugin_factory_->Create(
      Types::Plugin::kProcess, message_sender_, process_cache_,
      policies_features_broker_, device_user_, kBatchInterval);
  EXPECT_TRUE(plugin);
  SetPluginBatchSenderForTesting(plugin.get(),
                                 std::make_unique<BatchSenderType>());

  EXPECT_CALL(*skel_factory_, Create(Types::BpfSkeleton::kProcess, _, _))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_FALSE(plugin->Activate().ok());
}

TEST_F(ProcessPluginTestFixture, TestGetName) {
  ASSERT_EQ("Process", plugin_->GetName());
}

TEST_F(ProcessPluginTestFixture, TestBPFEventIsAvailable) {
  EXPECT_CALL(*bpf_skeleton_ref_, ConsumeEvent()).Times(1);
  // Notify the plugin that an event is available.
  cbs_.ring_buffer_read_ready_callback.Run();

  // Maybe serve up the event information.
  bpf::cros_event a;
  EXPECT_CALL(*batch_sender_, Enqueue(_)).Times(AnyNumber());
  cbs_.ring_buffer_event_callback.Run(a);
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginExecEvent) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Descending order in time starting from the youngest.
  constexpr uint64_t kPids[] = {3, 2, 1};
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  for (int i = 0; i < std::size(kPids); ++i) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    // Just some basic verification to make sure we consume the protos in the
    // expected order. The process cache unit test should cover the remaining
    // fields.
    hierarchy[i]->set_canonical_pid(kPids[i]);
  }

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessStartEvent,
                             .data.process_start = {.task_info =
                                                        {
                                                            .pid = kPids[0],
                                                            .start_time =
                                                                kSpawnStartTime,
                                                        },
                                                    .spawn_namespace =
                                                        {
                                                            .cgroup_ns = 1,
                                                            .pid_ns = 2,
                                                            .user_ns = 3,
                                                            .uts_ns = 4,
                                                            .mnt_ns = 5,
                                                            .net_ns = 6,
                                                            .ipc_ns = 7,
                                                        }}},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_,
              PutFromBpfExec(Ref(a.data.process_event.data.process_start)));
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(kPids[0], kSpawnStartTime, 3))
      .WillOnce(Return(ByMove(std::move(hierarchy))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*device_user_, GetDeviceUser).WillOnce(Return(kDeviceUser));

  std::unique_ptr<pb::ProcessEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::ProcessEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);

  EXPECT_EQ(kPids[0],
            actual_sent_event->process_exec().spawn_process().canonical_pid());
  EXPECT_EQ(kPids[1],
            actual_sent_event->process_exec().process().canonical_pid());
  EXPECT_EQ(kPids[2],
            actual_sent_event->process_exec().parent_process().canonical_pid());
  auto& ns = a.data.process_event.data.process_start.spawn_namespace;
  EXPECT_EQ(ns.cgroup_ns,
            actual_sent_event->process_exec().spawn_namespaces().cgroup_ns());
  EXPECT_EQ(ns.pid_ns,
            actual_sent_event->process_exec().spawn_namespaces().pid_ns());
  EXPECT_EQ(ns.user_ns,
            actual_sent_event->process_exec().spawn_namespaces().user_ns());
  EXPECT_EQ(ns.uts_ns,
            actual_sent_event->process_exec().spawn_namespaces().uts_ns());
  EXPECT_EQ(ns.mnt_ns,
            actual_sent_event->process_exec().spawn_namespaces().mnt_ns());
  EXPECT_EQ(ns.net_ns,
            actual_sent_event->process_exec().spawn_namespaces().net_ns());
  EXPECT_EQ(ns.ipc_ns,
            actual_sent_event->process_exec().spawn_namespaces().ipc_ns());

  // Common fields.
  EXPECT_EQ(kDeviceUser, actual_sent_event->common().device_user());
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginCoalesceTerminate) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  constexpr uint64_t kPid = 30;
  constexpr char kUuid[] = "uuid1";
  constexpr bpf::time_ns_t kSpawnStartTimeVeryOld = 1111;
  constexpr uint64_t kPidVeryOld = 5;
  constexpr char kUuidVeryOld[] = "very_old_uuid1";
  std::vector<std::unique_ptr<pb::Process>> exec_hierarchy;
  exec_hierarchy.push_back(std::make_unique<pb::Process>());
  exec_hierarchy[0]->set_process_uuid(kUuid);

  std::vector<std::unique_ptr<pb::Process>> terminate_hierarchy;
  terminate_hierarchy.push_back(std::make_unique<pb::Process>());
  terminate_hierarchy[0]->set_process_uuid(kUuid);

  std::vector<std::unique_ptr<pb::Process>> terminate_hierarchy_very_old;
  terminate_hierarchy_very_old.push_back(std::make_unique<pb::Process>());
  terminate_hierarchy_very_old[0]->set_process_uuid(kUuidVeryOld);

  const bpf::cros_event exec = {
      .data.process_event = {.type = bpf::kProcessStartEvent,
                             .data.process_start =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPid,
                                             .start_time = kSpawnStartTime,
                                         },
                                 }},
      .type = bpf::kProcessEvent,
  };
  const bpf::cros_event terminate = {
      .data.process_event = {.type = bpf::kProcessExitEvent,
                             .data.process_start =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPid,
                                             .start_time = kSpawnStartTime,
                                         },
                                 }},
      .type = bpf::kProcessEvent,
  };
  const bpf::cros_event terminate_very_old = {
      .data.process_event = {.type = bpf::kProcessExitEvent,
                             .data.process_start =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPidVeryOld,
                                             .start_time =
                                                 kSpawnStartTimeVeryOld,
                                         },
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_,
              PutFromBpfExec(Ref(exec.data.process_event.data.process_start)));
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPid, kSpawnStartTime, 3))
      .WillOnce(Return(ByMove(std::move(exec_hierarchy))));
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPid, kSpawnStartTime, 2))
      .WillOnce(Return(ByMove(std::move(terminate_hierarchy))));
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(kPidVeryOld, kSpawnStartTimeVeryOld, 2))
      .WillOnce(Return(ByMove(std::move(terminate_hierarchy_very_old))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*policies_features_broker_,
              GetFeature(PoliciesFeaturesBrokerInterface::Feature::
                             kCrOSLateBootSecagentdCoalesceTerminates))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*device_user_, GetDeviceUser).WillRepeatedly(Return(kDeviceUser));

  std::vector<std::unique_ptr<pb::ProcessEventAtomicVariant>>
      actual_sent_events;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .WillRepeatedly([&actual_sent_events](
                          std::unique_ptr<pb::ProcessEventAtomicVariant> e) {
        actual_sent_events.emplace_back(std::move(e));
      });
  EXPECT_CALL(
      *batch_sender_,
      Visit(Eq(pb::ProcessEventAtomicVariant::kProcessExec), Eq(kUuid), _))
      .WillOnce([&actual_sent_events](auto unused_type, const auto& unused_key,
                                      BatchSenderType::VisitCallback cb) {
        std::move(cb).Run(actual_sent_events[0].get());
        return true;
      });
  EXPECT_CALL(*batch_sender_,
              Visit(Eq(pb::ProcessEventAtomicVariant::kProcessExec),
                    Eq(kUuidVeryOld), _))
      .WillOnce([](auto unused_type, const auto& unused_key,
                   BatchSenderType::VisitCallback cb) {
        std::move(cb).Reset();
        return false;
      });

  cbs_.ring_buffer_event_callback.Run(exec);
  // Expect this first terminate to be coalesced because we just enqueued its
  // exec.
  cbs_.ring_buffer_event_callback.Run(terminate);
  cbs_.ring_buffer_event_callback.Run(terminate_very_old);

  ASSERT_EQ(2, actual_sent_events.size());
  EXPECT_EQ(
      kUuid,
      actual_sent_events[0]->process_exec().spawn_process().process_uuid());
  EXPECT_TRUE(
      actual_sent_events[0]->process_exec().has_terminate_timestamp_us());
  EXPECT_EQ(
      kUuidVeryOld,
      actual_sent_events[1]->process_terminate().process().process_uuid());
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginExecEventPartialHierarchy) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Populate just the spawned process and its parent. I.e one fewer that what
  // we'll be asked to return.
  constexpr uint64_t kPids[] = {3, 2};
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  for (int i = 0; i < std::size(kPids); ++i) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy[i]->set_canonical_pid(kPids[i]);
  }

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessStartEvent,
                             .data.process_start.task_info =
                                 {
                                     .pid = kPids[0],
                                     .start_time = kSpawnStartTime,
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_,
              PutFromBpfExec(Ref(a.data.process_event.data.process_start)));
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(kPids[0], kSpawnStartTime, 3))
      .WillOnce(Return(ByMove(std::move(hierarchy))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*device_user_, GetDeviceUser).WillRepeatedly(Return(kDeviceUser));

  std::unique_ptr<pb::ProcessEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::ProcessEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);

  EXPECT_EQ(kPids[0],
            actual_sent_event->process_exec().spawn_process().canonical_pid());
  EXPECT_EQ(kPids[1],
            actual_sent_event->process_exec().process().canonical_pid());
  EXPECT_FALSE(actual_sent_event->process_exec().has_parent_process());
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginFilteredExecEvent) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Descending order in time starting from the youngest.
  constexpr uint64_t kPids[] = {3, 2, 1};
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  for (int i = 0; i < std::size(kPids); ++i) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    // Just some basic verification to make sure we consume the protos in the
    // expected order. The process cache unit test should cover the remaining
    // fields.
    hierarchy[i]->set_canonical_pid(kPids[i]);
  }

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessStartEvent,
                             .data.process_start =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPids[0],
                                             .start_time = kSpawnStartTime,
                                         },
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_,
              PutFromBpfExec(Ref(a.data.process_event.data.process_start)));
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(kPids[0], kSpawnStartTime, 3))
      .WillOnce(Return(ByMove(std::move(hierarchy))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*batch_sender_, Enqueue(_)).Times(0);
  cbs_.ring_buffer_event_callback.Run(a);
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginExitEventCacheHit) {
  constexpr bpf::time_ns_t kStartTime = 2222;
  constexpr uint64_t kPids[] = {2, 1};
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  for (int i = 0; i < std::size(kPids); ++i) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy[i]->set_canonical_pid(kPids[i]);
  }

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessExitEvent,
                             .data.process_exit =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPids[0],
                                             .start_time = kStartTime,
                                         },
                                     .is_leaf = true,
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPids[0], kStartTime, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*device_user_, GetDeviceUser).WillRepeatedly(Return(kDeviceUser));

  std::unique_ptr<pb::ProcessEventAtomicVariant> actual_process_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .WillOnce([&actual_process_event](
                    std::unique_ptr<pb::ProcessEventAtomicVariant> e) {
        actual_process_event = std::move(e);
      });

  EXPECT_CALL(*process_cache_, EraseProcess(kPids[0], kStartTime));

  cbs_.ring_buffer_event_callback.Run(a);

  EXPECT_EQ(
      kPids[0],
      actual_process_event->process_terminate().process().canonical_pid());
  EXPECT_EQ(kPids[1], actual_process_event->process_terminate()
                          .parent_process()
                          .canonical_pid());
}

TEST_F(ProcessPluginTestFixture, TestProcessPluginExitEventCacheMiss) {
  constexpr bpf::time_ns_t kStartTimes[] = {2222, 1111};
  constexpr uint64_t kPids[] = {2, 1};
  constexpr char kParentImage[] = "/bin/bash";

  // The exiting process wasn't found in the cache.
  std::vector<std::unique_ptr<pb::Process>> hierarchy;

  // The parent, however, was found in procfs.
  std::vector<std::unique_ptr<pb::Process>> parent_hierarchy;
  parent_hierarchy.push_back(std::make_unique<pb::Process>());
  parent_hierarchy[0]->set_canonical_pid(kPids[1]);
  parent_hierarchy[0]->mutable_image()->set_pathname(kParentImage);

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessExitEvent,
                             .data.process_exit =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPids[0],
                                             .ppid = kPids[1],
                                             .start_time = kStartTimes[0],
                                             .parent_start_time =
                                                 kStartTimes[1],
                                         },
                                     .is_leaf = false,
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPids[0], kStartTimes[0], 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPids[1], kStartTimes[1], 1))
      .WillOnce(Return(ByMove(std::move(parent_hierarchy))));
  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(false));
  EXPECT_CALL(*device_user_, GetDeviceUser).WillRepeatedly(Return(kDeviceUser));

  std::unique_ptr<pb::ProcessEventAtomicVariant> actual_process_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .WillOnce([&actual_process_event](
                    std::unique_ptr<pb::ProcessEventAtomicVariant> e) {
        actual_process_event = std::move(e);
      });

  EXPECT_CALL(*process_cache_, EraseProcess(_, _)).Times(0);

  cbs_.ring_buffer_event_callback.Run(a);

  // Expect some process information to be filled in from the BPF event despite
  // the cache miss.
  EXPECT_TRUE(
      actual_process_event->process_terminate().process().has_process_uuid());
  EXPECT_EQ(
      kPids[0],
      actual_process_event->process_terminate().process().canonical_pid());
  EXPECT_EQ(kPids[1], actual_process_event->process_terminate()
                          .parent_process()
                          .canonical_pid());
  // Expect richer information about the parent due to the cache hit on the
  // parent.
  EXPECT_EQ(kParentImage, actual_process_event->process_terminate()
                              .parent_process()
                              .image()
                              .pathname());
}
TEST_F(ProcessPluginTestFixture, TestProcessPluginFilteredExitEvent) {
  constexpr bpf::time_ns_t kStartTime = 2222;
  constexpr uint64_t kPids[] = {2, 1};
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  for (int i = 0; i < std::size(kPids); ++i) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy[i]->set_canonical_pid(kPids[i]);
  }

  const bpf::cros_event a = {
      .data.process_event = {.type = bpf::kProcessExitEvent,
                             .data.process_exit =
                                 {
                                     .task_info =
                                         {
                                             .pid = kPids[0],
                                             .start_time = kStartTime,
                                         },
                                     .is_leaf = true,
                                 }},
      .type = bpf::kProcessEvent,
  };
  EXPECT_CALL(*process_cache_, GetProcessHierarchy(kPids[0], kStartTime, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  EXPECT_CALL(*process_cache_, IsEventFiltered(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*batch_sender_, Enqueue(_)).Times(0);
  EXPECT_CALL(*process_cache_, EraseProcess(kPids[0], kStartTime));
  cbs_.ring_buffer_event_callback.Run(a);
}

}  // namespace secagentd::testing
