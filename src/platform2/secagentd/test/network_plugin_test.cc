// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <netinet/in.h>
#include <sys/socket.h>
#include <cstddef>
#include <iterator>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "base/memory/scoped_refptr.h"
#include "gmock/gmock.h"  // IWYU pragma: keep
#include "google/protobuf/message_lite.h"
#include "google/protobuf/stubs/casts.h"
#include "google/protobuf/util/message_differencer.h"
#include "gtest/gtest.h"
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
#include "secagentd/test/test_utils.h"

namespace secagentd::testing {
namespace pb = cros_xdr::reporting;
namespace {
struct ExpectedProcess {
  uint64_t pid;
  uint64_t uid;
  std::string cmdline;
  uint64_t rel_start_time_s;
};
const uint64_t kDefaultPid{1452};
constexpr bpf::time_ns_t kSpawnStartTime{2222};

const bpf::cros_process_task_info kDefaultProcess = {
    .pid = 5139,
    .ppid = 5132,
    .start_time = 51382,
    .parent_start_time = 5786,
    .uid = 382,
    .gid = 4234,
};

const std::vector<ExpectedProcess> kDefaultProcessHierarchy{
    {.pid = kDefaultPid,
     .uid = 3123,
     .cmdline{"commandline1"},
     .rel_start_time_s = 144234},
    {.pid = 12314,
     .uid = 14123,
     .cmdline{"commandline2"},
     .rel_start_time_s = 51234},
};
bpf::cros_event CreateCrosFlowEvent(const bpf::cros_synthetic_network_flow& f) {
  bpf::cros_event rv = {
      .data.network_event{
          .type = bpf::cros_network_event_type::kSyntheticNetworkFlow},
      .type = bpf::kNetworkEvent};
  memmove(&rv.data.network_event.data.flow, &f, sizeof(f));
  return rv;
}
}  // namespace

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

class NetworkPluginTestFixture : public ::testing::Test {
 protected:
  using BatchSenderType = MockBatchSender<std::string,
                                          pb::XdrNetworkEvent,
                                          pb::NetworkEventAtomicVariant>;

  static constexpr uint32_t kBatchInterval = 10;

  static void SetPluginBatchSenderForTesting(
      PluginInterface* plugin, std::unique_ptr<BatchSenderType> batch_sender) {
    // This downcast here is very unfortunate but it avoids a lot of templating
    // in the plugin interface and the plugin factory. The factory generally
    // requires future cleanup to cleanly accommodate plugin specific dependency
    // injections.
    google::protobuf::down_cast<NetworkPlugin*>(plugin)
        ->SetBatchSenderForTesting(std::move(batch_sender));
  }

  void SetUp() override {
    bpf_skeleton = std::make_unique<MockBpfSkeleton>();
    bpf_skeleton_ = bpf_skeleton.get();
    skel_factory_ = base::MakeRefCounted<MockSkeletonFactory>();
    message_sender_ = base::MakeRefCounted<MockMessageSender>();
    process_cache_ = base::MakeRefCounted<MockProcessCache>();
    auto batch_sender = std::make_unique<BatchSenderType>();
    batch_sender_ = batch_sender.get();
    plugin_factory_ = std::make_unique<PluginFactory>(skel_factory_);
    device_user_ = base::MakeRefCounted<MockDeviceUser>();

    plugin_ = plugin_factory_->Create(Types::Plugin::kNetwork, message_sender_,
                                      process_cache_, policies_features_broker_,
                                      device_user_, kBatchInterval);
    EXPECT_NE(nullptr, plugin_);
    SetPluginBatchSenderForTesting(plugin_.get(), std::move(batch_sender));

    EXPECT_CALL(*skel_factory_,
                Create(Types::BpfSkeleton::kNetwork, _, kBatchInterval))
        .WillOnce(
            DoAll(SaveArg<1>(&cbs_), Return(ByMove(std::move(bpf_skeleton)))));
    EXPECT_CALL(*batch_sender_, Start());
    EXPECT_OK(plugin_->Activate());
  }

  scoped_refptr<MockSkeletonFactory> skel_factory_;
  scoped_refptr<MockMessageSender> message_sender_;
  scoped_refptr<MockProcessCache> process_cache_;
  scoped_refptr<MockDeviceUser> device_user_;
  scoped_refptr<MockPoliciesFeaturesBroker> policies_features_broker_;
  BatchSenderType* batch_sender_;
  std::unique_ptr<PluginFactory> plugin_factory_;
  std::unique_ptr<MockBpfSkeleton> bpf_skeleton;
  MockBpfSkeleton* bpf_skeleton_;
  std::unique_ptr<PluginInterface> plugin_;
  BpfCallbacks cbs_;
};

TEST_F(NetworkPluginTestFixture, TestActivationFailureBadSkeleton) {
  auto plugin = plugin_factory_->Create(
      Types::Plugin::kNetwork, message_sender_, process_cache_,
      policies_features_broker_, device_user_, kBatchInterval);
  EXPECT_TRUE(plugin);
  SetPluginBatchSenderForTesting(plugin.get(),
                                 std::make_unique<BatchSenderType>());

  EXPECT_CALL(*skel_factory_,
              Create(Types::BpfSkeleton::kNetwork, _, kBatchInterval))
      .WillOnce(Return(ByMove(nullptr)));
  EXPECT_FALSE(plugin->Activate().ok());
}

TEST_F(NetworkPluginTestFixture, TestGetName) {
  ASSERT_EQ("Network", plugin_->GetName());
}
TEST_F(NetworkPluginTestFixture, TestBPFEventIsAvailable) {
  const bpf::cros_event socket_listen_event = {
      .data.network_event =
          {
              .type = bpf::cros_network_event_type::kNetworkSocketListen,
              .data.socket_listen =
                  {
                      /* 192.168.0.1 */
                      .common = {.family = bpf::CROS_FAMILY_AF_INET,
                                 .protocol = bpf::CROS_PROTOCOL_TCP,
                                 .process{.pid = kDefaultPid,
                                          .start_time = kSpawnStartTime}},
                      .socket_type = SOCK_STREAM,
                      .port = 1234,
                      .ipv4_addr = 0x0100A8C0,
                  },
          },
      .type = bpf::kNetworkEvent,
  };
  EXPECT_CALL(*bpf_skeleton_, ConsumeEvent()).Times(1);
  // Notify the plugin that an event is available.
  cbs_.ring_buffer_read_ready_callback.Run();
  EXPECT_CALL(*message_sender_, SendMessage).Times(AnyNumber());
  cbs_.ring_buffer_event_callback.Run(socket_listen_event);
}

TEST_F(NetworkPluginTestFixture, TestWrongBPFEvent) {
  EXPECT_CALL(*bpf_skeleton_, ConsumeEvent()).Times(1);
  // Notify the plugin that an event is available.
  cbs_.ring_buffer_read_ready_callback.Run();
  EXPECT_CALL(*message_sender_, SendMessage).Times(0);
  cbs_.ring_buffer_event_callback.Run(
      bpf::cros_event{.type = bpf::kProcessEvent});
}

TEST_F(NetworkPluginTestFixture, TestSyntheticFlowEvent) {
  bpf::cros_network_5_tuple tuple;
  // inet_pton stores in network byte order.
  inet_pton(AF_INET, "168.152.10.1", &tuple.dest_addr.addr4);
  inet_pton(AF_INET, "192.168.0.1", &tuple.source_addr.addr4);
  tuple.source_port = 4591;
  tuple.dest_port = 5231;
  tuple.protocol = bpf::CROS_PROTOCOL_TCP;

  bpf::cros_flow_map_value val;
  val.direction = bpf::CROS_SOCKET_DIRECTION_OUT;
  val.garbage_collect_me = false;
  val.rx_bytes = 1456;
  val.tx_bytes = 2563;

  bpf::cros_synthetic_network_flow flow;
  flow.flow_map_key.five_tuple = tuple;
  flow.flow_map_value = val;

  flow.process_map_value.common.process = kDefaultProcess;

  auto event = CreateCrosFlowEvent(flow);
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  std::vector<pb::Process> expected_hierarchy;
  for (const auto& p : kDefaultProcessHierarchy) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy.back()->set_canonical_pid(p.pid);
    hierarchy.back()->set_canonical_uid(p.uid);
    hierarchy.back()->set_commandline(p.cmdline);
    hierarchy.back()->set_rel_start_time_s(p.rel_start_time_s);
    expected_hierarchy.emplace_back(*hierarchy.back());
  }
  auto& process =
      event.data.network_event.data.flow.process_map_value.common.process;
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(process.pid, process.start_time, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  std::unique_ptr<pb::NetworkEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .Times(1)
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::NetworkEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(event);
  EXPECT_THAT(expected_hierarchy[0],
              EqualsProto(actual_sent_event->network_flow().process()));
  EXPECT_THAT(expected_hierarchy[1],
              EqualsProto(actual_sent_event->network_flow().parent_process()));
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().local_ip(),
            "192.168.0.1");
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().local_port(),
            4591);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().remote_ip(),
            "168.152.10.1");
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().remote_port(),
            5231);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().protocol(),
            pb::TCP);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().direction(),
            pb::NetworkFlow_Direction_OUTGOING);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().rx_bytes(), 1456);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().tx_bytes(), 2563);
  EXPECT_EQ(actual_sent_event->network_flow().network_flow().community_id_v1(),
            "1:xQuGZjr6e08tldWqhl7702m03YU=");
}
TEST_F(NetworkPluginTestFixture, TestNetworkPluginListenEvent) {
  // Descending order in time starting from the youngest.
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  std::vector<pb::Process> expected_hierarchy;
  for (const auto& p : kDefaultProcessHierarchy) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy.back()->set_canonical_pid(p.pid);
    hierarchy.back()->set_canonical_uid(p.uid);
    hierarchy.back()->set_commandline(p.cmdline);
    hierarchy.back()->set_rel_start_time_s(p.rel_start_time_s);
    expected_hierarchy.emplace_back(*hierarchy.back());
  }
  const bpf::cros_event a = {
      .data.network_event =
          {
              .type = bpf::cros_network_event_type::kNetworkSocketListen,
              .data.socket_listen =
                  {
                      /* 192.168.0.1 */
                      .common = {.family = bpf::CROS_FAMILY_AF_INET,
                                 .protocol = bpf::CROS_PROTOCOL_TCP,
                                 .process{.pid = kDefaultPid,
                                          .start_time = kSpawnStartTime}},
                      .socket_type = SOCK_STREAM,
                      .port = 1234,
                      .ipv4_addr = 0x0100A8C0,
                  },
          },
      .type = bpf::kNetworkEvent,
  };
  const auto& socket_event = a.data.network_event.data.socket_listen;
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(socket_event.common.process.pid,
                                  socket_event.common.process.start_time, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  std::unique_ptr<pb::NetworkEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .Times(1)
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::NetworkEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);
  EXPECT_THAT(
      expected_hierarchy[0],
      EqualsProto(actual_sent_event->network_socket_listen().process()));
  EXPECT_THAT(
      expected_hierarchy[1],
      EqualsProto(actual_sent_event->network_socket_listen().parent_process()));
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().bind_addr(),
            "192.168.0.1");
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().bind_port(),
            socket_event.port);
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().protocol(),
            pb::NetworkProtocol::TCP);
}
using IPv6TestParam = std::pair<std::array<uint8_t, 16>, std::string>;
class IPv6VariationsTestFixture
    : public NetworkPluginTestFixture,
      public ::testing::WithParamInterface<IPv6TestParam> {};

/* Make sure that the compressed formatting of IPv6 is correct.*/
INSTANTIATE_TEST_SUITE_P(
    TestIPv6AddressFormatting,
    IPv6VariationsTestFixture,
    ::testing::Values(
        IPv6TestParam{{0xb4, 0x75, 0x34, 0x24, 0xde, 0x03, 0xa0, 0x90, 0xa0,
                       0x86, 0xb5, 0xff, 0x3c, 0x12, 0xb4, 0x56},
                      "b475:3424:de03:a090:a086:b5ff:3c12:b456"},
        /* 0: Test correct IPv6 compression of stripping leading zeroes.*/
        IPv6TestParam{{0xb4, 0x75, 00, 0x24, 0xde, 0x03, 0xa0, 0x90, 0xa0, 0x86,
                       0x0, 0xff, 0x3c, 0x12, 0xb4, 0x56},
                      "b475:24:de03:a090:a086:ff:3c12:b456"},
        /* 1: Test that a single group of 0's is not fully compressed. */
        IPv6TestParam{{0xb4, 0x75, 0x34, 0x24, 0x0, 0x0, 0xa0, 0x90, 0xa0, 0x86,
                       0xb5, 0xff, 0x3c, 0x12, 0xb4, 0x56},
                      "b475:3424:0:a090:a086:b5ff:3c12:b456"},
        /* 2: Test that multiple groups of 0s are compressed into :: */
        IPv6TestParam{{0xb4, 0x75, 0x34, 0x24, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                       0xb5, 0xff, 0x3c, 0x12, 0xb4, 0x56},
                      "b475:3424::b5ff:3c12:b456"},
        /* 3:Test that only the left most groups of 0's are compressed into ::*/
        IPv6TestParam{{0xb4, 0x75, 0x34, 0x24, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                       0xb5, 0xff, 0x0, 0x0, 0x0, 0x0},
                      "b475:3424::b5ff:0:0"}),
    [](::testing::TestParamInfo<IPv6TestParam> p) -> std::string {
      switch (p.index) {
        case 0:
          return "StripLeadingZeroes";
        case 1:
          return "Single0GroupNotCompressed";
        case 2:
          return "Multiple0GroupsCompressed";
        case 3:
          return "LeftMost0GroupsCompressed";
        default:
          return absl::StrFormat("MysteryTestCase%d", p.index);
      }
    });

TEST_P(IPv6VariationsTestFixture, TestSocketListenIPv6) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Descending order in time starting from the youngest.
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  std::vector<pb::Process> expected_hierarchy;
  for (const auto& p : kDefaultProcessHierarchy) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy.back()->set_canonical_pid(p.pid);
    hierarchy.back()->set_canonical_uid(p.uid);
    hierarchy.back()->set_commandline(p.cmdline);
    hierarchy.back()->set_rel_start_time_s(p.rel_start_time_s);
    expected_hierarchy.emplace_back(*hierarchy.back());
  }
  bpf::cros_event a = {
      .data.network_event =
          {
              .type = bpf::cros_network_event_type::kNetworkSocketListen,
              .data.socket_listen =
                  {/* 192.168.0.1 */
                   .common = {.family = bpf::CROS_FAMILY_AF_INET6,
                              .protocol = bpf::CROS_PROTOCOL_TCP,
                              .process{.pid = kDefaultPid,
                                       .start_time = kSpawnStartTime}},
                   .socket_type = 0,
                   .port = 1234},
          },
      .type = bpf::kNetworkEvent,
  };
  auto& ipv6_field = a.data.network_event.data.socket_listen.ipv6_addr;
  memmove(ipv6_field, GetParam().first.data(), sizeof(ipv6_field));
  auto expected_ipaddr = GetParam().second;
  const auto& socket_event = a.data.network_event.data.socket_listen;
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(socket_event.common.process.pid,
                                  socket_event.common.process.start_time, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  std::unique_ptr<pb::NetworkEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .Times(1)
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::NetworkEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().bind_addr(),
            expected_ipaddr);
}

class ProtocolVariationsTestFixture
    : public NetworkPluginTestFixture,
      public ::testing::WithParamInterface<bpf::cros_network_protocol> {};
using SocketTypeTestParam = std::pair<int, pb::SocketType>;
class SocketTypeVariationsTestFixture
    : public NetworkPluginTestFixture,
      public ::testing::WithParamInterface<SocketTypeTestParam> {};

/* Test all possible network protocols. */
INSTANTIATE_TEST_SUITE_P(
    TestDifferentProtocols,
    ProtocolVariationsTestFixture,
    ::testing::Values(bpf::cros_network_protocol::CROS_PROTOCOL_ICMP,
                      bpf::cros_network_protocol::CROS_PROTOCOL_RAW,
                      bpf::cros_network_protocol::CROS_PROTOCOL_TCP,
                      bpf::cros_network_protocol::CROS_PROTOCOL_UDP,
                      bpf::cros_network_protocol::CROS_PROTOCOL_UNKNOWN),
    [](::testing::TestParamInfo<bpf::cros_network_protocol> p) -> std::string {
      switch (p.param) {
        case bpf::cros_network_protocol::CROS_PROTOCOL_ICMP:
        case bpf::cros_network_protocol::CROS_PROTOCOL_ICMP6:
          return "ICMP";
        case bpf::cros_network_protocol::CROS_PROTOCOL_RAW:
          return "RAW";
        case bpf::cros_network_protocol::CROS_PROTOCOL_TCP:
          return "TCP";
        case bpf::cros_network_protocol::CROS_PROTOCOL_UDP:
          return "UDP";
        case bpf::cros_network_protocol::CROS_PROTOCOL_UNKNOWN:
          return "UnknownProtocol";
      }
    });

TEST_P(ProtocolVariationsTestFixture, TestSocketListenProtocols) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Descending order in time starting from the youngest.
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  std::vector<pb::Process> expected_hierarchy;
  for (const auto& p : kDefaultProcessHierarchy) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy.back()->set_canonical_pid(p.pid);
    hierarchy.back()->set_canonical_uid(p.uid);
    hierarchy.back()->set_commandline(p.cmdline);
    hierarchy.back()->set_rel_start_time_s(p.rel_start_time_s);
    expected_hierarchy.emplace_back(*hierarchy.back());
  }
  bpf::cros_event a = {
      .data.network_event =
          {
              .type = bpf::cros_network_event_type::kNetworkSocketListen,
              .data.socket_listen =
                  {.common = {.family = bpf::CROS_FAMILY_AF_INET,
                              .protocol = bpf::CROS_PROTOCOL_TCP,
                              .process{.pid = kDefaultPid,
                                       .start_time = kSpawnStartTime}},
                   .socket_type = SOCK_STREAM,
                   .port = 1234,
                   .ipv4_addr = 0x1020304},
          },
      .type = bpf::kNetworkEvent,
  };
  a.data.network_event.data.socket_listen.common.protocol = GetParam();
  pb::NetworkProtocol expected_protocol;
  switch (a.data.network_event.data.socket_listen.common.protocol) {
    case bpf::cros_network_protocol::CROS_PROTOCOL_ICMP:
    case bpf::cros_network_protocol::CROS_PROTOCOL_ICMP6:
      expected_protocol = pb::NetworkProtocol::ICMP;
      break;
    case bpf::cros_network_protocol::CROS_PROTOCOL_RAW:
      expected_protocol = pb::NetworkProtocol::RAW;
      break;
    case bpf::cros_network_protocol::CROS_PROTOCOL_TCP:
      expected_protocol = pb::NetworkProtocol::TCP;
      break;
    case bpf::cros_network_protocol::CROS_PROTOCOL_UDP:
      expected_protocol = pb::NetworkProtocol::UDP;
      break;
    case bpf::cros_network_protocol::CROS_PROTOCOL_UNKNOWN:
      expected_protocol = pb::NetworkProtocol::NETWORK_PROTOCOL_UNKNOWN;
      break;
  }
  const auto& socket_event = a.data.network_event.data.socket_listen;
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(socket_event.common.process.pid,
                                  socket_event.common.process.start_time, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  std::unique_ptr<pb::NetworkEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .Times(1)
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::NetworkEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().protocol(),
            expected_protocol);
}

/* Test all possible socket types. */
INSTANTIATE_TEST_SUITE_P(
    TestDifferentSocketTypes,
    SocketTypeVariationsTestFixture,
    ::testing::Values(
        SocketTypeTestParam{__socket_type::SOCK_STREAM,
                            pb::SocketType::SOCK_STREAM},
        SocketTypeTestParam{__socket_type::SOCK_DGRAM,
                            pb::SocketType::SOCK_DGRAM},
        SocketTypeTestParam{__socket_type::SOCK_RAW, pb::SocketType::SOCK_RAW},
        SocketTypeTestParam{__socket_type::SOCK_RDM, pb::SocketType::SOCK_RDM},
        SocketTypeTestParam{__socket_type::SOCK_PACKET,
                            pb::SocketType::SOCK_PACKET},
        SocketTypeTestParam{__socket_type::SOCK_SEQPACKET,
                            pb::SocketType::SOCK_SEQPACKET}),
    [](::testing::TestParamInfo<SocketTypeTestParam> p) -> std::string {
      switch (p.param.first) {
        case __socket_type::SOCK_STREAM:
          return "STREAM";
        case __socket_type::SOCK_RAW:
          return "RAW";
        case __socket_type::SOCK_DGRAM:
          return "DATAGRAM";
        case __socket_type::SOCK_RDM:
          return "RDM";
        case __socket_type::SOCK_PACKET:
          return "PACKET";
        case __socket_type::SOCK_SEQPACKET:
          return "SEQPACKET";
        default:
          return "UNKNOWN";
      }
    });

TEST_P(SocketTypeVariationsTestFixture, TestSocketListenSocketTypes) {
  constexpr bpf::time_ns_t kSpawnStartTime = 2222;
  // Descending order in time starting from the youngest.
  std::vector<std::unique_ptr<pb::Process>> hierarchy;
  std::vector<pb::Process> expected_hierarchy;
  for (const auto& p : kDefaultProcessHierarchy) {
    hierarchy.push_back(std::make_unique<pb::Process>());
    hierarchy.back()->set_canonical_pid(p.pid);
    hierarchy.back()->set_canonical_uid(p.uid);
    hierarchy.back()->set_commandline(p.cmdline);
    hierarchy.back()->set_rel_start_time_s(p.rel_start_time_s);
    expected_hierarchy.emplace_back(*hierarchy.back());
  }
  bpf::cros_event a = {
      .data.network_event =
          {
              .type = bpf::cros_network_event_type::kNetworkSocketListen,
              .data.socket_listen =
                  {.common = {.family = bpf::CROS_FAMILY_AF_INET,
                              .protocol = bpf::CROS_PROTOCOL_TCP,
                              .process{.pid = kDefaultPid,
                                       .start_time = kSpawnStartTime}},
                   .socket_type = SOCK_STREAM,
                   .port = 1234,
                   .ipv4_addr = 0x1020304},
          },
      .type = bpf::kNetworkEvent,
  };
  a.data.network_event.data.socket_listen.socket_type = GetParam().first;
  auto expected_socket_type = GetParam().second;
  const auto& socket_event = a.data.network_event.data.socket_listen;
  EXPECT_CALL(*process_cache_,
              GetProcessHierarchy(socket_event.common.process.pid,
                                  socket_event.common.process.start_time, 2))
      .WillOnce(Return(ByMove(std::move(hierarchy))));

  std::unique_ptr<pb::NetworkEventAtomicVariant> actual_sent_event;
  EXPECT_CALL(*batch_sender_, Enqueue(_))
      .Times(1)
      .WillOnce([&actual_sent_event](
                    std::unique_ptr<pb::NetworkEventAtomicVariant> e) {
        actual_sent_event = std::move(e);
      });

  cbs_.ring_buffer_event_callback.Run(a);
  EXPECT_EQ(actual_sent_event->network_socket_listen().socket().socket_type(),
            expected_socket_type);
}

struct CommunityHashTestParam {
  std::string source_address;
  std::string dest_address;
  uint16_t source_port;
  uint16_t dest_port;
  bpf::cros_network_protocol protocol;
  std::string expected;
};
class CommunityHashingTestFixture
    : public ::testing::Test,
      public ::testing::WithParamInterface<CommunityHashTestParam> {
 public:
  absl::StatusOr<std::array<uint8_t, 16>> TryIPv6StringToNBOBuffer(
      std::string_view in) {
    struct in6_addr addr;
    if (inet_pton(AF_INET6, in.data(), &addr) != 1) {
      return absl::InvalidArgumentError(
          absl::StrFormat("%s is not a valid ipv6 address.", in));
    }
    std::array<uint8_t, sizeof(addr.__in6_u.__u6_addr8)> rv;
    memmove(rv.data(), &addr.__in6_u.__u6_addr8[0], rv.size());
    return rv;
  }

  absl::StatusOr<std::array<uint8_t, 4>> TryIPv4StringToNBOBuffer(
      std::string_view in) {
    struct in_addr addr;
    if (inet_pton(AF_INET, in.data(), &addr) != 1) {
      return absl::InvalidArgumentError(
          absl::StrFormat("%s is not a valid ipv4 address.", in));
    }
    std::array<uint8_t, 4> rv;
    memmove(rv.data(), &addr.s_addr, rv.size());
    return rv;
  }
};
INSTANTIATE_TEST_SUITE_P(
    CommunityIDHashing,
    CommunityHashingTestFixture,
    ::testing::Values(
        // Same ip addr but different port.
        CommunityHashTestParam{
            // idx 0.
            .source_address = "b475:3424:de03:a090:a086:b5ff:3c12:b456",
            .dest_address = "b475:3424:de03:a090:a086:b5ff:3c12:b456",
            .source_port = 456,
            .dest_port = 457,
            .protocol = bpf::CROS_PROTOCOL_TCP,
            .expected = "1:9nlcNcNqbWThbbrqcZ653+nS/Ig="},

        // Same port but source address has a smaller IP address.
        CommunityHashTestParam{
            // idx 1.
            .source_address = "b475:3424:de03:a090:a086:b5ff:3c12:b453",
            .dest_address = "b475:3424:de03:a090:a086:b5ff:3c12:b456",
            .source_port = 457,
            .dest_port = 457,
            .protocol = bpf::CROS_PROTOCOL_UDP,
            .expected = "1:0bk6xBJMSDtsXhLKWuSD1waPfOg="},
        // Same port but dest address has a smaller IP address.
        CommunityHashTestParam{
            // idx 2.
            .source_address = "b475:3424:de03:a090:a086:b5ff:3c12:b456",
            .dest_address = "b475:3424:de03:a090:a086:b5ff:3c12:b453",
            .source_port = 457,
            .dest_port = 457,
            .protocol = bpf::CROS_PROTOCOL_UDP,
            .expected = "1:0bk6xBJMSDtsXhLKWuSD1waPfOg="},
        // Same ip addr but different port.
        CommunityHashTestParam{// idx 3.
                               .source_address = "192.168.0.1",
                               .dest_address = "192.168.0.1",
                               .source_port = 456,
                               .dest_port = 457,
                               .protocol = bpf::CROS_PROTOCOL_TCP,
                               .expected = "1:wtrJ3294c/p34IEHKppjTVgTvmY="},
        // Same port but source address has a smaller IP address.
        CommunityHashTestParam{// idx 4.
                               .source_address = "192.168.0.0",
                               .dest_address = "192.168.0.1",
                               .source_port = 457,
                               .dest_port = 457,
                               .protocol = bpf::CROS_PROTOCOL_TCP,
                               .expected = "1:fxjiNC2ogHm2gNZIiJssJkyUiGE="},
        // Same port but dest address has a smaller IP address.
        CommunityHashTestParam{// idx 5.
                               .source_address = "192.168.0.1",
                               .dest_address = "192.168.0.0",
                               .source_port = 457,
                               .dest_port = 457,
                               .protocol = bpf::CROS_PROTOCOL_TCP,
                               .expected = "1:fxjiNC2ogHm2gNZIiJssJkyUiGE="}),
    [](::testing::TestParamInfo<CommunityHashTestParam> p) -> std::string {
      switch (p.index) {
        case 0:
          return "IPv6SameAddrDifferentPorts";
        case 1:
          return "IPv6SourceAddressSmaller";
        case 2:
          return "IPv6DestAddrSmaller";
        case 3:
          return "IPv4SameAddrDifferentPorts";
        case 4:
          return "IPv4SourceAddressSmaller";
        case 5:
          return "IPv4DestAddrSmaller";
        default:
          return absl::StrFormat("MysteryTestCase%d", p.index);
      }
    });

TEST_P(CommunityHashingTestFixture, CommunityFlowIDHash) {
  auto i = GetParam();
  auto ipv4_source = TryIPv4StringToNBOBuffer(i.source_address);
  auto ipv4_dest = TryIPv4StringToNBOBuffer(i.dest_address);
  auto ipv6_source = TryIPv6StringToNBOBuffer(i.source_address);
  auto ipv6_dest = TryIPv6StringToNBOBuffer(i.dest_address);
  absl::Span<const uint8_t> source, dest;
  if (ipv4_source.ok()) {
    source = absl::MakeSpan(ipv4_source.value());
  } else if (ipv6_source.ok()) {
    source = absl::MakeSpan(ipv6_source.value());
  }

  if (ipv4_dest.ok()) {
    dest = absl::MakeSpan(ipv4_dest.value());
  } else if (ipv6_dest.ok()) {
    dest = absl::MakeSpan(ipv6_dest.value());
  }
  auto result = NetworkPlugin::ComputeCommunityHashv1(
      source, dest, i.source_port, i.dest_port, i.protocol);
  EXPECT_EQ(result, i.expected);
}
}  // namespace secagentd::testing
