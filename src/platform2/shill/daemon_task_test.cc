// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/rtnetlink.h>
#include <stdint.h>

#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/memory/ref_counted.h>
#include <base/run_loop.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/daemon_task.h"
#include "shill/logging.h"
#include "shill/mock_control.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_routing_table.h"
#include "shill/mojom/mock_mojo_service_provider.h"
#include "shill/net/io_handler.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/net/mock_process_manager.h"
#include "shill/net/mock_rtnl_handler.h"
#include "shill/net/ndisc.h"
#include "shill/net/nl80211_message.h"
#include "shill/network/mock_dhcp_provider.h"
#include "shill/shill_test_config.h"
#include "shill/supplicant/supplicant_manager.h"
#include "shill/test_event_dispatcher.h"

using ::testing::_;
using ::testing::Expectation;
using ::testing::Mock;
using ::testing::Return;
using ::testing::Test;

namespace shill {

class DaemonTaskForTest : public DaemonTask {
 public:
  DaemonTaskForTest(const Settings& setttings, Config* config)
      : DaemonTask(Settings(), config) {}
  ~DaemonTaskForTest() override = default;

  bool quit_result() const { return quit_result_; }

  void RunMessageLoop() { dispatcher_->DispatchForever(); }

  bool Quit(base::OnceClosure completion_callback) override {
    quit_result_ = DaemonTask::Quit(std::move(completion_callback));
    dispatcher_->PostTask(
        FROM_HERE,
        base::BindOnce(&EventDispatcher::QuitDispatchForever,
                       // dispatcher_ will not be deleted before RunLoop quits.
                       base::Unretained(dispatcher_.get())));
    return quit_result_;
  }

 private:
  bool quit_result_;
};

class DaemonTaskTest : public Test {
 public:
  DaemonTaskTest()
      : daemon_(DaemonTask::Settings(), &config_),
        dispatcher_(new EventDispatcherForTest()),
        control_(new MockControl()),
        metrics_(new MockMetrics()),
        manager_(new MockManager(control_, dispatcher_, metrics_)),
        device_info_(manager_),
        mojo_provider_(new MockMojoServiceProvider(manager_)) {}
  ~DaemonTaskTest() override = default;
  void SetUp() override {
    // Tests initialization done by the daemon's constructor
    daemon_.rtnl_handler_ = &rtnl_handler_;
    daemon_.routing_table_ = &routing_table_;
    daemon_.dhcp_provider_ = &dhcp_provider_;
    daemon_.process_manager_ = &process_manager_;
    daemon_.metrics_.reset(metrics_);        // Passes ownership
    daemon_.manager_.reset(manager_);        // Passes ownership
    daemon_.control_.reset(control_);        // Passes ownership
    daemon_.dispatcher_.reset(dispatcher_);  // Passes ownership
    daemon_.netlink_manager_ = &netlink_manager_;
    daemon_.mojo_provider_.reset(mojo_provider_);
  }
  void StartDaemon() { daemon_.Start(); }

  void StopDaemon() { daemon_.Stop(); }

  void RunDaemon() { daemon_.RunMessageLoop(); }

  void ApplySettings(const DaemonTask::Settings& settings) {
    daemon_.settings_ = settings;
    daemon_.ApplySettings();
  }

  MOCK_METHOD(void, TerminationAction, ());
  MOCK_METHOD(void, BreakTerminationLoop, ());

 protected:
  TestConfig config_;
  DaemonTaskForTest daemon_;
  MockRTNLHandler rtnl_handler_;
  MockRoutingTable routing_table_;
  MockDHCPProvider dhcp_provider_;
  MockProcessManager process_manager_;
  EventDispatcherForTest* dispatcher_;
  MockControl* control_;
  MockMetrics* metrics_;
  MockManager* manager_;
  MockNetlinkManager netlink_manager_;
  DeviceInfo device_info_;
  MockMojoServiceProvider* mojo_provider_;
};

TEST_F(DaemonTaskTest, StartStop) {
  // To ensure we do not have any stale routes, we flush a device's routes
  // when it is started.  This requires that the routing table is fully
  // populated before we create and start devices.  So test to make sure that
  // the RoutingTable starts before the Manager (which in turn starts
  // DeviceInfo who is responsible for creating and starting devices).
  // The result is that we request the dump of the routing table and when that
  // completes, we request the dump of the links.  For each link found, we
  // create and start the device.
  EXPECT_CALL(rtnl_handler_, Start(RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
                                   RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR |
                                   RTMGRP_IPV6_ROUTE | RTMGRP_ND_USEROPT));
  Expectation routing_table_started = EXPECT_CALL(routing_table_, Start());
  EXPECT_CALL(dhcp_provider_, Init(_, _, _));
  EXPECT_CALL(process_manager_, Init());
  EXPECT_CALL(netlink_manager_, Init());
  const uint16_t kNl80211MessageType = 42;  // Arbitrary.
  EXPECT_CALL(netlink_manager_,
              GetFamily(Nl80211Message::kMessageTypeString, _))
      .WillOnce(Return(kNl80211MessageType));
  EXPECT_CALL(netlink_manager_, Start());
  EXPECT_CALL(*manager_, Start()).After(routing_table_started);
  EXPECT_CALL(*mojo_provider_, Start());
  StartDaemon();
  Mock::VerifyAndClearExpectations(manager_);

  EXPECT_CALL(*mojo_provider_, Stop());
  EXPECT_CALL(*manager_, Stop());
  EXPECT_CALL(process_manager_, Stop());

  StopDaemon();
}

TEST_F(DaemonTaskTest, SupplicantAppearsAfterStop) {
  // This test verifies that the daemon won't crash upon receiving Dbus message
  // via ControlInterface, which outlives the Manager. The SupplicantManager is
  // owned by the Manager, which is freed after Stop().
  StartDaemon();
  manager_->supplicant_manager()->Start();

  StopDaemon();

  control_->supplicant_appear().Run();
  dispatcher_->DispatchPendingEvents();
}

#if !defined(DISABLE_FLOSS)
TEST_F(DaemonTaskTest, BTManagerAppearsAfterStop) {
  // This test verifies that the daemon won't crash upon receiving Dbus message
  // via ControlInterface, which outlives the Manager. The BluetoothManager is
  // owned by the Manager, which is freed after Stop().
  StartDaemon();
  manager_->bluetooth_manager()->Start();

  StopDaemon();

  control_->bluetooth_manager_appear().Run();
  dispatcher_->DispatchPendingEvents();
}
#endif  // DISABLE_FLOSS

ACTION_P2(CompleteAction, manager, name) {
  manager->TerminationActionComplete(name);
}

TEST_F(DaemonTaskTest, QuitWithTerminationAction) {
  // This expectation verifies that the termination actions are invoked.
  EXPECT_CALL(*this, TerminationAction())
      .WillOnce(CompleteAction(manager_, "daemon test"));
  EXPECT_CALL(*this, BreakTerminationLoop()).Times(1);

  manager_->AddTerminationAction(
      "daemon test", base::BindOnce(&DaemonTaskTest::TerminationAction,
                                    base::Unretained(this)));

  // Run Daemon::Quit() after the daemon starts running.
  dispatcher_->PostTask(
      FROM_HERE,
      base::BindOnce(IgnoreResult(&DaemonTask::Quit),
                     base::Unretained(&daemon_),
                     base::BindOnce(&DaemonTaskTest::BreakTerminationLoop,
                                    base::Unretained(this))));

  RunDaemon();
  EXPECT_FALSE(daemon_.quit_result());
}

TEST_F(DaemonTaskTest, QuitWithoutTerminationActions) {
  EXPECT_CALL(*this, BreakTerminationLoop()).Times(0);
  EXPECT_TRUE(daemon_.Quit(base::BindOnce(&DaemonTaskTest::BreakTerminationLoop,
                                          base::Unretained(this))));
}

TEST_F(DaemonTaskTest, ApplySettings) {
  DaemonTask::Settings settings;
  std::vector<std::string> kEmptyStringList;
  EXPECT_CALL(*manager_, SetBlockedDevices(kEmptyStringList));
  EXPECT_CALL(*manager_, SetIgnoreUnknownEthernet(false));
  ApplySettings(settings);
  Mock::VerifyAndClearExpectations(manager_);

  std::vector<std::string> kBlockedDevices = {"eth0", "eth1"};
  settings.devices_blocked = kBlockedDevices;
  settings.ignore_unknown_ethernet = false;
  EXPECT_CALL(*manager_, SetBlockedDevices(kBlockedDevices));
  EXPECT_CALL(*manager_, SetIgnoreUnknownEthernet(false));
  ApplySettings(settings);
  Mock::VerifyAndClearExpectations(manager_);
}

}  // namespace shill
