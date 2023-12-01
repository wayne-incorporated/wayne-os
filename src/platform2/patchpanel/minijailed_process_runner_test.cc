// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/minijailed_process_runner.h"

#include <linux/capability.h>
#include <sys/types.h>

#include <memory>

#include <brillo/minijail/mock_minijail.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "patchpanel/iptables.h"
#include "patchpanel/net_util.h"
#include "patchpanel/system.h"

using testing::_;
using testing::DoAll;
using testing::ElementsAre;
using testing::ElementsAreArray;
using testing::Eq;
using testing::Return;
using testing::SetArgPointee;
using testing::StrEq;

namespace patchpanel {
namespace {

class MockSystem : public System {
 public:
  MOCK_METHOD3(WaitPid, pid_t(pid_t pid, int* wstatus, int options));
};

TEST(MinijailProcessRunnerTest, modprobe_all) {
  brillo::MockMinijail mj;
  auto system = new MockSystem();
  MinijailedProcessRunner runner(&mj, std::unique_ptr<System>(system));

  uint64_t caps = CAP_TO_MASK(CAP_SYS_MODULE);
  pid_t pid = 123;
  EXPECT_CALL(mj, New());
  EXPECT_CALL(mj, DropRoot(_, StrEq("nobody"), StrEq("nobody")))
      .WillOnce(Return(true));
  EXPECT_CALL(mj, UseCapabilities(_, Eq(caps)));
  EXPECT_CALL(mj, RunPipesAndDestroy(
                      _,
                      ElementsAre(StrEq("/sbin/modprobe"), StrEq("-a"),
                                  StrEq("module1"), StrEq("module2"), nullptr),
                      _, nullptr, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(pid), Return(true)));
  EXPECT_CALL(*system, WaitPid(pid, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(pid)));

  EXPECT_TRUE(runner.modprobe_all({"module1", "module2"}));
}

TEST(MinijailProcessRunnerTest, ip) {
  brillo::MockMinijail mj;
  auto system = new MockSystem();
  MinijailedProcessRunner runner(&mj, std::unique_ptr<System>(system));

  uint64_t caps = CAP_TO_MASK(CAP_NET_ADMIN) | CAP_TO_MASK(CAP_NET_RAW);
  pid_t pid = 123;
  EXPECT_CALL(mj, New());
  EXPECT_CALL(mj, DropRoot(_, StrEq("nobody"), StrEq("nobody")))
      .WillOnce(Return(true));
  EXPECT_CALL(mj, UseCapabilities(_, Eq(caps)));
  EXPECT_CALL(mj, RunPipesAndDestroy(
                      _,
                      ElementsAre(StrEq("/bin/ip"), StrEq("obj"), StrEq("cmd"),
                                  StrEq("arg1"), StrEq("arg2"), nullptr),
                      _, nullptr, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(pid), Return(true)));
  EXPECT_CALL(*system, WaitPid(pid, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(pid)));

  EXPECT_TRUE(runner.ip("obj", "cmd", {"arg1", "arg2"}));
}

TEST(MinijailProcessRunnerTest, ip6) {
  brillo::MockMinijail mj;
  auto system = new MockSystem();
  MinijailedProcessRunner runner(&mj, std::unique_ptr<System>(system));

  uint64_t caps = CAP_TO_MASK(CAP_NET_ADMIN) | CAP_TO_MASK(CAP_NET_RAW);
  pid_t pid = 123;
  EXPECT_CALL(mj, New());
  EXPECT_CALL(mj, DropRoot(_, StrEq("nobody"), StrEq("nobody")))
      .WillOnce(Return(true));
  EXPECT_CALL(mj, UseCapabilities(_, Eq(caps)));
  EXPECT_CALL(
      mj, RunPipesAndDestroy(
              _,
              ElementsAre(StrEq("/bin/ip"), StrEq("-6"), StrEq("obj"),
                          StrEq("cmd"), StrEq("arg1"), StrEq("arg2"), nullptr),
              _, nullptr, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(pid), Return(true)));
  EXPECT_CALL(*system, WaitPid(pid, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(pid)));

  EXPECT_TRUE(runner.ip6("obj", "cmd", {"arg1", "arg2"}));
}

TEST(MinijailProcessRunnerTest, iptables) {
  brillo::MockMinijail mj;
  auto system = new MockSystem();
  MinijailedProcessRunner runner(&mj, std::unique_ptr<System>(system));

  pid_t pid = 123;
  EXPECT_CALL(mj, New());
  EXPECT_CALL(mj, DropRoot(_, _, _)).Times(0);
  EXPECT_CALL(mj, UseCapabilities(_, _)).Times(0);
  EXPECT_CALL(
      mj, RunPipesAndDestroy(
              _,
              ElementsAre(StrEq("/sbin/iptables"), StrEq("-t"), StrEq("filter"),
                          StrEq("-A"), StrEq("arg1"), StrEq("arg2"), nullptr),
              _, nullptr, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(pid), Return(true)));
  EXPECT_CALL(*system, WaitPid(pid, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(pid)));

  EXPECT_TRUE(runner.iptables(Iptables::Table::kFilter, Iptables::Command::kA,
                              {"arg1", "arg2"}));
}

TEST(MinijailProcessRunnerTest, ip6tables) {
  brillo::MockMinijail mj;
  auto system = new MockSystem();
  MinijailedProcessRunner runner(&mj, std::unique_ptr<System>(system));

  pid_t pid = 123;
  EXPECT_CALL(mj, New());
  EXPECT_CALL(mj, DropRoot(_, _, _)).Times(0);
  EXPECT_CALL(mj, UseCapabilities(_, _)).Times(0);
  EXPECT_CALL(
      mj, RunPipesAndDestroy(_,
                             ElementsAre(StrEq("/sbin/ip6tables"), StrEq("-t"),
                                         StrEq("mangle"), StrEq("-I"),
                                         StrEq("arg1"), StrEq("arg2"), nullptr),
                             _, nullptr, nullptr, _))
      .WillOnce(DoAll(SetArgPointee<2>(pid), Return(true)));
  EXPECT_CALL(*system, WaitPid(pid, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(pid)));

  EXPECT_TRUE(runner.ip6tables(Iptables::Table::kMangle, Iptables::Command::kI,
                               {"arg1", "arg2"}));
}

}  // namespace
}  // namespace patchpanel
