// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <sys/socket.h>

#include <utility>

#include <base/files/file_util.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <gtest/gtest.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/syslog/log_pipe.h"

namespace vm_tools {
namespace syslog {

// Size of the largest syslog record as defined by RFC3164.
constexpr size_t kMaxSyslogRecord = 1024;

class LogPipeTest : public ::testing::Test {
 public:
  LogPipeTest()
      : task_environment_(base::test::TaskEnvironment::MainThreadType::IO) {}

  void SendVmStartingUpSignal(int cid, LogPipeManager* manager) {
    concierge::VmStartedSignal vm_starting_up_signal;
    vm_starting_up_signal.set_owner_id("test-owner");
    vm_starting_up_signal.set_name(base::StringPrintf("vm-%d", cid));
    vm_starting_up_signal.mutable_vm_info()->set_cid(cid);

    dbus::Signal dbus_signal(concierge::kVmConciergeInterface,
                             concierge::kVmStartingUpSignal);
    dbus::MessageWriter writer(&dbus_signal);
    writer.AppendProtoAsArrayOfBytes(vm_starting_up_signal);

    manager->OnVmStartingUpSignal(&dbus_signal);
  }

  void SendVmStoppedSignal(int cid, LogPipeManager* manager) {
    concierge::VmStoppedSignal vm_stopped_signal;
    vm_stopped_signal.set_cid(cid);

    dbus::Signal dbus_signal(concierge::kVmConciergeInterface,
                             concierge::kVmStoppedSignal);
    dbus::MessageWriter writer(&dbus_signal);
    writer.AppendProtoAsArrayOfBytes(vm_stopped_signal);

    manager->OnVmStoppedSignal(&dbus_signal);
  }

  void CreateTestLogPipe(int cid, LogPipeManager* log_pipe_manager) {
    int log_fds[2];
    auto ret = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, log_fds);
    EXPECT_EQ(ret, 0);

    int dest_fds[2];
    ret = socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, dest_fds);

    log_pipe_manager->CreateLogPipeForTesting(
        cid, vm_tools::VmId("test-owner", base::StringPrintf("vm-%d", cid)),
        base::ScopedFD(dest_fds[0]), base::ScopedFD(log_fds[0]));

    log_sockets_[cid] = base::ScopedFD(log_fds[1]);
    dest_sockets_[cid] = base::ScopedFD(dest_fds[1]);
  }

  void SendOnLogSocket(int64_t cid, const std::string& line) {
    ASSERT_EQ(
        send(log_sockets_[cid].get(), line.c_str(), line.size(), MSG_NOSIGNAL),
        line.size());
  }

  std::string RecvOnDestSocket(int64_t cid) {
    char buf[kMaxSyslogRecord + 1] = {0};
    auto ret =
        recv(dest_sockets_[cid].get(), buf, kMaxSyslogRecord, MSG_DONTWAIT);
    return ret > 0 ? std::string(buf) : std::string();
  }

 private:
  std::map<int64_t, base::ScopedFD> log_sockets_;
  std::map<int64_t, base::ScopedFD> dest_sockets_;

  base::test::TaskEnvironment task_environment_;
};

TEST_F(LogPipeTest, ShutdownNoCrash) {
  base::RunLoop run_loop;
  auto manager = std::make_unique<LogPipeManager>(run_loop.QuitClosure());

  SendVmStartingUpSignal(4, manager.get());
  SendVmStartingUpSignal(5, manager.get());

  CreateTestLogPipe(4, manager.get());
  CreateTestLogPipe(5, manager.get());

  std::string log4 = "Log message for cid 4";
  std::string log5 = "Log message for cid 5";

  SendOnLogSocket(4, log4);
  SendOnLogSocket(5, log5);

  base::RunLoop().RunUntilIdle();

  SendVmStoppedSignal(5, manager.get());

  // Logs for cid 4 aren't yet flushed.
  std::string fwd_log4 = RecvOnDestSocket(4);
  EXPECT_TRUE(fwd_log4.empty());

  // Logs for cid 5 are flushed when the VM stops.
  std::string fwd_log5 = RecvOnDestSocket(5);
  EXPECT_NE(fwd_log5.find(log5), std::string::npos);

  base::RunLoop().RunUntilIdle();

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::unique_ptr<LogPipeManager> manager) { manager->OnSigterm(); },
          std::move(manager)));

  run_loop.Run();

  // Logs for cid 4 are flushed when the we SIGTERM.
  fwd_log4 = RecvOnDestSocket(4);
  EXPECT_NE(fwd_log4.find(log4), std::string::npos);

  // No crashing when the destructor runs.
  manager.reset();
}

}  // namespace syslog
}  // namespace vm_tools
