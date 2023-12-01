// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/guest_collector.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/un.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/scoped_minijail.h>
#include <grpcpp/grpcpp.h>

#include "vm_tools/syslog/parser.h"

namespace pb = google::protobuf;

namespace vm_tools {
namespace syslog {

namespace {
// Path to the standard syslog listening path.
constexpr char kDevLog[] = "/dev/log";

// Known host port for the LogCollector service.
constexpr unsigned int kLogCollectorPort = 9999;

// Path to the standard empty directory where we will jail the daemon.
constexpr char kPivotRoot[] = "/mnt/empty";

// Name for the "syslog" user and group.
constexpr char kSyslog[] = "syslog";
}  // namespace

std::unique_ptr<GuestCollector> GuestCollector::Create(
    base::OnceClosure shutdown_closure) {
  auto collector = base::WrapUnique<GuestCollector>(
      new GuestCollector(std::move(shutdown_closure)));

  if (!collector->Init()) {
    collector.reset();
  }
  return collector;
}

GuestCollector::GuestCollector(base::OnceClosure shutdown_closure)
    : shutdown_closure_(std::move(shutdown_closure)), weak_factory_(this) {}

GuestCollector::~GuestCollector() {
  FlushLogs();
}

bool GuestCollector::Init() {
  if (!BindLogSocket(base::FilePath(kDevLog))) {
    return false;
  }
  if (!StartWatcher(kFlushPeriod)) {
    return false;
  }

  // Start listening for SIGTERM.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);

  signal_fd_.reset(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Unable to create signalfd";
    return false;
  }
  signal_controller_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(), base::BindRepeating(&GuestCollector::OnSignalReadable,
                                            base::Unretained(this)));
  if (!signal_controller_) {
    LOG(ERROR) << "Failed to watch signal file descriptor";
    return false;
  }

  // Block the standard SIGTERM handler since we will be getting it via the
  // signalfd.
  sigprocmask(SIG_BLOCK, &mask, nullptr);

  // Create the stub to the LogCollector service on the host.
  stub_ = vm_tools::LogCollector::NewStub(grpc::CreateChannel(
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_HOST, kLogCollectorPort),
      grpc::InsecureChannelCredentials()));
  if (!stub_) {
    LOG(ERROR) << "Failed to create stub for LogCollector service";
    return false;
  }

  return EnterJail();
}

void GuestCollector::OnSignalReadable() {
  signalfd_siginfo info;
  if (read(signal_fd_.get(), &info, sizeof(info)) != sizeof(info)) {
    PLOG(ERROR) << "Failed to read from signalfd";
  }
  DCHECK_EQ(info.ssi_signo, SIGTERM);

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, std::move(shutdown_closure_));
}

bool GuestCollector::SendUserLogs() {
  vm_tools::EmptyMessage response;
  grpc::Status status;

  grpc::ClientContext ctx;
  status = stub_->CollectUserLogs(&ctx, syslog_request(), &response);

  if (!status.ok()) {
    LOG(ERROR) << "Failed to send user logs to LogCollector service.  Error "
               << "code " << status.error_code() << ": "
               << status.error_message();
    return false;
  }
  return true;
}

bool GuestCollector::EnterJail() {
  // Drop all unnecessary privileges.
  ScopedMinijail jail(minijail_new());
  if (!jail) {
    PLOG(ERROR) << "Failed to create minijail";
    return false;
  }

  minijail_change_user(jail.get(), kSyslog);
  minijail_change_group(jail.get(), kSyslog);
  minijail_no_new_privs(jail.get());

  // Pivot into an empty directory where we have no permissions.
  minijail_namespace_vfs(jail.get());
  minijail_enter_pivot_root(jail.get(), kPivotRoot);

  minijail_enter(jail.get());

  // Everything succeeded.
  return true;
}

std::unique_ptr<GuestCollector> GuestCollector::CreateForTesting(
    base::ScopedFD syslog_fd,
    std::unique_ptr<vm_tools::LogCollector::Stub> stub) {
  CHECK(stub);
  auto collector =
      base::WrapUnique<GuestCollector>(new GuestCollector(base::OnceClosure()));

  if (!collector->InitForTesting(std::move(syslog_fd), std::move(stub))) {
    collector.reset();
  }

  return collector;
}

bool GuestCollector::InitForTesting(
    base::ScopedFD syslog_fd,
    std::unique_ptr<vm_tools::LogCollector::Stub> stub) {
  // Store the stub for the LogCollector.
  stub_ = std::move(stub);
  SetSyslogFDForTesting(std::move(syslog_fd));
  // Start listening on the syslog socket.
  return StartWatcher(kFlushPeriodForTesting);
}

}  // namespace syslog
}  // namespace vm_tools
