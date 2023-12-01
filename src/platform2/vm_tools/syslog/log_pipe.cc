// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/log_pipe.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/signalfd.h>

#include <map>
#include <memory>
#include <utility>

#include <anomaly_detector/proto_bindings/anomaly_detector.pb.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/format_macros.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <vm_concierge/concierge_service.pb.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

#include "vm_tools/common/naming.h"
#include "vm_tools/syslog/rotator.h"

namespace vm_tools {
namespace syslog {

namespace {
// Cryptohome root base path.
constexpr char kCryptohomeRoot[] = "/run/daemon-store/crosvm";
// crosvm log directory name.
constexpr char kCrosvmLogDir[] = "log";
// extension for logging sockets.
constexpr char kLogSocketExtension[] = ".lsock";
// extension for log files.
constexpr char kLogFileExtension[] = ".log";

constexpr int64_t kInvalidCid = 0;
// how often to rotate logs in |managed_log_dir_|.
constexpr base::TimeDelta kLogRotationPeriod = base::Days(1);
// maximum log files to keep per vm in |managed_log_dir_|
constexpr int kMaxFilesPerLog = 5;

base::FilePath GetLogDir(const VmId& id) {
  return base::FilePath(kCryptohomeRoot)
      .Append(id.owner_id())
      .Append(kCrosvmLogDir);
}

base::FilePath GetCollectorPath(const VmId& id) {
  return GetLogDir(id)
      .Append(GetEncodedName(id.name()))
      .AddExtension(kLogSocketExtension);
}

base::FilePath GetForwarderPath(const VmId& id) {
  return GetLogDir(id)
      .Append(GetEncodedName(id.name()))
      .AddExtension(kLogFileExtension);
}

base::ScopedFD OpenForwarderPath(const VmId& id) {
  return base::ScopedFD(open(GetForwarderPath(id).value().c_str(),
                             O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0640));
}

}  // namespace

LogPipe::LogPipe(VmId vm_id,
                 std::unique_ptr<HostCollector> collector,
                 std::unique_ptr<Forwarder> forwarder)
    : vm_id_(vm_id),
      collector_(std::move(collector)),
      forwarder_(std::move(forwarder)) {}

std::unique_ptr<LogPipe> LogPipe::Create(
    scoped_refptr<dbus::Bus> bus,
    int64_t cid,
    const VmId& id,
    base::ScopedFD dest,
    VmKernelLogRequest::VmType vm_type,
    base::WeakPtr<LogPipeManager> manager) {
  auto forwarder = std::make_unique<Forwarder>(std::move(dest), false);
  auto collector =
      HostCollector::Create(bus, cid, GetCollectorPath(id), vm_type, manager);
  return std::unique_ptr<LogPipe>(
      new LogPipe(id, std::move(collector), std::move(forwarder)));
}

std::unique_ptr<LogPipe> LogPipe::CreateForTesting(
    int64_t cid,
    const vm_tools::VmId& id,
    base::ScopedFD dest,
    base::ScopedFD collector_fd,
    base::WeakPtr<LogPipeManager> manager) {
  auto forwarder = std::make_unique<Forwarder>(std::move(dest), false);
  auto collector =
      HostCollector::CreateForTesting(cid, std::move(collector_fd), manager);
  return std::unique_ptr<LogPipe>(
      new LogPipe(id, std::move(collector), std::move(forwarder)));
}

grpc::Status LogPipe::ForwardLogs(int64_t cid, const LogRequest& log_request) {
  return forwarder_->ForwardLogs(cid, log_request);
}

void LogPipe::Reopen() {
  if (!forwarder_->is_socket_destination()) {
    base::ScopedFD dest = OpenForwarderPath(vm_id_);
    if (!dest.is_valid()) {
      PLOG(ERROR) << "Failed to open vm_id " << vm_id_ << " log path.";
      return;
    }
    forwarder_->SetFileDestination(std::move(dest));
  }
}

void LogPipe::Flush() {
  collector_->FlushLogs();
}

LogPipeManager::LogPipeManager(base::OnceClosure shutdown_closure)
    : shutdown_closure_(std::move(shutdown_closure)),
      task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      weak_ptr_factory_(this) {}

LogPipeManager::~LogPipeManager() {
  for (auto& it : log_pipes_) {
    it.second->Flush();
  }
  log_pipes_.clear();
}

void LogPipeManager::CreateLogPipeForTesting(int64_t cid,
                                             const vm_tools::VmId& id,
                                             base::ScopedFD dest_fd,
                                             base::ScopedFD collector_fd) {
  DCHECK(dest_fd.is_valid());
  DCHECK(collector_fd.is_valid());
  log_pipes_[cid] = LogPipe::CreateForTesting(cid, id, std::move(dest_fd),
                                              std::move(collector_fd),
                                              weak_ptr_factory_.GetWeakPtr());
}

bool LogPipeManager::Init(base::ScopedFD syslog_fd,
                          bool only_forward_to_syslog) {
  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(std::move(opts));

  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return false;
  }

  if (syslog_fd.is_valid()) {
    syslog_forwarder_.reset(new Forwarder(std::move(syslog_fd), true));
    only_forward_to_syslog_ = only_forward_to_syslog;
  } else {
    if (only_forward_to_syslog) {
      LOG(ERROR) << "Forwarding to syslogd unavailable.";
      return false;
    }
  }

  ConnectToConcierge();
  SetupSigtermHandler();

  // Start a timer to periodically rotate logs.
  timer_.Start(FROM_HERE, kLogRotationPeriod,
               base::BindRepeating(&LogPipeManager::RotateLogs,
                                   weak_ptr_factory_.GetWeakPtr()));
  LOG(INFO) << "Started RotateLogs timer";
  return true;
}

void LogPipeManager::ConnectToConcierge() {
  auto concierge_proxy = bus_->GetObjectProxy(
      concierge::kVmConciergeServiceName,
      dbus::ObjectPath(concierge::kVmConciergeServicePath));

  if (!concierge_proxy) {
    LOG(ERROR) << "Failed to get Concerge proxy";
    return;
  }
  LOG(INFO) << "Connecting to dbus signal " << concierge::kVmStartingUpSignal;
  concierge_proxy->ConnectToSignal(
      concierge::kVmConciergeInterface, concierge::kVmStartingUpSignal,
      base::BindRepeating(&LogPipeManager::OnVmStartingUpSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&LogPipeManager::OnSignalConnected,
                     weak_ptr_factory_.GetWeakPtr()));
  LOG(INFO) << "Connecting to dbus signal " << concierge::kVmStoppedSignal;
  concierge_proxy->ConnectToSignal(
      concierge::kVmConciergeInterface, concierge::kVmStoppedSignal,
      base::BindRepeating(&LogPipeManager::OnVmStoppedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&LogPipeManager::OnSignalConnected,
                     weak_ptr_factory_.GetWeakPtr()));
}

bool LogPipeManager::SetupSigtermHandler() {
  // Set up the signalfd for receiving SIGCHLD and SIGTERM.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);

  signal_fd_.reset(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create signalfd";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(),
      base::BindRepeating(&LogPipeManager::OnSigterm, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch signalfd";
    return false;
  }

  // Now block signals from the normal signal handling path so that we will get
  // them via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed to block signals via sigprocmask";
    return false;
  }
  return true;
}

void LogPipeManager::OnSigterm() {
  LOG(INFO) << "Shutting down due to SIGTERM";

  task_runner_->PostTask(FROM_HERE, std::move(shutdown_closure_));
}

void LogPipeManager::OnVmStartingUpSignal(dbus::Signal* signal) {
  DCHECK_EQ(signal->GetInterface(), concierge::kVmConciergeInterface);
  DCHECK_EQ(signal->GetMember(), concierge::kVmStartingUpSignal);

  concierge::VmStartedSignal vm_started_signal;
  dbus::MessageReader reader(signal);
  if (!reader.PopArrayOfBytesAsProto(&vm_started_signal)) {
    PLOG(ERROR) << "Failed to parse proto from DBus Signal";
    return;
  }
  VmId vm_id(vm_started_signal.owner_id(), vm_started_signal.name());
  int64_t cid = vm_started_signal.vm_info().cid();
  auto vm_type = static_cast<VmKernelLogRequest::VmType>(
      vm_started_signal.vm_info().vm_type());

  LOG(INFO) << "Received VmStartingUpSignal for " << vm_id << ", cid " << cid
            << ", type " << VmKernelLogRequest::VmType_Name(vm_type);

  base::ScopedFD dest = OpenForwarderPath(vm_id);
  if (!dest.is_valid()) {
    PLOG(ERROR) << "Failed to open log path " << GetForwarderPath(vm_id);
    return;
  }

  base::AutoLock lock(log_pipes_lock_);
  managed_log_dirs_.insert(GetLogDir(vm_id));
  log_pipes_[cid] = LogPipe::Create(bus_, cid, vm_id, std::move(dest), vm_type,
                                    weak_ptr_factory_.GetWeakPtr());
}

void LogPipeManager::OnVmStoppedSignal(dbus::Signal* signal) {
  DCHECK_EQ(signal->GetInterface(), concierge::kVmConciergeInterface);
  DCHECK_EQ(signal->GetMember(), concierge::kVmStoppedSignal);

  concierge::VmStoppedSignal vm_stopped_signal;
  dbus::MessageReader reader(signal);
  if (!reader.PopArrayOfBytesAsProto(&vm_stopped_signal)) {
    PLOG(ERROR) << "Failed to parse proto from DBus Signal";
    return;
  }
  int64_t cid = vm_stopped_signal.cid();
  LOG(INFO) << "Received VmStoppedSignal for cid " << cid;

  {
    base::ReleasableAutoLock lock(&log_pipes_lock_);
    auto it = log_pipes_.find(cid);
    if (it != log_pipes_.end()) {
      lock.Release();
      // Flush re-acquires the lock. Erasing from |log_pipes_| happens only
      // on this thread, so the iterator stays valid.
      it->second->Flush();
    } else {
      return;
    }
  }
  base::AutoLock lock(log_pipes_lock_);
  log_pipes_.erase(cid);
}

void LogPipeManager::OnSignalConnected(const std::string& interface_name,
                                       const std::string& signal_name,
                                       bool is_connected) {
  DCHECK_EQ(interface_name, concierge::kVmConciergeInterface);
  if (!is_connected)
    LOG(ERROR) << "Failed to connect to signal: " << signal_name;

  if (signal_name == concierge::kVmStartingUpSignal) {
    is_vm_started_signal_connected_ = is_connected;
  } else if (signal_name == concierge::kVmStoppedSignal) {
    is_vm_stopped_signal_connected_ = is_connected;
  }
}

namespace {

int64_t CidFromCtx(const grpc::ServerContext& ctx) {
  int64_t cid;
  if (sscanf(ctx.peer().c_str(), "vsock:%" PRId64, &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address: " << ctx.peer();
    return kInvalidCid;
  }
  return cid;
}

}  // namespace

grpc::Status LogPipeManager::CollectKernelLogs(grpc::ServerContext* ctx,
                                               const LogRequest* request,
                                               EmptyMessage* response) {
  return grpc::Status(grpc::UNIMPLEMENTED, "");
}

grpc::Status LogPipeManager::CollectUserLogs(grpc::ServerContext* ctx,
                                             const LogRequest* request,
                                             EmptyMessage* response) {
  DCHECK(ctx);
  DCHECK(request);
  // Write these logs immediately, since they were already buffered on the
  // GuestCollector.
  int64_t cid = CidFromCtx(*ctx);
  return WriteSyslogRecords(cid, *request);
}

grpc::Status LogPipeManager::WriteSyslogRecords(int64_t cid,
                                                const LogRequest& log_request) {
  if (only_forward_to_syslog_) {
    return syslog_forwarder_->ForwardLogs(cid, log_request);
  }

  base::AutoLock lock(log_pipes_lock_);
  auto it = log_pipes_.find(cid);
  if (it == log_pipes_.end()) {
    if (syslog_forwarder_) {
      return syslog_forwarder_->ForwardLogs(cid, log_request);
    }
    LOG(ERROR) << "Unknown vm cid " << cid << " wants to write logs";
    return grpc::Status(grpc::INTERNAL, "Unknown vm, no syslog forwarding");
  }

  return it->second->ForwardLogs(cid, log_request);
}

void LogPipeManager::RotateLogs() {
  if (managed_log_dirs_.empty()) {
    return;
  }

  base::AutoLock lock(log_pipes_lock_);
  for (auto managed_log_dir : managed_log_dirs_) {
    LOG(INFO) << "Rotating logs in " << managed_log_dir;
    syslog::Rotator rotator;
    rotator.RotateLogFiles(managed_log_dir, kMaxFilesPerLog);
  }
  for (auto& it : log_pipes_) {
    it.second->Reopen();
  }
}

}  // namespace syslog
}  // namespace vm_tools
