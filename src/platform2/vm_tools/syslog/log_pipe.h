// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef VM_TOOLS_SYSLOG_LOG_PIPE_H_
#define VM_TOOLS_SYSLOG_LOG_PIPE_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <base/thread_annotations.h>
#include <base/timer/timer.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

#include "vm_tools/common/vm_id.h"
#include "vm_tools/syslog/forwarder.h"
#include "vm_tools/syslog/host_collector.h"

namespace dbus {
class Signal;
}  // namespace dbus

namespace vm_tools {
class LogRequest;

namespace syslog {

// LogPipe holds an HostCollector and associated Forwarder.
class LogPipe {
 public:
  static std::unique_ptr<LogPipe> Create(scoped_refptr<dbus::Bus> bus,
                                         int64_t cid,
                                         const vm_tools::VmId& id,
                                         base::ScopedFD dest,
                                         VmKernelLogRequest::VmType vm_type,
                                         base::WeakPtr<LogPipeManager> manager);

  static std::unique_ptr<LogPipe> CreateForTesting(
      int64_t cid,
      const vm_tools::VmId& id,
      base::ScopedFD dest,
      base::ScopedFD collector_fd,
      base::WeakPtr<LogPipeManager> manager);

  grpc::Status ForwardLogs(int64_t cid, const LogRequest& log_request);
  void Reopen();
  void Flush();

 private:
  LogPipe(VmId vm_id,
          std::unique_ptr<HostCollector> collector,
          std::unique_ptr<Forwarder> forwarder);
  LogPipe(const LogPipe&) = delete;
  LogPipe& operator=(const LogPipe&) = delete;

  VmId vm_id_;
  std::unique_ptr<HostCollector> collector_;
  std::unique_ptr<Forwarder> forwarder_;
};

// LogPipeManager maintains a map LogPipe instances, updated in response to
// VmStartingUpSignal from Concierge.
// It also implements LogCollector::Service, serializing writes to the correct
// LogPipe.
// It schedules periodic file rotation in the set of managed log directories of
// known VMs.
// It listens for SIGTERM to shut down.
class LogPipeManager final : public LogCollector::Service {
 public:
  explicit LogPipeManager(base::OnceClosure shutdown_closure);
  LogPipeManager(const LogPipeManager&) = delete;
  LogPipeManager& operator=(const LogPipeManager&) = delete;

  ~LogPipeManager();

  bool Init(base::ScopedFD syslog_fd, bool only_forward_to_syslog);

  void OnVmStartingUpSignal(dbus::Signal* signal);
  void OnVmStoppedSignal(dbus::Signal* signal);

  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool is_connected);

  grpc::Status WriteSyslogRecords(int64_t cid, const LogRequest& log_request);
  void OnSigterm();

  void CreateLogPipeForTesting(int64_t cid,
                               const vm_tools::VmId& id,
                               base::ScopedFD syslog_fd,
                               base::ScopedFD collector_fd);

 private:
  // vm_tools::LogCollector::Service overrides.
  grpc::Status CollectKernelLogs(grpc::ServerContext* ctx,
                                 const vm_tools::LogRequest* request,
                                 vm_tools::EmptyMessage* response) override;
  grpc::Status CollectUserLogs(grpc::ServerContext* ctx,
                               const vm_tools::LogRequest* request,
                               vm_tools::EmptyMessage* response) override;

  void ConnectToConcierge();
  bool SetupSigtermHandler();
  void RotateLogs();

  bool is_vm_started_signal_connected_ = false;
  bool is_vm_stopped_signal_connected_ = false;

  std::set<base::FilePath> managed_log_dirs_;

  base::Lock log_pipes_lock_;
  std::map<int64_t, std::unique_ptr<LogPipe>> log_pipes_
      GUARDED_BY(log_pipes_lock_);

  bool only_forward_to_syslog_ = false;
  // Used exclusively when |only_forward_to_syslog_| is true, otherwise used
  // as a log destination for unrecognized VMs (cid not a key in |log_pipes_|).
  std::unique_ptr<Forwarder> syslog_forwarder_;

  // Timer used for periodically rotating log files in |managed_log_dirs_|.
  base::RepeatingTimer timer_;
  base::OnceClosure shutdown_closure_;

  // Task runner for the D-Bus thread. Operations like connecting to dBus
  // signals need to be posted to this runner.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // File descriptor and watcher for the SIGTERM event.
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  scoped_refptr<dbus::Bus> bus_;

  base::WeakPtrFactory<LogPipeManager> weak_ptr_factory_;
};

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_LOG_PIPE_H_
