// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef VM_TOOLS_SYSLOG_HOST_COLLECTOR_H_
#define VM_TOOLS_SYSLOG_HOST_COLLECTOR_H_

#include <memory>

#include <chromeos/dbus/service_constants.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <dbus/message.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

#include "vm_tools/syslog/collector.h"

namespace vm_tools {
namespace syslog {

class LogPipeManager;

// Responsible for listening on logsocket for any userspace applications that
// wish to log messages.
class HostCollector : public Collector {
 public:
  ~HostCollector() override;

  static std::unique_ptr<HostCollector> Create(
      scoped_refptr<dbus::Bus> bus,
      int64_t cid,
      base::FilePath logsocket_path,
      VmKernelLogRequest::VmType vm_type,
      base::WeakPtr<LogPipeManager> log_pipe_manager);

  static std::unique_ptr<HostCollector> CreateForTesting(
      int64_t cid,
      base::ScopedFD syslog_fd,
      base::WeakPtr<LogPipeManager> log_pipe_manager);

 protected:
  // Sends logs to LogPipeManager.
  bool SendUserLogs() override;

 private:
  // Protected default constructor.  Use the static factory function to create
  // new instances of this class.
  explicit HostCollector(scoped_refptr<dbus::Bus> bus,
                         int64_t cid,
                         VmKernelLogRequest::VmType vm_type,
                         base::WeakPtr<LogPipeManager> log_pipe_manager);
  HostCollector(const HostCollector&) = delete;
  HostCollector& operator=(const HostCollector&) = delete;

  int64_t cid_;

  base::WeakPtr<LogPipeManager> log_pipe_manager_;

  dbus::ObjectProxy* anomaly_detector_proxy_ = nullptr;
  VmKernelLogRequest::VmType vm_type_;

  base::WeakPtrFactory<Collector> weak_factory_;
};

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_HOST_COLLECTOR_H_
