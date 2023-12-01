// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/host_collector.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/un.h>

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>

#include "vm_tools/syslog/log_pipe.h"

namespace pb = google::protobuf;

namespace vm_tools {
namespace syslog {

HostCollector::HostCollector(scoped_refptr<dbus::Bus> bus,
                             int64_t cid,
                             VmKernelLogRequest::VmType vm_type,
                             base::WeakPtr<LogPipeManager> log_pipe_manager)
    : cid_(cid),
      log_pipe_manager_(log_pipe_manager),
      vm_type_(vm_type),
      weak_factory_(this) {
  if (bus) {
    anomaly_detector_proxy_ = bus->GetObjectProxy(
        anomaly_detector::kAnomalyEventServiceName,
        dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath));
    if (!anomaly_detector_proxy_) {
      LOG(ERROR) << "Failed to get anomaly_detector object proxy";
    }
  }
}

HostCollector::~HostCollector() = default;

std::unique_ptr<HostCollector> HostCollector::Create(
    scoped_refptr<dbus::Bus> bus,
    int64_t cid,
    base::FilePath logsocket_path,
    VmKernelLogRequest::VmType vm_type,
    base::WeakPtr<LogPipeManager> log_pipe_manager) {
  LOG(INFO) << "Creating HostCollector watching " << logsocket_path;
  auto collector = base::WrapUnique<HostCollector>(
      new HostCollector(bus, cid, vm_type, log_pipe_manager));
  if (!collector->BindLogSocket(logsocket_path)) {
    collector.reset();
    return collector;
  }

  if (!collector->StartWatcher(kFlushPeriod)) {
    collector.reset();
  }

  return collector;
}

std::unique_ptr<HostCollector> HostCollector::CreateForTesting(
    int64_t cid,
    base::ScopedFD syslog_fd,
    base::WeakPtr<LogPipeManager> log_pipe_manager) {
  CHECK(log_pipe_manager);
  CHECK(syslog_fd.is_valid());

  auto collector = base::WrapUnique(new HostCollector(
      /*bus=*/nullptr, cid, /*vm_type=*/VmKernelLogRequest::UNKNOWN,
      log_pipe_manager));
  collector->SetSyslogFDForTesting(std::move(syslog_fd));

  if (!collector->StartWatcher(kFlushPeriodForTesting)) {
    collector.reset();
  }

  return collector;
}

bool HostCollector::SendUserLogs() {
  if (!log_pipe_manager_) {
    return false;
  }
  // We call LogPipeManager directly rather than through a stub because
  // we're in the same process.
  grpc::Status status =
      log_pipe_manager_->WriteSyslogRecords(cid_, syslog_request());

  if (!anomaly_detector_proxy_)
    return status.ok();

  dbus::MethodCall method_call(anomaly_detector::kAnomalyEventServiceInterface,
                               anomaly_detector::kAnomalyVmKernelLogMethod);
  dbus::MessageWriter writer(&method_call);

  VmKernelLogRequest request;
  request.set_vm_type(vm_type_);
  request.set_cid(cid_);
  *request.mutable_records() = syslog_request().records();

  writer.AppendProtoAsArrayOfBytes(request);
  anomaly_detector_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce([](dbus::Response* response) {
        if (!response) {
          LOG(ERROR) << "anomaly_detector failed to take VM log message!";
        }
      }));

  return status.ok();
}

}  // namespace syslog
}  // namespace vm_tools
