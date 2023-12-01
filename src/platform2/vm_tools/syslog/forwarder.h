// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SYSLOG_FORWARDER_H_
#define VM_TOOLS_SYSLOG_FORWARDER_H_

#include <memory>

#include <base/files/scoped_file.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

namespace vm_tools {
namespace syslog {

// Responsible for collecting log records from the VM, scrubbing them,
// and then forwarding them to the host syslog daemon.
class Forwarder {
 public:
  explicit Forwarder(base::ScopedFD destination,
                     bool is_socket_destination = true);
  Forwarder(const Forwarder&) = delete;
  Forwarder& operator=(const Forwarder&) = delete;

  ~Forwarder() = default;

  // Common implementation for actually forwarding logs to the syslog daemon.
  grpc::Status ForwardLogs(int64_t cid, const vm_tools::LogRequest& request);

  void SetFileDestination(base::ScopedFD destination);
  bool is_socket_destination() const { return is_socket_destination_; }

 private:
  base::ScopedFD destination_;
  bool is_socket_destination_;
};

}  // namespace syslog
}  // namespace vm_tools

#endif  //  VM_TOOLS_SYSLOG_FORWARDER_H_
