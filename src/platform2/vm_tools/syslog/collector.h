// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SYSLOG_COLLECTOR_H_
#define VM_TOOLS_SYSLOG_COLLECTOR_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <google/protobuf/arena.h>
#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

namespace vm_tools {
namespace syslog {

class Collector {
 public:
  virtual ~Collector();

  void SetSyslogFDForTesting(base::ScopedFD syslog_fd);

  // Called periodically to flush any logs that have been buffered.
  void FlushLogs();

 protected:
  // Override SendUserLogs to deliver logs to listening services.
  virtual bool SendUserLogs() = 0;

  bool BindLogSocket(const base::FilePath& name);

  bool StartWatcher(base::TimeDelta flush_period);

  // Called when |syslog_fd_| becomes readable.
  void OnSyslogReadable();

  const LogRequest& syslog_request() const { return *syslog_request_; }

  // Periodic interval for flushing buffered logs.
  static constexpr base::TimeDelta kFlushPeriod = base::Milliseconds(5000);

  // Periodic interval for flushing buffered logs during testing.
  static constexpr base::TimeDelta kFlushPeriodForTesting =
      base::Milliseconds(500);

 private:
  // File descriptor bound to logging socket.
  base::ScopedFD syslog_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> syslog_controller_;

  // Shared arena used for allocating log records.
  google::protobuf::Arena arena_;

  // Non-owning pointer to the current syslog LogRequest.  Owned by arena_.
  vm_tools::LogRequest* syslog_request_;

  // Size of all the currently buffered log records.
  size_t buffered_size_;

  // Timer used for periodically flushing buffered log records.
  base::RepeatingTimer timer_;

  // Reads one log record from the socket and adds it to |syslog_request_|.
  // Returns true if there may still be more data to read from the socket.
  bool ReadOneSyslogRecord();

  base::WeakPtrFactory<Collector> weak_factory_{this};
};

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_COLLECTOR_H_
