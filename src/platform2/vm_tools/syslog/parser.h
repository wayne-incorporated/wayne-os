// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SYSLOG_PARSER_H_
#define VM_TOOLS_SYSLOG_PARSER_H_

#include <stdint.h>

#include <base/time/time.h>
#include <vm_protos/proto_bindings/vm_host.pb.h>

namespace vm_tools {
namespace syslog {

// Parse the priority value out of a syslog record.  If successful, stores the
// LogSeverity in |severity| and returns the number of bytes consumed from
// |buf|.  Returns 0 on failure and leaves severity unchanged.
size_t ParseSyslogPriority(const char* buf, vm_tools::LogSeverity* severity);

// Parse the timestamp out of a syslog record.  If successful, stores the
// timestamp in |timestamp| and returns the number of bytes consumed from the
// buffer.  Returns 0 on failure and stores the current time in |timestamp|,
size_t ParseSyslogTimestamp(const char* buf, vm_tools::Timestamp* timestamp);

// Parse a syslog record according to RFC3164 and store it in |record|.  Returns
// true if successful.  |buf| must be a null-terminated string.  Returns false
// and clears |record| if |buf| contains an invalid syslog record.
bool ParseSyslogRecord(const char* buf,
                       size_t len,
                       vm_tools::LogRecord* record);

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_PARSER_H_
