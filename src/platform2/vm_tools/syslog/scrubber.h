// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SYSLOG_SCRUBBER_H_
#define VM_TOOLS_SYSLOG_SCRUBBER_H_

#include <string>

#include <vm_protos/proto_bindings/vm_host.grpc.pb.h>

namespace vm_tools {
namespace syslog {

// Parses |severity| and returns a string that can be used as a valid PRI part
// of a syslog message.
std::string ParseProtoSeverity(vm_tools::LogSeverity severity);

// Parses |timestamp| into an RFC3164 compliant string that can be included as
// part of a syslog message.
std::string ParseProtoTimestamp(const vm_tools::Timestamp& timestamp);

// Scrubs |content| and returns a valid UTF-8 string. Assumes |content| is
// encoded as UTF-8. Invalid code points are replaced with (U+fffd). Control
// characters and other valid but non-character code points are converted into
// octal numbers with a minimum width of 3 digits and prefixed with '#'. For
// example if the BEL character (U+0007) appears in |content| it will be
// converted to "#007".
std::string ScrubProtoContent(const std::string& content);

}  // namespace syslog
}  // namespace vm_tools

#endif  // VM_TOOLS_SYSLOG_SCRUBBER_H_
