// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/forwarder.h"

#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <array>
#include <cinttypes>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "vm_tools/syslog/scrubber.h"

using std::string;

namespace vm_tools {
namespace syslog {
Forwarder::Forwarder(base::ScopedFD destination, bool is_socket_destination)
    : destination_(std::move(destination)),
      is_socket_destination_(is_socket_destination) {}

void Forwarder::SetFileDestination(base::ScopedFD destination) {
  CHECK(destination.is_valid());
  is_socket_destination_ = false;
  if (destination_.get() != destination.get())
    destination_ = std::move(destination);
}

grpc::Status Forwarder::ForwardLogs(int64_t cid,
                                    const vm_tools::LogRequest& request) {
  CHECK(destination_.is_valid());
  string prefix = base::StringPrintf(" VM(%" PRId64 "): ", cid);

  std::vector<string> priorities, timestamps, contents;
  priorities.reserve(request.records_size());
  timestamps.reserve(request.records_size());
  contents.reserve(request.records_size());

  constexpr uint8_t kIovCount = 4;
  std::vector<std::array<struct iovec, kIovCount>> iovs;
  iovs.reserve(request.records_size());

  std::vector<struct mmsghdr> msgs;
  msgs.reserve(request.records_size());

  for (const vm_tools::LogRecord& record : request.records()) {
    priorities.emplace_back(ParseProtoSeverity(record.severity()));
    timestamps.emplace_back(ParseProtoTimestamp(record.timestamp()));
    contents.emplace_back(ScrubProtoContent(record.content()));

    if (is_socket_destination_) {
      // Build the message.
      iovs.emplace_back(std::array<struct iovec, kIovCount>{{
          {
              .iov_base = static_cast<void*>(
                  const_cast<char*>(priorities.back().c_str())),
              .iov_len = priorities.back().size(),
          },
          {
              .iov_base = static_cast<void*>(
                  const_cast<char*>(timestamps.back().c_str())),
              .iov_len = timestamps.back().size(),
          },
          {
              .iov_base = static_cast<void*>(const_cast<char*>(prefix.c_str())),
              .iov_len = prefix.size(),
          },
          {
              .iov_base = static_cast<void*>(
                  const_cast<char*>(contents.back().c_str())),
              .iov_len = contents.back().size(),
          },
      }});

      msgs.emplace_back((struct mmsghdr){
          // clang-format off
          .msg_hdr = {
              .msg_name = nullptr,
              .msg_namelen = 0,
              .msg_iov = iovs.back().data(),
              .msg_iovlen = iovs.back().size(),
              .msg_control = nullptr,
              .msg_controllen = 0,
              .msg_flags = 0,
          },
          // clang-format on
          .msg_len = 0,
      });
    }
  }

  if (is_socket_destination_) {
    if (sendmmsg(destination_.get(), msgs.data(), msgs.size(), 0 /*flags*/) !=
        msgs.size()) {
      PLOG(ERROR) << "Failed to send log records to syslog daemon";
      return grpc::Status(grpc::INTERNAL,
                          "failed to send log records to syslog daemon");
    }
  } else {
    // Write messages to file
    std::ostringstream lines_stream;
    for (int i = 0; i < request.records_size(); ++i) {
      lines_stream << timestamps[i] << " " << priorities[i] << " " << prefix
                   << contents[i] << "\n";
    }
    const std::string lines = lines_stream.str();
    if (!base::WriteFileDescriptor(destination_.get(), lines)) {
      PLOG(ERROR) << "Failed to write log records to file" << lines;
      return grpc::Status(grpc::INTERNAL,
                          "failed to write log records to file");
    }
  }

  return grpc::Status::OK;
}

}  // namespace syslog
}  // namespace vm_tools
