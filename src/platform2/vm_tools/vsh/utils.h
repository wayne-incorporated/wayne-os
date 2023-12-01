// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_VSH_UTILS_H_
#define VM_TOOLS_VSH_UTILS_H_

// Generic utility functions that need to be shared between the vsh client
// and server.

#include <string>

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <base/files/scoped_file.h>
#include <base/logging.h>

#include <google/protobuf/message_lite.h>

namespace vm_tools {
namespace vsh {

// Path to the /dev node for the controlling terminal.
constexpr char kDevTtyPath[] = "/dev/tty";

// Maximum amount of data that can be sent in a single DataMessage. This is
// picked based on the max message size with generous room for protobuf
// overhead.
constexpr int kMaxDataSize = 4000;

// Maximum size allowed for a single protobuf message.
constexpr int kMaxMessageSize = 4096;

// Reserved keyword for connecting to the VM shell instead of a container.
// All lxd containers must also be valid hostnames, so any string that is
// not a valid hostname will work here without colliding with lxd's naming.
constexpr char kVmShell[] = "/vm_shell";

// Sends a protobuf MessageLite to the given socket fd.
bool SendMessage(int sockfd, const google::protobuf::MessageLite& message);

// Receives a protobuf MessageLite from the given socket fd.
bool RecvMessage(int sockfd, google::protobuf::MessageLite* message);

// Posts a task to the main message loop to shut down.
void Shutdown();

// Format a log message for dmesg and write it to the given fd.
bool WriteKernelLogToFd(int fd,
                        logging::LogSeverity severity,
                        std::string_view prefix,
                        const std::string& message,
                        size_t message_start);

}  // namespace vsh
}  // namespace vm_tools

#endif  // VM_TOOLS_VSH_UTILS_H_
