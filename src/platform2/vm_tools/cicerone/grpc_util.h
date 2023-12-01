// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_GRPC_UTIL_H_
#define VM_TOOLS_CICERONE_GRPC_UTIL_H_

#include <grpcpp/grpcpp.h>

namespace vm_tools {
namespace cicerone {

// How long to wait before timing out on regular RPCs.
constexpr int64_t kDefaultTimeoutSeconds = 60;

// How long to wait before timing out on connecting to Tremplin or Garcon.
constexpr int64_t kConnectTimeoutSeconds = 5;

// How long to wait while doing more complex operations like starting or
// creating a container.
constexpr int64_t kLongOperationTimeoutSeconds = 120;

gpr_timespec ToGprDeadline(int64_t seconds);

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_GRPC_UTIL_H_
