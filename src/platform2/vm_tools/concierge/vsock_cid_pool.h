// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VSOCK_CID_POOL_H_
#define VM_TOOLS_CONCIERGE_VSOCK_CID_POOL_H_

#include <stdint.h>

namespace vm_tools {
namespace concierge {

// Manages a pool of virtual socket context IDs to be assigned to VMs.
class VsockCidPool {
 public:
  VsockCidPool() = default;
  VsockCidPool(const VsockCidPool&) = delete;
  VsockCidPool& operator=(const VsockCidPool&) = delete;

  ~VsockCidPool() = default;

  // Allocates and returns a vsock context id.  Returns 0 if it is unable to
  // allocate a cid because 0 is a reserved cid.
  uint32_t Allocate();
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VSOCK_CID_POOL_H_
