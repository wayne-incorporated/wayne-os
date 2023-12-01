// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/startup_listener_impl.h"

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>

namespace vm_tools {
namespace concierge {

grpc::Status StartupListenerImpl::VmReady(grpc::ServerContext* ctx,
                                          const vm_tools::EmptyMessage* request,
                                          vm_tools::EmptyMessage* response) {
  uint64_t cid = 0;
  if (sscanf(ctx->peer().c_str(), "vsock:%" PRIu64, &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address " << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid peer for StartupListener");
  }

  base::AutoLock lock(vm_lock_);
  auto iter = pending_vms_.find(cid);
  if (iter == pending_vms_.end()) {
    LOG(ERROR) << "Received VmReady from vm with unknown context id: " << cid;
    return grpc::Status(grpc::FAILED_PRECONDITION, "VM is not known");
  }

  // Signal to the main concierge thread that this VM is ready. Note we have to
  // write 8 bytes to an event fd for successful signaling.
  int64_t dummy = 1;
  if (HANDLE_EINTR(write(iter->second, &dummy, sizeof(dummy))) <
      sizeof(dummy)) {
    LOG(ERROR) << "Failed to signal event fd for context id: " << cid;
    return grpc::Status(grpc::FAILED_PRECONDITION, "Failed to signal event fd");
  }
  pending_vms_.erase(iter);
  return grpc::Status::OK;
}

grpc::Status StartupListenerImpl::VmInstallStatus(
    grpc::ServerContext* ctx,
    const vm_tools::VmInstallState* status,
    vm_tools::EmptyMessage* response) {
  LOG(INFO) << "Received VM install status: " << status->state();
  LOG(INFO) << "Install Step:" << status->in_progress_step();
  return grpc::Status::OK;
}

void StartupListenerImpl::AddPendingVm(uint32_t cid, int32_t event_fd) {
  base::AutoLock lock(vm_lock_);
  pending_vms_[cid] = event_fd;
}

void StartupListenerImpl::RemovePendingVm(uint32_t cid) {
  base::AutoLock lock(vm_lock_);

  pending_vms_.erase(cid);
}

}  // namespace concierge
}  // namespace vm_tools
