// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VMM_SWAP_LOW_DISK_POLICY_H_
#define VM_TOOLS_CONCIERGE_VMM_SWAP_LOW_DISK_POLICY_H_

#include <memory>

#include <base/files/file_path.h>
#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>
#include <spaced/disk_usage_proxy.h>

namespace vm_tools::concierge {

// Allow enabling vmm-swap only when there is enough disk space available.
class VmmSwapLowDiskPolicy final {
 public:
  VmmSwapLowDiskPolicy(base::FilePath swap_dir,
                       raw_ref<spaced::DiskUsageProxy> disk_usage_policy);
  VmmSwapLowDiskPolicy(const VmmSwapLowDiskPolicy&) = delete;
  VmmSwapLowDiskPolicy& operator=(const VmmSwapLowDiskPolicy&) = delete;

  // 2 GiB which cryptohome starts cleaning up disk space
  // (`cryptohome::kTargetFreeSpaceAfterCleanup`) and spaced sends a low disk
  // signal for (`spaced::GetDiskSpaceState`).
  static constexpr int64_t kTargetMinimumFreeDiskSpace = 2LL << 30;

  // Returns whether there is enough disk space even after vmm-swap is enabled.
  //
  // If there is not enough disk space and enabling vmm-swap can be predicted to
  // cause low disk warning from spaced, vmm-swap is not allowed to enable.
  void CanEnable(const int64_t guest_memory_size,
                 base::OnceCallback<void(bool)> callback);

 private:
  // Proxy for interacting with spaced.
  const raw_ref<spaced::DiskUsageProxy> disk_usage_policy_;
  const base::FilePath swap_dir_;
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_VMM_SWAP_LOW_DISK_POLICY_H_
