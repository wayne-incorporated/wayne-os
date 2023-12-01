// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vmm_swap_low_disk_policy.h"

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <spaced/disk_usage_proxy.h>
#include <utility>

namespace vm_tools::concierge {

VmmSwapLowDiskPolicy::VmmSwapLowDiskPolicy(
    base::FilePath swap_dir, raw_ref<spaced::DiskUsageProxy> disk_usage_policy)
    : disk_usage_policy_(disk_usage_policy), swap_dir_(swap_dir) {}

void VmmSwapLowDiskPolicy::CanEnable(int64_t guest_memory_size,
                                     base::OnceCallback<void(bool)> callback) {
  disk_usage_policy_->GetFreeDiskSpaceAsync(
      swap_dir_,
      base::BindOnce(
          [](base::OnceCallback<void(bool)> callback, int64_t guest_memory_size,
             int64_t free_size) {
            if (free_size < 0) {
              LOG(ERROR) << "Failed to get free disk space from spaced";
              std::move(callback).Run(false);
              return;
            }
            std::move(callback).Run(
                free_size >= (kTargetMinimumFreeDiskSpace + guest_memory_size));
          },
          std::move(callback), guest_memory_size));
}

}  // namespace vm_tools::concierge
