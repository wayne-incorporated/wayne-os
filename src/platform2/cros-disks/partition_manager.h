// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_PARTITION_MANAGER_H_
#define CROS_DISKS_PARTITION_MANAGER_H_

#include <memory>
#include <set>
#include <string>

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/disk_monitor.h"
#include "cros-disks/sandboxed_process.h"

namespace cros_disks {

using PartitionCompleteCallback =
    base::OnceCallback<void(const base::FilePath&, PartitionError)>;

class PartitionManager {
 public:
  PartitionManager(brillo::ProcessReaper* process_reaper,
                   DiskMonitor* disk_monitor)
      : process_reaper_(process_reaper), disk_monitor_(disk_monitor) {}
  PartitionManager(const PartitionManager&) = delete;
  PartitionManager& operator=(const PartitionManager&) = delete;

  virtual ~PartitionManager() = default;

  // Starts a partition process of a given device to partition it into one
  // partition.
  void StartSinglePartitionFormat(const base::FilePath& device_path,
                                  PartitionCompleteCallback callback);

 protected:
  // virtual to be used for testing purpose.
  virtual std::unique_ptr<SandboxedProcess> CreateSandboxedProcess() const;

 private:
  void OnPartitionProcessTerminated(const base::FilePath& device_path,
                                    PartitionCompleteCallback callback,
                                    const siginfo_t& info);

  brillo::ProcessReaper* process_reaper_;

  // A list of outstanding partitioning processes indexed by device path.
  std::set<base::FilePath> partition_process_;

  DiskMonitor* disk_monitor_;

  base::WeakPtrFactory<PartitionManager> weak_ptr_factory_{this};
};

}  // namespace cros_disks

#endif  // CROS_DISKS_PARTITION_MANAGER_H_
