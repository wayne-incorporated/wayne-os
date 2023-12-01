// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/guest_metrics.h"

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/numerics/safe_conversions.h>
#include <base/ranges/algorithm.h>
#include <base/system/sys_info.h>
#include <base/time/time.h>

#include <dbus/exported_object.h>
#include <dbus/object_proxy.h>
#include <dbus/vm_concierge/dbus-constants.h>
#include <vm_concierge/concierge_service.pb.h>

namespace vm_tools {
namespace cicerone {

// chromeos_metrics::CumulativeMetrics constants:
constexpr base::TimeDelta kDailyUpdatePeriod = base::Minutes(5);
constexpr base::TimeDelta kDailyAccumulatePeriod = base::Hours(24);
constexpr char kDailyMetricsBackingDir[] = "/var/lib/vm_cicerone/metrics/daily";

// Borealis metric IDs
constexpr char kBorealisSwapBytesRead[] = "Borealis.Disk.SwapReadsDaily";
constexpr char kBorealisSwapBytesReadGuest[] = "borealis-swap-kb-read";

constexpr char kBorealisSwapBytesWritten[] = "Borealis.Disk.SwapWritesDaily";
constexpr char kBorealisSwapBytesWrittenGuest[] = "borealis-swap-kb-written";

constexpr char kBorealisDiskBytesRead[] = "Borealis.Disk.StatefulReadsDaily";
constexpr char kBorealisDiskBytesReadGuest[] = "borealis-disk-kb-read";

constexpr char kBorealisDiskBytesWritten[] =
    "Borealis.Disk.StatefulWritesDaily";
constexpr char kBorealisDiskBytesWrittenGuest[] = "borealis-disk-kb-written";

constexpr char kBorealisAudioUsedSubdevices[] = "Borealis.Audio.UsedSubdevices";
constexpr char kBorealisAudioUsedSubdevicesGuest[] =
    "borealis-audio-used-subdevices";

constexpr char kBorealisDiskHighestDirtyPagesDaily[] =
    "Borealis.Disk.HighestDirtyPagesDaily";
constexpr char kBorealisDiskHighestDirtyPagesDailyGuest[] =
    "borealis-dirty-pages";

constexpr char kBorealisStartupFsckResult[] = "Borealis.Startup.fsckResult";
constexpr char kBorealisStartupFsckResultGuest[] = "borealis-fsck-result";

constexpr char kBorealisStartupFsckTime[] = "Borealis.Startup.fsckTime";
constexpr char kBorealisStartupFsckTimeGuest[] = "borealis-fsck-runtime";

// Borealis space related metric IDs
// note: The guest reports how many inodes are being used in the guest
// and then we get information about guest/host space from concierge to
// calculate these metrics.

constexpr char kBorealisDiskInodeCountAtStartupGuest[] = "borealis-inode-count";

constexpr char kBorealisDiskInodeRatioAtStartup[] =
    "Borealis.Disk.InodeRatioAtStartup";
constexpr char kBorealisDiskVMUsageToTotalSpacePercentageAtStartup[] =
    "Borealis.Disk.VMUsageToTotalSpacePercentageAtStartup";
constexpr char kBorealisDiskVMUsageToTotalUsagePercentageAtStartup[] =
    "Borealis.Disk.VMUsageToTotalUsagePercentageAtStartup";

// Crostini metric IDs
constexpr char kCrostiniSwapBytesRead[] = "Crostini.Disk.SwapReadsDaily";
constexpr char kCrostiniSwapBytesReadGuest[] = "crostini-swap-kb-read";

constexpr char kCrostiniSwapBytesWritten[] = "Crostini.Disk.SwapWritesDaily";
constexpr char kCrostiniSwapBytesWrittenGuest[] = "crostini-swap-kb-written";

constexpr char kCrostiniDiskBytesRead[] = "Crostini.Disk.StatefulReadsDaily";
constexpr char kCrostiniDiskBytesReadGuest[] = "crostini-disk-kb-read";

constexpr char kCrostiniDiskBytesWritten[] =
    "Crostini.Disk.StatefulWritesDaily";
constexpr char kCrostiniDiskBytesWrittenGuest[] = "crostini-disk-kb-written";

// Helper function that maps an fsck result to it's respective enum.
BorealisFsckResult MapFsckResultToEnum(int fsck_result) {
  // See exit codes for fsck from: https://linux.die.net/man/8/fsck.
  if (fsck_result > 191) {
    // 191 is the highest possible documented error code for fsck (sum
    // of all errors).
    return BorealisFsckResult::kUnexpected;
  }
  switch (fsck_result) {
    case 0:
      return BorealisFsckResult::kNoErrors;
      break;
    case 1:
      return BorealisFsckResult::kErrorsCorrected;
      break;
    case 2:
      return BorealisFsckResult::kSystemShouldReboot;
      break;
    case 4:
      return BorealisFsckResult::kErrorsLeftUncorrected;
      break;
    case 8:
      return BorealisFsckResult::kOperationalError;
      break;
    case 16:
      return BorealisFsckResult::kUsageError;
      break;
    case 32:
      return BorealisFsckResult::kCancelled;
      break;
    case 128:
      return BorealisFsckResult::kSharedLibraryError;
      break;
    default:
      // If the exit code is less than 191 and not one of the error codes,
      // then it must be a combined error (sum of one or more errors).
      return BorealisFsckResult::kCombinedError;
      break;
  }
}

int64_t GuestMetrics::SysinfoProvider::AmountOfTotalDiskSpace(
    base::FilePath path) {
  return base::SysInfo::AmountOfTotalDiskSpace(path);
}

int64_t GuestMetrics::SysinfoProvider::AmountOfFreeDiskSpace(
    base::FilePath path) {
  return base::SysInfo::AmountOfFreeDiskSpace(path);
}

GuestMetrics::GuestMetrics(scoped_refptr<dbus::Bus> bus)
    : GuestMetrics(bus, base::FilePath(kDailyMetricsBackingDir)) {}

GuestMetrics::GuestMetrics(scoped_refptr<dbus::Bus> bus,
                           base::FilePath cumulative_metrics_path)
    : bus_(bus),
      daily_metrics_(cumulative_metrics_path,
                     {kBorealisSwapBytesRead, kBorealisSwapBytesWritten,
                      kBorealisDiskBytesRead, kBorealisDiskBytesWritten,
                      kBorealisDiskHighestDirtyPagesDaily,
                      kCrostiniSwapBytesRead, kCrostiniSwapBytesWritten,
                      kCrostiniDiskBytesRead, kCrostiniDiskBytesWritten},
                     kDailyUpdatePeriod,
                     base::BindRepeating(&GuestMetrics::UpdateDailyMetrics,
                                         base::Unretained(this)),
                     kDailyAccumulatePeriod,
                     base::BindRepeating(&GuestMetrics::ReportDailyMetrics,
                                         base::Unretained(this))),
      metrics_lib_(std::make_unique<MetricsLibrary>()),
      sysinfo_provider_(std::make_unique<SysinfoProvider>()),
      weak_ptr_factory_(this) {}

void GuestMetrics::GenerateSpaceMetrics(const std::string& owner_id,
                                        const std::string& vm_name,
                                        int inode_count) {
  // Request vm disks from concierge.
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kListVmDisksMethod);
  vm_tools::concierge::ListVmDisksRequest request;
  dbus::MessageWriter writer(&method_call);

  request.set_cryptohome_id(owner_id);
  request.set_storage_location(
      vm_tools::concierge::StorageLocation::STORAGE_CRYPTOHOME_ROOT);
  request.set_vm_name(vm_name);
  writer.AppendProtoAsArrayOfBytes(request);
  bus_->GetObjectProxy(
          vm_tools::concierge::kVmConciergeServiceName,
          dbus::ObjectPath(vm_tools::concierge::kVmConciergeServicePath))
      ->CallMethod(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          base::BindOnce(&GuestMetrics::HandleListVmDisksDbusResponse,
                         weak_ptr_factory_.GetWeakPtr(), vm_name, inode_count));
}

void GuestMetrics::HandleListVmDisksDbusResponse(
    const std::string& vm_name,
    int inode_count,
    dbus::Response* dbus_response) {
  vm_tools::concierge::ListVmDisksResponse response;
  if (!dbus_response) {
    LOG(ERROR) << "Failed to list vm disks from concierege";
    return;
  }
  dbus::MessageReader reader(dbus_response);
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Unable to parse ListVmDisksResponse from message";
    return;
  }
  auto image = base::ranges::find(response.images(), vm_name,
                                  &vm_tools::concierge::VmDiskInfo::name);
  if (image == response.images().end()) {
    LOG(ERROR) << "no VM found with name " << vm_name;
    return;
  }

  // Max value 10MB. This represents how large, on average, each file in
  // Borealis is. We currently preallocate inodes with the assumption
  // that the average size is 32KiB.
  metrics_lib_->SendToUMA(
      kBorealisDiskInodeRatioAtStartup,
      static_cast<int>(static_cast<float>((image->size()) /
                                          static_cast<float>(inode_count)) /
                       1024),
      0, 10240, 50);

  int64_t total_space = sysinfo_provider_->AmountOfTotalDiskSpace(
      base::FilePath(image->path()).DirName());
  if (total_space <= 0) {
    LOG(ERROR) << "Failed to get total disk space for "
               << base::FilePath(image->path()).DirName();
    return;
  }
  metrics_lib_->SendPercentageToUMA(
      kBorealisDiskVMUsageToTotalSpacePercentageAtStartup,
      static_cast<int>(static_cast<float>(image->size()) /
                       static_cast<float>(total_space) * 100));

  int64_t free_space = sysinfo_provider_->AmountOfFreeDiskSpace(
      base::FilePath(image->path()).DirName());
  if (free_space <= 0) {
    LOG(ERROR) << "Failed to get free disk space for "
               << base::FilePath(image->path()).DirName();
    return;
  }

  int64_t total_used_space = total_space - free_space;
  if (total_used_space <= 0) {
    LOG(ERROR) << "Free space greater than total space";
    return;
  }
  metrics_lib_->SendPercentageToUMA(
      kBorealisDiskVMUsageToTotalUsagePercentageAtStartup,
      static_cast<int>(static_cast<float>(image->size()) /
                       static_cast<float>(total_used_space) * 100));
}

bool GuestMetrics::HandleMetric(const std::string& owner_id,
                                const std::string& vm_name,
                                const std::string& container_name,
                                const std::string& name,
                                int value) {
  // This is the central handling point for all metrics emitted by VMs.
  if (vm_name == "borealis" && container_name == "penguin") {
    // Metrics emitted by Borealis VMs.
    if (name == kBorealisSwapBytesReadGuest) {
      daily_metrics_.Add(kBorealisSwapBytesRead, value);
    } else if (name == kBorealisSwapBytesWrittenGuest) {
      daily_metrics_.Add(kBorealisSwapBytesWritten, value);
    } else if (name == kBorealisDiskBytesReadGuest) {
      daily_metrics_.Add(kBorealisDiskBytesRead, value);
    } else if (name == kBorealisDiskBytesWrittenGuest) {
      daily_metrics_.Add(kBorealisDiskBytesWritten, value);
    } else if (name == kBorealisDiskHighestDirtyPagesDailyGuest) {
      if (daily_metrics_.Get(kBorealisDiskHighestDirtyPagesDaily) < value)
        daily_metrics_.Set(kBorealisDiskHighestDirtyPagesDaily, value);
    } else if (name == kBorealisDiskInodeCountAtStartupGuest) {
      GenerateSpaceMetrics(owner_id, vm_name, value);
    } else if (name == kBorealisStartupFsckResultGuest) {
      metrics_lib_->SendEnumToUMA(kBorealisStartupFsckResult,
                                  MapFsckResultToEnum(value));
    } else if (name == kBorealisStartupFsckTimeGuest) {
      metrics_lib_->SendToUMA(kBorealisStartupFsckTime, value, 0, 60000, 60);
    } else if (name == kBorealisAudioUsedSubdevicesGuest) {
      metrics_lib_->SendToUMA(kBorealisAudioUsedSubdevices, value, 0, 50, 51);
    } else {
      LOG(ERROR) << "Unknown Borealis metric " << name;
      return false;
    }
  } else if (vm_name == "termina" && container_name == "penguin") {
    // Metrics emitted by Crostini (AKA termina) VMs.
    if (name == kCrostiniSwapBytesReadGuest) {
      daily_metrics_.Add(kCrostiniSwapBytesRead, value);
    } else if (name == kCrostiniSwapBytesWrittenGuest) {
      daily_metrics_.Add(kCrostiniSwapBytesWritten, value);
    } else if (name == kCrostiniDiskBytesReadGuest) {
      daily_metrics_.Add(kCrostiniDiskBytesRead, value);
    } else if (name == kCrostiniDiskBytesWrittenGuest) {
      daily_metrics_.Add(kCrostiniDiskBytesWritten, value);
    } else {
      LOG(ERROR) << "Unknown Crostini metric " << name;
      return false;
    }
  } else {
    LOG(ERROR) << "No metrics are known for VM " << vm_name << " and container "
               << container_name;
    return false;
  }
  return true;
}

void GuestMetrics::UpdateDailyMetrics(chromeos_metrics::CumulativeMetrics* cm) {
  // This is a no-op; currently all metric data is accumulated in HandleMetric.
}

void GuestMetrics::ReportDailyMetrics(chromeos_metrics::CumulativeMetrics* cm) {
  // Borealis metrics
  int swapin = daily_metrics_.Get(kBorealisSwapBytesRead);
  int swapout = daily_metrics_.Get(kBorealisSwapBytesWritten);
  int blocksin = daily_metrics_.Get(kBorealisDiskBytesRead);
  int blocksout = daily_metrics_.Get(kBorealisDiskBytesWritten);
  int highestpages = daily_metrics_.Get(kBorealisDiskHighestDirtyPagesDaily);

  // Range chosen to match Platform.StatefulWritesDaily.
  metrics_lib_->SendToUMA(kBorealisSwapBytesRead, swapin, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kBorealisSwapBytesWritten, swapout, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kBorealisDiskBytesRead, blocksin, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kBorealisDiskBytesWritten, blocksout, 0, 209715200,
                          50);
  if (highestpages) {
    // Max size is 16GB. The max possible value for this is tied to how much
    // memory a device has and the config options used. With default options,
    // we'd expect this to max out at ~20% of memory.
    metrics_lib_->SendToUMA(kBorealisDiskHighestDirtyPagesDaily, highestpages,
                            1, 16777216, 50);
  }

  // Crostini metrics
  swapin = daily_metrics_.Get(kCrostiniSwapBytesRead);
  swapout = daily_metrics_.Get(kCrostiniSwapBytesWritten);
  blocksin = daily_metrics_.Get(kCrostiniDiskBytesRead);
  blocksout = daily_metrics_.Get(kCrostiniDiskBytesWritten);

  // Range chosen to match Platform.StatefulWritesDaily.
  metrics_lib_->SendToUMA(kCrostiniSwapBytesRead, swapin, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kCrostiniSwapBytesWritten, swapout, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kCrostiniDiskBytesRead, blocksin, 0, 209715200, 50);
  metrics_lib_->SendToUMA(kCrostiniDiskBytesWritten, blocksout, 0, 209715200,
                          50);
}

}  // namespace cicerone
}  // namespace vm_tools
