// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_GUEST_METRICS_H_
#define VM_TOOLS_CICERONE_GUEST_METRICS_H_

#include <array>
#include <memory>
#include <string>
#include <utility>

#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <metrics/cumulative_metrics.h>
#include <metrics/metrics_library.h>
#include <base/time/time.h>

namespace vm_tools {
namespace cicerone {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
// Taken from chromium/src/tools/metrics/histograms/enums.xml
enum class BorealisFsckResult {
  kUnexpected = 0,
  kCombinedError = 1,
  kNoErrors = 2,
  kErrorsCorrected = 3,
  kSystemShouldReboot = 4,
  kErrorsLeftUncorrected = 5,
  kOperationalError = 6,
  kUsageError = 7,
  kCancelled = 8,
  kSharedLibraryError = 9,
  kMaxValue = kSharedLibraryError,
};

// Handler for metrics emitted by VM guests.
class GuestMetrics {
 public:
  // Provider for returning sysinfo.
  class SysinfoProvider {
   public:
    SysinfoProvider() = default;
    virtual ~SysinfoProvider() = default;
    virtual int64_t AmountOfTotalDiskSpace(base::FilePath path);
    virtual int64_t AmountOfFreeDiskSpace(base::FilePath path);
  };

  explicit GuestMetrics(scoped_refptr<dbus::Bus> bus);
  // Specify path for testing
  explicit GuestMetrics(scoped_refptr<dbus::Bus> bus,
                        base::FilePath cumulative_metrics_path);
  virtual ~GuestMetrics() = default;

  // Called by Service class upon receiving a ReportMetrics RPC from the guest.
  virtual bool HandleMetric(const std::string& owner_id,
                            const std::string& vm_name,
                            const std::string& container_name,
                            const std::string& name,
                            int value);

  // Called by |daily_metrics_| regularly to gather metrics to be reported
  // daily.
  void UpdateDailyMetrics(chromeos_metrics::CumulativeMetrics* cm);

  // Called once a day to send daily metrics to UMA.
  void ReportDailyMetrics(chromeos_metrics::CumulativeMetrics* cm);

  void SetMetricsLibraryForTesting(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib) {
    metrics_lib_ = std::move(metrics_lib);
  }

  MetricsLibraryInterface* metrics_library_for_testing() {
    return metrics_lib_.get();
  }

  void ReportMetricsImmediatelyForTesting() {
    ReportDailyMetrics(&daily_metrics_);
  }

  void SetSysinfoProviderForTesting(std::unique_ptr<SysinfoProvider> provider) {
    sysinfo_provider_ = std::move(provider);
  }

 private:
  // Gets disk image info from concierge and combines that
  // with the inode count from the guest to generate and
  // emit space related metrics.
  void GenerateSpaceMetrics(const std::string& owner_id,
                            const std::string& vm_name,
                            int inode_count);

  // Handles the ListVmDisks response from GenerateSpaceMetrics.
  void HandleListVmDisksDbusResponse(const std::string& vm_name,
                                     int inode_count,
                                     dbus::Response* dbus_response);

  scoped_refptr<dbus::Bus> bus_;
  // Accumulator for metrics that are to be reported daily.
  chromeos_metrics::CumulativeMetrics daily_metrics_;

  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  std::unique_ptr<SysinfoProvider> sysinfo_provider_;
  base::WeakPtrFactory<GuestMetrics> weak_ptr_factory_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_GUEST_METRICS_H_
