// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_MANAGER_H_
#define LORGNETTE_MANAGER_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/containers/flat_set.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>
#include <metrics/metrics_library.h>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"
#include "lorgnette/sane_client.h"

using brillo::dbus_utils::DBusMethodResponse;

namespace brillo {

namespace dbus_utils {
class ExportedObjectManager;
}  // namespace dbus_utils

}  // namespace brillo

namespace lorgnette {

// This enum corresponds to Chromium's ScanJobFailureReason in
// src/ash/webui/scanning/scanning_uma.h
// DO NOT CHANGE THESE VALUES without changing values in the original file.
enum class ScanJobFailureReason {
  kUnknownScannerError = 0,
  kScannerNotFound = 1,
  kUnsupportedScanToPath = 2,
  kSaveToDiskFailed = 3,
  kDeviceBusy = 4,
  kAdfJammed = 5,
  kAdfEmpty = 6,
  kFlatbedOpen = 7,
  kIoError = 8,
  kSuccess = 9,
  kMaxValue = kSuccess,
};

namespace impl {

// Returns a byte vector containing the serialized representation of |proto|.
template <typename T>
std::vector<uint8_t> SerializeProto(const T& proto) {
  std::vector<uint8_t> serialized;
  serialized.resize(proto.ByteSizeLong());
  proto.SerializeToArray(serialized.data(), serialized.size());
  return serialized;
}

// Attempts to parse a ColorMode from the mode names used by SANE. If |mode|
// is not recognized, returns MODE_UNSPECIFIED.
ColorMode ColorModeFromSaneString(const std::string& mode);

}  // namespace impl

using StatusSignalSender =
    base::RepeatingCallback<void(const ScanStatusChangedSignal&)>;

class FirewallManager;

class Manager {
 public:
  Manager(base::RepeatingCallback<void(base::TimeDelta)> activity_callback,
          SaneClient* sane_client);
  Manager(const Manager&) = delete;
  Manager& operator=(const Manager&) = delete;
  virtual ~Manager();

  void SetFirewallManager(FirewallManager* firewall_manager);

  // Implementation of MethodInterface.
  virtual bool ListScanners(brillo::ErrorPtr* error,
                            ListScannersResponse* scanner_list_out);
  virtual bool GetScannerCapabilities(brillo::ErrorPtr* error,
                                      const std::string& device_name,
                                      ScannerCapabilities* capabilities);
  virtual StartScanResponse StartScan(const StartScanRequest& request);
  virtual void GetNextImage(
      std::unique_ptr<DBusMethodResponse<GetNextImageResponse>> response,
      const GetNextImageRequest& get_next_image_request,
      const base::ScopedFD& out_fd);
  virtual CancelScanResponse CancelScan(
      const CancelScanRequest& cancel_scan_request);

  void SetProgressSignalInterval(base::TimeDelta interval);

  // Register the callback to call when we send a ScanStatusChanged signal for
  // tests.
  void SetScanStatusChangedSignalSender(StatusSignalSender sender);

  void RemoveDuplicateScanners(std::vector<ScannerInfo>* scanners,
                               base::flat_set<std::string> seen_vidpid,
                               base::flat_set<std::string> seen_busdev,
                               const std::vector<ScannerInfo>& sane_scanners);

  // Returns false if a particular scanner model is blocked (e.g. because of
  // known backend incompatibilities).
  static bool ScannerCanBeUsed(const ScannerInfo& scanner);

 private:
  friend class ManagerTest;

  struct ScanJobState {
    std::string device_name;
    bool in_use = false;
    bool cancelled = false;
    std::unique_ptr<SaneDevice> device;
    int current_page = 1;
    // The total number of pages to scan for the scan job. If this is nullopt,
    // keep scanning until we get an error.
    std::optional<int> total_pages;
    // The image format for scanned images for the scan job.
    ImageFormat format;
  };

  static const char kMetricScanRequested[];
  static const char kMetricScanSucceeded[];
  static const char kMetricScanFailed[];
  static const char kMetricScanFailedFailureReason[];

  bool StartScanInternal(brillo::ErrorPtr* error,
                         ScanFailureMode* failure_mode,
                         const StartScanRequest& request,
                         std::unique_ptr<SaneDevice>* device_out);

  void GetNextImageInternal(const std::string& uuid,
                            ScanJobState* scan_state,
                            base::ScopedFILE out_file);

  ScanState RunScanLoop(brillo::ErrorPtr* error,
                        ScanFailureMode* failure_mode,
                        ScanJobState* scan_state,
                        base::ScopedFILE out_file,
                        const std::string& scan_uuid);

  void ReportScanRequested(const std::string& device_name);
  void ReportScanSucceeded(const std::string& device_name);
  void ReportScanFailed(const std::string& device_name,
                        const ScanFailureMode failure_mode);

  void SendStatusSignal(const std::string& uuid,
                        const ScanState state,
                        const int page,
                        const int progress,
                        const bool more_pages);
  void SendCancelledSignal(const std::string& uuid);
  void SendFailureSignal(const std::string& uuid,
                         const std::string& failure_reason,
                         const ScanFailureMode failure_mode);

  SEQUENCE_CHECKER(sequence_checker_);

  base::RepeatingCallback<void(base::TimeDelta)> activity_callback_
      GUARDED_BY_CONTEXT(sequence_checker_);
  std::unique_ptr<MetricsLibraryInterface> metrics_library_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Manages port access for receiving replies from network scanners.
  // Not owned.
  FirewallManager* firewall_manager_ GUARDED_BY_CONTEXT(sequence_checker_);

  // Manages connection to SANE for listing and connecting to scanners.
  // Not owned.
  SaneClient* sane_client_ GUARDED_BY_CONTEXT(sequence_checker_);

  // A callback to call when we attempt to send a D-Bus signal. This is used
  // for testing in order to track the signals sent from StartScan.
  StatusSignalSender status_signal_sender_;
  base::TimeDelta progress_signal_interval_;

  // Mapping from scan UUIDs to the state for that scan job.
  base::flat_map<std::string, ScanJobState> active_scans_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Keep as the last member variable.
  base::WeakPtrFactory<Manager> weak_factory_
      GUARDED_BY_CONTEXT(sequence_checker_){this};
};

}  // namespace lorgnette

#endif  // LORGNETTE_MANAGER_H_
