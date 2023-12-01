// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_METRICS_H_
#define DLCSERVICE_METRICS_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <metrics/metrics_library.h>

#include "dlcservice/error.h"

namespace dlcservice {

namespace metrics {
extern const char kMetricInstallResult[];
extern const char kMetricUninstallResult[];

// IMPORTANT: Please read this before making any changes to the file:
// - Never change existing numerical values on the enums, because the same
// numbering is used in the UMA website. If you don't need a value, comment out
// the value that is no longer needed, and remove it from the map in metrics.cc;
// this will let the error fall into the |kUnknownError| bucket.
// - Never reuse a number.
// - When adding a new value, a new entry has to be added in
// chromium/src/tools/metrics/histograms/enums.xml
enum class InstallResult {
  kUnknownError = 0,
  kSuccessNewInstall = 1,
  kSuccessAlreadyInstalled = 2,
  kFailedToCreateDirectory = 3,
  kFailedInstallInUpdateEngine = 4,
  kFailedInvalidDlc = 5,
  kFailedNeedReboot = 6,
  kFailedUpdateEngineBusy = 7,
  kFailedToVerifyImage = 8,
  kFailedToMountImage = 9,
  kFailedNoImageFound = 10,
  kFailedCreationDuringHibernateResume = 11,
  kNumConstants
};

enum class UninstallResult {
  kUnknownError = 0,
  kSuccess = 1,
  kFailedInvalidDlc = 2,
  kFailedUpdateEngineBusy = 3,
  kNumConstants
};
}  // namespace metrics

// Performs UMA metrics logging for the dlcservice daemon.
class Metrics {
 public:
  explicit Metrics(std::unique_ptr<MetricsLibraryInterface> metrics_library)
      : metrics_library_(std::move(metrics_library)) {}

  virtual ~Metrics() = default;

  // Initializes the class.
  void Init();

  // Sends the |InstallResult| value for a successful installation. There are
  // two success scenarios, |kSuccessNewInstall| and |kSuccessAlreadyInstalled|.
  void SendInstallResultSuccess(const bool& installed_by_ue);

  // Sends the |InstallResult| value for when the installation was not
  // successful.
  void SendInstallResultFailure(brillo::ErrorPtr* err);

  // Sends the |UninstallResult| value. If |err| is empty, send |kSuccess|,
  // otherwise send a failure value.
  void SendUninstallResult(brillo::ErrorPtr* err);

 protected:
  // For testing.
  Metrics() = default;
  // Sends the value for |InstallResult|.
  virtual void SendInstallResult(metrics::InstallResult result);

  // Sends the value for |UninstallResult|.
  virtual void SendUninstallResult(metrics::UninstallResult result);

 private:
  std::unique_ptr<MetricsLibraryInterface> metrics_library_;
  // Map DBus error codes and |dlcservice::error|s to |InstallResult| values.
  typedef std::map<std::string, metrics::InstallResult> InstallResultMap;
  static InstallResultMap install_result_;
  // Map DBus error codes and |dlcservice::error|s to |UninstallResult| values.
  typedef std::map<std::string, metrics::UninstallResult> UninstallResultMap;
  static UninstallResultMap uninstall_result_;

  Metrics(const Metrics&) = delete;
  Metrics& operator=(const Metrics&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_METRICS_H_
