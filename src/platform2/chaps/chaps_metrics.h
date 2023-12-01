// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_METRICS_H_
#define CHAPS_CHAPS_METRICS_H_

#include <string>

#include <base/time/time.h>
#include <metrics/metrics_library.h>

namespace chaps {

inline constexpr char kReinitializingToken[] =
    "Platform.Chaps.ReinitializingToken";

inline constexpr char kTPMAvailability[] = "Platform.Chaps.TPMAvailability";

inline constexpr char kDatabaseCorrupted[] = "Chaps.DatabaseCorrupted";

inline constexpr char kDatabaseRepairFailure[] = "Chaps.DatabaseRepairFailure";

inline constexpr char kDatabaseCreateFailure[] = "Chaps.DatabaseCreateFailure";

inline constexpr char kDatabaseOpenedSuccessfully[] =
    "Chaps.DatabaseOpenedSuccessfully";

inline constexpr char kDatabaseOpenAttempt[] = "Chaps.DatabaseOpenAttempt";

inline constexpr char kChapsSessionHistogramPrefix[] = "Platform.Chaps.Session";

inline constexpr char kChapsTokenManagerHistogramPrefix[] =
    "Platform.Chaps.TokenManager";

// List of reasons to initializing token. These entries
// should not be renumbered and numeric values should never be reused.
// These values are persisted to logs.
enum class ReinitializingTokenStatus {
  kFailedToUnseal = 0,
  kBadAuthorizationData = 1,
  kFailedToDecryptRootKey = 2,
  kFailedToValidate = 3,
  kMaxValue
};

// The TPM availability status. These entries
// should not be renumbered and numeric values should never be reused.
// These values are persisted to logs.
enum class TPMAvailabilityStatus {
  kTPMAvailable = 0,
  kTPMUnavailable = 1,
  kMaxValue
};

// The token manager command execution status. These values are persisted to
// logs. Entries should not be renumbered and numeric values should never be
// reused. Please keep in sync with "TokenManagerStatus" in
// tools/metrics/histograms/enums.xml in the Chromium repo.
enum class TokenManagerStatus {
  kCommandSuccess = 0,
  kInitStage2Failed = 1,
  kInvalidIsolateCredential = 2,
  kLoadExistingToken = 3,
  kFailedToLoadSoftwareToken = 4,
  kUnknownPath = 5,
  kIncorrectOldAuthorizationData = 6,
  kFailedToChangeAuthData = 7,
  kFailedToWriteAuthKeyBlob = 8,
  kFailedToWriteAuthDataHashBlob = 9,
  kTokenNotInitialized = 10,
  kFailedToDecryptRootKey = 11,
  kFailedToEncryptRootKey = 12,
  kFailedToWriteRootKeyBlob = 13,
  kMaxValue
};

// This class provides wrapping functions for callers to report Chaps related
// metrics without bothering to know all the constant declarations.
class ChapsMetrics : private MetricsLibrary {
 public:
  ChapsMetrics() = default;
  ChapsMetrics(const ChapsMetrics&) = delete;
  ChapsMetrics& operator=(const ChapsMetrics&) = delete;

  virtual ~ChapsMetrics() = default;

  // The |status| value is reported to the
  // "Platform.Chaps.ReinitializingToken" enum histogram.
  virtual void ReportReinitializingTokenStatus(
      ReinitializingTokenStatus status);

  // The |status| value is reported to the "Platform.Chaps.TPMAvailability" enum
  // histogram.
  virtual void ReportTPMAvailabilityStatus(TPMAvailabilityStatus status);

  // Cros events are translated to an enum and reported to the generic
  // "Platform.CrOSEvent" enum histogram. The |event| string must be registered
  // in metrics/metrics_library.cc:kCrosEventNames.
  virtual void ReportCrosEvent(const std::string& event);

  // The |operation| and |status| value is reported to the
  // "Platform.Chaps.Session" enum histogram.
  virtual void ReportChapsSessionStatus(const std::string& operation,
                                        int status);

  // The |operation| and |status| value is reported to the
  // "Platform.Chaps.TokenManager" enum histogram.
  virtual void ReportChapsTokenManagerStatus(const std::string& operation,
                                             TokenManagerStatus status);

  void set_metrics_library_for_testing(
      MetricsLibraryInterface* metrics_library) {
    metrics_library_ = metrics_library;
  }

 private:
  MetricsLibraryInterface* metrics_library_{this};
};

}  // namespace chaps

#endif  // CHAPS_CHAPS_METRICS_H_
