// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_METRICS_LIBRARY_H_
#define METRICS_METRICS_LIBRARY_H_

#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <optional>
#include <string>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/memory/scoped_refptr.h>

#include "metrics/metrics_writer.h"
#include "policy/libpolicy.h"

class MetricsLibraryInterface {
 public:
  virtual void Init() = 0;  // TODO(chromium:940343): Remove this function.
  virtual bool AreMetricsEnabled() = 0;
  virtual bool IsAppSyncEnabled() = 0;
  virtual bool IsGuestMode() = 0;
  virtual bool SendToUMA(
      const std::string& name, int sample, int min, int max, int nbuckets) = 0;
  template <typename T>
  bool SendEnumToUMA(const std::string& name, T sample) {
    static_assert(std::is_enum<T>::value, "T is not an enum.");
    // This also ensures that an enumeration that doesn't define kMaxValue fails
    // with a semi-useful error ("no member named 'kMaxValue' in ...").
    static_assert(static_cast<uintmax_t>(T::kMaxValue) <=
                      static_cast<uintmax_t>(INT_MAX) - 1,
                  "Enumeration's kMaxValue is out of range of INT_MAX!");
    DCHECK_LE(static_cast<uintmax_t>(sample),
              static_cast<uintmax_t>(T::kMaxValue));
    return SendEnumToUMA(name, static_cast<int>(sample),
                         static_cast<int>(T::kMaxValue) + 1);
  }
  virtual bool SendEnumToUMA(const std::string& name,
                             int sample,
                             int exclusive_max) = 0;
  template <typename T>
  bool SendRepeatedEnumToUMA(const std::string& name,
                             T sample,
                             int num_samples) {
    static_assert(std::is_enum<T>::value, "T is not an enum.");
    // This also ensures that an enumeration that doesn't define kMaxValue fails
    // with a semi-useful error ("no member named 'kMaxValue' in ...").
    static_assert(static_cast<uintmax_t>(T::kMaxValue) <=
                      static_cast<uintmax_t>(INT_MAX) - 1,
                  "Enumeration's kMaxValue is out of range of INT_MAX!");
    DCHECK_LE(static_cast<uintmax_t>(sample),
              static_cast<uintmax_t>(T::kMaxValue));
    return SendRepeatedEnumToUMA(name, static_cast<int>(sample),
                                 static_cast<int>(T::kMaxValue) + 1,
                                 num_samples);
  }
  virtual bool SendRepeatedEnumToUMA(const std::string& name,
                                     int sample,
                                     int exclusive_max,
                                     int num_samples) = 0;
  virtual bool SendLinearToUMA(const std::string& name,
                               int sample,
                               int max) = 0;
  virtual bool SendPercentageToUMA(const std::string& name, int sample) = 0;
  virtual bool SendBoolToUMA(const std::string& name, bool sample) = 0;
  virtual bool SendSparseToUMA(const std::string& name, int sample) = 0;
  virtual bool SendUserActionToUMA(const std::string& action) = 0;
  virtual bool SendCrashToUMA(const char* crash_kind) = 0;
  virtual bool SendCrosEventToUMA(const std::string& event) = 0;
#if USE_METRICS_UPLOADER
  virtual bool SendRepeatedToUMA(const std::string& name,
                                 int sample,
                                 int min,
                                 int max,
                                 int nbuckets,
                                 int num_samples) = 0;
#endif
  virtual void SetOutputFile(const std::string& output_file) = 0;
  virtual ~MetricsLibraryInterface() {}
};

// Library used to send metrics to Chrome/UMA. The thread-safety of Send*
// methods in this class depends on the `MetricsWriter`.
// It is not thread-safe by default (`SynchronousMetricsWriter`). Do not call
// them in parallel.
class MetricsLibrary : public MetricsLibraryInterface {
 public:
  // Creates `MetricsLibrary`.
  //
  // This sets `SynchronousMetricsWriter` as the default.
  MetricsLibrary();
  // Creates `MetricsLibrary` with custom `MetricsWriter`.
  //
  // Example:
  //    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("name");
  //    scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner =
  //      base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
  //    scoped_refptr<AsynchronousMetricsWriter> metrics_writer =
  //      base::MakeRefCounted<AsynchronousMetricsWriter>(sequenced_task_runner,
  //                                                        false);
  //    MetricsLibrary metrics = MetricsLibrary(metrics_writer);
  explicit MetricsLibrary(scoped_refptr<MetricsWriter> metrics_writer);
  MetricsLibrary(const MetricsLibrary&) = delete;
  MetricsLibrary& operator=(const MetricsLibrary&) = delete;

  ~MetricsLibrary() override;

  // Formerly used to initialize the library.
  // TODO(chromium:940343): Remove this function.
  void Init() override;

  // Returns whether or not the machine is running in guest mode.
  bool IsGuestMode() override;

  // Returns whether or not metrics collection is enabled.
  bool AreMetricsEnabled() override;

  // Returns where or not users have opted in to AppSync.
  bool IsAppSyncEnabled() override;

  // Chrome normally manages Enable/Disable state. These functions are
  // intended ONLY for use by devices which don't run Chrome (e.g. Onhub)
  // but are based on Chrome OS.
  // In those cases, "User Consent" is given via an "external" app
  // (e.g. cloud service or directly from a smart phone app).
  //
  // Enable metrics by creating and populating the Consent file.
  bool EnableMetrics();

  // Disable metrics by deleting the Consent file.
  bool DisableMetrics();

  // Look up the consent id for metrics reporting.
  // Note: Should only be used by internal system projects.
  bool ConsentId(std::string* id);

  // Send output to the specified file. This is
  // useful when running in a context where the metrics reporting system isn't
  // fully available (e.g. when /var is not mounted). Note that the contents of
  // custom output files will not be sent to the server automatically, but need
  // to be imported via Replay() to get picked up by the reporting pipeline.
  void SetOutputFile(const std::string& output_file) override;

  // Replays metrics from the given file as if the events contained in |file|
  // where being generated via the SendXYZ functions.
  bool Replay(const std::string& input_file);

  // Sends histogram data to Chrome for transport to UMA and returns
  // true on success. This method results in the equivalent of an
  // asynchronous non-blocking RPC to UMA_HISTOGRAM_CUSTOM_COUNTS
  // inside Chrome (see base/histogram.h).
  //
  // |sample| is the sample value to be recorded (|min| <= |sample| < |max|).
  // |min| is the minimum value of the histogram samples (|min| > 0).
  // |max| is the maximum value of the histogram samples.
  // |nbuckets| is the number of histogram buckets.
  // [0,min) is the implicit underflow bucket.
  // [|max|,infinity) is the implicit overflow bucket.
  //
  // Note that the memory allocated in Chrome for each histogram is
  // proportional to the number of buckets. Therefore, it is strongly
  // recommended to keep this number low (e.g., 50 is normal, while
  // 100 is high).
  //
  // The new metric must be documented in
  // //tools/metrics/histograms/metadata/platform/histograms.xml in the Chromium
  // repository.
  bool SendToUMA(const std::string& name,
                 int sample,
                 int min,
                 int max,
                 int nbuckets) override;

  // Sends enumerated histogram data to Chrome for transport to UMA and
  // returns true on success. These methods result in the equivalent of
  // an asynchronous non-blocking RPC to UMA_HISTOGRAM_ENUMERATION
  // inside Chrome (see base/metrics/histogram_macros.h).
  //
  // |sample| is the value to be recorded (0 <= |sample| < |exclusive_max|).
  // |exclusive_max| should be set to 1 more than the largest enum value.
  // (-infinity, 0) is the implicit underflow bucket.
  // [|exclusive_max|,infinity) is the implicit overflow bucket.
  //
  // An enumeration histogram requires |exclusive_max| + 1 number of
  // buckets. Note that the memory allocated in Chrome for each
  // histogram is proportional to the number of buckets. Therefore, it
  // is strongly recommended to keep this number low (e.g., 50 is
  // normal, while 100 is high).
  //
  // The new metric must be documented in
  // //tools/metrics/histograms/metadata/platform/histograms.xml in the Chromium
  // repository.
  // Sample usage:
  //   // These values are logged to UMA. Entries should not be renumbered and
  //   // numeric values should never be reused. Please keep in sync with
  //   // "MyEnum" in tools/metrics/histograms/enums.xml in the Chromium repo.
  //   enum class MyEnum {
  //     kFirstValue = 0,
  //     kSecondValue = 1,
  //     ...
  //     kFinalValue = N,
  //     kMaxValue = kFinalValue,
  //   };
  //   SendEnumToUMA("My.Enumeration", MyEnum::kSomeValue);
  //   // or
  //   SendEnumToUMA("My.Enumeration",
  //                 static_cast<int>(MyEnum::kSomeValue),
  //                 static_cast<int>(MyEnum::kMaxValue) + 1);
  using MetricsLibraryInterface::SendEnumToUMA;
  bool SendEnumToUMA(const std::string& name,
                     int sample,
                     int exclusive_max) override;

  // Sends |num_samples| samples with the same value to chrome.
  // Otherwise equivalent to SendEnumToUMA().
  // Warning: Use sparingly as too many samples being sent can cause
  // messages to be dropped (Limit of 100k per 30 seconds).
  bool SendRepeatedEnumToUMA(const std::string& name,
                             int sample,
                             int exclusive_max,
                             int num_samples) override;

  // Sends linear histogram data to Chrome for transport to UMA and
  // returns true on success. These methods result in the equivalent of an
  // asynchronous non-blocking RPC to UMA_HISTOGRAM_EXACT_LINEAR inside Chrome
  // (see base/metrics/histogram_macros.h).
  //
  // |sample| is the value to be recorded (0 <= |sample| < |exclusive_max|).
  // (-infinity, 0) is the implicit underflow bucket.
  // [|exclusive_max|,infinity) is the implicit overflow bucket.
  //
  // |exclusive_max| should be 101 or less.
  //
  // The new metric must be documented in
  // //tools/metrics/histograms/metadata/platform/histograms.xml in the Chromium
  // repository.
  bool SendLinearToUMA(const std::string& name,
                       int sample,
                       int exclusive_max) override;

  // Sends percentage histogram data to Chrome for transport to UMA and
  // returns true on success.  This is a specialization of SendLinearToUMA with
  // |exclusive_max| = 101 for percentage values. These methods result in the
  // equivalent of an asynchronous non-blocking RPC to UMA_HISTOGRAM_PERCENTAGE
  // inside Chrome (see base/metrics/histogram_macros.h).
  bool SendPercentageToUMA(const std::string& name, int sample) override;

  // Specialization of SendEnumToUMA for boolean values.
  bool SendBoolToUMA(const std::string& name, bool sample) override;

  // Sends sparse histogram sample to Chrome for transport to UMA.  Returns
  // true on success.
  //
  // |sample| is the 32-bit integer value to be recorded.
  bool SendSparseToUMA(const std::string& name, int sample) override;

  // Sends a user action to Chrome for transport to UMA and returns true on
  // success. This method results in the equivalent of an asynchronous
  // non-blocking RPC to UserMetrics::RecordAction.
  //
  // |action| is the user-generated event (e.g., "MuteKeyPressed").
  //
  // The new metric must be added to AddChromeOSActions() in
  // //tools/metrics/actions/extract_actions.py in the Chromium repository,
  // which should then be run to generate a hash for the new action.
  bool SendUserActionToUMA(const std::string& action) override;

  // Sends a signal to UMA that a crash of the given |crash_kind|
  // has occurred.  Used by UMA to generate stability statistics.
  bool SendCrashToUMA(const char* crash_kind) override;

  // Sends a "generic Chrome OS event" to UMA.  This is an event name
  // that is translated into an enumerated histogram entry.  Event names
  // must first be registered in metrics_library.cc.  See that file for
  // more details.
  bool SendCrosEventToUMA(const std::string& event) override;

#if USE_METRICS_UPLOADER
  // Sends |num_samples| samples with the same value to chrome.
  // Otherwise equivalent to SendToUMA().
  bool SendRepeatedToUMA(const std::string& name,
                         int sample,
                         int min,
                         int max,
                         int nbuckets,
                         int num_samples) override;
#endif

  void SetConsentFileForTest(const base::FilePath& consent_file);

  void SetDaemonStoreForTest(const base::FilePath& daemon_store) {
    daemon_store_dir_ = daemon_store;
  }

  void SetAppSyncDaemonStoreForTest(
      const base::FilePath& appsync_daemon_store) {
    appsync_daemon_store_dir_ = appsync_daemon_store;
  }

 private:
  friend class CMetricsLibraryTest;
  friend class MetricsLibraryTest;

  // This function is used by tests only to mock the device policies.
  void SetPolicyProvider(policy::PolicyProvider* provider);

  // Check the per-user metrics consent, returning true if *all* of the
  // logged-in users enabled consent and false if *any* disabled it.
  // Return nullopt if we're unable to check per-user consent, if no users
  // have overridden device policy, or if no users are logged in.
  // We check all files because determining *which* consent file to use is
  // tricky.
  // We can't necessarily make a dbus call to session-manager (what if
  // session-manager is not up, or session-manager calls AreMetricsEnabled?) and
  // anyway it's not totally clear which user a metric or crash is from if
  // multiple users are signed in simultaneously.
  std::optional<bool> ArePerUserMetricsEnabled();

  // Checks for user opt-in to AppSync. All the same caveats as
  // ArePerUserMetricsEnabled apply.
  std::optional<bool> IsPerUserAppSyncEnabled();

  // Helper function which contains all the logic for ArePerUserMetricsEnabled
  // and IsPerUserAppSyncEnabled.
  std::optional<bool> CheckUserConsent(const base::FilePath& root_path,
                                       const std::string consent_file);

  // Time at which we last checked if metrics were enabled.
  time_t cached_enabled_time_;

  // Time at which we last checked if AppSync opt-in is enabled.
  time_t cached_appsync_enabled_time_;

  // Cached state of whether or not metrics were enabled.
  bool cached_enabled_;

  // Cached state of whether or not AppSync opt-in is enabled.
  bool cached_appsync_enabled_;

  scoped_refptr<MetricsWriter> metrics_writer_;
  base::FilePath consent_file_;
  base::FilePath daemon_store_dir_;
  base::FilePath appsync_daemon_store_dir_;

  std::unique_ptr<policy::PolicyProvider> policy_provider_;
};

#endif  // METRICS_METRICS_LIBRARY_H_
