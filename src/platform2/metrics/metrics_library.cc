// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/metrics_library.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include "base/files/file_path.h"
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/uuid.h>
#include <brillo/files/safe_fd.h>
#include <errno.h>
#include <session_manager/dbus-proxies.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <vector>

#include "base/memory/scoped_refptr.h"
#include "metrics/metrics_writer.h"
#include "metrics/serialization/metric_sample.h"
#include "metrics/serialization/serialization_utils.h"

#include "policy/device_policy.h"

using brillo::SafeFD;
using org::chromium::SessionManagerInterfaceProxy;

namespace {

// If you change this path make sure to also change the corresponding rollback
// constant: src/platform2/oobe_config/rollback_constants.cc
constexpr char kConsentFile[] = "/home/chronos/Consent To Send Stats";
constexpr char kDaemonStoreUmaConsentDir[] = "/run/daemon-store/uma-consent";
constexpr char kDaemonStoreAppSyncOptinDir[] =
    "/run/daemon-store/appsync-optin";
constexpr char kDaemonStoreConsentFile[] = "consent-enabled";
constexpr char kDaemonStoreOptinFile[] = "opted-in";
constexpr char kCrosEventHistogramName[] = "Platform.CrOSEvent";
const int kCrosEventHistogramMax = 100;
const int kMaxNumberOfSamples = 512;

// Add new cros events here.
//
// The index of the event is sent in the message, so please do not
// reorder the names.
//
// Note: All updates here must also update Chrome's enums.xml database.
// Please see this document for more details:
// https://chromium.googlesource.com/chromium/src/+/HEAD/tools/metrics/histograms/
//
// You can view them live here:
// https://uma.googleplex.com/histograms/?histograms=Platform.CrOSEvent
const char* kCrosEventNames[] = {
    "ModemManagerCommandSendFailure",           // 0
    "HwWatchdogReboot",                         // 1
    "Cras.NoCodecsFoundAtBoot",                 // 2
    "Chaps.DatabaseCorrupted",                  // 3
    "Chaps.DatabaseRepairFailure",              // 4
    "Chaps.DatabaseCreateFailure",              // 5
    "Attestation.OriginSpecificExhausted",      // 6
    "SpringPowerSupply.Original.High",          // 7
    "SpringPowerSupply.Other.High",             // 8
    "SpringPowerSupply.Original.Low",           // 9
    "SpringPowerSupply.ChargerIdle",            // 10
    "TPM.NonZeroDictionaryAttackCounter",       // 11
    "TPM.EarlyResetDuringCommand",              // 12
    "VeyronEmmcUpgrade.Success",                // 13
    "VeyronEmmcUpgrade.WaitForKernelRollup",    // 14
    "VeyronEmmcUpgrade.WaitForFirmwareRollup",  // 15
    "VeyronEmmcUpgrade.BadEmmcProperties",      // 16
    "VeyronEmmcUpgrade.FailedDiskAccess",       // 17
    "VeyronEmmcUpgrade.FailedWPEnable",         // 18
    "VeyronEmmcUpgrade.SignatureDetected",      // 19
    "Watchdog.StartupFailed",                   // 20
    "Vm.VmcStart",                              // 21
    "Vm.VmcStartSuccess",                       // 22
    "Vm.DiskEraseFailed",                       // 23
    "Fingerprint.MCU.Reboot",                   // 24
    "Crash.Chrome.CrashesFromKernel",           // 25
    "Crash.Chrome.MissedCrashes",               // 26
    "Crash.Collector.CollectionCount",          // 27
    "Cryptohome.DoubleMountRequest",            // 28
    "SessionManager.SafeModeEnabled",           // 29
    "Crash.Sender.FailedCrashRemoval",          // 30
    "Crash.Sender.AttemptedCrashRemoval",       // 31
    "Chaps.DatabaseOpenedSuccessfully",         // 32
    "Chaps.DatabaseOpenAttempt",                // 33
    "Crostini.OomEvent",                        // 34
};

// Update this to be last entry + 1 when you add new entries to the end. Checks
// that no one tries to remove entries from the middle or misnumbers during a
// merge conflict.
static_assert(std::size(kCrosEventNames) == 35,
              "CrosEvent enums not lining up properly");

}  // namespace

MetricsLibrary::MetricsLibrary()
    : MetricsLibrary(base::MakeRefCounted<SynchronousMetricsWriter>()) {}

MetricsLibrary::MetricsLibrary(scoped_refptr<MetricsWriter> metrics_writer)
    : cached_enabled_time_(0),
      cached_appsync_enabled_time_(0),
      cached_enabled_(false),
      cached_appsync_enabled_(false),
      metrics_writer_(std::move(metrics_writer)),
      consent_file_(base::FilePath(kConsentFile)),
      daemon_store_dir_(kDaemonStoreUmaConsentDir),
      appsync_daemon_store_dir_(kDaemonStoreAppSyncOptinDir) {}

MetricsLibrary::~MetricsLibrary() {}

bool MetricsLibrary::IsGuestMode() {
  // Shortcut check whether there is any logged-in user.
  if (access("/run/state/logged-in", F_OK) != 0)
    return false;

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  CHECK(bus->Connect());

  brillo::ErrorPtr error;
  bool is_guest = false;
  SessionManagerInterfaceProxy session_manager_interface(bus);
  session_manager_interface.IsGuestSessionActive(&is_guest, &error);
  return is_guest;
}

bool MetricsLibrary::ConsentId(std::string* id) {
  // Do not allow symlinks.
  base::ScopedFD fd(
      open(consent_file_.value().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd.get() < 0)
    return false;

  // We declare a slightly larger buffer than needed so we can detect if it's
  // been corrupted with a lot of bad data.
  char buf[40];
  ssize_t len = read(fd.get(), buf, sizeof(buf));

  // If we couldn't get any data, just fail right away.
  if (len <= 0)
    return false;

  // Chop the trailing newline to make parsing below easier.
  if (buf[len - 1] == '\n')
    buf[--len] = '\0';

  // Make sure it's a valid UUID.  Support older installs that omitted dashes.
  if (len != 32 && len != 36)
    return false;

  ssize_t i;
  id->clear();
  for (i = 0; i < len; ++i) {
    char c = buf[i];
    *id += c;

    // For long UUIDs, require dashes at certain positions.
    if (len == 36 && (i == 8 || i == 13 || i == 18 || i == 23)) {
      if (c == '-')
        continue;
      return false;
    }

    // All the rest should be hexdigits.
    if (base::IsHexDigit(c))
      continue;

    return false;
  }

  return true;
}

std::optional<bool> MetricsLibrary::ArePerUserMetricsEnabled() {
  return CheckUserConsent(daemon_store_dir_, kDaemonStoreConsentFile);
}

std::optional<bool> MetricsLibrary::IsPerUserAppSyncEnabled() {
  return CheckUserConsent(appsync_daemon_store_dir_, kDaemonStoreOptinFile);
}

// AppSync opt-in/UMA consent are determined as follows:
//  * if all users logged in have opted in, return true
//  * if at least one user has not opted in, return false
//  * if no users exist, there can be no apps to sync, return false
std::optional<bool> MetricsLibrary::CheckUserConsent(
    const base::FilePath& root_path, std::string consent_file) {
  base::FileEnumerator consent_files(
      root_path,
      /*recursive=*/true, base::FileEnumerator::FILES, consent_file,
      base::FileEnumerator::FolderSearchPolicy::ALL);
  SafeFD::SafeFDResult root_err = SafeFD::Root();
  if (SafeFD::IsError(root_err.second)) {
    LOG(ERROR) << "Failed to open root directory: "
               << static_cast<int>(root_err.second);
    return std::nullopt;
  }
  bool checked_any = false;
  for (base::FilePath name = consent_files.Next(); !name.empty();
       name = consent_files.Next()) {
    SafeFD::SafeFDResult file_err =
        root_err.first.OpenExistingFile(name, O_RDONLY | O_CLOEXEC);
    if (SafeFD::IsError(file_err.second)) {
      LOG(ERROR) << "Failed to open file: " << name.value() << ": "
                 << static_cast<int>(file_err.second);
      continue;
    }
    auto read_result = file_err.first.ReadContents();
    if (SafeFD::IsError(read_result.second)) {
      LOG(ERROR) << "Failed to read file: " << name.value() << ": "
                 << static_cast<int>(read_result.second);
      continue;
    }
    checked_any = true;
    std::string consent(read_result.first.begin(), read_result.first.end());
    if (consent != "1") {
      return false;
    }
  }

  if (checked_any) {
    // If we got here and didn't bail, all active users consented.
    return true;
  }
  return std::nullopt;
}

bool MetricsLibrary::AreMetricsEnabled() {
  time_t this_check_time = time(nullptr);
  if (this_check_time != cached_enabled_time_) {
    cached_enabled_time_ = this_check_time;

    std::optional<bool> user_consent = ArePerUserMetricsEnabled();
    if (user_consent.has_value() && !user_consent.value()) {
      // If the user consented, also make sure device owner opted in.
      // (Theoretically, if device policy is off, the user shouldn't be *able*
      // to opt in based on the current-as-of-2022-03 design, but add this as
      // a secondary layer of defense.)
      // If the user opted out, we opt out.
      return false;
    }

    if (!policy_provider_.get())
      policy_provider_.reset(new policy::PolicyProvider());
    policy_provider_->Reload();

    const policy::DevicePolicy* device_policy = nullptr;
    if (policy_provider_->device_policy_is_loaded())
      device_policy = &policy_provider_->GetDevicePolicy();

    // If policy couldn't be loaded or the metrics policy is not set, default to
    // enabled for enterprise-enrolled devices, cf. https://crbug/456186, or
    // respect the consent file if it is present for migration purposes. In all
    // other cases, default to disabled.
    // TODO(pastarmovj)
    std::string id_unused;
    bool metrics_enabled = false;
    bool metrics_policy = false;
    if (device_policy && device_policy->GetMetricsEnabled(&metrics_policy)) {
      metrics_enabled = metrics_policy;
      VLOG(2) << "AreMetricsEnabled: " << metrics_enabled << " (device policy)";
    } else if (device_policy && device_policy->IsEnterpriseManaged()) {
      metrics_enabled = true;
      VLOG(2) << "AreMetricsEnabled: 1 (enterprise managed)";
    } else {
      metrics_enabled = ConsentId(&id_unused);
      VLOG(2) << "AreMetricsEnabled: " << metrics_enabled
              << "(consent ID file)";
    }
    cached_enabled_ = (metrics_enabled && !IsGuestMode());
  }
  return cached_enabled_;
}

bool MetricsLibrary::IsAppSyncEnabled() {
  time_t this_check_time = time(nullptr);
  if (this_check_time != cached_appsync_enabled_time_) {
    cached_appsync_enabled_time_ = this_check_time;

    std::optional<bool> appsync_optin = IsPerUserAppSyncEnabled();

    cached_appsync_enabled_ = appsync_optin.value_or(false);
  }

  return cached_appsync_enabled_;
}

bool MetricsLibrary::EnableMetrics() {
  // Already enabled? Don't touch anything.
  if (AreMetricsEnabled())
    return true;

  std::string guid = base::Uuid::GenerateRandomV4().AsLowercaseString();

  if (guid.empty())
    return false;

  // http://crbug.com/383003 says we must be world readable.
  mode_t mask = umask(0022);
  int write_len = base::WriteFile(base::FilePath(consent_file_), guid.c_str(),
                                  guid.length());
  umask(mask);

  return write_len == static_cast<int>(guid.length());
}

bool MetricsLibrary::DisableMetrics() {
  return base::DeleteFile(base::FilePath(consent_file_));
}

void MetricsLibrary::Init() {
  // Deprecated.  Initialization code should go in constructor.
  // Remove this function when it is no longer used.
}

void MetricsLibrary::SetOutputFile(const std::string& output_file) {
  metrics_writer_->SetOutputFile(output_file);
}

bool MetricsLibrary::Replay(const std::string& input_file) {
  std::vector<metrics::MetricSample> samples;
  if (!metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
          input_file, &samples,
          metrics::SerializationUtils::kSampleBatchMaxLength)) {
    return false;
  }
  return metrics_writer_->WriteMetrics(samples);
}

bool MetricsLibrary::SendToUMA(
    const std::string& name, int sample, int min, int max, int nbuckets) {
  return metrics_writer_->WriteMetrics({metrics::MetricSample::HistogramSample(
      name, sample, min, max, nbuckets)});
}

#if USE_METRICS_UPLOADER
bool MetricsLibrary::SendRepeatedToUMA(const std::string& name,
                                       int sample,
                                       int min,
                                       int max,
                                       int nbuckets,
                                       int num_samples) {
  return metrics::SerializationUtils::WriteMetricsToFile(
      {metrics::MetricSample::HistogramSample(name, sample, min, max, nbuckets,
                                              num_samples)},
      uma_events_file_.value());
}
#endif

void MetricsLibrary::SetConsentFileForTest(const base::FilePath& consent_file) {
  consent_file_ = consent_file;
}

bool MetricsLibrary::SendEnumToUMA(const std::string& name,
                                   int sample,
                                   int max) {
  return SendRepeatedEnumToUMA(name, sample, max, 1);
}

bool MetricsLibrary::SendRepeatedEnumToUMA(const std::string& name,
                                           int sample,
                                           int max,
                                           int num_samples) {
  if (num_samples >= kMaxNumberOfSamples) {
    // Emit warning for now to monitor if usage is too great.
    LOG(ERROR) << "num_samples must be less than" << kMaxNumberOfSamples
               << ". num_samples=" << num_samples;
    return false;
  }

  return metrics_writer_->WriteMetrics(std::vector<metrics::MetricSample>(
      num_samples,
      metrics::MetricSample::LinearHistogramSample(name, sample, max)));
}

bool MetricsLibrary::SendLinearToUMA(const std::string& name,
                                     int sample,
                                     int max) {
  return metrics_writer_->WriteMetrics(
      {metrics::MetricSample::LinearHistogramSample(name, sample, max)});
}

bool MetricsLibrary::SendPercentageToUMA(const std::string& name, int sample) {
  return SendLinearToUMA(name, sample, 101);
}

bool MetricsLibrary::SendBoolToUMA(const std::string& name, bool sample) {
  return metrics_writer_->WriteMetrics(
      {metrics::MetricSample::LinearHistogramSample(name, sample ? 1 : 0, 2)});
}

bool MetricsLibrary::SendSparseToUMA(const std::string& name, int sample) {
  return metrics_writer_->WriteMetrics(
      {metrics::MetricSample::SparseHistogramSample(name, sample)});
}

bool MetricsLibrary::SendUserActionToUMA(const std::string& action) {
  return metrics_writer_->WriteMetrics(
      {metrics::MetricSample::UserActionSample(action)});
}

bool MetricsLibrary::SendCrashToUMA(const char* crash_kind) {
  return metrics_writer_->WriteMetrics(
      {metrics::MetricSample::CrashSample(crash_kind)});
}

void MetricsLibrary::SetPolicyProvider(policy::PolicyProvider* provider) {
  policy_provider_.reset(provider);
}

bool MetricsLibrary::SendCrosEventToUMA(const std::string& event) {
  for (size_t i = 0; i < std::size(kCrosEventNames); i++) {
    if (strcmp(event.c_str(), kCrosEventNames[i]) == 0) {
      return SendEnumToUMA(kCrosEventHistogramName, i, kCrosEventHistogramMax);
    }
  }
  LOG(WARNING) << "Unknown CrosEvent '" << event << "'";
  return false;
}
