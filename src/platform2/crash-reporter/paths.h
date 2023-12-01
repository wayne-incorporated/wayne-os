// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_PATHS_H_
#define CRASH_REPORTER_PATHS_H_

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>

namespace paths {

// Directory where we keep various state flags.
constexpr char kSystemRunStateDirectory[] = "/run/crash_reporter";

// Subdirectory to store crashes that occur when persistent storage is not
// available.
constexpr char kSystemRunCrashDirectory[] = "/run/crash_reporter/crash";

// Directory where crash_reporter stores flag for metrics_daemon.
constexpr char kSystemRunMetricsFlagDirectory[] =
    "/run/metrics/external/crash-reporter";

// Directory where crash_reporter stores files (ex. saved version info).
constexpr char kCrashReporterStateDirectory[] = "/var/lib/crash_reporter";

// Directory where system crashes are saved.
constexpr char kSystemCrashDirectory[] = "/var/spool/crash";

// Ephemeral directory to persist crashes in absence of /var/spool. Any crashes
// stored here will be lost on power loss/reboot.
constexpr char kEncryptedRebootVaultCrashDirectory[] =
    "/mnt/stateful_partition/reboot_vault/crash";

// Path to indicate OOBE completion.
constexpr char kOobeCompletePath[] = "/home/chronos/.oobe_completed";

// Directory where system configuration files are located.
constexpr char kEtcDirectory[] = "/etc";

// The system file that gives the number of file descriptors in use.
constexpr char kProcFileNr[] = "/proc/sys/fs/file-nr";

// The system file that gives information about the amount of memory in use.
constexpr char kProcMeminfo[] = "/proc/meminfo";

// Main system log path.
constexpr char kMessageLogPath[] = "/var/log/messages";

// Directory containing system Chrome logs (when the user isn't logged in).
constexpr char kSystemChromeLogDirectory[] = "/var/log/chrome";

// Directory where per-user crashes are saved before the user logs in.
//
// Normally this path is not used.  Unfortunately, there are a few edge cases
// where we need this.  Any process that runs as kDefaultUserName that crashes
// is consider a "user crash".  That includes the initial Chrome browser that
// runs the login screen.  If that blows up, there is no logged in user yet,
// so there is no per-user dir for us to stash things in.  Instead we fallback
// to this path as it is at least encrypted on a per-system basis.
//
// This also comes up when running integration tests.  The GUI is sitting at the
// login screen while tests are sshing in, changing users, and triggering
// crashes as the user (purposefully).
constexpr char kFallbackUserCrashDirectory[] = "/home/chronos/crash";

// The paths /home/root/<hash>/crash are bind mounted to
// /run/daemon-store/crash/<hash> by cryptohomed. We prefer to use this path
// because it requires fewer privileges to access and it provides a way to
// expose the crash spool directory to a daemon without exposing the whole
// daemon-store.
constexpr char kCryptohomeCrashDirectory[] = "/run/daemon-store/crash";

// File whose existence indicates this is a developer image.
constexpr char kLeaveCoreFile[] = "/root/.leave_core";

// Base name of file whose existence indicates a crash test is currently
// running. File will be in directory kSystemRunStateDirectory.
// This is used in integration tests, including tast.platform.KernelWarning and
// tast.platform.ServiceFailure. (see local/crash/crash.go in the tast-tests
// repo)
constexpr char kCrashTestInProgress[] = "crash-test-in-progress";

// Base name of file whose existence indicates that we should treat consent as
// granted. File will be in directory kSystemRunStateDirectory.
// This is used in integration tests, including tast.platform.KernelWarning and
// tast.platform.ServiceFailure. (see local/crash/crash.go in the tast-tests
// repo)
constexpr char kMockConsent[] = "mock-consent";

// Base name of file whose existence indicates that the anomaly detector is
// ready for anomalies.
constexpr char kAnomalyDetectorReady[] = "anomaly-detector-ready";

// Base name of file whose contents tell us which crashes, if any, to filter.
// Used for tests only. Exact details of how the file is interpreted can be
// found on the method documentation of `utils::SkipCrashCollection`
constexpr char kFilterInFile[] = "filter-in";

// Base name of file whose contents tell us which crashes, if any, to *ignore*.
// Used for tests only. Implementation details can be found on the method
// documentation of `utils::SkipCrashCollection`
constexpr char kFilterOutFile[] = "filter-out";

// Base name of the file containing the name of the in-progress tast test, if
// any.  If there is a tast test name here when a crash happens, it's added to
// the .meta file.
constexpr char kInProgressTestName[] = "test-in-prog";

// Base name of file whose existence indicates uploading of device coredumps is
// allowed.
constexpr char kDeviceCoredumpUploadAllowed[] =
    "device_coredump_upload_allowed";

// Base name of file that contains ChromeOS version info.
constexpr char kLsbRelease[] = "lsb-release";

// Basename of file in the state directory that has the client ID.
constexpr char kClientId[] = "client_id";

// Crash sender lock in case the sender is already running.
constexpr char kCrashSenderLockFile[] = "/run/lock/crash_sender";

// Location in the home dir (or fallback home dir) where experiment IDs are
// written.
constexpr char kVariationsListFile[] = ".variations-list.txt";

// Fallback directory to the home dir, where we write variant-list if no one's
// logged in.
constexpr char kFallbackToHomeDir[] = "/home/chronos";

// File to override consent *FOR BOOT COLLECTORS ONLY*. Must match
// kOutOfCryptohomeConsent in chromium repo's
// per_user_state_manager_chromeos.cc.
constexpr char kBootConsentFile[] = "/home/chronos/boot-collect-consent";

// Used to build up the path to a watchdog's boot status:
// For example: /sys/class/watchdog/watchdog0/bootstatus
constexpr char kWatchdogSysPath[] = "/sys/class/watchdog/";

// A file inside kSystemRunStateDirectory. Used by ui.ChromeCrashEarly.loose to
// indicate we should relax the normal size limits on core files in
// Chrome early-crash mode.
constexpr char kRunningLooseChromeCrashEarlyTestFile[] =
    "running-loose-chrome-crash-early-test";

// Contains the last GSC crash log ID, so we only report each GSC crash once.
constexpr char kGscPrevCrashLogIdPath[] =
    "/mnt/stateful_partition/unencrypted/preserve/gsc_prev_crash_log_id";

// Gets a FilePath from the given path. A prefix will be added if the prefix is
// set with SetPrefixForTesting().
base::FilePath Get(base::StringPiece file_path);

// Gets a FilePath from the given directory and the base name. A prefix will be
// added if the prefix is set with SetPrefixForTesting().
base::FilePath GetAt(base::StringPiece directory, base::StringPiece base_name);

// Sets a prefix that'll be added when Get() is called, for unit testing.
// For example, if "/tmp" is set as the prefix, Get("/run/foo") will return
// "/tmp/run/foo". Passing "" will reset the prefix.
void SetPrefixForTesting(const base::FilePath& prefix);

}  // namespace paths

#endif  // CRASH_REPORTER_PATHS_H_
