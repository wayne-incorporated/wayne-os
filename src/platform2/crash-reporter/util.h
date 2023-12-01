// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_UTIL_H_
#define CRASH_REPORTER_UTIL_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/time/clock.h>
#include <base/time/time.h>
#include <brillo/process/process.h>
#include <brillo/streams/stream.h>
#include <metrics/metrics_library.h>
#include <session_manager/dbus-proxies.h>

namespace util {

// From //net/crash/collector/collector.h
extern const int kDefaultMaxUploadBytes;

// Returns true if integration tests are currently running.
bool IsCrashTestInProgress();

// Returns true if uploading of device coredumps is allowed.
bool IsDeviceCoredumpUploadAllowed();

// Returns true if running on a developer image.
bool IsDeveloperImage();

// Returns true if running on a test image.
bool IsTestImage();

// Returns true if running on an official image.
bool IsOfficialImage();

// Returns true if we are mocking metrics consent as granted.
bool HasMockConsent();

// Returns true if we are running ui.ChromeCrashEarly.loose and want to allow
// larger core files in that mode.
bool UseLooseCoreSizeForChromeCrashEarly();

// Determines whether feedback is allowed, based on:
// * The presence/absence of mock consent
// * Whether this is a developer image
// * Whether the metrics library indicates consent
// Does not take ownership of |metrics_lib|
bool IsFeedbackAllowed(MetricsLibraryInterface* metrics_lib);

// Determines whether feedback is allowed, for early boot collectors.
// If the boot-collector-consent file is present, and contains anything other
// than "1" (the opt-in value), skip collecting the crash. Otherwise, fall back
// to IsFeedbackAllowed().
// This mirrors metrics_lib's AreMetricsEnabled method, which checks the
// per-user consent file and determines there's no consent if it's present and
// contains anything but "1".
// Does not take ownership of |metrics_lib|
bool IsBootFeedbackAllowed(MetricsLibraryInterface* metrics_lib);

// Returns true if we should skip crash collection (based on the filter-in
// and filter-out files).
// Specifically, if filter-in exists, crash_reporter will exit early unless its
// contents are a substring of the command-line parameters.
// Alternatively, if filter-in contains the string "none", then crash_reporter
// will always exit early.
// If filter-out exists, crash_reporter will exit early *if* its contents
// are a substring of the command-line parameters.
bool SkipCrashCollection(int argc, const char* const argv[]);

// Change group ownership of "file" to "group", and grant g+rw (optionally x).
bool SetGroupAndPermissions(const base::FilePath& file,
                            const char* group,
                            bool execute);

// Returns the timestamp for the OS version we are currently running. Returns
// a null (zero-valued) base::Time if it is unable to calculate it for some
// reason.
base::Time GetOsTimestamp();

// Returns true if this version is old enough that we do not want to upload the
// crash reports anymore. This just checks if |timestamp| is more than 180
// days old. If |timestamp| is null (zero-valued) then this will return false.
bool IsBuildTimestampTooOldForUploads(int64_t build_time_millis,
                                      base::Clock* clock);

// Gets a string describing the hardware class of the device. Returns
// "undefined" if this cannot be determined.
std::string GetHardwareClass();

// Returns the boot mode which will either be "dev", "missing-crossystem" (if it
// cannot be determined) or the empty string.
std::string GetBootModeString();

// Tries to find |key| in a key-value file named |base_name| in |directories| in
// the specified order, and writes the value to |value|. This function returns
// as soon as the key is found (i.e. if the key is found in the first directory,
// the remaining directories won't be checked). Returns true on success.
bool GetCachedKeyValue(const base::FilePath& base_name,
                       const std::string& key,
                       const std::vector<base::FilePath>& directories,
                       std::string* value);

// Similar to GetCachedKeyValue(), but this version checks the predefined
// default directories.
bool GetCachedKeyValueDefault(const base::FilePath& base_name,
                              const std::string& key,
                              std::string* value);

// Get the user home directories via D-Bus using |session_manager_proxy|.
// Returns true on success.
bool GetUserHomeDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories);

// Gets the user crash directories via D-Bus using |session_manager_proxy|.
// Returns true on success.
bool GetUserCrashDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories);

bool GetDaemonStoreCrashDirectories(
    org::chromium::SessionManagerInterfaceProxyInterface* session_manager_proxy,
    std::vector<base::FilePath>* directories);

// Gzip's the |data| passed in and returns the compressed data. Returns an empty
// vector on failure.
std::vector<unsigned char> GzipStream(brillo::StreamPtr data);

// Runs |process| and redirects |fd| to |output|. Returns the exit code, or -1
// if the process failed to start.
int RunAndCaptureOutput(brillo::ProcessImpl* process,
                        int fd,
                        std::string* output);

// Breaks up |error| using std::getline and then does a LOG(ERROR) of each
// individual line.
void LogMultilineError(const std::string& error);

// Read the memfd file contents. Return false on failure.
bool ReadMemfdToString(int mem_fd, std::string* contents);

// Return the weight for SELinux failures. We'll only collect
// 1.0/GetSelinuxWeight() of the failures.
int GetSelinuxWeight();

// Return the weight to use for selinux failures when reporting to crash.
// Historically, the SELinux weight was 1000, but we did not report this to
// crash as weighted at all. So, the actual number of selinux reports has always
// been 1000x too low.
// For consistency, and to avoid a sudden change in the apparent number of
// selinux violations, adjust the actual weight reported by GetSelinuxWeight
// to be in line with historical levels.
int GetSelinuxWeightForCrash();

// Return the weight for service failures. We'll only collect
// 1.0/GetServiceFailureWeight() of the failures.
int GetServiceFailureWeight();

// Return the weight for suspend failures. We'll only collect
// 1.0/GetSuspendFailureWeight() of the failures.
int GetSuspendFailureWeight();

// Return the weight for oom events. We'll only collect
// 1.0/GetOomEventWeight() of the failures.
int GetOomEventWeight();

// Return the weight for kernel warnings with the specified command-line flag.
// We'll only collect 1.0/GetKernelWarningWeight(flag) of the failures.
int GetKernelWarningWeight(const std::string& flag);

// Return the weight for stateful umount failures.
int GetUmountStatefulFailureWeight();

// Return the weight for cryptohome recovery failures. We'll only collect
// 1.0/GetRecoveryFailureWeight() of the failures.
int GetRecoveryFailureWeight();

// Read the content binding to fd to stream.
bool ReadFdToStream(unsigned int fd, std::stringstream* stream);

// Read a line from a file to out_str and return size of the read line.
int GetNextLine(base::File& file, std::string& out_str);

#if USE_DIRENCRYPTION
// Joins the session key if the kernel supports ext4 directory encryption.
void JoinSessionKeyring();
#endif  // USE_DIRENCRYPTION

// Hash a string to a number.  We define our own hash function to not
// be dependent on a C++ library that might change.
unsigned HashString(base::StringPiece input);

// Get the absolute path to this binary given its command-line arguments,
// and allowing override with the LD_ARGV0 environment variable.
base::FilePath GetPathToThisBinary(const char* const argv[]);

// Replace digests with a placeholder this can help preserve privacy and group
// reports together whenever digests are present in the crash's unique
// signature.
bool RedactDigests(std::string* to_filter);

// Given the path to a Chrome metadata.json file, parse out the Chrome version
// in the file. Return std::nullopt and logs error message on error, otherwise
// return the version as a string.
std::optional<std::string> ExtractChromeVersionFromMetadata(
    const base::FilePath& metadata_path);

}  // namespace util

#endif  // CRASH_REPORTER_UTIL_H_
