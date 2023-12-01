// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CRASH_SENDER_UTIL_H_
#define CRASH_REPORTER_CRASH_SENDER_UTIL_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/time/clock.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/http/http_form_data.h>
#include <brillo/http/http_transport.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <metrics/metrics_library.h>
#include <session_manager/dbus-proxies.h>
#include <shill/dbus-proxies.h>
#include <third_party/abseil-cpp/absl/types/variant.h>

#include "crash-reporter/crash_sender_base.h"

namespace util {

// URL to send official build crash reports to.
constexpr char kReportUploadProdUrl[] = "https://clients2.google.com/cr/report";

// URL to send test/dev build crash reports to.
constexpr char kReportUploadStagingUrl[] =
    "https://clients2.google.com/cr/staging_report";

// Maximum crashes to send per 24 hours.
constexpr int kMaxCrashRate = 32;

// Maximum bytes of crash reports to send per 24 hours. Note that "whichever
// comes last" maximum with kMaxCrashRate; that is, we'll always send 32 crashes
// per 24 hours, even if that exceeds 24MB, and we'll always send 24MB per 24
// hours, even if that exceeds 32 crashes.
constexpr int kMaxCrashBytes = 24 * 1024 * 1024;

// Maximum time to sleep before attempting to send a crash report. This value is
// inclusive as an upper bound, thus 0 means a crash report can be sent
// immediately.
constexpr int kMaxSpreadTimeInSeconds = 600;

// Parsed command line flags.
struct CommandLineFlags {
  base::TimeDelta max_spread_time;
  std::string crash_directory;
  bool ignore_rate_limits = false;
  bool ignore_hold_off_time = false;
  bool allow_dev_sending = false;
  bool ignore_pause_file = false;
  bool test_mode = false;
  bool upload_old_reports = false;
  bool force_upload_on_test_images = false;
  bool consent_already_checked_by_crash_reporter = false;
  bool dry_run = false;
};

// Represents a metadata file name, and its parsed metadata.
typedef std::pair<base::FilePath, CrashInfo> MetaFile;

// Parses the command line, and handles the command line flags.
//
// On error, the process exits as a failure with an error message for the
// first-encountered error.
void ParseCommandLine(int argc,
                      const char* const* argv,
                      CommandLineFlags* flags);

// Returns true if the marker file exists indicating we should pause sending.
// This can be overridden with a command line flag to the program.
bool DoesPauseFileExist();

// Gets the base part of a crash report file, such as:
// name.01234.5678.9012.meta -> name.01234.5678.9012
// name.01234.5678.1234.9012.meta -> name.01234.5678.1234.9012
// name.01234.5678.9012.log.tar.xz -> name.01234.5678.9012
// name.01234.5678.1234.9012.log.tar.xz -> name.01234.5678.1234.9012
// This supports both 4-segment and 5-segment basenames, as long as the last
// segment always is numeric and the extension does not start with an
// all-numeric component.
//
// We make sure "name" is sanitized in CrashCollector::Sanitize to not include
// any periods. The directory part will be preserved.
base::FilePath GetBasePartOfCrashFile(const base::FilePath& file_name);

// Removes orphaned files in |crash_dir|, that are files 24 hours old or older,
// without corresponding meta file.
void RemoveOrphanedCrashFiles(const base::FilePath& crash_dir);

// Sort the vector of crash reports so that the report we want to send first
// is at the front of the vector.
void SortReports(std::vector<MetaFile>* reports);

// Returns the list of meta data files (files with ".meta" suffix), sorted by
// the timestamp in the old-to-new order.
std::vector<base::FilePath> GetMetaFiles(const base::FilePath& crash_dir);

// Returns true if the metadata indicates that the crash was already uploaded.
bool IsAlreadyUploaded(const base::FilePath& meta_file);

// Returns true if the given timestamp file is new enough, indicating that there
// was a recent attempt to send a crash report.
bool IsTimestampNewEnough(const base::FilePath& timestamp_file);

// Returns true if sending a crash report now does not exceed |max_crash_rate|
// crashes and |max_crash_bytes| bytes per 24 hours.
//
// |timestamps_dir| contains the state files indicating how many sends have
// happened and how big they were.
bool IsBelowRate(const base::FilePath& timestamps_dir,
                 int max_crash_rate,
                 int max_crash_bytes);

// Records a crash send attempt so that IsBelowRate knows about it.
// |timestamps_dir| should be the same directory passed to IsBelowRate().
// |bytes| is the number of bytes sent over the network.
void RecordSendAttempt(const base::FilePath& timestamps_dir, int bytes);

// Gets the crash type based on crash details. Returns std::nullopt if the crash
// type is unknown. This is mainly used by healthD for fatal crashes.
std::optional<std::string> GetFatalCrashType(const CrashDetails& details);

// A helper class for sending crashes. The behaviors can be customized with
// Options class for unit testing.
//
// Crash reports will be sent even when the device is on a mobile data
// connection (see crbug.com/185110 for discussion).
class Sender : public SenderBase {
 public:
  struct Options : SenderBase::Options {
    // Shill FlimFlam Manager proxy interface for determining network state.
    org::chromium::flimflam::ManagerProxyInterface* shill_proxy = nullptr;

    // Maximum crashes to send per 24 hours. (We'll send more if still below
    // max_crash_bytes.)
    int max_crash_rate = kMaxCrashRate;

    // Maximum bytes we will upload per 24 hours. (We'll send more if still
    // below max_crash_rate.)
    int max_crash_bytes = kMaxCrashBytes;

    // Maximum time to sleep before attempting to send.
    base::TimeDelta max_spread_time;

    // Boundary to use in the form data.
    std::string form_data_boundary;

    // If true, we will ignore other checks when deciding if we should write to
    // the Chrome uploads.log file.
    bool always_write_uploads_log = false;

    // If true, we allow sending crash reports for unofficial test images and
    // the reports are uploaded to a staging crash server instead.
    bool allow_dev_sending = false;

    // If true, just touch the kTestModeSuccessfulFile if the crash report
    // looks legible instead of actually uploading it.
    bool test_mode = false;

    // If true, ignore timestamp check and upload old reports.
    bool upload_old_reports = false;

    // If true, always upload on test images and add a flag to the metadata
    // indicating that it's from a test image.
    bool force_upload_on_test_images = false;

    // If true, the caller is asserting that it is crash_reporter and has
    // already checked for consent, so any additional checks are not needed.
    bool consent_already_checked_by_crash_reporter = false;

    // If true, crash_sender will run under the dry run mode -- it will not
    // upload any crashes and writes log content to stdout.
    bool dry_run = false;
  };

  Sender(std::unique_ptr<MetricsLibraryInterface> metrics_lib,
         std::unique_ptr<base::Clock> clock,
         const Options& options);
  Sender(const Sender&) = delete;
  Sender& operator=(const Sender&) = delete;

  // Chooses an action to take for the crash report associated with the given
  // meta file, and reports the reason. The crash information will be stored in
  // |info| for reuse.
  SenderBase::Action ChooseAction(const base::FilePath& meta_file,
                                  std::string* reason,
                                  CrashInfo* info);

  // Removes invalid files in |crash_dir|, that are unknown, corrupted, or
  // invalid in other ways, and picks crash reports that should be sent to the
  // server. The meta files of the latter will be stored in |to_send|.
  void RemoveAndPickCrashFiles(const base::FilePath& directory,
                               std::vector<MetaFile>* reports_to_send);

  // Creates an Http transport object for invoking the Crash Server.
  virtual std::shared_ptr<brillo::http::Transport> GetTransport();

  // Sends each crash in |crash_meta_files|, in multiple steps:
  //
  // For each meta file:
  // - Sleeps to avoid overloading the network
  // - Checks if the device enters guest mode, and stops if entered.
  // - Enforces the rate limit per 24 hours.
  // - Removes crash files that are successfully uploaded.
  void SendCrashes(const std::vector<MetaFile>& crash_meta_files);

  // Given the |details| for a crash, creates a brillo::http::FormData object
  // which will have all of the fields for submission to the crash server
  // populated. Returns a nullptr if there were critical errors in populating
  // the data. This also logs out all of the details during the process. On
  // success, |product_name_out| is also set to the product name (it's not
  // possible to extract data from the returned FormData object in a
  // non-destructive manner).
  std::unique_ptr<brillo::http::FormData> CreateCrashFormData(
      const CrashDetails& details, std::string* product_name_out);

 private:
  friend class IsNetworkOnlineTest;
  FRIEND_TEST(CrashSenderUtilTest, RemoveReportFiles);
  FRIEND_TEST(CrashSenderUtilTest, RemoveReportFilesUnderDryRunMode);
  FRIEND_TEST(CrashSenderUtilTest, FailRemoveReportFilesSendsMetric);

  // Removes report files associated with the given meta file.
  // More specifically, if "foo.meta" is given, "foo.*" will be removed.
  void RemoveReportFiles(const base::FilePath& meta_file);

  // Send the specified reason for removing a crash to UMA.
  void RecordCrashRemoveReason(SenderBase::CrashRemoveReason reason) override;

  // Creates a JSON entity with the required fields for uploads.log file.
  base::Value::Dict CreateJsonEntity(const std::string& report_id,
                                     const std::string& product_name,
                                     const CrashDetails& details);

  // Creates an upload log entry and returns it. On failure, returns the reason.
  absl::variant<std::string, SenderBase::CrashRemoveReason>
  CreateUploadLogEntry(const std::string& report_id,
                       const std::string& product_name,
                       const CrashDetails& details);

  // Requests to send a crash report represented with the given crash details.
  // If the return code is kRetryUploading, the failure can be retried and the
  // caller should not remove the crash report. Otherwise, the caller should
  // remove the crash report using the returned removal reason code.
  SenderBase::CrashRemoveReason RequestToSendCrash(const CrashDetails& details);

  // Writes upload.log based on crash details and report ID. Writes to stdout
  // under the dry run mode.
  SenderBase::CrashRemoveReason WriteUploadLog(const CrashDetails& details,
                                               const std::string& report_id,
                                               std::string product_name);

  // Returns true if we have consent to send crashes to Google.
  bool HasCrashUploadingConsent(const CrashInfo& info);

  // Is this a "safe" device coredump, from an allowlist of driver names
  // for devices whose device coredump does not contain PII?
  bool IsSafeDeviceCoredump(const CrashInfo& info);

  // Checks if we have an online connection state so we can try sending crash
  // reports.
  bool IsNetworkOnline();

  // Creates a `ScopedProcessingFileBase` object based on whether we are running
  // under the dry run mode. ".processing" file should never be created under
  // the dry run mode but must be created under other scenarios.
  std::unique_ptr<ScopedProcessingFileBase> MakeScopedProcessingFile(
      const base::FilePath& meta_file) override;

  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;
  std::unique_ptr<org::chromium::flimflam::ManagerProxyInterface> shill_proxy_;
  std::vector<std::string> proxy_servers_;
  std::string form_data_boundary_;
  bool always_write_uploads_log_;
  const int max_crash_rate_;
  const int max_crash_bytes_;
  const base::TimeDelta max_spread_time_;
  bool allow_dev_sending_;
  const bool test_mode_;
  const bool upload_old_reports_;
  const bool force_upload_on_test_images_;
  const bool consent_already_checked_by_crash_reporter_;
  const bool dry_run_;
};

}  // namespace util

#endif  // CRASH_REPORTER_CRASH_SENDER_UTIL_H_
