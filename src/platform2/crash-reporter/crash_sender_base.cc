// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_sender_base.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/uuid.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/crash_sender_util.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {
constexpr char kUploadVarPrefix[] = "upload_var_";
constexpr char kUploadTextPrefix[] = "upload_text_";
constexpr char kUploadFilePrefix[] = "upload_file_";
constexpr char kOsTimestamp[] = "os_millis";
constexpr char kProcessingExt[] = ".processing";
constexpr char kRecentIncompleteMeta[] = "Recent incomplete metadata";

// Length of the client ID. This is a standard GUID which has the dashes
// removed.
constexpr size_t kClientIdLength = 32U;

// Buffer size for reading a meta file into memory, in bytes.
constexpr size_t kMaxMetaFileSize = 1024 * 1024;

// Returns true if the given report kind is known.
// TODO(satorux): Move collector constants to a common file.
bool IsKnownKind(const std::string& kind) {
  return (kind == constants::kKindForMinidump || kind == "kcrash" ||
          kind == "log" || kind == "devcore" || kind == "eccrash" ||
          kind == "bertdump" || kind == "txt" ||
          kind == constants::kKindForJavaScriptError);
}

// Returns true if the given key is valid for crash metadata.
bool IsValidKey(const std::string& key) {
  if (key.empty())
    return false;

  for (const char c : key) {
    if (!(base::IsAsciiAlpha(c) || base::IsAsciiDigit(c) || c == '_' ||
          c == '-' || c == '.')) {
      return false;
    }
  }

  return true;
}

// Converts metadata into CrashInfo.
void MetadataToCrashInfo(const brillo::KeyValueStore& metadata,
                         util::CrashInfo* info) {
  info->payload_file = util::GetFilePathFromMetadata(metadata, "payload");
  info->payload_kind = util::GetKindFromPayloadPath(info->payload_file);
}

}  // namespace

namespace util {

bool g_force_is_mock = false;
bool g_force_is_mock_successful = false;

std::string GetImageType() {
  if (util::IsTestImage())
    return "test";
  else if (util::IsDeveloperImage())
    return "dev";
  else if (IsMock() && !IsMockSuccessful())
    return "mock-fail";
  else
    return "";
}

base::FilePath GetFilePathFromMetadata(const brillo::KeyValueStore& metadata,
                                       const std::string& key) {
  std::string value;
  if (!metadata.GetString(key, &value))
    return base::FilePath();

  return base::FilePath(value);
}

std::string GetKindFromPayloadPath(const base::FilePath& payload_path) {
  std::vector<std::string> parts =
      base::SplitString(payload_path.BaseName().value(), ".",
                        base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  // Suppress "gz".
  if (parts.size() >= 2 && parts.back() == "gz")
    parts.pop_back();

  if (parts.size() <= 1)
    return "";

  std::string extension = parts.back();
  if (extension == constants::kMinidumpExtension)
    return constants::kKindForMinidump;
  if (extension == constants::kJavaScriptStackExtension)
    return constants::kKindForJavaScriptError;

  return extension;
}

bool ParseMetadata(const std::string& raw_metadata,
                   brillo::KeyValueStore* metadata) {
  metadata->Clear();
  if (!metadata->LoadFromString(raw_metadata))
    return false;

  for (const auto& key : metadata->GetKeys()) {
    if (!IsValidKey(key))
      return false;
  }

  return true;
}

bool IsCompleteMetadata(const brillo::KeyValueStore& metadata) {
  // *.meta files always end with done=1 so we can tell if they are complete.
  std::string value;
  if (!metadata.GetString("done", &value))
    return false;
  return value == "1";
}

void RecordCrashDone() {
  if (IsMock()) {
    // For testing purposes, emit a message to log so that we
    // know when the test has received all the messages from this run.
    // The string is referenced in
    // third_party/autotest/files/client/cros/crash/crash_test.py and
    // platform/tast-tests/src/chromiumos/tast/local/crash/sender.go
    LOG(INFO) << "crash_sender done. (mock)";
    base::FilePath done_file =
        paths::GetAt(paths::kSystemRunStateDirectory, paths::kCrashSenderDone);
    if (base::WriteFile(done_file, "", 0) != 0) {
      PLOG(ERROR) << "Error writing out crash-sender-done file: " << done_file;
    }
  }
}

bool IsMock() {
  if (g_force_is_mock) {
    return true;
  }

  return IsIntegrationTest();
}

bool IsIntegrationTest() {
  return base::PathExists(
      paths::GetAt(paths::kSystemRunStateDirectory, paths::kMockCrashSending));
}

bool IsMockSuccessful() {
  if (g_force_is_mock_successful) {
    return true;
  }
  int64_t file_size;
  return base::GetFileSize(paths::GetAt(paths::kSystemRunStateDirectory,
                                        paths::kMockCrashSending),
                           &file_size) &&
         !file_size;
}

bool GetSleepTime(const base::FilePath& meta_file,
                  const base::TimeDelta& max_spread_time,
                  const base::TimeDelta& hold_off_time,
                  base::TimeDelta* sleep_time) {
  base::File::Info info;
  if (!base::GetFileInfo(meta_file, &info)) {
    PLOG(ERROR) << "Failed to get file info: " << meta_file.value();
    return false;
  }

  // The meta file should be written *after* all to-be-uploaded files that it
  // references.  Nevertheless, as a safeguard, a hold-off time after writing
  // the meta file is ensured.  Also, sending of crash reports is spread out
  // randomly by up to |max_spread_time|. Thus, for the sleep call the greater
  // of the two delays is used. Use max() to ensure that holdoff_time is not
  // negative.
  const base::TimeDelta hold_off_time_remaining =
      std::max(info.last_modified + hold_off_time - base::Time::Now(),
               base::TimeDelta());

  const int seconds = (max_spread_time.InSeconds() <= 0
                           ? 0
                           : base::RandInt(0, max_spread_time.InSeconds()));
  const base::TimeDelta spread_time = base::Seconds(seconds);

  *sleep_time = std::max(spread_time, hold_off_time_remaining);

  return true;
}

std::string GetClientId() {
  std::string client_id;
  base::FilePath client_id_dir = paths::Get(paths::kCrashSenderStateDirectory);
  if (!base::CreateDirectory(client_id_dir)) {
    PLOG(ERROR) << "Failed to create directory: " << client_id_dir.value();
    return "";
  }
  base::FilePath client_id_file = client_id_dir.Append(paths::kClientId);
  if (base::PathExists(client_id_file)) {
    if (!base::ReadFileToString(client_id_file, &client_id)) {
      PLOG(ERROR) << "Error reading client ID file: " << client_id_file.value();
    } else if (client_id.length() != kClientIdLength) {
      // Don't log what this is, otherwise we may need to scrub it.
      LOG(ERROR) << "Client ID has wrong format, regenerate it";
    } else {
      return client_id;
    }
  }
  client_id = base::Uuid::GenerateRandomV4().AsLowercaseString();
  // Strip out the dashes, we don't want those.
  base::RemoveChars(client_id, "-", &client_id);

  if (base::WriteFile(client_id_file, client_id.c_str(), client_id.length()) !=
      client_id.length()) {
    PLOG(ERROR) << "Error writing out client ID to file: "
                << client_id_file.value();
  }

  return client_id;
}

ScopedProcessingFileBase::ScopedProcessingFileBase() = default;
ScopedProcessingFileBase::~ScopedProcessingFileBase() = default;

ScopedProcessingFile::ScopedProcessingFile(const base::FilePath& meta_file)
    : processing_file_(meta_file.ReplaceExtension(kProcessingExt)) {
  base::File f(processing_file_,
               base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!f.IsValid()) {
    LOG(ERROR) << "Failed to mark crash as being processed";
  }
}

ScopedProcessingFile::~ScopedProcessingFile() {
  if (!base::DeleteFile(processing_file_)) {
    LOG(ERROR) << "Failed to remove .processing file. Crash will be deleted.";
  }
}

DummyScopedProcessingFile::DummyScopedProcessingFile(
    const base::FilePath& meta_file) {}

DummyScopedProcessingFile::~DummyScopedProcessingFile() = default;

SenderBase::SenderBase(std::unique_ptr<base::Clock> clock,
                       const SenderBase::Options& options)
    : sleep_function_(options.sleep_function),
      hold_off_time_(options.hold_off_time),
      log_extra_times_(options.log_extra_times),
      clock_(std::move(clock)),
      session_manager_proxy_(options.session_manager_proxy) {}

base::File SenderBase::AcquireLockFileOrDie() {
  // TODO(b/197518716): Remove extra logging once this flake is resolved.
  if (log_extra_times_) {
    LOG(INFO) << "AcquireLockFileOrDie: " << base::Time::Now();
  }

  base::FilePath lock_file_path = paths::Get(paths::kCrashSenderLockFile);
  base::File lock_file(lock_file_path, base::File::FLAG_OPEN_ALWAYS |
                                           base::File::FLAG_READ |
                                           base::File::FLAG_WRITE);
  if (!lock_file.IsValid()) {
    LOG(FATAL) << "Error opening " << lock_file_path.value() << ": "
               << base::File::ErrorToString(lock_file.error_details());
  }

  base::TimeDelta wait_for_lock_file = base::Minutes(5);

  if (IsCrashTestInProgress()) {
    // When running crash.SenderLock test, don't wait a full 5 minutes before
    // completing the test.
    wait_for_lock_file = base::Seconds(1);
  }

  base::Time stop_time = clock_->Now() + wait_for_lock_file;
  while (clock_->Now() < stop_time) {
    if (lock_file.Lock(base::File::LockMode::kExclusive) ==
        base::File::FILE_OK) {
      // TODO(b/197518716): Remove extra logging once this flake is resolved.
      if (log_extra_times_) {
        LOG(INFO) << "AcquireLockFileOrDie: early return: "
                  << base::Time::Now();
      }
      return lock_file;
    }
    const base::TimeDelta kSleepTime = base::Seconds(1);
    if (sleep_function_.is_null()) {
      base::PlatformThread::Sleep(kSleepTime);
    } else {
      sleep_function_.Run(kSleepTime);
    }
  }

  // Last try. Exit if this one doesn't succeed.
  auto result = lock_file.Lock(base::File::LockMode::kExclusive);
  if (result != base::File::FILE_OK) {
    // Note: If another process is holding the lock, this will just say
    // something unhelpful like "FILE_ERROR_FAILED"; File::Lock doesn't have a
    // separate return code corresponding to EWOULDBLOCK.
    LOG(ERROR) << "Failed to acquire a lock: "
               << base::File::ErrorToString(result);
    // TODO(b/197518716): Remove extra logging once this flake is resolved.
    if (log_extra_times_) {
      LOG(INFO) << "AcquireLockFileOrDie: failure: " << base::Time::Now();
    }
    RecordCrashDone();
    exit(EXIT_FAILURE);
  }

  // TODO(b/197518716): Remove extra logging once this flake is resolved.
  if (log_extra_times_) {
    LOG(INFO) << "AcquireLockFileOrDie: late return: " << base::Time::Now();
  }
  return lock_file;
}

SenderBase::Action SenderBase::EvaluateMetaFileMinimal(
    const base::FilePath& meta_file,
    bool allow_old_os_timestamps,
    std::string* reason,
    CrashInfo* info,
    std::unique_ptr<ScopedProcessingFileBase>* processing_file) {
  if (base::PathExists(meta_file.ReplaceExtension(kProcessingExt))) {
    *reason = ".processing file already exists for: " + meta_file.value();
    RecordCrashRemoveReason(kProcessingFileExists);
    return kRemove;
  }

  auto f = MakeScopedProcessingFile(meta_file);
  if (processing_file) {
    // The caller wants to take care of this, so move it to their scope before
    // we return.
    *processing_file = std::move(f);
  }

  if (IsMock()) {
    CHECK(!crash_during_testing_) << "crashing as requested";
  }

  std::string raw_metadata;
  if (!base::ReadFileToStringWithMaxSize(meta_file, &raw_metadata,
                                         kMaxMetaFileSize)) {
    if (raw_metadata.empty()) {
      *reason = "Metadata file is inaccessible: " + meta_file.value();
      return kIgnore;
    }

    *reason = "Metadata file is unusually large: " + meta_file.value();
    RecordCrashRemoveReason(kLargeMetaFile);
    return kRemove;
  }

  base::File::Info file_info;
  if (!base::GetFileInfo(meta_file, &file_info)) {
    // Should not happen since it succeeded to read the file.
    *reason = "Failed to get file info";
    return kIgnore;
  }

  const base::TimeDelta delta = clock_->Now() - file_info.last_modified;

  if (!ParseMetadata(raw_metadata, &info->metadata)) {
    // If the file fails to parse but is still relatively new, it's possible
    // that we're racing with the file write and, for example, may have read in
    // a partial line.
    // Therefore, don't give up on a meta file as corrupt until it's been around
    // for long enough that we can be sure that race is not happening.
    if (delta.InHours() >= 1) {
      *reason = "Corrupted metadata: " + raw_metadata;
      RecordCrashRemoveReason(kUnparseableMetaFile);
      return kRemove;
    } else {
      *reason = kRecentIncompleteMeta;
      return kIgnore;
    }
  }

  MetadataToCrashInfo(info->metadata, info);
  info->last_modified = file_info.last_modified;

  // Before verifying any properties of the metadata file (e.g. that all fields
  // are completely written), we must check that it is actually complete.
  // For example, we shouldn't remove a metadata file due to a missing payload
  // while that meta file is still being written.
  if (!IsCompleteMetadata(info->metadata)) {
    if (delta.InHours() >= 24) {
      *reason = "Removing old incomplete metadata";
      RecordCrashRemoveReason(kOldIncompleteMeta);
      return kRemove;
    } else {
      *reason = kRecentIncompleteMeta;
      return kIgnore;
    }
  }

  if (info->payload_file.empty()) {
    *reason = "Payload is not found in the meta data: " + raw_metadata;
    RecordCrashRemoveReason(kPayloadUnspecified);
    return kRemove;
  }

  // Check for absolute path, or Append will CHECK-fail.
  if (info->payload_file.IsAbsolute()) {
    *reason =
        "Corrupt meta: payload path is absolute: " + info->payload_file.value();
    RecordCrashRemoveReason(kPayloadAbsolute);
    return kRemove;
  }

  // Make it an absolute path.
  info->payload_file = meta_file.DirName().Append(info->payload_file);

  if (!base::PathExists(info->payload_file)) {
    *reason = "Missing payload: " + info->payload_file.value();
    RecordCrashRemoveReason(kPayloadNonexistent);
    return kRemove;
  }

  if (!IsKnownKind(info->payload_kind)) {
    *reason = "Unknown kind: " + info->payload_kind;
    RecordCrashRemoveReason(kPayloadKindUnknown);
    return kRemove;
  }

  // If we have an OS timestamp in the metadata and it's too old to upload and
  // we're not allowing old os timestamps then remove the report.
  std::string os_timestamp_str;
  int64_t os_millis;
  if (!allow_old_os_timestamps &&
      info->metadata.GetString(kOsTimestamp, &os_timestamp_str) &&
      base::StringToInt64(os_timestamp_str, &os_millis) &&
      util::IsBuildTimestampTooOldForUploads(os_millis, clock_.get())) {
    std::string build_time_str;
    // If the OS timestamp is too old, and we don't have a browser build time
    // (typically sent from Lacros), remove the report with reason
    // kOSVersionTooOld.
    // If on the other hand, the OS is too old *but* lacros exists and is
    // sufficiently new, we send the report.
    // If Lacros provides a build time that's too old, but the OS is
    // sufficiently new, we'll send the crash anyway, as it's possible there's
    // an ash<->lacros compatibility issue.
    int64_t build_time_millis;
    if (!info->metadata.GetString("build_time_millis", &build_time_str)) {
      *reason = "Old OS version";
      RecordCrashRemoveReason(kOSVersionTooOld);
      return kRemove;
    } else if (base::StringToInt64(build_time_str, &build_time_millis) &&
               util::IsBuildTimestampTooOldForUploads(build_time_millis,
                                                      clock_.get())) {
      *reason = "Old LaCros version";
      RecordCrashRemoveReason(kLaCrosVersionTooOld);
      return kRemove;
    }
  }

  return kSend;
}

std::vector<base::FilePath> SenderBase::GetUserCrashDirectories() {
  // Set up the session manager proxy if it's not given from the options.
  if (!session_manager_proxy_) {
    EnsureDBusIsReady();
    session_manager_proxy_.reset(
        new org::chromium::SessionManagerInterfaceProxy(bus_));
  }

  std::vector<base::FilePath> directories;
  util::GetUserCrashDirectories(session_manager_proxy_.get(), &directories);
  util::GetDaemonStoreCrashDirectories(session_manager_proxy_.get(),
                                       &directories);

  return directories;
}

void SenderBase::EnsureDBusIsReady() {
  if (!bus_) {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::Bus(options);
    CHECK(bus_->Connect());
  }
}

FullCrash SenderBase::ReadMetaFile(const CrashDetails& details) {
  FullCrash crash;

  if (!details.metadata.GetString("exec_name", &crash.exec_name)) {
    crash.exec_name = kUndefined;
  }

  if (!details.metadata.GetString("board", &crash.board) &&
      !GetCachedKeyValueDefault(base::FilePath(paths::kLsbRelease),
                                "CHROMEOS_RELEASE_BOARD", &crash.board)) {
    crash.board = kUndefined;
  }

  crash.hwclass = util::GetHardwareClass();

  // When uploading Chrome reports we need to report the right product and
  // version. If the meta file does not specify it we try to examine os-release
  // content. If not available there product gets assigned default product name
  // and version is derived from CHROMEOS_RELEASE_VERSION in /etc/lsb-release.
  if (!details.metadata.GetString("upload_var_prod", &crash.prod)) {
    crash.prod =
        GetOsReleaseValue({"GOOGLE_CRASH_ID", "ID"}).value_or(kChromeOsProduct);
  }

  if (!details.metadata.GetString("upload_var_ver", &crash.ver)) {
    if (!details.metadata.GetString("ver", &crash.ver)) {
      crash.ver = GetOsReleaseValue(
                      {"GOOGLE_CRASH_VERSION_ID", "BUILD_ID", "VERSION_ID"})
                      .value_or(kUndefined);
    }
  }

  // Ignore failures here; it's ok if this is missing.
  details.metadata.GetString("sig", &crash.sig);

  base::FilePath payload_file = details.payload_file;
  // Payload file should have been made absolute in EvaluateMetaFileMinimal
  if (!payload_file.IsAbsolute()) {
    payload_file = details.meta_file.DirName().Append(payload_file);
  }

  crash.payload =
      std::make_pair("upload_file_" + details.payload_kind, payload_file);
  // The crash infrastructure expects "upload_file_minidump" for minidumps but
  // expects just "JavascriptError" for JavaScript errors. See
  // FileStorage::kDumpFileName vs FileStorage::kJsStacktraceFileName.
  if (details.payload_kind == constants::kKindForJavaScriptError) {
    crash.payload.first = constants::kKindForJavaScriptError;
  }

  crash.image_type = GetImageType();
  crash.boot_mode = util::GetBootModeString();

  // Ignore failures here; it's ok if this is missing.
  details.metadata.GetString("error_type", &crash.error_type);

  crash.guid = details.client_id;

  for (const auto& key : details.metadata.GetKeys()) {
    if (!base::StartsWith(key, "upload_", base::CompareCase::SENSITIVE) ||
        key == "upload_var_prod" || key == "upload_var_ver" ||
        key == "upload_var_guid") {
      continue;
    }
    std::string value;
    details.metadata.GetString(key, &value);
    bool is_upload_var =
        base::StartsWith(key, kUploadVarPrefix, base::CompareCase::SENSITIVE);
    bool is_upload_text =
        base::StartsWith(key, kUploadTextPrefix, base::CompareCase::SENSITIVE);
    bool is_upload_file =
        base::StartsWith(key, kUploadFilePrefix, base::CompareCase::SENSITIVE);
    if (is_upload_var) {
      crash.key_vals.emplace_back(key.substr(sizeof(kUploadVarPrefix) - 1),
                                  value);
    } else if (is_upload_text || is_upload_file) {
      base::FilePath value_file(value);
      // Upload only files without path information in them
      if (value_file.value().find('/') != std::string::npos) {
        LOG(ERROR) << "Blocking path file " << value_file.value();
        crash.key_vals.emplace_back("file_blocked_by_path", value_file.value());
      } else {
        value_file = details.meta_file.DirName().Append(value_file);
        if (is_upload_text) {
          std::string value_content;
          if (base::ReadFileToString(value_file, &value_content)) {
            crash.key_vals.emplace_back(
                key.substr(sizeof(kUploadTextPrefix) - 1), value_content);
          } else {
            LOG(ERROR) << "Failed attaching file contents from "
                       << value_file.value();
          }
        } else {  // not is_upload_text so must be is_upload_file
          crash.files.emplace_back(key.substr(sizeof(kUploadFilePrefix) - 1),
                                   value_file);
        }
      }
    }
  }

  return crash;
}

std::optional<std::string> SenderBase::GetOsReleaseValue(
    const std::vector<std::string>& keys) {
  if (!os_release_reader_) {
    os_release_reader_ = std::make_unique<brillo::OsReleaseReader>();
    os_release_reader_->Load();
  }
  std::string value;
  for (const auto& key : keys) {
    if (os_release_reader_->GetString(key, &value))
      return std::optional<std::string>(value);
  }
  return std::optional<std::string>();
}

}  // namespace util
