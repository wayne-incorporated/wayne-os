// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CRASH_REPORTER_CRASH_SENDER_BASE_H_
#define CRASH_REPORTER_CRASH_SENDER_BASE_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/time/clock.h>
#include <base/time/time.h>
#include <brillo/key_value_store.h>
#include <brillo/osrelease_reader.h>
#include <session_manager/dbus-proxies.h>

namespace util {

// Maximum time to wait for ensuring a meta file is complete.
constexpr base::TimeDelta kMaxHoldOffTime = base::Seconds(30);
constexpr char kUndefined[] = "undefined";
constexpr char kChromeOsProduct[] = "ChromeOS";

// Crash information obtained in ChooseAction().
struct CrashInfo {
  brillo::KeyValueStore metadata;
  base::FilePath payload_file;
  std::string payload_kind;
  // Last modification time of the associated .meta file
  base::Time last_modified;
};

// Details of a crash report. Contains more information than CrashInfo, as
// additional information is extracted at a stage later stage.
struct CrashDetails {
  base::FilePath meta_file;
  base::FilePath payload_file;
  std::string payload_kind;
  std::string client_id;
  const brillo::KeyValueStore& metadata;
};

// Struct representing a fully-read-in meta file. Contains all fields that will
// be sent in crash report, with upload_file_ files and the payload left as
// FilePaths.
struct FullCrash {
  // Name of exec that crashed.
  std::string exec_name;
  // Board (e.g. "eve") of device
  std::string board;
  // Hardware class
  std::string hwclass;
  // product -- named this way to match name crash server expects
  std::string prod;
  // version -- named this way to match name crash server expects
  std::string ver;
  // Signature -- named this way to match name crash server expects
  std::string sig;
  // image type e.g. ("dev", "test", "")
  std::string image_type;
  // boot mode (e.g. "dev" or "")
  std::string boot_mode;
  // Error type (arbitrary, specified by client)
  std::string error_type;
  // client ID of machine
  std::string guid;
  // Payload of the crash. If this cannot be added, report should fail.
  std::pair<std::string, base::FilePath> payload;
  // Arbitrary human-readable key-value pairs.
  std::vector<std::pair<std::string, std::string>> key_vals;
  // Non-payload files to upload (possibly non-human-readable contents). If
  // attaching a non-payload file fails, log an error but continue.
  std::vector<std::pair<std::string, base::FilePath>> files;
};

// Testing hook. Set to true to force IsMock() to always return true. Easier
// than creating the mock file in internal tests (such as fuzz tests).
extern bool g_force_is_mock;

// Testing hook. Set to true to force IsMockSuccessful() to always return true.
// Easier than creating the mock file in internal tests (such as fuzz tests).
extern bool g_force_is_mock_successful;

// Gets the full path pointed by |key| in the given metadata.
// Returns an empty path if the key is not found.
base::FilePath GetFilePathFromMetadata(const brillo::KeyValueStore& metadata,
                                       const std::string& key);

// Returns which kind of report from the given payload path. Returns an empty
// string if the kind is unknown.
std::string GetKindFromPayloadPath(const base::FilePath& payload_path);

// Parses |raw_metadata| into |metadata|. Keys in metadata are validated (keys
// should consist of expected characters). Returns true on success.
// The original contents of |metadata| will be lost.
bool ParseMetadata(const std::string& raw_metadata,
                   brillo::KeyValueStore* metadata);

// Returns true if the metadata is complete.
bool IsCompleteMetadata(const brillo::KeyValueStore& metadata);

// Records that the crash sending is done.
void RecordCrashDone();

// Returns true if mock is enabled.
bool IsMock();

// Returns true if we're running under an Integration test.
bool IsIntegrationTest();

// Returns true if mock is enabled and we should succeed.
bool IsMockSuccessful();

// Returns the string that describes the type of image. Returns an empty string
// if we shouldn't specify the image type.
std::string GetImageType();

// Computes a sleep time needed before attempting to send a new crash report.
// On success, returns true and stores the result in |sleep_time|. On error,
// returns false.
bool GetSleepTime(const base::FilePath& meta_file,
                  const base::TimeDelta& max_spread_time,
                  const base::TimeDelta& hold_off_time,
                  base::TimeDelta* sleep_time);

// Gets the client ID if it exists, otherwise it generates it, saves it and
// returns that new ID. If it is unable to create the directory for storage, the
// empty string is returned.
std::string GetClientId();

class ScopedProcessingFileBase {
 public:
  // Disallow copy and assign (and implicitly, move).
  ScopedProcessingFileBase(const ScopedProcessingFileBase& other) = delete;
  ScopedProcessingFileBase& operator=(const ScopedProcessingFileBase& other) =
      delete;
  virtual ~ScopedProcessingFileBase();

 protected:
  ScopedProcessingFileBase();
};

// This class assists us in recovering from crashes while processing crashes.
// When it is constructed, it attempts to create a ".processing" file for the
// given metadata file, and when it is destructed it removes it.
// If crash_sender crashes, or otherwise exits without running the destructor,
// the .processing file will still exist. ChooseAction uses the existence of
// this file to determine that the crash may be malformed and avoid processing
// it again. It also has a dummy sibling `DummyScopedProcessingFile` that
// handles situations that ".processing" files shouldn't be created, such as the
// dry run mode.
class ScopedProcessingFile : public ScopedProcessingFileBase {
 public:
  explicit ScopedProcessingFile(const base::FilePath& meta_file);
  ~ScopedProcessingFile() override;

 private:
  const base::FilePath processing_file_;
};

// A sibling of `ScopedProcessingFile` that does nothing.
class DummyScopedProcessingFile : public ScopedProcessingFileBase {
 public:
  explicit DummyScopedProcessingFile(const base::FilePath& meta_file);
  ~DummyScopedProcessingFile() override;
};

// Base class for crash reading functionality. Used by both crash sender and
// crash serializer.
class SenderBase {
 public:
  struct Options {
    // Session manager client for locating the user-specific crash directories.
    org::chromium::SessionManagerInterfaceProxyInterface*
        session_manager_proxy = nullptr;

    // Do not send the crash report until the meta file is at least this old.
    // This avoids problems with crash reports being sent out while they are
    // still being written.
    base::TimeDelta hold_off_time = kMaxHoldOffTime;

    // Alternate sleep function for unit testing.
    base::RepeatingCallback<void(base::TimeDelta)> sleep_function;

    // Whether to log times in AcquireLockFileOrDie.
    bool log_extra_times = false;
  };

  SenderBase(std::unique_ptr<base::Clock> clock, const Options& options);

  virtual ~SenderBase() = default;

  // Actions returned by ChooseAction().
  enum Action {
    kRemove,  // Should remove the crash report.
    kIgnore,  // Should ignore (keep) the crash report.
    kSend,    // Should send the crash report.
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused
  enum CrashRemoveReason {
    kTotalRemoval = 0,
    kNotOfficialImage = 1,
    kNoMetricsConsent = 2,
    kProcessingFileExists = 3,
    kLargeMetaFile = 4,
    kUnparseableMetaFile = 5,
    kPayloadUnspecified = 6,
    kPayloadAbsolute = 7,
    kPayloadNonexistent = 8,
    kPayloadKindUnknown = 9,
    kOSVersionTooOld = 10,
    kOldIncompleteMeta = 11,
    kFinishedUploading = 12,
    kAlreadyUploaded = 13,
    kTooManyRequests = 14,
    // Do not remove just yet
    kRetryUploading = 15,
    kLaCrosVersionTooOld = 16,
    kDryRun = 17,
    // Keep kSendReasonCount one larger than any other enum value.
    kSendReasonCount = 18,
  };

  // Lock the lock file so no concurrently running process can access the
  // disk files. Dies if lock file cannot be acquired after a delay.
  //
  // Returns the File object holding the lock.
  base::File AcquireLockFileOrDie();

  // Get a list of all directories that might hold user-specific crashes.
  std::vector<base::FilePath> GetUserCrashDirectories();

  // For tests only, crash while sending crashes.
  void SetCrashDuringSendForTesting(bool crash) {
    crash_during_testing_ = crash;
  }

  // Read the meta file and return a struct representing its contents.
  FullCrash ReadMetaFile(const CrashDetails& details);

 protected:
  // Do a minimal evaluation of the given meta file, only performing basic
  // validation (e.g. that it's fully written, that the payload field is valid,
  // etc).
  // In particular, this does _not_ check metrics consent, guest mode, or
  // whether the crash is already uploaded.
  // Arguments:
  //  |meta_file| - The path to the metadata file to process.
  //  |allow_old_os_timestamps| - True iff we should return kSend for metadata
  //                              files created on old (>6 mo) OS versions
  //  |reason| - output parameter. Human-readable description of the reason for
  //             the given action. useful for logs.
  //  |info| - output parameter. CrashInfo struct created while evaluating meta
  //           file.
  //  |processing_file| - optional output parameter. If non-null, a
  //                      ScopedProcessingFile will be placed into it.
  //                      This file should remain in scope during all
  //                      additional processing of the meta file.
  Action EvaluateMetaFileMinimal(
      const base::FilePath& meta_file,
      bool allow_old_os_timestamps,
      std::string* reason,
      CrashInfo* info,
      std::unique_ptr<ScopedProcessingFileBase>* processing_file);

  // Record the reason for removing a crash.
  virtual void RecordCrashRemoveReason(CrashRemoveReason reason) = 0;

  // Makes sure we have the DBus object initialized and connected.
  void EnsureDBusIsReady();

  // These are accessed by child classes.
  base::RepeatingCallback<void(base::TimeDelta)> sleep_function_;
  scoped_refptr<dbus::Bus> bus_;
  bool crash_during_testing_ = false;
  const base::TimeDelta hold_off_time_;
  const bool log_extra_times_ = false;

 private:
  // Creates a `ScopedProcessingFileBase` object. Called in
  // EvaluateMetaFileMinimal.
  virtual std::unique_ptr<ScopedProcessingFileBase> MakeScopedProcessingFile(
      const base::FilePath& meta_file) = 0;

  // Looks through |keys| in the os-release data using brillo::OsReleaseReader.
  // Keys are searched in order until a value is found. Returns the value in
  // the Optional if found, otherwise the Optional is empty.
  std::optional<std::string> GetOsReleaseValue(
      const std::vector<std::string>& keys);

  std::unique_ptr<base::Clock> clock_;
  std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
      session_manager_proxy_;
  std::unique_ptr<brillo::OsReleaseReader> os_release_reader_;
};

}  // namespace util

#endif  // CRASH_REPORTER_CRASH_SENDER_BASE_H_
