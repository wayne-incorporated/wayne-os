// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The crash collector is a base class for all collectors to use. It implements
// common functionality, such as writing out .meta files.
// It is not a collector in and of itself.

#ifndef CRASH_REPORTER_CRASH_COLLECTOR_H_
#define CRASH_REPORTER_CRASH_COLLECTOR_H_

#include <sys/stat.h>
#include <sys/types.h>

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/time/clock.h>
#include <base/time/time.h>
#include <debugd/dbus-proxies.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <metrics/metrics_library.h>
#include <policy/device_policy.h>
#include <session_manager/dbus-proxies.h>
#include <zlib.h>

// Walk the directory tree to make sure we avoid symlinks.
// All parent parts must already exist else we return false.
bool ValidatePathAndOpen(const base::FilePath& dir, int* outfd);

// Extract environmental variables of interest and write them to the stream.
// This is exported primarily for regression testing.
void ExtractEnvironmentVars(const std::string& contents,
                            std::ostringstream* stream);

// User crash collector.
class CrashCollector {
 public:
  enum CrashDirectorySelectionMethod {
    // Force reports to be stored in the user crash directory, even if we are
    // not running as the "chronos" user.
    kAlwaysUseUserCrashDirectory,
    // Use the normal crash directory selection process: Store in the
    // daemon-store crash directory if a user is logged in, otherwise store in
    // the system crash directory or /home/chronos/crash.
    kUseNormalCrashDirectorySelectionMethod,
    // Force reports to be stored in daemon store, even if we are not
    // running as the "chronos" user, in the daemon-store experiment, or logged
    // in. If not logged in, methods to get the crash directory will fail.
    kAlwaysUseDaemonStore,
    // Always use the system crash directory.
    kAlwaysUseSystemCrashDirectory
  };

  enum CrashSendingMode {
    // Use the normal crash sending mode: Write crash files out to disk, and
    // assume crash_sender will be along later to send them out.
    kNormalCrashSendMode,
    // Use a special mode suitable when we are in a login-crash-loop. where
    // Chrome keeps crashing right after login, and we're about to log the user
    // out because we can't get into a good logged-in state. Write the crash
    // files into special in-memory locations, since the normal user crash
    // directory is in the cryptohome which will be locked out momentarily, and
    // send those in-memory files over to debugd for immediate upload, since
    // they are in volatile storage and the user may turn off their machine in
    // frustration shortly.
    kCrashLoopSendingMode
  };

  enum ErrorType {
    kErrorNone,
    kErrorSystemIssue,
    kErrorReadCoreData,
    kErrorUnusableProcFiles,
    kErrorInvalidCoreFile,
    kErrorUnsupported32BitCoreFile,
    kErrorCore2MinidumpConversion,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class CrashSeverity {
    kUnspecified = 0,
    kFatal = 1,
    kError = 2,
    kWarning = 3,
    kInfo = 4,
    kMaxValue = kInfo,
  };

  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class Product {
    kUnspecified = 0,
    kUi = 1,
    kPlatform = 2,
    kArc = 3,
    kLacros = 4,
    kMaxValue = kLacros,
  };

  struct ComputedCrashSeverity {
    CrashSeverity crash_severity;
    Product product_group;
  };

  explicit CrashCollector(const std::string& collector_name,
                          const std::string& tag = "");

  explicit CrashCollector(
      const std::string& collector_name,
      CrashDirectorySelectionMethod crash_directory_selection_method,
      CrashSendingMode crash_sending_mode,
      const std::string& tag = "");

  CrashCollector(const CrashCollector&) = delete;
  CrashCollector& operator=(const CrashCollector&) = delete;

  virtual ~CrashCollector();

  void set_lsb_release_for_test(const base::FilePath& lsb_release) {
    lsb_release_ = lsb_release;
  }

  // For testing, set the directory always returned by
  // GetCreatedCrashDirectoryByEuid.
  void set_crash_directory_for_test(const base::FilePath& forced_directory) {
    forced_crash_directory_ = forced_directory;
  }

  // For testing, set the directory where cached files are stored instead of
  // kCrashReporterStatePath.
  void set_reporter_state_directory_for_test(
      const base::FilePath& forced_directory) {
    crash_reporter_state_path_ = forced_directory;
  }

  void set_metrics_library_for_test(
      std::unique_ptr<MetricsLibraryInterface> metrics_lib) {
    metrics_lib_ = std::move(metrics_lib);
  }

  // For testing, set the log config file path instead of kDefaultLogConfig.
  void set_log_config_path(const std::string& path) {
    log_config_path_ = base::FilePath(path);
  }

  // For testing, set the clock to use to get the report timestamp.
  void set_test_clock(std::unique_ptr<base::Clock> test_clock) {
    test_clock_ = std::move(test_clock);
  }

  // For testing, use to set the kernel version rather than relying on uname.
  void set_test_kernel_info(const std::string& kernel_name,
                            const std::string& kernel_version) {
    test_kernel_name_ = kernel_name;
    test_kernel_version_ = kernel_version;
  }

  // For testing, use to set the mock device policy object instead.
  void set_device_policy_for_test(
      std::unique_ptr<policy::DevicePolicy> device_policy) {
    device_policy_loaded_ = false;
    device_policy_ = std::move(device_policy);
  }

  // For testing, force UseDaemonStore to return true or false, instead of
  // using a random number.
  void force_daemon_store_for_testing(bool use_daemon_store) {
    force_daemon_store_.emplace(use_daemon_store);
  }

  // For testing, return the in-memory files generated when in
  // kCrashLoopSendingMode. Since in_memory_files_ is a move-only type, this
  // clears the in_memory_files_ member variable.
  std::vector<std::tuple<std::string, base::ScopedFD>>
  get_in_memory_files_for_test() {
    return std::move(in_memory_files_);
  }

  // Allow tests to control the current machine uptime returned from
  // GetUptime().
  void set_current_uptime_for_test(base::TimeDelta uptime);

  // Get the complete set of extra metadata (as a string with newline-separated
  // key-value pairs, exactly as it will be written to the .meta file). For
  // testing purposes.
  std::string get_extra_metadata_for_test() const { return extra_metadata_; }

  void SetUseSavedLsb(bool use_saved_lsb) { use_saved_lsb_ = use_saved_lsb; }

  // Initialize the crash collector for detection of crashes, given a
  // metrics collection enabled oracle.
  void Initialize(bool early);

  // Return the number of bytes successfully written by all calls to
  // WriteNewFile() and WriteNewCompressedFile() so far. For
  // WriteNewCompressedFile(), the count is of bytes on disk, after compression.
  off_t get_bytes_written() const { return bytes_written_; }

  // Initialize the system crash paths.
  static bool InitializeSystemCrashDirectories(bool early);

  // Initialize metrics path. Returns true if flag directory is created.
  static bool InitializeSystemMetricsDirectories();

  // Add non-standard meta data to the crash metadata file.  Call
  // before calling FinishCrash.  Key must not contain "=" or "\n" characters.
  // Value must not contain "\n" characters.
  void AddCrashMetaData(const std::string& key, const std::string& value);

 protected:
  friend class CrashCollectorTest;
  FRIEND_TEST(ArcContextTest, GetAndroidVersion);
  FRIEND_TEST(ChromeCollectorTest, HandleCrash);
  FRIEND_TEST(CrashCollectorTest, CrashLoopModeCreatesInMemoryCompressedFiles);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_CrashLoopModeCreatesInMemoryCompressedFiles);
  FRIEND_TEST(CrashCollectorTest, CrashLoopModeCreatesInMemoryFiles);
  FRIEND_TEST(CrashCollectorTest, DISABLED_CrashLoopModeCreatesInMemoryFiles);
  FRIEND_TEST(CrashCollectorTest, CrashLoopModeCreatesMultipleInMemoryFiles);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_CrashLoopModeCreatesMultipleInMemoryFiles);
  FRIEND_TEST(CrashCollectorTest,
              CrashLoopModeWillNotCreateDuplicateCompressedFileNames);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_CrashLoopModeWillNotCreateDuplicateCompressedFileNames);
  FRIEND_TEST(CrashCollectorTest, CrashLoopModeWillNotCreateDuplicateFileNames);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_CrashLoopModeWillNotCreateDuplicateFileNames);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityCorrectBasename);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityStrangeNames);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityUsual);
  FRIEND_TEST(CrashCollectorTest, CreateDirectoryWithSettingsMode);
  FRIEND_TEST(CrashCollectorTest, CreateDirectoryWithSettingsNonDir);
  FRIEND_TEST(CrashCollectorTest, CreateDirectoryWithSettingsSubdir);
  FRIEND_TEST(CrashCollectorTest, CreateDirectoryWithSettingsSymlinks);
  FRIEND_TEST(CrashCollectorTest,
              CreateDirectoryWithSettings_FixPermissionsShallow);
  FRIEND_TEST(CrashCollectorTest,
              CreateDirectoryWithSettings_FixPermissionsRecursive);
  FRIEND_TEST(CrashCollectorTest,
              RunAsRoot_CreateDirectoryWithSettings_FixOwners);
  FRIEND_TEST(CrashCollectorTest,
              CreateDirectoryWithSettings_FixSubdirPermissions);
  FRIEND_TEST(CrashCollectorTest, FormatDumpBasename);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfoOld);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfoOldLoggedOut);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfoNew);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfoNewLoggedOut);
  FRIEND_TEST(CrashCollectorTest, GetCrashPath);
  FRIEND_TEST(CrashCollectorTest, GetLogContents);
  FRIEND_TEST(CrashCollectorTest, GetMultipleLogContents);
  FRIEND_TEST(CrashCollectorTest, GetProcessTree);
  FRIEND_TEST(CrashCollectorTest, GetProcessPath);
  FRIEND_TEST(CrashCollectorTest, GetUptime);
  FRIEND_TEST(CrashCollectorTest, Initialize);
  FRIEND_TEST(CrashCollectorParameterizedTest, MetaData);
  FRIEND_TEST(CrashCollectorTest, ErrorCollectionMetaData);
  FRIEND_TEST(CrashCollectorTest, MetaDataDoesntCreateSymlink);
  FRIEND_TEST(CrashCollectorTest, MetaDataDoesntOverwriteSymlink);
  FRIEND_TEST(CrashCollectorTest, CollectionLogsToUMA);
  FRIEND_TEST(CrashCollectorTest, ParseProcessTicksFromStat);
  FRIEND_TEST(CrashCollectorTest, Sanitize);
  FRIEND_TEST(CrashCollectorTest, StripMacAddressesBasic);
  FRIEND_TEST(CrashCollectorTest, StripMacAddressesBulk);
  FRIEND_TEST(CrashCollectorTest, StripSensitiveDataSample);
  FRIEND_TEST(CrashCollectorTest, StripEmailAddresses);
  FRIEND_TEST(CrashCollectorTest, StripIPv4Addresses);
  FRIEND_TEST(CrashCollectorTest, StripGaiaId);
  FRIEND_TEST(CrashCollectorTest, StripLocationInformation);
  FRIEND_TEST(CrashCollectorTest, StripIPv4Addresses);
  FRIEND_TEST(CrashCollectorTest, StripIPv6Addresses);
  FRIEND_TEST(CrashCollectorTest, StripSerialNumbers);
  FRIEND_TEST(CrashCollectorTest, StripRecoveryId);
  FRIEND_TEST(CrashCollectorTest, RemoveNewFileFailsOnNonExistantFiles);
  FRIEND_TEST(CrashCollectorTest,
              RemoveNewFileFailsOnNonExistantFilesInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest, RemoveNewFileRemovesCompressedFiles);
  FRIEND_TEST(CrashCollectorTest,
              RemoveNewFileRemovesCompressedFilesInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_RemoveNewFileRemovesCompressedFilesInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest,
              RemoveNewFileRemovesCorrectFileInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_RemoveNewFileRemovesCorrectFileInCrashLoopMode);
  FRIEND_TEST(CopyFirstNBytesParameterizedTest, CopyFirstNBytes);
  FRIEND_TEST(CrashCollectorTest, CopyFirstNBytesFailsOnExistingFile);
  FRIEND_TEST(CrashCollectorTest, RemoveNewFileRemovesNormalFiles);
  FRIEND_TEST(CrashCollectorTest,
              RemoveNewFileRemovesNormalFilesInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest,
              DISABLED_RemoveNewFileRemovesNormalFilesInCrashLoopMode);
  FRIEND_TEST(CrashCollectorTest, TruncatedLog);
  FRIEND_TEST(CrashCollectorTest, WriteNewFile);
  FRIEND_TEST(CrashCollectorTest, CopyToNewFile);
  FRIEND_TEST(CrashCollectorTest, CopyToNewCompressedFile);
  FRIEND_TEST(CrashCollectorTest, CopyToNewCompressedFileFailsIfFileExists);
  FRIEND_TEST(CrashCollectorTest, CopyToNewCompressedFileZeroSize);
  FRIEND_TEST(CrashCollectorTest, GetNewFileHandle);
  FRIEND_TEST(CrashCollectorTest, GetNewFileHandle_Symlink);
  FRIEND_TEST(CrashCollectorTest, WriteNewCompressedFile);
  FRIEND_TEST(CrashCollectorTest, WriteNewCompressedFileFailsIfFileExists);
  FRIEND_TEST(CrashCollectorTest, ComputeSeverity_DefaultUnspecified);
  FRIEND_TEST(UserCollectorTest, HandleSyscall);

  // Default value if OS version/description cannot be determined.
  static const char* const kUnknownValue;

  // Set maximum enqueued crashes in a crash directory.
  static const int kMaxCrashDirectorySize;

  // Try to set up D-Bus, returning true on success and false on failure.
  virtual bool TrySetUpDBus();
  // Set up D-Bus, CHECK-failing on failure.
  virtual void SetUpDBus();

  // Creates a new file and returns a file descriptor to it.
  base::ScopedFD GetNewFileHandle(const base::FilePath& filename);

  // Writes |data| to |filename|, which must be a new file.
  // If the file already exists or writing fails, return a negative value.
  // Otherwise returns the number of bytes written.
  int WriteNewFile(const base::FilePath& filename, base::StringPiece data);

  // Copies |source_fd| to |target_path|, which must be a new file.
  // If the file already exists or writing fails, return false.
  // Otherwise returns true.
  // Does _not_ increment get_bytes_written().
  // Probably does not do what you want in kCrashLoopSendingMode (will create a
  // memfd file).
  bool CopyFdToNewFile(base::ScopedFD source_fd,
                       const base::FilePath& target_path);

  // Copies |source_fd| to |target_path|, which must be a new file ending in
  // ".gz". File will be a gzip-compressed file.
  // If the file already exists or writing fails, return false.
  // Otherwise returns true.
  bool CopyFdToNewCompressedFile(base::ScopedFD source_fd,
                                 const base::FilePath& target_path);

  // Copies up to |bytes_to_copy| bytes from |source_pipe_fd|, which must be a
  // pipe, to |target_path|, which must be a new file. If the file already
  // exists or writing fails, return std::nullopt. Otherwise returns the actual
  // number of bytes written. Note that both underflow (reaching EOF before
  // writing |bytes_to_copy| bytes) and overflow (reaching |bytes_to_copy| bytes
  // before EOF) return success (returns an integer byte count not
  // std::nullopt).
  // Does _not_ increment get_bytes_written().
  // Probably does not do what you want in kCrashLoopSendingMode (will create a
  // memfd file).
  std::optional<int> CopyFirstNBytesOfFdToNewFile(
      int source_pipe_fd, const base::FilePath& target_path, int bytes_to_copy);

  // Writes |data| of |size| to |filename|, which must be a new file ending in
  // ".gz". File will be a gzip-compressed file. Returns true on success,
  // false on failure.
  bool WriteNewCompressedFile(const base::FilePath& filename,
                              const char* data,
                              size_t size);

  // Deletes a file created by WriteNewFile() or WriteNewCompressedFile(). Also
  // decrements get_bytes_written() by the file size. Needed because
  // base::DeleteFile() doesn't work on files created when in
  // kCrashLoopSendingMode.
  bool RemoveNewFile(const base::FilePath& filename);

  // Return a filename that has only [a-z0-1_] characters by mapping
  // all others into '_'.
  std::string Sanitize(const std::string& name);

  // Strip any data that the user might not want sent up to the crash server.
  // |contents| is modified in-place.
  void StripSensitiveData(std::string* contents);

  // This is going away once the experiment is done.
  // TODO(b/186659673): Validate daemon-store usage and remove this.
  std::optional<base::FilePath> GetCrashDirectoryInfoOld(
      uid_t process_euid,
      uid_t default_user_id,
      mode_t* mode,
      uid_t* directory_owner,
      gid_t* directory_group);
  // Once the daemon-store experiment is done, rename to just
  // GetCrashDirectoryInfo
  // TODO(b/186659673): Validate daemon-store usage and rename this.
  std::optional<base::FilePath> GetCrashDirectoryInfoNew(
      uid_t process_euid,
      uid_t default_user_id,
      mode_t* mode,
      uid_t* directory_owner,
      gid_t* directory_group);

  // Determines the crash directory for given euid, and creates the directory if
  // necessary with appropriate permissions.  If |out_of_capacity| is not
  // nullptr, it is set to indicate if the call failed due to not having
  // capacity in the crash directory. Returns true whether or not directory
  // needed to be created, false on any failure.  If the crash directory is at
  // capacity, returns false.
  bool GetCreatedCrashDirectoryByEuid(uid_t euid,
                                      base::FilePath* crash_file_path,
                                      bool* out_of_capacity);

  // Create a directory using the specified mode/user/group, and make sure it
  // is actually a directory with the specified permissions.
  // If |files_mode| is set, the call will recursively change permissions on
  // |dir| such that:
  //   * any directories under it in the file heirarchy have mode |mode|
  //   * any files under it in the heirarchy have mode |files_mode|
  //   * all files AND directories under it are owned by owner:group
  static bool CreateDirectoryWithSettings(const base::FilePath& dir,
                                          mode_t mode,
                                          uid_t owner,
                                          gid_t group,
                                          int* dir_fd,
                                          mode_t files_mode = 0);

  // Format crash name based on components.
  std::string FormatDumpBasename(const std::string& exec_name,
                                 time_t timestamp,
                                 pid_t pid);

  // Create a file path to a file in |crash_directory| with the given
  // |basename| and |extension|.
  base::FilePath GetCrashPath(const base::FilePath& crash_directory,
                              const std::string& basename,
                              const std::string& extension);

  // Returns the path /proc/<pid>.
  static base::FilePath GetProcessPath(pid_t pid);

  // Sets |*uptime| to the amount of time since the computer booted.
  bool GetUptime(base::TimeDelta* uptime);

  // Sets |*uptime| to the uptime (the amount of time since the computer booted)
  // at the time the process started.
  static bool GetUptimeAtProcessStart(pid_t pid, base::TimeDelta* uptime);

  virtual bool GetExecutableBaseNameAndDirectoryFromPid(
      pid_t pid, std::string* base_name, base::FilePath* exec_directory);

  // Check given crash directory still has remaining capacity for another
  // crash.
  bool CheckHasCapacity(const base::FilePath& crash_directory);
  bool CheckHasCapacity(const base::FilePath& crash_directory,
                        const std::string& display_path);

  // Write a log applicable to |exec_name| to |output_file| based on the
  // log configuration file at |config_path|. If |output_file| ends in .gz, it
  // will be compressed in gzip format, otherwise it will be plaintext.
  bool GetLogContents(const base::FilePath& config_path,
                      const std::string& exec_name,
                      const base::FilePath& output_file);
  // Write a log to |output_file| based on the passed string |log_contents|. If
  // |output_file| ends in .gz, it will be compressed in gzip format, otherwise
  // it will be plaintext. The contents will also be redacted to avoid leaking
  // any sensitive contents.
  bool WriteLogContents(std::string& log_contents,
                        const base::FilePath& output_file);

  // Write logs applicable to |exec_names| to |output_file| based on the
  // log configuration file at |config_path|. If |output_file| ends in .gz, it
  // will be compressed in gzip format, otherwise it will be plaintext.
  // This function returns false only if all of the log commands fail to run.
  bool GetMultipleLogContents(const base::FilePath& config_path,
                              const std::vector<std::string>& exec_names,
                              const base::FilePath& output_file);

  // Write details about the process tree of |pid| to |output_file|.
  bool GetProcessTree(pid_t pid, const base::FilePath& output_file);

  // Add a file to be uploaded to the crash reporter server. The file must
  // persist until the crash report is sent; ideally it should live in the same
  // place as the .meta file, so it can be cleaned up automatically.
  void AddCrashMetaUploadFile(const std::string& key, const std::string& path);

  // Add non-standard meta data to the crash metadata file.
  // Data added though this call will be uploaded to the crash reporter server,
  // appearing as a form field. Virtual for testing.
  virtual void AddCrashMetaUploadData(const std::string& key,
                                      const std::string& value);

  // Like AddCrashMetaUploadData, but loads the value from the file at |path|.
  // The file is not uploaded as an attachment, unlike AddCrashMetaUploadFile.
  void AddCrashMetaUploadText(const std::string& key, const std::string& path);

  // Gets the corresponding value for |key| from the lsb-release file.
  // If |use_saved_lsb_| is true, prefer the lsb-release saved in
  // crash_reporter_state_path_.
  std::string GetLsbReleaseValue(const std::string& key) const;

  // Returns the OS version written to the metadata file.
  std::string GetOsVersion() const;

  // Returns the OS milestone written to the metadata file.
  std::string GetOsMilestone() const;

  // Returns the OS description written to the metadata file.
  std::string GetOsDescription() const;

  // Returns the channel name written to the metadata file.
  std::string GetChannel() const;

  // Returns the product version written to the metadata file.
  virtual std::string GetProductVersion() const;

  // Returns the kernel name from uname (e.g. "Linux").
  std::string GetKernelName() const;

  // Returns the uname string formatted as
  // 3.8.11 #1 SMP Wed Aug 22 02:18:30 PDT 2018
  std::string GetKernelVersion() const;

  // Returns the enrollment status written to the metadata file.
  std::optional<bool> IsEnterpriseEnrolled();

  // Returns the severity level and product group of the crash.
  virtual ComputedCrashSeverity ComputeSeverity(const std::string& exec_name);

  // Called after all files have been written and we want to send out this
  // crash. Write a file of metadata about crash and, if in crash-loop mode,
  // sends the UploadSingleCrash message to debugd. Not called if we failed to
  // make a good crash report.
  virtual void FinishCrash(const base::FilePath& meta_path,
                           const std::string& exec_name,
                           const std::string& payload_name);

  // Returns true if chrome crashes should be handled.
  bool ShouldHandleChromeCrashes();

  std::string extra_metadata_;
  const std::string collector_name_;
  base::FilePath forced_crash_directory_;
  base::FilePath lsb_release_;
  base::FilePath system_crash_path_;
  base::FilePath crash_reporter_state_path_;
  base::FilePath log_config_path_;
  size_t max_log_size_;
  std::unique_ptr<base::Clock> test_clock_;
  std::string test_kernel_name_;
  std::string test_kernel_version_;
  bool device_policy_loaded_;
  std::unique_ptr<policy::DevicePolicy> device_policy_;

  // Should reports always be stored in the user crash directory, or can they be
  // stored in the system directory if we are not running as "chronos"?
  CrashDirectorySelectionMethod crash_directory_selection_method_;

  scoped_refptr<dbus::Bus> bus_;

  // D-Bus proxy for session manager interface.
  std::unique_ptr<org::chromium::SessionManagerInterfaceProxyInterface>
      session_manager_proxy_;

  // D-Bus proxy for debugd interface.
  std::unique_ptr<org::chromium::debugdProxyInterface> debugd_proxy_;

  // If kCrashLoopSendingMode, reports are stored in memory and sent over DBus
  // to debugd when finished. Otherwise, we store the crash reports on disk and
  // rely on crash_sender to later pick it up and send it.
  const CrashSendingMode crash_sending_mode_;

  // Record information about a crash collector failure in a new crash report.
  // Clears metadata for existing report.
  // orig_exec: Name of the executable in which we were processing a crash when
  // the failure happened.
  void EnqueueCollectionErrorLog(ErrorType error_type,
                                 const std::string& orig_exec);

  // Logs a |message| detailing a crash, along with the |reason| for which the
  // collector handled or ignored it.
  void LogCrash(const std::string& message, const std::string& reason) const;

 private:
  static bool ParseProcessTicksFromStat(base::StringPiece stat,
                                        uint64_t* ticks);

  // Adds variations (experiment IDs) to crash reports. Returns true on success.
  bool AddVariations();

  bool GetUserCrashDirectoriesOld(std::vector<base::FilePath>* directories,
                                  bool use_daemon_store);
  base::FilePath GetUserCrashDirectoryOld(bool use_daemon_store);
  std::optional<base::FilePath> GetUserCrashDirectoryNew();

  // If set, UseDaemonStore will always return the contained value.
  std::optional<bool> force_daemon_store_;

  // True when FinishCrash has been called. Once true, no new files should be
  // created.
  bool is_finished_;

  // If crash_loop_mode_ is true, all files are collected in here instead of
  // being written to disk. The first element of the tuple is the base filename,
  // the second is a memfd_create file descriptor with the file contents.
  std::vector<std::tuple<std::string, base::ScopedFD>> in_memory_files_;

  // Number of bytes successfully written by all calls to WriteNewFile() and
  // WriteNewCompressedFile() so far. For WriteNewCompressedFile(), the count is
  // of bytes on disk, after compression.
  off_t bytes_written_;

  // Returns true if there is already a file in in_memory_files_ with
  // filename.BaseName().
  bool InMemoryFileExists(const base::FilePath& filename) const;

  // Opens a new compressed file for writing. Returns a valid fd for the
  // compressed file on success, and an invalid fd on failure.
  // |compressed_output| holds the pointer to the compressed file descriptor.
  base::ScopedFD OpenNewCompressedFileForWriting(const base::FilePath& filename,
                                                 gzFile* compressed_output);

  // Writes |bytes| amount of |data| to |compressed_output| as compressed data.
  // Returns true on success and false on failure. The |compressed_output| file
  // is closed on failure.
  bool WriteCompressedFile(gzFile compressed_output,
                           const char* data,
                           size_t bytes);

  // Closes the compressed file and increments get_bytes_written(). Returns true
  // on success.
  bool CloseCompressedFileAndUpdateStats(gzFile compressed_output,
                                         base::ScopedFD fd_dup,
                                         const base::FilePath& filename);

  // Determine whether to attempt to use daemon-store.
  // This is for a temporary experiment and will be removed.
  // TODO(b/186659673): Validate daemon-store usage and always use it.
  bool UseDaemonStore();

  // Returns an error type signature for a given |error_type| value,
  // which is reported to the crash server along with the
  // crash_reporter-user-collection signature.
  std::string GetErrorTypeSignature(ErrorType error_type) const;

  // If not null, GetUptime() will return *override_uptime_for_testing_;
  std::unique_ptr<base::TimeDelta> override_uptime_for_testing_;

  // Prepended to log messages to differentiate between collectors.
  const std::string tag_;

  std::unique_ptr<MetricsLibraryInterface> metrics_lib_;

  // Is this an early-boot crash collection?
  bool early_ = false;

  // Prefer the lsb-release saved in crash_reporter_state_path_?
  bool use_saved_lsb_ = false;
};

// Information to invoke a specific call on a collector.
struct InvocationInfo {
  // True iff this callback should be invoked.
  // Once this is true and we invoke the associated callback, main() returns,
  // so only one handler can run for each execution of crash_reporter.
  bool should_handle;
  // If set to true, AppSync consent should be checked (via metrics_lib)
  // before any collectors are run. Defaults to false.
  bool should_check_appsync = false;
  // Callback to invoke if |should_handle| is true. (can be null).
  base::RepeatingCallback<bool()> cb;
};

// Information required to initialize and invoke a collector.
struct CollectorInfo {
  // Shared pointer to the collector.
  std::shared_ptr<CrashCollector> collector;
  // Initialization function. If none is specified, invoke the default
  // crash_collector Initialize().
  base::RepeatingClosure init;
  // List of handlers with associated conditions.
  // If a particular condition is true, run init and the associated handler (if
  // any). If there is no associated handler, keep going.
  std::vector<InvocationInfo> handlers;
};

#endif  // CRASH_REPORTER_CRASH_COLLECTOR_H_
