// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// UserCollector handles program crashes in userspace. When the kernel detects
// a crashing program, it invokes this collector via
// /proc/sys/kernel/core_pattern.
// This handler ignores chrome crashes (letting chrome_collector handle them
// when it is directly invoked).

#ifndef CRASH_REPORTER_USER_COLLECTOR_H_
#define CRASH_REPORTER_USER_COLLECTOR_H_

#include <functional>
#include <string>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/user_collector_base.h"

// User crash collector.
class UserCollector : public UserCollectorBase {
 public:
  UserCollector();
  UserCollector(const UserCollector&) = delete;
  UserCollector& operator=(const UserCollector&) = delete;

  // Initialize the user crash collector for detection of crashes,
  // given the path to this executable, metrics collection enabled
  // oracle, and system logger facility. Crash detection/reporting
  // is not enabled until Enable is called.
  void Initialize(const std::string& our_path,
                  bool core2md_failure,
                  bool directory_failure,
                  bool early);

  ~UserCollector() override;

  // Enable collection.
  bool Enable(bool early) { return SetUpInternal(true /* enabled */, early); }

  // Disable collection.
  bool Disable() {
    return SetUpInternal(false /* enabled */, false /* early */);
  }

  // Set (override the default) core file pattern.
  void set_core_pattern_file(const std::string& pattern) {
    core_pattern_file_ = pattern;
  }

  // Set (override the default) core pipe limit file.
  void set_core_pipe_limit_file(const std::string& path) {
    core_pipe_limit_file_ = path;
  }

  void set_filter_path(const std::string& filter_path) {
    filter_path_ = filter_path;
  }

  // Normally, /proc/<pid>/cmdline uses \0 to separate args.
  static constexpr char kNormalCmdlineSeparator = '\0';
  // However, chrome subprocesses of Chrome end up with spaces separating
  // args because they rewrite their command lines.
  static constexpr char kChromeSubprocessCmdlineSeparator = ' ';

 protected:
  void FinishCrash(const base::FilePath& meta_path,
                   const std::string& exec_name,
                   const std::string& payload_name) override;

  void BeginHandlingCrash(pid_t pid,
                          const std::string& exec,
                          const base::FilePath& exec_directory) override;

 private:
  friend class UserCollectorTest;
  FRIEND_TEST(UserCollectorTest, ClobberContainerDirectory);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesBadPid);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesOK);
  FRIEND_TEST(UserCollectorTest, GetExecutableBaseNameFromPid);
  FRIEND_TEST(UserCollectorTest, GetFirstLineWithPrefix);
  FRIEND_TEST(UserCollectorTest, GetIdFromStatus);
  FRIEND_TEST(UserCollectorTest, GetRustSignature);
  FRIEND_TEST(UserCollectorTest, GetStateFromStatus);
  FRIEND_TEST(UserCollectorTest, ParseCrashAttributes);
  FRIEND_TEST(UserCollectorTest, ShouldDumpFiltering);
  FRIEND_TEST(UserCollectorTest, ShouldDumpChromeOverridesDeveloperImage);
  FRIEND_TEST(UserCollectorTest, ShouldDumpDeveloperImageOverridesConsent);
  FRIEND_TEST(UserCollectorTest, ShouldDumpUserConsentProductionImage);
  FRIEND_TEST(UserCollectorTest, ValidateProcFiles);
  FRIEND_TEST(UserCollectorTest, ValidateCoreFile);
  FRIEND_TEST(UserCollectorNoFixtureTest, GuessChromeProductNameTest);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, BasicTrue);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, DISABLED_BasicTrue);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfBreakpad);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, DISABLED_FalseIfBreakpad);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfCrashpadIsChild);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfRenderer);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfNonChrome);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, DISABLED_BadProcFilesIgnored);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, BadProcFilesIgnored);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfTooOld);
  FRIEND_TEST(ShouldCaptureEarlyChromeCrashTest, FalseIfNotChrome);
  friend class CopyStdinToCoreFileTest;
  FRIEND_TEST(CopyStdinToCoreFileTest, Test);
  FRIEND_TEST(BeginHandlingCrashTest, SetsUpForEarlyChromeCrashes);
  FRIEND_TEST(BeginHandlingCrashTest, DISABLED_SetsUpForEarlyChromeCrashes);
  FRIEND_TEST(BeginHandlingCrashTest, IgnoresNonEarlyBrowser);
  FRIEND_TEST(BeginHandlingCrashTest, NoEffectIfNotChrome);

  // Returns true if we want to try to capture a crash of Chrome because we
  // think it may have happened early -- specifically, before crashpad was
  // initialized. Such crashes won't be captured through the normal
  // ChromeCollector. We get less information by capturing them through
  // UserCollector, but we can still get stack traces.
  bool ShouldCaptureEarlyChromeCrash(const std::string& exec, pid_t pid);

  // Guess at whether a crash in the Chrome executable located in
  // |exec_directory| should have a product name of Chrome_Lacros or
  // Chrome_ChromeOS.
  static const char* GuessChromeProductName(
      const base::FilePath& exec_directory);

  std::string GetPattern(bool enabled, bool early) const;
  bool SetUpInternal(bool enabled, bool early);

  bool CopyOffProcFiles(pid_t pid, const base::FilePath& container_dir);

  // Validates the proc files at |container_dir| and returns true if they
  // are usable for the core-to-minidump conversion later. For instance, if
  // a process is reaped by the kernel before the copying of its proc files
  // takes place, some proc files like /proc/<pid>/maps may contain nothing
  // and thus become unusable.
  bool ValidateProcFiles(const base::FilePath& container_dir) const;

  // Validates the core file at |core_path| and returns kErrorNone if
  // the file contains the ELF magic bytes and an ELF class that matches the
  // platform (i.e. 32-bit ELF on a 32-bit platform or 64-bit ELF on a 64-bit
  // platform), which is due to the limitation in core2md. It returns an error
  // type otherwise.
  ErrorType ValidateCoreFile(const base::FilePath& core_path) const;
  // Copy off stdin to a core file.
  bool CopyStdinToCoreFile(const base::FilePath& core_path);
  // Heart of CopyStdinToCoreFile. Split out for easier unit testing. Does NOT
  // take ownership of input_fd and will not close it. input_fd must be a pipe.
  bool CopyPipeToCoreFile(int input_fd, const base::FilePath& core_path);
  bool RunCoreToMinidump(const base::FilePath& core_path,
                         const base::FilePath& procfs_directory,
                         const base::FilePath& minidump_path,
                         const base::FilePath& temp_directory);

  bool RunFilter(pid_t pid);

  bool ShouldDump(pid_t pid,
                  bool handle_chrome_crashes,
                  const std::string& exec,
                  std::string* reason);

  // UserCollectorBase overrides.
  bool ShouldDump(pid_t pid,
                  uid_t uid,
                  const std::string& exec,
                  std::string* reason) override;
  ErrorType ConvertCoreToMinidump(pid_t pid,
                                  const base::FilePath& container_dir,
                                  const base::FilePath& core_path,
                                  const base::FilePath& minidump_path) override;

  std::string core_pattern_file_;
  std::string core_pipe_limit_file_;
  std::string our_path_;
  std::string filter_path_;

  // Invoke special handling for early Chrome crashes. In particular, this
  // limits the size of the core file we're willing to process.
  //
  // For the most part, we accept whatever cores we're given; the user pain of
  // programs crashing outweighs user pain from the slowdown caused by writing
  // out a large core file. However, for chrome it's different. The core files
  // are massive (well over a GB), take 20+ seconds to write out, and in most
  // cases, crashes are being caught by the much-faster crashpad-to-
  // chrome_collector path anyways. We sometimes try to grab a Chrome core
  // (if we think it's likely crashpad will miss it -- see
  // ShouldCaptureEarlyChromeCrash), but we protect ourselves by stopping if the
  // core file exceeds kMaxChromeCoreSize (except in some tests, which use
  // kMaxChromeCoreSizeLoose).
  bool handling_early_chrome_crash_;

  // For handling_early_chrome_crash_ mode:
  // Chrome core dumps can be extremely large. Writing them to disk will lock
  // up the machine for up to a minute. The pre-crashpad-init core files
  // should be much smaller; however, to avoid problems if we accidentally try
  // to ingest a post-crashpad-init core file, only copy the first 40MiB and
  // error out if there's more data after that first 40MiB. (In May 2022,
  // core size of an early crash on eve is 17MiB; this gives us a little room
  // for growth while still protecting us from filling up the disk with a
  // massively-oversized core.)
  static constexpr int kMaxChromeCoreSize = 40 * 1024 * 1024;

  // The maximum size when running the "loose" variant of the
  // ui.ChromeCrashEarly tast test. We need this for Chrome CQ -- Chrome CQ
  // tests non-is_official_build Chrome builds, which produce larger cores.
  static constexpr int kMaxChromeCoreSizeLoose = 100 * 1024 * 1024;

  // Force a core2md failure for testing.
  bool core2md_failure_;
};

#endif  // CRASH_REPORTER_USER_COLLECTOR_H_
