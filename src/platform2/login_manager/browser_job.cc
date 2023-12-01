// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This class is most definitely NOT re-entrant.

#include "login_manager/browser_job.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>

#include <algorithm>
#include <queue>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/ranges/algorithm.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <chromeos/switches/chrome_switches.h>

#include "login_manager/file_checker.h"
#include "login_manager/login_metrics.h"
#include "login_manager/subprocess.h"
#include "login_manager/system_utils.h"

namespace login_manager {

const char BrowserJobInterface::kLoginManagerFlag[] = "--login-manager";
const char BrowserJobInterface::kLoginUserFlag[] = "--login-user=";
const char BrowserJobInterface::kLoginProfileFlag[] = "--login-profile=";
const char BrowserJobInterface::kCrashLoopBeforeFlag[] = "--crash-loop-before=";
const char BrowserJobInterface::kBrowserDataMigrationForUserFlag[] =
    "--browser-data-migration-for-user=";
const char BrowserJobInterface::kBrowserDataMigrationModeFlag[] =
    "--browser-data-migration-mode=";
const char BrowserJobInterface::kBrowserDataBackwardMigrationForUserFlag[] =
    "--browser-data-backward-migration-for-user=";
const char BrowserJobInterface::kDisallowLacrosFlag[] = "--disallow-lacros";

const char BrowserJob::kFirstExecAfterBootFlag[] = "--first-exec-after-boot";

// Check for last 4 runs with extra args to detect startup crash. 4 allows
// the case of applying flags in guest sessions, where we have:
//   1st chrome start to show the login screen
//   2nd chrome start to enter guest sessions
//   3rd chrome start to apply flags from about:flags page
// If `kUseExtraArgsRuns` is 3 and the 3rd run is less than
// `kRestartWindowSecond` seconds (100s) apart from 1st run, it would be
// considered as too crashy and flags are dropped for the 3rd run.
// See https://crbug.com/1129951.
const int BrowserJob::kUseExtraArgsRuns = 4;
static_assert(BrowserJob::kUseExtraArgsRuns > 1,
              "kUseExtraArgsRuns should be greater than 1 because extra "
              "arguments could need one restart to apply them.");

const int BrowserJob::kRestartTries = BrowserJob::kUseExtraArgsRuns + 2;
const time_t BrowserJob::kRestartWindowSeconds = 100;

const char BrowserJobInterface::kGuestSessionFlag[] = "--bwsi";

namespace {

constexpr char kVmoduleFlag[] = "--vmodule=";
constexpr char kEnableFeaturesFlag[] = "--enable-features=";
constexpr char kDisableFeaturesFlag[] = "--disable-features=";
constexpr char kEnableBlinkFeaturesFlag[] = "--enable-blink-features=";
constexpr char kDisableBlinkFeaturesFlag[] = "--disable-blink-features=";
constexpr char kSafeModeFlag[] = "--safe-mode";

constexpr char kSessionManagerSafeModeEnabled[] =
    "SessionManager.SafeModeEnabled";

// Erases all occurrences of |arg| within |args|. Returns true if any entries
// were removed or false otherwise.
bool RemoveArgs(std::vector<std::string>* args, const std::string& arg) {
  std::vector<std::string>::iterator new_end =
      std::remove(args->begin(), args->end(), arg);
  if (new_end == args->end())
    return false;

  args->erase(new_end, args->end());
  return true;
}

// Joins the values of all switches in |args| prefixed by |prefix| using
// |separator| and appends a merged version of the switch. If |keep_existing| is
// true, all earlier occurrences of the switch are preserved; otherwise, they
// are removed.
void MergeSwitches(std::vector<std::string>* args,
                   const std::string& prefix,
                   const std::string& separator,
                   bool keep_existing) {
  std::string values;
  auto head = args->begin();
  for (const auto& arg : *args) {
    bool match = base::StartsWith(arg, prefix, base::CompareCase::SENSITIVE);
    if (match) {
      if (!values.empty())
        values += separator;
      values += arg.substr(prefix.size());
    }
    if (!match || keep_existing) {
      *head++ = arg;
    }
  }
  if (head != args->end())
    args->erase(head, args->end());
  if (!values.empty())
    args->push_back(prefix + values);
}

std::string GetUnprefixedFlagName(const std::string& flag) {
  static const char* const kSwitchPrefixes[] = {"--", "-"};

  std::string unprefixed = flag;
  for (const char* const prefix : kSwitchPrefixes) {
    std::string prefix_str(prefix);
    if (flag.rfind(prefix, 0) == 0) {
      unprefixed = flag.substr(prefix_str.length());
      break;
    }
  }

  return unprefixed.substr(0, unprefixed.find('='));
}

}  // namespace

BrowserJob::BrowserJob(const std::vector<std::string>& arguments,
                       const std::vector<std::string>& environment_variables,
                       FileChecker* checker,
                       LoginMetrics* metrics,
                       SystemUtils* utils,
                       const BrowserJob::Config& cfg,
                       std::unique_ptr<SubprocessInterface> subprocess)
    : arguments_(arguments),
      environment_variables_(environment_variables),
      file_checker_(checker),
      login_metrics_(metrics),
      system_(utils),
      start_times_(std::deque<time_t>(kRestartTries, 0)),
      config_(cfg),
      subprocess_(std::move(subprocess)) {
  // Take over managing kLoginManagerFlag.
  if (RemoveArgs(&arguments_, kLoginManagerFlag)) {
    removed_login_manager_flag_ = true;
    login_arguments_.push_back(kLoginManagerFlag);
  }
}

BrowserJob::~BrowserJob() {}

pid_t BrowserJob::CurrentPid() const {
  return subprocess_->GetPid();
}

bool BrowserJob::IsGuestSession() {
  return base::ranges::count(arguments_, kGuestSessionFlag) > 0;
}

bool BrowserJob::ShouldRunBrowser() {
  return !file_checker_ || !file_checker_->exists();
}

bool BrowserJob::ShouldStop() const {
  return system_->time(nullptr) - start_times_.front() < kRestartWindowSeconds;
}

void BrowserJob::RecordTime() {
  start_times_.push_back(system_->time(nullptr));
  start_times_.pop_front();
  DCHECK_EQ(kRestartTries, start_times_.size());
}

bool BrowserJob::RunInBackground() {
  CHECK(login_metrics_);
  bool first_boot = !login_metrics_->HasRecordedChromeExec();
  login_metrics_->RecordStats("chrome-exec");

  // Skip `RecordTime()` if ash is being launched for browser data migration and
  // browser backward data migration so that the relaunch for migration is not
  // considered a launch crash by `ShouldDropExtraArguments()`. Without this
  // "safe-mode" gets triggered for migration after a restart to apply flags.
  // 1. Ash is launched.
  // 2. Ash is relaunched to apply flags.
  // 3. Ash is relaunched to do migration.
  // 4. Ash is relaunched to put users back in session.
  if (browser_data_migration_arguments_.empty() &&
      browser_data_backward_migration_arguments_.empty()) {
    RecordTime();
  }

  extra_one_time_arguments_.clear();
  if (first_boot)
    extra_one_time_arguments_.push_back(kFirstExecAfterBootFlag);

  // Must happen after RecordTime(). After RecordTime(), ShouldStop() is
  // basically returning what it would return if this instance of the browser
  // crashed and wanted to be restarted again.
  if (ShouldStop()) {
    // This might be the last restart left in a crash-loop. If so, we don't want
    // crash_reporter to do its normal behavior of writing the crash dump into
    // the user directory, because after that next Chrome crash, the user will
    // be logged out, at which point the crash dump will become inaccessible.
    // Instead, instruct crash_reporter to keep the crash dump in-memory and
    // immediately upload it using UploadSingleCrash.
    time_t crash_loop_before = start_times_.front() + kRestartWindowSeconds;
    std::string crash_loop_before_arg =
        kCrashLoopBeforeFlag +
        base::NumberToString(static_cast<uint64_t>(crash_loop_before));
    extra_one_time_arguments_.push_back(crash_loop_before_arg);
  }

  const std::vector<std::string> argv(ExportArgv());
  const std::vector<std::string> env_vars(ExportEnvironmentVariables());
  LOG(INFO) << "Running browser " << base::JoinString(argv, " ");

  bool enter_existing_mount_ns = false;
  if (IsGuestSession()) {
    if (config_.isolate_guest_session &&
        config_.chrome_mount_ns_path.has_value()) {
      enter_existing_mount_ns = true;
    } else {
      LOG(INFO) << "Entering new mount namespace for browser.";
      subprocess_->UseNewMountNamespace();
    }
  } else {
    // Regular session.
    if (config_.isolate_regular_session &&
        config_.chrome_mount_ns_path.has_value()) {
      enter_existing_mount_ns = true;
    }
  }

  if (enter_existing_mount_ns) {
    base::FilePath ns_path = config_.chrome_mount_ns_path.value();
    LOG(INFO) << "Entering mount namespace '" << ns_path.value()
              << "' for browser";
    subprocess_->EnterExistingMountNamespace(ns_path);
  }

  return subprocess_->ForkAndExec(argv, env_vars);
}

void BrowserJob::KillEverything(int signal, const std::string& message) {
  if (subprocess_->GetPid() < 0)
    return;

  LOG(INFO) << "Terminating process group for browser " << subprocess_->GetPid()
            << " with signal " << signal << ": " << message;
  subprocess_->KillEverything(signal);
}

void BrowserJob::Kill(int signal, const std::string& message) {
  const pid_t pid = subprocess_->GetPid();
  if (pid < 0)
    return;

  LOG(INFO) << "Terminating browser process " << pid << " with signal "
            << signal << ": " << message;
  subprocess_->Kill(signal);
}

bool BrowserJob::WaitForExit(base::TimeDelta timeout) {
  const pid_t pid = subprocess_->GetPid();
  if (pid < 0)
    return true;

  return system_->ProcessGroupIsGone(pid, timeout);
}

void BrowserJob::AbortAndKillAll(base::TimeDelta timeout) {
  const pid_t pid = subprocess_->GetPid();
  if (pid < 0)
    return;

  if (system_->ProcessGroupIsGone(pid, base::TimeDelta())) {
    DLOG(INFO) << "Cleaned up browser process " << pid;
    return;
  }

  if (!system_->ProcessIsGone(pid, base::TimeDelta())) {
    LOG(WARNING) << "Aborting browser process " << pid;

    std::string message = "Browser aborted";
    // Send a SIGABRT to the browser process so that it generates a crash
    // report. We don't send SIGABRT to the other processes because the reports
    // are often corrupt and we aren't getting any value out of them.
    Kill(SIGABRT, message);

    // Wait to allow Breakpad or Crashpad time to collect the crash report.
    if (system_->ProcessGroupIsGone(pid, timeout)) {
      DLOG(INFO) << "browser group " << pid << " gone after SIGABRT wait";
      return;
    }
  }

  std::string message = base::StringPrintf(
      "Browser group took more than %" PRId64 " seconds to exit after signal.",
      timeout.InSeconds());
  LOG(WARNING) << "Killing browser process " << pid << "'s process group "
               << timeout.InSeconds() << " seconds after sending SIGABRT";
  KillEverything(SIGKILL, message);

  constexpr base::TimeDelta kTimeoutForSecondKill = base::Seconds(1);
  if (!system_->ProcessGroupIsGone(pid, kTimeoutForSecondKill)) {
    LOG(WARNING) << "Browser process " << pid << "'s group still not gone "
                 << kTimeoutForSecondKill << " after sending SIGKILL signal";
  }
}

// When user logs in we want to restart chrome in browsing mode with
// user signed in. Hence we remove --login-manager flag and add
// --login-user=|account_id| and --login-profile=|userhash| flags.
void BrowserJob::StartSession(const std::string& account_id,
                              const std::string& userhash) {
  if (!session_already_started_) {
    login_arguments_.clear();
    login_arguments_.push_back(kLoginUserFlag + account_id);
    login_arguments_.push_back(kLoginProfileFlag + userhash);
  }
  session_already_started_ = true;
}

void BrowserJob::StopSession() {
  login_arguments_.clear();
  if (removed_login_manager_flag_) {
    login_arguments_.push_back(kLoginManagerFlag);
    removed_login_manager_flag_ = false;
  }
}

const std::string BrowserJob::GetName() const {
  base::FilePath exec_file(arguments_[0]);
  return exec_file.BaseName().value();
}

void BrowserJob::SetArguments(const std::vector<std::string>& arguments) {
  // Ensure we preserve the program name to be executed, if we have one.
  std::string argv0;
  if (!arguments_.empty())
    argv0 = arguments_[0];

  arguments_ = arguments;

  if (!argv0.empty()) {
    if (arguments_.size())
      arguments_[0] = argv0;
    else
      arguments_.push_back(argv0);
  }
}

void BrowserJob::SetExtraArguments(const std::vector<std::string>& arguments) {
  extra_arguments_.clear();
  auto is_not_unsafe = [](const std::string& flag) {
    // A list of flags that shouldn't be user-configurable on Chrome OS.
    // Keeping this the list watertight will be hard to impossible in practice,
    // so this is only a temporary measure until we have a more robust solution
    // for flag handling. See crbug.com/1073940 for details.
    static const char* const kUnsafeFlags[] = {
        "allow-sandbox-debugging",
        "disable-gpu-sandbox",
        "disable-namespace-sandbox",
        "disable-seccomp-filter-sandbox",
        "disable-setuid-sandbox",
        "gpu-launcher",
        "no-sandbox",
        "no-zygote-sandbox",
        "ppapi-plugin-launcher",
        "remote-debugging-port",
        "renderer-cmd-prefix",
        "single-process",
        "utility-cmd-prefix",
    };
    return std::find(std::begin(kUnsafeFlags), std::end(kUnsafeFlags),
                     GetUnprefixedFlagName(flag)) == std::end(kUnsafeFlags);
  };
  std::copy_if(arguments.begin(), arguments.end(),
               std::back_inserter(extra_arguments_), is_not_unsafe);
}

void BrowserJob::SetFeatureFlags(
    const std::vector<std::string>& feature_flags,
    const std::map<std::string, std::string>& origin_list_flags) {
  feature_flags_ = feature_flags;
  origin_list_flags_ = origin_list_flags;
}

void BrowserJob::SetTestArguments(const std::vector<std::string>& arguments) {
  test_arguments_ = arguments;
}

void BrowserJob::SetAdditionalEnvironmentVariables(
    const std::vector<std::string>& env_vars) {
  additional_environment_variables_ = env_vars;
}

void BrowserJob::ClearPid() {
  subprocess_->ClearPid();
}

void BrowserJob::SetMultiUserSessionStarted() {
  multi_user_session_started_ = true;
}

std::vector<std::string> BrowserJob::ExportArgv() const {
  std::vector<std::string> to_return(arguments_.begin(), arguments_.end());

  // Browser forward and backward data migration are exclusive.
  // No migration is performed if both are false or both are true.
  if (browser_data_migration_arguments_.empty() ==
      browser_data_backward_migration_arguments_.empty()) {
    CHECK(browser_data_migration_arguments_.empty() &&
          browser_data_backward_migration_arguments_.empty())
        << "Both forward and backward migration have been called.";

    to_return.insert(to_return.end(), login_arguments_.begin(),
                     login_arguments_.end());
  } else {
    // Browser data migration for lacros happens in the following steps.
    // 1. Inside the login flow in ash-chrome, whether migration is required or
    // not is checked.
    // 2. If required, ash-chrome calls DBus method to session manager to be
    // relaunched with specific args for migration.
    // 3. Ash-chrome terminates itself.
    // 4. Ash-chrome is relaunched to carry out the migration.
    // 5. Ash-chrome terminates itself once migration is completed.
    // 6. Ash-chrome is relaunched to display user's home screen.
    //
    // If |browser_data_migration_arguments_| is not empty, it means that
    // |SetBrowserDataMigrationArgsForUser| was called. With these arguments
    // present, ash-chrome gets launched to run browser data migration from
    // ash-chrome to lacros-chrome. Concretely browser data files in
    // ash-chrome's user data dir will be copied/moved to lacros-chrome's user
    // data dir. |ClearBrowserDataMigrationArgs()| must be called after
    // launching ash-chrome for data migration so ash-chrome doesn't get stuck
    // in migration mode.
    to_return.insert(to_return.end(), browser_data_migration_arguments_.begin(),
                     browser_data_migration_arguments_.end());

    // Backward migration works simmilarly:
    // If |browser_data_backward_migration_arguments_| is not empty, it means
    // that |SetBrowserDataBackwardMigrationArgsForUser| was called.
    // |ClearBrowserDataBackwardMigrationArgs()| must be called after
    // launching ash-chrome for data backward migration.
    to_return.insert(to_return.end(),
                     browser_data_backward_migration_arguments_.begin(),
                     browser_data_backward_migration_arguments_.end());
  }

  if (ShouldDropExtraArguments()) {
    LOG(WARNING) << "Dropping extra arguments and setting safe-mode switch due "
                    "to crashy browser.";
    to_return.emplace_back(kSafeModeFlag);
    login_metrics_->ReportCrosEvent(kSessionManagerSafeModeEnabled);
  } else {
    to_return.insert(to_return.end(), extra_arguments_.begin(),
                     extra_arguments_.end());

    // Encode feature flags.
    base::Value::List feature_flag_list;
    for (const auto& feature_flag : feature_flags_) {
      feature_flag_list.Append(feature_flag);
    }
    if (!feature_flag_list.empty()) {
      std::sort(feature_flag_list.begin(), feature_flag_list.end());
      std::string encoded;
      base::JSONWriter::Write(feature_flag_list, &encoded);
      to_return.push_back(base::StringPrintf(
          "--%s=%s", chromeos::switches::kFeatureFlags, encoded.c_str()));
    }

    // Encode origin list values.
    base::Value::Dict origin_list_dict;
    for (const auto& entry : origin_list_flags_) {
      origin_list_dict.Set(entry.first, entry.second);
    }
    if (!origin_list_dict.empty()) {
      std::string encoded;
      base::JSONWriter::Write(origin_list_dict, &encoded);
      to_return.push_back(base::StringPrintf(
          "--%s=%s", chromeos::switches::kFeatureFlagsOriginList,
          encoded.c_str()));
    }
  }

  if (!extra_one_time_arguments_.empty()) {
    to_return.insert(to_return.end(), extra_one_time_arguments_.begin(),
                     extra_one_time_arguments_.end());
  }

  if (multi_user_session_started_) {
    to_return.push_back(kDisallowLacrosFlag);
  }

  to_return.insert(to_return.end(), test_arguments_.begin(),
                   test_arguments_.end());

  // Chrome doesn't support repeated switches in most cases. Merge switches
  // containing comma-separated values that may be supplied via multiple sources
  // (e.g. chrome_setup.cc, chrome://flags, Telemetry).
  //
  // --enable-features and --disable-features may be placed within sentinel
  // values (--flag-switches-begin/end, --policy-switches-begin/end). To
  // preserve those positions, keep the existing flags while also appending
  // merged versions at the end of the command line. Chrome will use the final,
  // merged flags: https://crbug.com/767266
  //
  // Chrome merges --enable-blink-features and --disable-blink-features for
  // renderer processes (see content::FeaturesFromSwitch()), but we still merge
  // the values here to produce shorter command lines.
  MergeSwitches(&to_return, kVmoduleFlag, ",", false /* keep_existing */);
  MergeSwitches(&to_return, kEnableFeaturesFlag, ",", true /* keep_existing */);
  MergeSwitches(&to_return, kDisableFeaturesFlag, ",",
                true /* keep_existing */);
  MergeSwitches(&to_return, kEnableBlinkFeaturesFlag, ",",
                false /* keep_existing */);
  MergeSwitches(&to_return, kDisableBlinkFeaturesFlag, ",",
                false /* keep_existing */);

  return to_return;
}

std::vector<std::string> BrowserJob::ExportEnvironmentVariables() const {
  std::vector<std::string> vars = environment_variables_;
  vars.insert(vars.end(), additional_environment_variables_.begin(),
              additional_environment_variables_.end());
  return vars;
}

bool BrowserJob::ShouldDropExtraArguments() const {
  // Check start_time_with_extra_args != 0 so that test cases such as
  // SetExtraArguments and ExportArgv pass without mocking time().
  const time_t start_time_with_extra_args =
      start_times_[kRestartTries - kUseExtraArgsRuns];
  return (start_time_with_extra_args != 0 &&
          system_->time(nullptr) - start_time_with_extra_args <
              kRestartWindowSeconds);
}

void BrowserJob::SetBrowserDataMigrationArgsForUser(const std::string& userhash,
                                                    const std::string& mode) {
  browser_data_migration_arguments_.clear();
  browser_data_migration_arguments_.push_back(kBrowserDataMigrationForUserFlag +
                                              userhash);

  browser_data_migration_arguments_.push_back(kBrowserDataMigrationModeFlag +
                                              mode);

  browser_data_migration_arguments_.push_back(kLoginManagerFlag);
}

void BrowserJob::ClearBrowserDataMigrationArgs() {
  browser_data_migration_arguments_.clear();
}

void BrowserJob::SetBrowserDataBackwardMigrationArgsForUser(
    const std::string& userhash) {
  browser_data_backward_migration_arguments_.clear();
  browser_data_backward_migration_arguments_.push_back(
      kBrowserDataBackwardMigrationForUserFlag + userhash);

  browser_data_backward_migration_arguments_.push_back(kLoginManagerFlag);
}

void BrowserJob::ClearBrowserDataBackwardMigrationArgs() {
  browser_data_backward_migration_arguments_.clear();
}

}  // namespace login_manager
