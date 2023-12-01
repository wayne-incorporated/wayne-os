// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/metrics_daemon.h"

#include <fcntl.h>
#include <fstream>
#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/hash/hash.h>
#include <base/logging.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/dbus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "metrics/process_meter.h"
#include "uploader/upload_service.h"

// Returns a pointer for use in PostDelayedTask.  The daemon never exits on its
// own: it can only abort or get killed.  Thus the daemon instance is never
// deleted, and base::Unretained() is appropriate.  This macro exists so we can
// comment this fact in one place.  A function is hard to write because of the
// retturn type.
#define GET_THIS_FOR_POSTTASK() (base::Unretained(this))

using base::FilePath;
using base::StringPrintf;
using base::Time;
using base::TimeDelta;
using base::TimeTicks;
using chromeos_metrics::PersistentInteger;
using std::map;
using std::string;
using std::vector;

namespace chromeos_metrics {
namespace {

const char kCrashReporterInterface[] = "org.chromium.CrashReporter";
const char kCrashReporterUserCrashSignal[] = "UserCrash";
const char kCrashReporterMatchRule[] =
    "type='signal',interface='%s',path='/',member='%s'";

// Build type of an official build.
// See chromite/scripts/cros_set_lsb_release.py.
const char kOfficialBuild[] = "Official Build";

const int kMillisPerSecond = 1000;
const int kSecondsPerMinute = 60;
const int kMinutesPerHour = 60;
const int kHoursPerDay = 24;
const int kMinutesPerDay = kHoursPerDay * kMinutesPerHour;
const int kSecondsPerDay = kSecondsPerMinute * kMinutesPerDay;
const int kDaysPerWeek = 7;
const int kSecondsPerWeek = kSecondsPerDay * kDaysPerWeek;

// Initial interval until the first call to UpdateStats(), The initial update
// happens sooner than subsequent updates to capture short usage times. (e.g.
// situations where a user uses their device for 1-2 minutes only).
const uint32_t kInitialUpdateStatsIntervalMs = 60'000;  // one minute
// Interval between calls to UpdateStats().
const uint32_t kUpdateStatsIntervalMs = 300'000;  // five minutes

// Don't accept any individual usage time samples of more than 2 hours
const uint32_t kMaxAcceptableUnaggregatedUsageTime =
    2 * kMinutesPerHour * kSecondsPerMinute;

// Maximum amount of system memory that will be reported without overflow.
const int kMaximumMemorySizeInKB = 128 * 1024 * 1024;

const char kKernelCrashDetectedFile[] =
    "/run/metrics/external/crash-reporter/kernel-crash-detected";
const char kUncleanShutdownDetectedFile[] =
    "/run/metrics/external/crash-reporter/unclean-shutdown-detected";

// Path of flag created by crouton when it starts.
const char kCroutonStartedFile[] =
    "/run/metrics/external/crouton/crouton-started";

constexpr base::TimeDelta kVmlogInterval = base::Seconds(2);

constexpr char kVmlogDir[] = "/var/log/vmlog";

// Memory use stats collection intervals.  We collect some memory use interval
// at these intervals after boot, and we stop collecting after the last one,
// with the assumption that in most cases the memory use won't change much
// after that.
const int kMemuseIntervals[] = {
    1 * kSecondsPerMinute,    // 1 minute mark
    4 * kSecondsPerMinute,    // 5 minute mark
    25 * kSecondsPerMinute,   // 0.5 hour mark
    120 * kSecondsPerMinute,  // 2.5 hour mark
    600 * kSecondsPerMinute,  // 12.5 hour mark
};

constexpr char kDailyUseTimeName[] = "Platform.DailyUseTime";
constexpr char kUnaggregatedUseTimeName[] = "Platform.UnaggregatedUsageTime";
constexpr char kUnaggregatedUseTimeOverflowName[] =
    "Platform.UnaggregatedUsageTimeTooBig";
constexpr char kCumulativeUseTimeName[] = "Platform.CumulativeUseTime";
constexpr char kCumulativeCpuTimeName[] = "Platform.CumulativeCpuTime";
constexpr char kKernelCrashIntervalName[] = "Platform.KernelCrashInterval";
constexpr char kUncleanShutdownIntervalName[] =
    "Platform.UncleanShutdownInterval";
constexpr char kUserCrashIntervalName[] = "Platform.UserCrashInterval";
constexpr char kAnyCrashesDailyName[] = "Platform.AnyCrashesDaily";
constexpr char kAnyCrashesWeeklyName[] = "Platform.AnyCrashesWeekly";
constexpr char kUserCrashesDailyName[] = "Platform.UserCrashesDaily";
constexpr char kUserCrashesWeeklyName[] = "Platform.UserCrashesWeekly";
constexpr char kKernelCrashesDailyName[] = "Platform.KernelCrashesDaily";
constexpr char kKernelCrashesWeeklyName[] = "Platform.KernelCrashesWeekly";
constexpr char kKernelCrashesSinceUpdateName[] =
    "Platform.KernelCrashesSinceUpdate";
constexpr char kUncleanShutdownsDailyName[] = "Platform.UncleanShutdownsDaily";
constexpr char kUncleanShutdownsWeeklyName[] =
    "Platform.UncleanShutdownsWeekly";

// Max process allocation size in megabytes, used as an upper bound for UMA
// histograms (these are all consumer devices, and 64 GB should be good for a
// few more years).
constexpr int kMaxMemSizeMiB = 64 * (1 << 10);

}  // namespace

// disk stats metrics

// The {Read,Write}Sectors numbers are in sectors/second.
// A sector is usually 512 bytes.

const char MetricsDaemon::kMetricReadSectorsLongName[] =
    "Platform.ReadSectorsLong";
const char MetricsDaemon::kMetricWriteSectorsLongName[] =
    "Platform.WriteSectorsLong";
const char MetricsDaemon::kMetricReadSectorsShortName[] =
    "Platform.ReadSectorsShort";
const char MetricsDaemon::kMetricWriteSectorsShortName[] =
    "Platform.WriteSectorsShort";

const int MetricsDaemon::kMetricStatsShortInterval = 1;       // seconds
const int MetricsDaemon::kMetricStatsLongInterval = 30;       // seconds
const int MetricsDaemon::kMetricMeminfoInterval = 30;         // seconds
const int MetricsDaemon::kMetricDetachableBaseInterval = 30;  // seconds
constexpr base::TimeDelta MetricsDaemon::kMetricReportProcessMemoryInterval =
    base::Minutes(10);

// Assume a max rate of 250Mb/s for reads (worse for writes) and 512 byte
// sectors.
const int MetricsDaemon::kMetricSectorsIOMax = 500000;  // sectors/second
const int MetricsDaemon::kMetricSectorsBuckets = 50;    // buckets
// Page size is 4k, sector size is 0.5k.  We're not interested in page fault
// rates that the disk cannot sustain.
const int MetricsDaemon::kMetricPageFaultsMax = kMetricSectorsIOMax / 8;
const int MetricsDaemon::kMetricPageFaultsBuckets = 50;

// Assume a max rate of 54000000 pages/day, based on current 99 percentile
// for Platform.SwapOutLong being about 1500 pages/second. Assume 10 hours
// of use per day.
const int MetricsDaemon::kMetricDailySwapMax = 54000000;
const int MetricsDaemon::kMetricDailySwapBuckets = 50;

// Major page faults, i.e. the ones that require data to be read from disk or
// decompressed from zram.  "Anon" and "File" qualifiers are in grammatically
// incorrect positions for better sorting in UMA.

const char MetricsDaemon::kMetricPageFaultsLongName[] =
    "Platform.PageFaultsLong";
const char MetricsDaemon::kMetricPageFaultsShortName[] =
    "Platform.PageFaultsShort";
const char MetricsDaemon::kMetricFilePageFaultsLongName[] =
    "Platform.PageFaultsFileLong";
const char MetricsDaemon::kMetricFilePageFaultsShortName[] =
    "Platform.PageFaultsFileShort";
const char MetricsDaemon::kMetricAnonPageFaultsLongName[] =
    "Platform.PageFaultsAnonLong";
const char MetricsDaemon::kMetricAnonPageFaultsShortName[] =
    "Platform.PageFaultsAnonShort";

// Swap in and Swap out

const char MetricsDaemon::kMetricSwapInDailyName[] = "Platform.SwapInDaily";
const char MetricsDaemon::kMetricSwapInLongName[] = "Platform.SwapInLong";
const char MetricsDaemon::kMetricSwapInShortName[] = "Platform.SwapInShort";

const char MetricsDaemon::kMetricSwapOutDailyName[] = "Platform.SwapOutDaily";
const char MetricsDaemon::kMetricSwapOutLongName[] = "Platform.SwapOutLong";
const char MetricsDaemon::kMetricSwapOutShortName[] = "Platform.SwapOutShort";

const char MetricsDaemon::kMetricsProcStatFileName[] = "/proc/stat";
const int MetricsDaemon::kMetricsProcStatFirstLineItemsCount = 11;

// Thermal CPU throttling.

const char MetricsDaemon::kMetricScaledCpuFrequencyName[] =
    "Platform.CpuFrequencyThermalScaling";

// Zram sysfs entries.

const char MetricsDaemon::kComprDataSizeName[] = "compr_data_size";
const char MetricsDaemon::kOrigDataSizeName[] = "orig_data_size";
const char MetricsDaemon::kZeroPagesName[] = "zero_pages";
const char MetricsDaemon::kMMStatName[] = "mm_stat";

// Detachable base autosuspend metrics.

const char MetricsDaemon::kMetricDetachableBaseActivePercentName[] =
    "Platform.DetachableBase.ActivePercent";

// Detachable base autosuspend sysfs entries.

const char MetricsDaemon::kHammerSysfsPathPath[] =
    "/run/metrics/external/hammer/hammer_sysfs_path";
const char MetricsDaemon::kDetachableBaseSysfsLevelName[] = "power/level";
const char MetricsDaemon::kDetachableBaseSysfsLevelValue[] = "auto";
const char MetricsDaemon::kDetachableBaseSysfsActiveTimeName[] =
    "power/runtime_active_time";
const char MetricsDaemon::kDetachableBaseSysfsSuspendedTimeName[] =
    "power/runtime_suspended_time";

// crouton metrics

const char MetricsDaemon::kMetricCroutonStarted[] = "Platform.Crouton.Started";

MetricsDaemon::MetricsDaemon()
    : memuse_final_time_(0),
      memuse_interval_index_(0),
      read_sectors_(0),
      write_sectors_(0),
      vmstats_(),
      stats_state_(kStatsShort),
      stats_initial_time_(0),
      ticks_per_second_(0),
      latest_cpu_use_ticks_(0),
      detachable_base_active_time_(0),
      detachable_base_suspended_time_(0) {}

MetricsDaemon::~MetricsDaemon() {}

double MetricsDaemon::GetActiveTime() {
  struct timespec ts;
  int r = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (r < 0) {
    PLOG(WARNING) << "clock_gettime(CLOCK_MONOTONIC) failed";
    return 0;
  } else {
    return ts.tv_sec + static_cast<double>(ts.tv_nsec) / (1000 * 1000 * 1000);
  }
}

int MetricsDaemon::Run() {
  if (CheckSystemCrash(kKernelCrashDetectedFile)) {
    ProcessKernelCrash();
  }

  if (CheckSystemCrash(kUncleanShutdownDetectedFile)) {
    ProcessUncleanShutdown();
  }

  // On OS version change, clear version stats (which are reported daily).
  int32_t version = GetOsVersionHash();
  if (version_cycle_->Get() != version) {
    version_cycle_->Set(version);
    kernel_crashes_version_count_->Set(0);
    version_cumulative_active_use_->Set(0);
    version_cumulative_cpu_use_->Set(0);
  }

  return brillo::DBusDaemon::Run();
}

void MetricsDaemon::RunUploaderTest() {
  upload_service_.reset(new UploadService(
      new SystemProfileCache(true, config_root_), metrics_lib_, server_));
  upload_service_->Init(upload_interval_, metrics_file_,
                        true /* uploads_enabled */);
  upload_service_->UploadEvent();
}

uint32_t MetricsDaemon::GetOsVersionHash() {
  static uint32_t cached_version_hash = 0;
  static bool version_hash_is_cached = false;
  if (version_hash_is_cached)
    return cached_version_hash;
  version_hash_is_cached = true;
  std::string version;
  if (base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION", &version)) {
    cached_version_hash = base::Hash(version);
  } else if (testing_) {
    cached_version_hash = 42;  // return any plausible value for the hash
  } else {
    LOG(FATAL) << "could not find CHROMEOS_RELEASE_VERSION";
  }
  return cached_version_hash;
}

bool MetricsDaemon::IsOnOfficialBuild() const {
  std::string build_type;
  return (base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_BUILD_TYPE",
                                            &build_type) &&
          build_type == kOfficialBuild);
}

void MetricsDaemon::Init(bool testing,
                         bool uploader_active,
                         MetricsLibraryInterface* metrics_lib,
                         const string& diskstats_path,
                         const string& vmstats_path,
                         const string& scaling_max_freq_path,
                         const string& cpuinfo_max_freq_path,
                         const base::TimeDelta& upload_interval,
                         const string& server,
                         const string& metrics_file,
                         const string& config_root,
                         const base::FilePath& backing_dir) {
  testing_ = testing;
  uploader_active_ = uploader_active;
  config_root_ = config_root;
  DCHECK(metrics_lib != nullptr);
  metrics_lib_ = metrics_lib;
  backing_dir_ = backing_dir;

  upload_interval_ = upload_interval;
  server_ = server;
  metrics_file_ = metrics_file;

  // Get ticks per second (HZ) on this system.
  // Sysconf cannot fail, so no sanity checks are needed.
  ticks_per_second_ = sysconf(_SC_CLK_TCK);

  daily_active_use_.reset(
      new PersistentInteger(backing_dir_.Append(kDailyUseTimeName)));
  version_cumulative_active_use_.reset(
      new PersistentInteger(backing_dir_.Append(kCumulativeUseTimeName)));
  version_cumulative_cpu_use_.reset(
      new PersistentInteger(backing_dir_.Append(kCumulativeCpuTimeName)));
  kernel_crash_interval_.reset(
      new PersistentInteger(backing_dir_.Append(kKernelCrashIntervalName)));
  unclean_shutdown_interval_.reset(
      new PersistentInteger(backing_dir_.Append(kUncleanShutdownIntervalName)));
  user_crash_interval_.reset(
      new PersistentInteger(backing_dir_.Append(kUserCrashIntervalName)));
  any_crashes_daily_count_.reset(
      new PersistentInteger(backing_dir_.Append(kAnyCrashesDailyName)));
  any_crashes_weekly_count_.reset(
      new PersistentInteger(backing_dir_.Append(kAnyCrashesWeeklyName)));
  user_crashes_daily_count_.reset(
      new PersistentInteger(backing_dir_.Append(kUserCrashesDailyName)));
  user_crashes_weekly_count_.reset(
      new PersistentInteger(backing_dir_.Append(kUserCrashesWeeklyName)));
  kernel_crashes_daily_count_.reset(
      new PersistentInteger(backing_dir_.Append(kKernelCrashesDailyName)));
  kernel_crashes_weekly_count_.reset(
      new PersistentInteger(backing_dir_.Append(kKernelCrashesWeeklyName)));
  kernel_crashes_version_count_.reset(new PersistentInteger(
      backing_dir_.Append(kKernelCrashesSinceUpdateName)));
  unclean_shutdowns_daily_count_.reset(
      new PersistentInteger(backing_dir_.Append(kUncleanShutdownsDailyName)));
  unclean_shutdowns_weekly_count_.reset(
      new PersistentInteger(backing_dir_.Append(kUncleanShutdownsWeeklyName)));

  daily_cycle_.reset(new PersistentInteger(backing_dir_.Append("daily.cycle")));
  weekly_cycle_.reset(
      new PersistentInteger(backing_dir_.Append("weekly.cycle")));
  version_cycle_.reset(
      new PersistentInteger(backing_dir_.Append("version.cycle")));

  diskstats_path_ = diskstats_path;
  vmstats_path_ = vmstats_path;
  scaling_max_freq_path_ = scaling_max_freq_path;
  cpuinfo_max_freq_path_ = cpuinfo_max_freq_path;

  vmstats_daily_success = VmStatsReadStats(&vmstats_daily_start);

  // Start the "last update" time at the time of metrics daemon starting.
  // This isn't entirely accurate -- in general, the tick counter will start
  // counting when the kernel starts executing, while metrics_daemon will only
  // start up once boot has mostly completed.
  // However, we need to initialize because:
  // 1. metrics_daemon might crash and restart. In this case, if we did not
  // initialize last_update_stats_time_, the first values we calculate based on
  // it will be based on the overall uptime of the device, rather than the
  // actual interval between updates.
  // 2. TimeTicks doesn't guarantee anything about when the value it returns
  // will be zero -- only that the value is monotonically nondecreasing. In
  // principle, on some platforms, it could start at a large number on boot.
  last_update_stats_time_ = TimeTicks::Now();

  // If testing, initialize Stats Reporter without connecting DBus
  if (testing_)
    StatsReporterInit();
}

int MetricsDaemon::OnInit() {
  int return_code = brillo::DBusDaemon::OnInit();
  if (return_code != EX_OK)
    return return_code;

  StatsReporterInit();

  // Start collecting meminfo stats.
  ScheduleMeminfoCallback(kMetricMeminfoInterval);
  memuse_final_time_ = GetActiveTime() + kMemuseIntervals[0];
  ScheduleMemuseCallback(kMemuseIntervals[0]);

  // Start collecting process memory stats.
  ScheduleReportProcessMemory(kMetricReportProcessMemoryInterval);

  // Start collecting detachable base stats.
  ScheduleDetachableBaseCallback(kMetricDetachableBaseInterval);

  if (testing_)
    return EX_OK;

  vmlog_writer_.reset(new chromeos_metrics::VmlogWriter(
      base::FilePath(kVmlogDir), kVmlogInterval));
  bus_->AssertOnDBusThread();
  CHECK(bus_->SetUpAsyncOperations());

  if (bus_->IsConnected()) {
    const std::string match_rule =
        base::StringPrintf(kCrashReporterMatchRule, kCrashReporterInterface,
                           kCrashReporterUserCrashSignal);

    // A filter function is used here because there is no permanent object
    // proxy exported by crash_reporter as it is a short-lived program.
    //
    // It might be theoretically possible to convert it to use
    // ObjectProxy::ConnectToSignal, but it's probably not worth the effort,
    // especially since ConnectToSignal uses FilterFunctions under the hood
    // anyways.
    bus_->AddFilterFunction(&MetricsDaemon::MessageFilter, this);

    DBusError error;
    dbus_error_init(&error);
    bus_->AddMatch(match_rule, &error);

    if (dbus_error_is_set(&error)) {
      LOG(ERROR) << "Failed to add match rule \"" << match_rule << "\". Got "
                 << error.name << ": " << error.message;
      return EX_SOFTWARE;
    }
  } else {
    LOG(ERROR) << "DBus isn't connected.";
    return EX_UNAVAILABLE;
  }

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::HandleUpdateStatsTimeout,
                     GET_THIS_FOR_POSTTASK()),
      base::Milliseconds(kInitialUpdateStatsIntervalMs));

  // Emit a "0" value on start, to provide a baseline for this metric.
  SendLinearSample(kMetricCroutonStarted, 0, 2, 3);
  SendCroutonStats();

  if (uploader_active_) {
    bool is_official = IsOnOfficialBuild();
    LOG(INFO) << "uploader enabled"
              << (is_official ? "" : " (dummy mode for unofficial build)");
    upload_service_.reset(
        new UploadService(new SystemProfileCache(), metrics_lib_, server_));
    upload_service_->Init(upload_interval_, metrics_file_,
                          is_official /* uploads_enabled */);
  }

  return EX_OK;
}

void MetricsDaemon::OnShutdown(int* return_code) {
  if (!testing_ && bus_->IsConnected()) {
    const std::string match_rule =
        base::StringPrintf(kCrashReporterMatchRule, kCrashReporterInterface,
                           kCrashReporterUserCrashSignal);

    bus_->RemoveFilterFunction(&MetricsDaemon::MessageFilter, this);

    DBusError error;
    dbus_error_init(&error);
    bus_->RemoveMatch(match_rule, &error);

    if (dbus_error_is_set(&error)) {
      LOG(ERROR) << "Failed to remove match rule \"" << match_rule << "\". Got "
                 << error.name << ": " << error.message;
    }
  }
  brillo::DBusDaemon::OnShutdown(return_code);
}

// static
DBusHandlerResult MetricsDaemon::MessageFilter(DBusConnection* connection,
                                               DBusMessage* message,
                                               void* user_data) {
  int message_type = dbus_message_get_type(message);
  if (message_type != DBUS_MESSAGE_TYPE_SIGNAL) {
    DLOG(WARNING) << "unexpected message type " << message_type;
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  // Signal messages always have interfaces.
  const std::string interface(dbus_message_get_interface(message));
  const std::string member(dbus_message_get_member(message));

  MetricsDaemon* daemon = static_cast<MetricsDaemon*>(user_data);

  DBusMessageIter iter;
  dbus_message_iter_init(message, &iter);
  if (interface == kCrashReporterInterface) {
    CHECK_EQ(member, kCrashReporterUserCrashSignal);
    daemon->ProcessUserCrash();
  } else {
    // Ignore messages from the bus itself.
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  return DBUS_HANDLER_RESULT_HANDLED;
}

// One might argue that parts of this should go into
// chromium/src/base/sys_info_chromeos.c instead, but put it here for now.

TimeDelta MetricsDaemon::GetIncrementalCpuUse() {
  FilePath proc_stat_path = FilePath(kMetricsProcStatFileName);
  std::string proc_stat_string;
  if (!base::ReadFileToString(proc_stat_path, &proc_stat_string)) {
    LOG(WARNING) << "cannot open " << kMetricsProcStatFileName;
    return TimeDelta();
  }

  std::vector<std::string> proc_stat_lines = base::SplitString(
      proc_stat_string, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (proc_stat_lines.empty()) {
    LOG(WARNING) << "cannot parse " << kMetricsProcStatFileName << ": "
                 << proc_stat_string;
    return TimeDelta();
  }
  std::vector<std::string> proc_stat_totals =
      base::SplitString(proc_stat_lines[0], base::kWhitespaceASCII,
                        base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  uint64_t user_ticks, user_nice_ticks, system_ticks;
  if (proc_stat_totals.size() != kMetricsProcStatFirstLineItemsCount ||
      proc_stat_totals[0] != "cpu" ||
      !base::StringToUint64(proc_stat_totals[1], &user_ticks) ||
      !base::StringToUint64(proc_stat_totals[2], &user_nice_ticks) ||
      !base::StringToUint64(proc_stat_totals[3], &system_ticks)) {
    LOG(WARNING) << "cannot parse first line: " << proc_stat_lines[0];
    return TimeDelta(base::Seconds(0));
  }

  uint64_t total_cpu_use_ticks = user_ticks + user_nice_ticks + system_ticks;

  // Sanity check.
  if (total_cpu_use_ticks < latest_cpu_use_ticks_) {
    LOG(WARNING) << "CPU time decreasing from " << latest_cpu_use_ticks_
                 << " to " << total_cpu_use_ticks;
    return TimeDelta();
  }

  uint64_t diff = total_cpu_use_ticks - latest_cpu_use_ticks_;
  latest_cpu_use_ticks_ = total_cpu_use_ticks;
  // Use microseconds to avoid significant truncations.
  return base::Microseconds(diff * 1000 * 1000 / ticks_per_second_);
}

void MetricsDaemon::ProcessUserCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(user_crash_interval_, kUserCrashIntervalName);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  user_crashes_daily_count_->Add(1);
  user_crashes_weekly_count_->Add(1);
}

void MetricsDaemon::ProcessKernelCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(kernel_crash_interval_,
                                  kKernelCrashIntervalName);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  kernel_crashes_daily_count_->Add(1);
  kernel_crashes_weekly_count_->Add(1);

  kernel_crashes_version_count_->Add(1);
}

void MetricsDaemon::ProcessUncleanShutdown() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(unclean_shutdown_interval_,
                                  kUncleanShutdownIntervalName);

  unclean_shutdowns_daily_count_->Add(1);
  LOG(INFO) << "metrics_daemon processing unclean shutdown; new value: "
            << unclean_shutdowns_daily_count_->Get();
  unclean_shutdowns_weekly_count_->Add(1);
  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
}

bool MetricsDaemon::CheckSystemCrash(const string& crash_file) {
  FilePath crash_detected(crash_file);
  if (!base::PathExists(crash_detected))
    return false;

  // Deletes the crash-detected file so that the daemon doesn't report
  // another kernel crash in case it's restarted.
  base::DeleteFile(crash_detected);  // not recursive
  return true;
}

void MetricsDaemon::StatsReporterInit() {
  DiskStatsReadStats(&read_sectors_, &write_sectors_);
  VmStatsReadStats(&vmstats_);
  // The first time around just run the long stat, so we don't delay boot.
  stats_state_ = kStatsLong;
  stats_initial_time_ = GetActiveTime();
  if (stats_initial_time_ < 0) {
    LOG(WARNING) << "not collecting disk stats";
  } else {
    ScheduleStatsCallback(kMetricStatsLongInterval);
  }
}

void MetricsDaemon::ScheduleStatsCallback(int wait) {
  if (testing_) {
    return;
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::StatsCallback, GET_THIS_FOR_POSTTASK()),
      base::Seconds(wait));
}

bool MetricsDaemon::DiskStatsReadStats(uint64_t* read_sectors,
                                       uint64_t* write_sectors) {
  int nchars;
  int nitems;
  bool success = false;
  char line[200];
  if (diskstats_path_.empty()) {
    return false;
  }
  int file = HANDLE_EINTR(open(diskstats_path_.c_str(), O_RDONLY));
  if (file < 0) {
    PLOG(WARNING) << "cannot open " << diskstats_path_;
    return false;
  }
  nchars = HANDLE_EINTR(read(file, line, sizeof(line)));
  if (nchars < 0) {
    PLOG(WARNING) << "cannot read from " << diskstats_path_;
    return false;
  } else {
    LOG_IF(WARNING, nchars == sizeof(line))
        << "line too long in " << diskstats_path_;
    line[nchars] = '\0';
    nitems = sscanf(line, "%*d %*d %" PRIu64 " %*d %*d %*d %" PRIu64,
                    read_sectors, write_sectors);
    if (nitems == 2) {
      success = true;
    } else {
      LOG(WARNING) << "found " << nitems << " items in " << diskstats_path_
                   << ", expected 2";
    }
  }
  IGNORE_EINTR(close(file));
  return success;
}

bool MetricsDaemon::VmStatsReadStats(struct VmstatRecord* stats) {
  std::ifstream vmstat_stream(vmstats_path_, std::ifstream::in);
  if (vmstat_stream.fail()) {
    LOG(WARNING) << "Couldn't open " << vmstats_path_;
    return false;
  }
  return VmStatsParseStats(&vmstat_stream, stats);
}

bool MetricsDaemon::ReadFreqToInt(const string& sysfs_file_name, int* value) {
  const FilePath sysfs_path(sysfs_file_name);
  string value_string;
  if (!base::ReadFileToString(sysfs_path, &value_string)) {
    LOG(WARNING) << "cannot read " << sysfs_path.value().c_str();
    return false;
  }
  if (!base::RemoveChars(value_string, "\n", &value_string)) {
    LOG(WARNING) << "no newline in " << value_string;
    // Continue even though the lack of newline is suspicious.
  }
  if (!base::StringToInt(value_string, value)) {
    LOG(WARNING) << "cannot convert " << value_string << " to int";
    return false;
  }
  return true;
}

void MetricsDaemon::SendCpuThrottleMetrics() {
  // |max_freq| is 0 only the first time through.
  static int max_freq = 0;
  if (max_freq == -1)
    // Give up, as sysfs did not report max_freq correctly.
    return;
  if (max_freq == 0 || testing_) {
    // One-time initialization of max_freq.  (Every time when testing.)
    if (!ReadFreqToInt(cpuinfo_max_freq_path_, &max_freq)) {
      max_freq = -1;
      return;
    }
    if (max_freq == 0) {
      LOG(WARNING) << "sysfs reports 0 max CPU frequency\n";
      max_freq = -1;
      return;
    }
    if (max_freq % 10000 == 1000) {
      // Special case: system has turbo mode, and max non-turbo frequency is
      // max_freq - 1000.  This relies on "normal" (non-turbo) frequencies
      // being multiples of (at least) 10 MHz.  Although there is no guarantee
      // of this, it seems a fairly reasonable assumption.  Otherwise we should
      // read scaling_available_frequencies, sort the frequencies, compare the
      // two highest ones, and check if they differ by 1000 (kHz) (and that's a
      // hack too, no telling when it will change).
      max_freq -= 1000;
    }
  }
  int scaled_freq = 0;
  if (!ReadFreqToInt(scaling_max_freq_path_, &scaled_freq))
    return;
  // Frequencies are in kHz.  If scaled_freq > max_freq, turbo is on, but
  // scaled_freq is not the actual turbo frequency.  We indicate this situation
  // with a 101% value.
  int percent = scaled_freq > max_freq ? 101 : scaled_freq / (max_freq / 100);
  SendLinearSample(kMetricScaledCpuFrequencyName, percent, 101, 102);
}

// Collects disk and vm stats alternating over a short and a long interval.

void MetricsDaemon::StatsCallback() {
  uint64_t read_sectors_now, write_sectors_now;
  struct VmstatRecord vmstats_now;
  double time_now = GetActiveTime();
  double delta_time = time_now - stats_initial_time_;
  if (testing_) {
    // Fake the time when testing.
    delta_time = stats_state_ == kStatsShort ? kMetricStatsShortInterval
                                             : kMetricStatsLongInterval;
  }
  bool diskstats_success =
      DiskStatsReadStats(&read_sectors_now, &write_sectors_now);
  int delta_read = read_sectors_now - read_sectors_;
  int delta_write = write_sectors_now - write_sectors_;
  int read_sectors_per_second = delta_read / delta_time;
  int write_sectors_per_second = delta_write / delta_time;
  bool vmstats_success = VmStatsReadStats(&vmstats_now);
  uint64_t delta_faults = vmstats_now.page_faults_ - vmstats_.page_faults_;
  uint64_t delta_file_faults =
      vmstats_now.file_page_faults_ - vmstats_.file_page_faults_;
  uint64_t delta_anon_faults =
      vmstats_now.anon_page_faults_ - vmstats_.anon_page_faults_;
  uint64_t delta_swap_in = vmstats_now.swap_in_ - vmstats_.swap_in_;
  uint64_t delta_swap_out = vmstats_now.swap_out_ - vmstats_.swap_out_;
  uint64_t page_faults_per_second = delta_faults / delta_time;
  uint64_t file_page_faults_per_second = delta_file_faults / delta_time;
  uint64_t anon_page_faults_per_second = delta_anon_faults / delta_time;
  uint64_t swap_in_per_second = delta_swap_in / delta_time;
  uint64_t swap_out_per_second = delta_swap_out / delta_time;

  switch (stats_state_) {
    case kStatsShort:
      if (diskstats_success) {
        SendSample(kMetricReadSectorsShortName, read_sectors_per_second, 1,
                   kMetricSectorsIOMax, kMetricSectorsBuckets);
        SendSample(kMetricWriteSectorsShortName, write_sectors_per_second, 1,
                   kMetricSectorsIOMax, kMetricSectorsBuckets);
      }
      if (vmstats_success) {
        SendSample(kMetricPageFaultsShortName, page_faults_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricFilePageFaultsShortName, file_page_faults_per_second,
                   1, kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricAnonPageFaultsShortName, anon_page_faults_per_second,
                   1, kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricSwapInShortName, swap_in_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricSwapOutShortName, swap_out_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);
      }
      // Schedule long callback.
      stats_state_ = kStatsLong;
      ScheduleStatsCallback(kMetricStatsLongInterval -
                            kMetricStatsShortInterval);
      break;
    case kStatsLong:
      if (diskstats_success) {
        SendSample(kMetricReadSectorsLongName, read_sectors_per_second, 1,
                   kMetricSectorsIOMax, kMetricSectorsBuckets);
        SendSample(kMetricWriteSectorsLongName, write_sectors_per_second, 1,
                   kMetricSectorsIOMax, kMetricSectorsBuckets);
        // Reset sector counters.
        read_sectors_ = read_sectors_now;
        write_sectors_ = write_sectors_now;
      }
      if (vmstats_success) {
        SendSample(kMetricPageFaultsLongName, page_faults_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricFilePageFaultsLongName, file_page_faults_per_second,
                   1, kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricAnonPageFaultsLongName, anon_page_faults_per_second,
                   1, kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricSwapInLongName, swap_in_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);
        SendSample(kMetricSwapOutLongName, swap_out_per_second, 1,
                   kMetricPageFaultsMax, kMetricPageFaultsBuckets);

        vmstats_ = vmstats_now;
      }
      SendCpuThrottleMetrics();
      // Set start time for new cycle.
      stats_initial_time_ = time_now;
      // Schedule short callback.
      stats_state_ = kStatsShort;
      ScheduleStatsCallback(kMetricStatsShortInterval);
      break;
    default:
      LOG(FATAL) << "Invalid stats state";
  }
}

void MetricsDaemon::ScheduleMeminfoCallback(int wait) {
  if (testing_)
    return;
  base::TimeDelta wait_delta = base::Seconds(wait);
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::MeminfoCallback, GET_THIS_FOR_POSTTASK(),
                     wait_delta),
      wait_delta);
}

void MetricsDaemon::MeminfoCallback(base::TimeDelta wait) {
  string meminfo_raw;
  const FilePath meminfo_path("/proc/meminfo");
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return;
  }
  // Make both calls even if the first one fails.  Only stop rescheduling if
  // both calls fail, since some platforms do not support zram.
  bool success = ProcessMeminfo(meminfo_raw);
  success = ReportZram(base::FilePath("/sys/block/zram0")) || success;
  if (success) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&MetricsDaemon::MeminfoCallback, GET_THIS_FOR_POSTTASK(),
                       wait),
        wait);
  }
}

void MetricsDaemon::ScheduleReportProcessMemory(base::TimeDelta interval) {
  if (testing_)
    return;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::ReportProcessMemoryCallback,
                     GET_THIS_FOR_POSTTASK(), interval),
      interval);
}

void MetricsDaemon::ReportProcessMemoryCallback(base::TimeDelta wait) {
  ReportProcessMemory();
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::ReportProcessMemoryCallback,
                     GET_THIS_FOR_POSTTASK(), wait),
      wait);
}

void MetricsDaemon::ReportProcessMemory() {
  base::FilePath procfs_path("/proc");
  base::FilePath run_path("/run");
  ProcessInfo info(procfs_path, run_path);
  info.Collect();
  info.Classify();
  for (int i = 0; i < PG_KINDS_COUNT; i++) {
    ProcessGroupKind kind = static_cast<ProcessGroupKind>(i);
    ProcessMemoryStats stats;
    // base::size is not compile time value, thus not usable by static_assert.
    // use sizeof instead, sizeof(kProcessMemoryUMANames[i]) should return
    // (number of elements * size of pointers), so is sizeof(stats.rss_sizes)
    // since both kProcessMemoryUMANames[i] and rss_sizes are arrays with fixed
    // size defined.
    static_assert(sizeof(kProcessMemoryUMANames[i]) /
                          sizeof(*kProcessMemoryUMANames[i]) ==
                      sizeof(stats.rss_sizes) / sizeof(*stats.rss_sizes),
                  "RSS array size mismatch");
    AccumulateProcessGroupStats(procfs_path, info.GetGroup(kind), &stats);
    ReportProcessGroupStats(kProcessMemoryUMANames[i], stats);
  }
}

void MetricsDaemon::ReportProcessGroupStats(
    const char* const uma_names[MEM_KINDS_COUNT],
    const ProcessMemoryStats& stats) {
  const uint64_t MiB = 1 << 20;
  for (int i = 0; i < std::size(stats.rss_sizes); i++) {
    SendSample(uma_names[i], stats.rss_sizes[i] / MiB, 1, kMaxMemSizeMiB, 50);
  }
}

void MetricsDaemon::ScheduleDetachableBaseCallback(int wait) {
  if (testing_)
    return;

  base::TimeDelta wait_delta = base::Seconds(wait);
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::DetachableBaseCallback,
                     GET_THIS_FOR_POSTTASK(),
                     base::FilePath{kHammerSysfsPathPath}, wait_delta),
      wait_delta);
}

void MetricsDaemon::DetachableBaseCallback(const base::FilePath sysfs_path_path,
                                           base::TimeDelta wait) {
  uint64_t active_time, suspended_time;

  if (GetDetachableBaseTimes(sysfs_path_path, &active_time, &suspended_time)) {
    // Edge case: disconnected and reconnected since the last callback.
    if (active_time < detachable_base_active_time_ ||
        suspended_time < detachable_base_suspended_time_) {
      DLOG(INFO) << "Detachable base removed (or time counter overflow)";
      detachable_base_active_time_ = active_time;
      detachable_base_suspended_time_ = suspended_time;
    }

    if (detachable_base_active_time_ == 0 &&
        detachable_base_suspended_time_ == 0)
      DLOG(INFO) << "Detachable base detected, start reporting activity";

    uint64_t delta_active = active_time - detachable_base_active_time_;
    uint64_t delta_suspended = suspended_time - detachable_base_suspended_time_;

    if ((delta_active + delta_suspended) > 0) {
      double active_ratio =
          static_cast<double>(delta_active) / (delta_active + delta_suspended);

      DLOG(INFO) << "Detachable base active_ratio: "
                 << base::StringPrintf("%.8f", active_ratio);

      // Linear scale, min=0, max=100, buckets=101.
      SendLinearSample(kMetricDetachableBaseActivePercentName,
                       active_ratio * 100, 100, 101);
    }
  } else {
    if (detachable_base_active_time_ != 0 &&
        detachable_base_suspended_time_ != 0)
      DLOG(INFO) << "Detachable base removed";
    active_time = 0;
    suspended_time = 0;
  }

  detachable_base_active_time_ = active_time;
  detachable_base_suspended_time_ = suspended_time;

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::DetachableBaseCallback,
                     GET_THIS_FOR_POSTTASK(), sysfs_path_path, wait),
      wait);
}

bool MetricsDaemon::GetDetachableBaseTimes(const base::FilePath sysfs_path_path,
                                           uint64_t* active_time,
                                           uint64_t* suspended_time) {
  base::FilePath sysfs_path;
  std::string content;

  if (!base::ReadFileToString(sysfs_path_path, &content))
    return false;
  base::TrimWhitespaceASCII(content, base::TRIM_TRAILING, &content);

  sysfs_path = base::FilePath(content);
  if (!base::ReadFileToString(sysfs_path.Append(kDetachableBaseSysfsLevelName),
                              &content))
    return false;
  base::TrimWhitespaceASCII(content, base::TRIM_TRAILING, &content);

  if (content != "auto")
    return false;

  bool r1 =
      ReadFileToUint64(sysfs_path.Append(kDetachableBaseSysfsActiveTimeName),
                       active_time, false);
  bool r2 =
      ReadFileToUint64(sysfs_path.Append(kDetachableBaseSysfsSuspendedTimeName),
                       suspended_time, false);
  if (!r1 || !r2)
    return false;

  return true;
}

// static
bool MetricsDaemon::ReadFileToUint64(const base::FilePath& path,
                                     uint64_t* value,
                                     bool warn_on_read_failure) {
  std::string content;
  if (!base::ReadFileToString(path, &content)) {
    if (warn_on_read_failure)
      PLOG(WARNING) << "cannot read " << path.MaybeAsASCII();
    return false;
  }
  // Remove final newline.
  base::TrimWhitespaceASCII(content, base::TRIM_TRAILING, &content);
  if (!base::StringToUint64(content, value)) {
    LOG(WARNING) << "invalid integer " << content << " in file "
                 << path.value();
    return false;
  }
  return true;
}

// static
bool MetricsDaemon::ReadZramStat(const base::FilePath& zram_dir,
                                 uint64_t* compr_data_size_out,
                                 uint64_t* orig_data_size_out,
                                 uint64_t* zero_pages_out,
                                 uint64_t* incompr_pages_out) {
  const base::FilePath mm_stat_path = zram_dir.Append(kMMStatName);
  std::string content;

  if (!base::ReadFileToString(mm_stat_path, &content)) {
    // If mm_stat is not present, try to read zram stat from the old stat files.
    if (!ReadFileToUint64(zram_dir.Append(kComprDataSizeName),
                          compr_data_size_out) ||
        !ReadFileToUint64(zram_dir.Append(kOrigDataSizeName),
                          orig_data_size_out) ||
        !ReadFileToUint64(zram_dir.Append(kZeroPagesName), zero_pages_out)) {
      LOG(WARNING) << "Cannot open zram stat files";
      return false;
    }
    *incompr_pages_out = 0;
    return true;
  }

  int num_items =
      sscanf(content.c_str(),
             "%" PRIu64 " %" PRIu64 " %*d %*d %*d %" PRIu64 " %*d %" PRIu64,
             orig_data_size_out, compr_data_size_out, zero_pages_out,
             incompr_pages_out);
  // incompr_pages is only expected in kernel >= 4.19
  if (num_items == 3) {
    *incompr_pages_out = 0;
  }
  if (num_items < 3) {
    LOG(WARNING) << "Found " << num_items << " item(s) in "
                 << mm_stat_path.value() << ", expected at least 3";
    return false;
  }

  return true;
}

bool MetricsDaemon::ReportZram(const base::FilePath& zram_dir) {
  if (!base::DirectoryExists(zram_dir)) {
    return false;
  }

  // Data sizes are in bytes.  |zero_pages| and |incompr_pages| are in number of
  // pages.
  uint64_t compr_data_size, orig_data_size, zero_pages, incompr_pages;
  const size_t page_size = 4096;

  if (!ReadZramStat(zram_dir, &compr_data_size, &orig_data_size, &zero_pages,
                    &incompr_pages)) {
    return false;
  }

  // |orig_data_size| does not include zero-filled pages.
  orig_data_size += zero_pages * page_size;

  if (incompr_pages > 0) {
    // incompr_pages is the number of incompressible 4k pages.
    const int incompr_pages_size = incompr_pages * page_size;
    // The values of interest for incompr_pages size is between 1MB and 1GB.
    // The units are number of 4k pages.
    SendSample("Platform.ZramIncompressiblePages", incompr_pages, 256,
               256 * 1024, 50);
    SendLinearSample("Platform.ZramIncompressibleRatioPercent.PreCompression",
                     incompr_pages_size * 100 / orig_data_size, 100, 101);
    SendLinearSample("Platform.ZramIncompressibleRatioPercent.PostCompression",
                     incompr_pages_size * 100 / compr_data_size, 100, 101);
  }

  const int compr_data_size_mb = compr_data_size >> 20;
  const int savings_mb = (orig_data_size - compr_data_size) >> 20;

  // Report compressed size in megabytes.  100 MB or less has little impact.
  SendSample("Platform.ZramCompressedSize", compr_data_size_mb, 100, 4000, 50);
  SendSample("Platform.ZramSavings", savings_mb, 100, 4000, 50);
  // The compression ratio is multiplied by 100 for better resolution.  The
  // ratios of interest are between 1 and 6 (100% and 600% as reported).  We
  // don't want samples when very little memory is being compressed.
  //
  // A race in older versions of zram can make orig_data_size underflow and
  // be reported as a large positive number, so we also need to ensure that
  // orig_data_size multiplied by 100 isn't going to overflow.
  if (compr_data_size_mb >= 1 &&
      orig_data_size < (1ull << (sizeof(orig_data_size) * 8 - 1)) / 100) {
    SendSample("Platform.ZramCompressionRatioPercent",
               orig_data_size * 100 / compr_data_size, 100, 600, 50);
  }
  // The values of interest for zero_pages are between 1MB and 1GB.  The units
  // are number of pages.
  SendSample("Platform.ZramZeroPages", zero_pages, 256, 256 * 1024, 50);
  // Send ratio sample only when the ratio exists.
  if (orig_data_size > 0) {
    const int zero_percent = zero_pages * page_size * 100 / orig_data_size;
    SendSample("Platform.ZramZeroRatioPercent", zero_percent, 1, 50, 50);
  }

  return true;
}

bool MetricsDaemon::ProcessMeminfo(const string& meminfo_raw) {
  static const MeminfoRecord fields_array[] = {
      {"MemTotal", "MemTotal"},  // SPECIAL CASE: total system memory
      {"MemFree", "MemFree"},
      {"Buffers", "Buffers"},
      {"Cached", "Cached"},
      // { "SwapCached", "SwapCached" },
      {"Active", "Active"},
      {"Inactive", "Inactive"},
      {"ActiveAnon", "Active(anon)", kMeminfoOp_Anon},
      {"InactiveAnon", "Inactive(anon)", kMeminfoOp_Anon},
      {"ActiveFile", "Active(file)", kMeminfoOp_File},
      {"InactiveFile", "Inactive(file)", kMeminfoOp_File},
      {"Unevictable", "Unevictable", kMeminfoOp_HistLog},
      // { "Mlocked", "Mlocked" },
      {"SwapTotal", "SwapTotal", kMeminfoOp_SwapTotal},
      {"SwapFree", "SwapFree", kMeminfoOp_SwapFree},
      // { "Dirty", "Dirty" },
      // { "Writeback", "Writeback" },
      {"AnonPages", "AnonPages"},
      {"Mapped", "Mapped"},
      {"Shmem", "Shmem", kMeminfoOp_HistLog},
      {"Slab", "Slab", kMeminfoOp_HistLog},
      // { "SReclaimable", "SReclaimable" },
      // { "SUnreclaim", "SUnreclaim" },
  };
  vector<MeminfoRecord> fields(fields_array,
                               fields_array + std::size(fields_array));
  if (!FillMeminfo(meminfo_raw, &fields)) {
    return false;
  }
  int total_memory = fields[0].value;
  if (total_memory == 0) {
    // this "cannot happen"
    LOG(WARNING) << "borked meminfo parser";
    return false;
  }
  int swap_total = 0;
  int swap_free = 0;
  int mem_free_derived = 0;    // free + cached + buffers
  int mem_used_derived = 0;    // total - free_derived
  int process_data_total = 0;  // anon (active and inactive) + swap
  int file_total = 0;          // file active and inactive
  // Send all fields retrieved, except total memory.
  for (unsigned int i = 1; i < fields.size(); i++) {
    string metrics_name =
        base::StringPrintf("Platform.Meminfo%s", fields[i].name);
    int percent;
    switch (fields[i].op) {
      case kMeminfoOp_HistPercent:
        // report value as percent of total memory
        percent = fields[i].value * 100 / total_memory;
        SendLinearSample(metrics_name, percent, 100, 101);
        break;
      case kMeminfoOp_HistLog:
        // report value in kbytes, log scale, 256GiB max
        SendSample(metrics_name, fields[i].value, 1, 256 * 1024 * 1024, 100);
        break;
      case kMeminfoOp_SwapTotal:
        swap_total = fields[i].value;
        break;
      case kMeminfoOp_SwapFree:
        swap_free = fields[i].value;
        break;
      case kMeminfoOp_Anon:
        process_data_total += fields[i].value;
        break;
      case kMeminfoOp_File:
        file_total += fields[i].value;
        break;
    }
    if (strcmp(fields[i].match, "MemFree") == 0 ||
        strcmp(fields[i].match, "Buffers") == 0 ||
        strcmp(fields[i].match, "Cached") == 0) {
      mem_free_derived += fields[i].value;
    }
  }
  int swap_used = swap_total - swap_free;
  if (swap_total > 0) {
    int swap_used_percent = swap_used * 100 / swap_total;
    SendSample("Platform.MeminfoSwapUsed", swap_used, 1, 256 * 1024 * 1024,
               100);
    SendLinearSample("Platform.MeminfoSwapUsedPercent", swap_used_percent, 100,
                     101);
  }
  process_data_total += swap_used;
  mem_used_derived = total_memory - mem_free_derived;
  SendSample("Platform.MeminfoMemFreeDerived", mem_free_derived, 1,
             kMaximumMemorySizeInKB, 100);
  SendSample("Platform.MeminfoMemUsedDerived", mem_used_derived, 1,
             kMaximumMemorySizeInKB, 100);
  SendSample("Platform.MeminfoMemTotal", total_memory, 1,
             kMaximumMemorySizeInKB, 100);
  SendSample("Platform.MeminfoProcessDataTotal", process_data_total, 1,
             kMaximumMemorySizeInKB, 100);
  SendSample("Platform.MeminfoFileTotal", file_total, 1, kMaximumMemorySizeInKB,
             100);
  return true;
}

bool MetricsDaemon::FillMeminfo(const string& meminfo_raw,
                                vector<MeminfoRecord>* fields) {
  vector<string> lines = base::SplitString(
      meminfo_raw, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  // Scan meminfo output and collect field values.  Each field name has to
  // match a meminfo entry (case insensitive) after removing non-alpha
  // characters from the entry.
  size_t ifield = 0;
  for (size_t iline = 0; iline < lines.size() && ifield < fields->size();
       iline++) {
    vector<string> tokens = base::SplitString(
        lines[iline], ": ", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    if (strcmp((*fields)[ifield].match, tokens[0].c_str()) == 0) {
      // Name matches. Parse value and save.
      char* rest;
      (*fields)[ifield].value =
          static_cast<int>(strtol(tokens[1].c_str(), &rest, 10));
      if (*rest != '\0') {
        LOG(WARNING) << "missing meminfo value";
        return false;
      }
      ifield++;
    }
  }
  if (ifield < fields->size()) {
    // End of input reached while scanning.
    LOG(WARNING) << "cannot find field " << (*fields)[ifield].match
                 << " and following";
    return false;
  }
  return true;
}

void MetricsDaemon::ScheduleMemuseCallback(double interval) {
  if (testing_) {
    return;
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::MemuseCallback, GET_THIS_FOR_POSTTASK()),
      base::Seconds(interval));
}

void MetricsDaemon::MemuseCallback() {
  // Since we only care about active time (i.e. uptime minus sleep time) but
  // the callbacks are driven by real time (uptime), we check if we should
  // reschedule this callback due to intervening sleep periods.
  double now = GetActiveTime();
  // Avoid intervals of less than one second.
  double remaining_time = ceil(memuse_final_time_ - now);
  if (remaining_time > 0) {
    ScheduleMemuseCallback(remaining_time);
  } else {
    // Report stats and advance the measurement interval unless there are
    // errors or we've completed the last interval.
    if (MemuseCallbackWork() &&
        memuse_interval_index_ < std::size(kMemuseIntervals)) {
      double interval = kMemuseIntervals[memuse_interval_index_++];
      memuse_final_time_ = now + interval;
      ScheduleMemuseCallback(interval);
    }
  }
}

bool MetricsDaemon::MemuseCallbackWork() {
  string meminfo_raw;
  const FilePath meminfo_path("/proc/meminfo");
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return false;
  }
  return ProcessMemuse(meminfo_raw);
}

bool MetricsDaemon::ProcessMemuse(const string& meminfo_raw) {
  static const MeminfoRecord fields_array[] = {
      {"MemTotal", "MemTotal"},  // SPECIAL CASE: total system memory
      {"ActiveAnon", "Active(anon)"},
      {"InactiveAnon", "Inactive(anon)"},
  };
  vector<MeminfoRecord> fields(fields_array,
                               fields_array + std::size(fields_array));
  if (!FillMeminfo(meminfo_raw, &fields)) {
    return false;
  }
  int total = fields[0].value;
  int active_anon = fields[1].value;
  int inactive_anon = fields[2].value;
  if (total == 0) {
    // this "cannot happen"
    LOG(WARNING) << "borked meminfo parser";
    return false;
  }
  string metrics_name =
      base::StringPrintf("Platform.MemuseAnon%d", memuse_interval_index_);
  SendLinearSample(metrics_name, (active_anon + inactive_anon) * 100 / total,
                   100, 101);
  return true;
}

void MetricsDaemon::SendSample(
    const string& name, int sample, int min, int max, int nbuckets) {
  metrics_lib_->SendToUMA(name, sample, min, max, nbuckets);
}

void MetricsDaemon::SendKernelCrashesCumulativeCountStats() {
  // Report the number of crashes for this OS version, but don't clear the
  // counter.  It is cleared elsewhere on version change.
  int64_t crashes_count = kernel_crashes_version_count_->Get();
  SendSample(kKernelCrashesSinceUpdateName, crashes_count,
             1,     // value of first bucket
             500,   // value of last bucket
             100);  // number of buckets

  int64_t cpu_use_ms = version_cumulative_cpu_use_->Get();
  SendSample(kCumulativeCpuTimeName,
             cpu_use_ms / 1000,  // stat is in seconds
             1,                  // device may be used very little...
             8 * 1000 * 1000,    // ... or a lot (a little over 90 days)
             100);

  // On the first run after an autoupdate, cpu_use_ms and active_use_seconds
  // can be zero.  Avoid division by zero.
  if (cpu_use_ms > 0) {
    // Send the crash frequency since update in number of crashes per CPU year.
    SendSample("Platform.KernelCrashesPerCpuYear",
               crashes_count * kSecondsPerDay * 365 * 1000 / cpu_use_ms, 1,
               1000 * 1000,  // about one crash every 30s of CPU time
               100);
  }

  int64_t active_use_seconds = version_cumulative_active_use_->Get();
  if (active_use_seconds > 0) {
    SendSample(kCumulativeUseTimeName, active_use_seconds,
               1,                // device may be used very little...
               8 * 1000 * 1000,  // ... or a lot (about 90 days)
               100);
    // Same as above, but per year of active time.
    SendSample("Platform.KernelCrashesPerActiveYear",
               crashes_count * kSecondsPerDay * 365 / active_use_seconds, 1,
               1000 * 1000,  // about one crash every 30s of active time
               100);
  }
}

void MetricsDaemon::SendAndResetDailyUseSample() {
  // Since metrics_daemon only updates statistics every kUpdateStatsIntervalMs,
  // we will often report devices that are active for exactly 24 hours as being
  // active for slightly more than 24 hours. Round down in such cases to exactly
  // 24 hours, since we cannot be active for more than 24 hours in a day.  Do
  // *not* round down times more than that, because they could be due to
  // unrelated bugs that we don't want to mask.
  int64_t dau_seconds = daily_active_use_->GetAndClear();
  if (dau_seconds > kSecondsPerDay &&
      dau_seconds <=
          kSecondsPerDay + (kUpdateStatsIntervalMs / kMillisPerSecond)) {
    // Shift the extra over to the current day.
    daily_active_use_->Add(dau_seconds - kSecondsPerDay);

    // Then record only the maximum daily amount today.
    dau_seconds = kSecondsPerDay;
  }
  SendSample(kDailyUseTimeName, dau_seconds,
             1,               // value of first bucket
             kSecondsPerDay,  // value of last bucket
             50);             // number of buckets
}

void MetricsDaemon::SendAndResetCrashIntervalSample(
    const std::unique_ptr<PersistentInteger>& interval,
    const std::string& name) {
  SendSample(name, interval->GetAndClear(),
             1,                    // value of first bucket
             4 * kSecondsPerWeek,  // value of last bucket
             50);                  // number of buckets
}

void MetricsDaemon::SendAndResetCrashFrequencySample(
    const std::unique_ptr<PersistentInteger>& frequency,
    const std::string& name) {
  SendSample(name, frequency->GetAndClear(),
             1,    // value of first bucket
             100,  // value of last bucket
             50);  // number of buckets
}

void MetricsDaemon::SendAndResetDailyVmstats() {
  struct VmstatRecord vmstats_now;
  bool vmstats_success = VmStatsReadStats(&vmstats_now);
  if (vmstats_success && vmstats_daily_success) {
    uint64_t delta_swap_in =
        vmstats_now.swap_in_ - vmstats_daily_start.swap_in_;
    uint64_t delta_swap_out =
        vmstats_now.swap_out_ - vmstats_daily_start.swap_out_;
    SendSample(kMetricSwapInDailyName, delta_swap_in, 1, kMetricDailySwapMax,
               kMetricDailySwapBuckets);
    SendSample(kMetricSwapOutDailyName, delta_swap_out, 1, kMetricDailySwapMax,
               kMetricDailySwapBuckets);
  }
  vmstats_daily_start = vmstats_now;
  vmstats_daily_success = vmstats_success;
}

void MetricsDaemon::SendLinearSample(const string& name,
                                     int sample,
                                     int max,
                                     int nbuckets) {
  // TODO(semenzato): add a proper linear histogram to the Chrome external
  // metrics API.
  LOG_IF(FATAL, nbuckets != max + 1) << "unsupported histogram scale";
  metrics_lib_->SendEnumToUMA(name, sample, max);
}

void MetricsDaemon::SendCroutonStats() {
  // Report the presence of kCroutonStartedFile. We only report each state
  // exactly once per boot. "0" state reported on init.
  if (PathExists(FilePath(kCroutonStartedFile))) {
    SendLinearSample(kMetricCroutonStarted, 1, 2, 3);
  } else {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&MetricsDaemon::SendCroutonStats,
                       GET_THIS_FOR_POSTTASK()),
        base::Milliseconds(kUpdateStatsIntervalMs));
  }
}

void MetricsDaemon::UpdateStats(TimeTicks now_ticks, Time now_wall_time) {
  const int elapsed_seconds = (now_ticks - last_update_stats_time_).InSeconds();
  daily_active_use_->Add(elapsed_seconds);
  version_cumulative_active_use_->Add(elapsed_seconds);
  user_crash_interval_->Add(elapsed_seconds);
  kernel_crash_interval_->Add(elapsed_seconds);
  version_cumulative_cpu_use_->Add(GetIncrementalCpuUse().InMilliseconds());

  const TimeDelta since_epoch = now_wall_time - Time::UnixEpoch();
  const int day = since_epoch.InDays();
  const int week = day / 7;

  if (elapsed_seconds > kMaxAcceptableUnaggregatedUsageTime) {
    LOG(ERROR) << "Unexpectedly large elapsed_seconds. "
               << "now_ticks: " << now_ticks
               << " elapsed_seconds: " << elapsed_seconds
               << " last_update_stats_time_: " << last_update_stats_time_;
    SendSample(kUnaggregatedUseTimeOverflowName, elapsed_seconds,
               kMaxAcceptableUnaggregatedUsageTime,  // value of first bucket
               INT_MAX / 2,                          // value of last bucket
               50);                                  // number of buckets
  } else {
    // Allow some slack time above the expected max of 5 minutes.
    const int max_time =
        kUpdateStatsIntervalMs / kMillisPerSecond + kSecondsPerMinute;
    SendSample(kUnaggregatedUseTimeName, elapsed_seconds,
               1,         // value of first bucket
               max_time,  // value of last bucket
               50);       // number of buckets
  }

  last_update_stats_time_ = now_ticks;

  if (daily_cycle_->Get() != day) {
    daily_cycle_->Set(day);
    SendAndResetDailyUseSample();
    SendAndResetCrashFrequencySample(any_crashes_daily_count_,
                                     kAnyCrashesDailyName);
    SendAndResetCrashFrequencySample(user_crashes_daily_count_,
                                     kUserCrashesDailyName);
    SendAndResetCrashFrequencySample(kernel_crashes_daily_count_,
                                     kKernelCrashesDailyName);
    SendAndResetCrashFrequencySample(unclean_shutdowns_daily_count_,
                                     kUncleanShutdownsDailyName);
    SendKernelCrashesCumulativeCountStats();
    SendAndResetDailyVmstats();
  }

  if (weekly_cycle_->Get() != week) {
    weekly_cycle_->Set(week);
    SendAndResetCrashFrequencySample(any_crashes_weekly_count_,
                                     kAnyCrashesWeeklyName);
    SendAndResetCrashFrequencySample(user_crashes_weekly_count_,
                                     kUserCrashesWeeklyName);
    SendAndResetCrashFrequencySample(kernel_crashes_weekly_count_,
                                     kKernelCrashesWeeklyName);
    SendAndResetCrashFrequencySample(unclean_shutdowns_weekly_count_,
                                     kUncleanShutdownsWeeklyName);
  }
}

void MetricsDaemon::HandleUpdateStatsTimeout() {
  UpdateStats(TimeTicks::Now(), Time::Now());
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&MetricsDaemon::HandleUpdateStatsTimeout,
                     GET_THIS_FOR_POSTTASK()),
      base::Milliseconds(kUpdateStatsIntervalMs));
}

}  // namespace chromeos_metrics
