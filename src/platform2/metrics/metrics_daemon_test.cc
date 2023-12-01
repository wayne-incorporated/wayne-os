// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <inttypes.h>
#include <utime.h>

#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "metrics/metrics_daemon.h"
#include "metrics/metrics_library_mock.h"
#include "metrics/persistent_integer_mock.h"

using base::FilePath;
using base::StringPrintf;
using base::Time;
using base::TimeDelta;
using base::TimeTicks;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::Le;
using ::testing::Return;
using ::testing::StrictMock;

namespace chromeos_metrics {

namespace {
const char kFakeDiskStatsName[] = "fake-disk-stats";
const char kFakeDiskStatsFormat[] =
    "    1793     1788    %" PRIu64
    "   105580    "
    "    196      175     %" PRIu64 "    30290        0    44060   135850\n";
const uint64_t kFakeReadSectors[] = {80000, 100000};
const uint64_t kFakeWriteSectors[] = {3000, 4000};

const char kFakeVmStatsName[] = "fake-vm-stats";
const char kFakeScalingMaxFreqPath[] = "fake-scaling-max-freq";
const char kFakeCpuinfoMaxFreqPath[] = "fake-cpuinfo-max-freq";
const char kMetricsServer[] = "https://clients4.google.com/uma/v2";
const char kMetricsFilePath[] = "uma-events";

void PerisistentIntegerCreationCallback(const base::FilePath& path) {
  const std::string base_name = path.BaseName().value();
  const bool startsWithPlatform = base::StartsWith(base_name, "Platform");
  const bool endsWithCycle = base::EndsWith(base_name, ".cycle");
  const bool endsWithMock = base::EndsWith(base_name, ".mock");
  CHECK(startsWithPlatform || endsWithCycle || endsWithMock)
      << base_name
      << " is not a valid name. If it should be, please update the "
         "pre-start script in init/metrics_daemon.conf and "
         "then update this test";
}

}  // namespace

class MetricsDaemonTest : public testing::Test {
 protected:
  std::string kFakeDiskStats0;
  std::string kFakeDiskStats1;

  virtual void SetUp() {
    PersistentInteger::SetCreationCallbackForTesting(
        base::BindRepeating(&PerisistentIntegerCreationCallback));

    // Create the backing directory.
    CHECK(persistent_integer_backing_dir_.CreateUniqueTempDir());
    backing_dir_path_ = persistent_integer_backing_dir_.GetPath();

    fake_disk_stats_ = backing_dir_path_.Append(kFakeDiskStatsName);
    fake_vm_stats_ = backing_dir_path_.Append(kFakeVmStatsName);
    fake_scaling_max_freq_ = backing_dir_path_.Append(kFakeScalingMaxFreqPath);
    fake_cpuinfo_max_freq_ = backing_dir_path_.Append(kFakeCpuinfoMaxFreqPath);
    fake_metrics_file_ = backing_dir_path_.Append(kMetricsFilePath);
    fake_mm_stat_file_ = backing_dir_path_.Append(MetricsDaemon::kMMStatName);

    kFakeDiskStats0 = base::StringPrintf(
        kFakeDiskStatsFormat, kFakeReadSectors[0], kFakeWriteSectors[0]);
    kFakeDiskStats1 = base::StringPrintf(
        kFakeDiskStatsFormat, kFakeReadSectors[1], kFakeWriteSectors[1]);
    CreateFakeDiskStatsFile(kFakeDiskStats0.c_str());
    CreateUint64ValueFile(fake_cpuinfo_max_freq_, 10000000);
    CreateUint64ValueFile(fake_scaling_max_freq_, 10000000);

    test_start_ = base::TimeTicks::Now();

    daemon_.Init(true, false, &metrics_lib_, fake_disk_stats_.value(),
                 fake_vm_stats_.value(), fake_scaling_max_freq_.value(),
                 fake_cpuinfo_max_freq_.value(), base::Minutes(30),
                 kMetricsServer, fake_metrics_file_.value(), "/",
                 backing_dir_path_);

    // Replace original persistent values with mock ones.
    base::FilePath m1 = backing_dir_path_.Append("1.mock");
    daily_active_use_mock_ = new StrictMock<PersistentIntegerMock>(m1);
    daemon_.daily_active_use_.reset(daily_active_use_mock_);

    base::FilePath m2 = backing_dir_path_.Append("2.mock");
    kernel_crash_interval_mock_ = new StrictMock<PersistentIntegerMock>(m2);
    daemon_.kernel_crash_interval_.reset(kernel_crash_interval_mock_);

    base::FilePath m3 = backing_dir_path_.Append("3.mock");
    user_crash_interval_mock_ = new StrictMock<PersistentIntegerMock>(m3);
    daemon_.user_crash_interval_.reset(user_crash_interval_mock_);

    base::FilePath m4 = backing_dir_path_.Append("4.mock");
    unclean_shutdown_interval_mock_ = new StrictMock<PersistentIntegerMock>(m4);
    daemon_.unclean_shutdown_interval_.reset(unclean_shutdown_interval_mock_);
  }

  virtual void TearDown() {
    PersistentInteger::ClearCreationCallbackForTesting();
  }

  // Adds active use aggregation counters update expectations that a count no
  // larger than the specified upper bound will be added.
  void ExpectActiveUseUpdate(int upper_bound) {
    EXPECT_CALL(metrics_lib_, SendToUMA("Platform.UnaggregatedUsageTime",
                                        Le(upper_bound), 1, 360, 50));

    EXPECT_CALL(*daily_active_use_mock_, GetAndClear())
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*daily_active_use_mock_, Add(Le(upper_bound)))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_mock_, Add(Le(upper_bound)))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_mock_, Add(Le(upper_bound)))
        .Times(1)
        .RetiresOnSaturation();
  }

  // As above, but ignore values of counter updates.
  void IgnoreActiveUseUpdate() {
    EXPECT_CALL(*daily_active_use_mock_, Add(_)).Times(1).RetiresOnSaturation();
    EXPECT_CALL(*daily_active_use_mock_, GetAndClear())
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_mock_, Add(_))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_mock_, Add(_))
        .Times(1)
        .RetiresOnSaturation();
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectSample(const std::string& name, int sample) {
    EXPECT_CALL(metrics_lib_, SendToUMA(name, sample, _, _, _))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Creates a new DBus signal message with zero or more string arguments.
  // The message can be deallocated through DeleteDBusMessage.
  //
  // |path| is the object emitting the signal.
  // |interface| is the interface the signal is emitted from.
  // |name| is the name of the signal.
  // |arg_values| contains the values of the string arguments.
  DBusMessage* NewDBusSignalString(const string& path,
                                   const string& interface,
                                   const string& name,
                                   const vector<string>& arg_values) {
    DBusMessage* msg =
        dbus_message_new_signal(path.c_str(), interface.c_str(), name.c_str());
    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);
    for (vector<string>::const_iterator it = arg_values.begin();
         it != arg_values.end(); ++it) {
      const char* str_value = it->c_str();
      dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &str_value);
    }
    return msg;
  }

  // Deallocates the DBus message |msg| previously allocated through
  // dbus_message_new*.
  void DeleteDBusMessage(DBusMessage* msg) { dbus_message_unref(msg); }

  // Creates or overwrites an input file containing fake disk stats.
  void CreateFakeDiskStatsFile(const char* fake_stats) {
    EXPECT_TRUE(base::WriteFile(fake_disk_stats_, std::string(fake_stats)));
  }

  // Creates or overwrites the file in |path| so that it contains the printable
  // representation of |value|.
  void CreateUint64ValueFile(const base::FilePath& path, uint64_t value) {
    base::DeleteFile(path);
    std::string value_string = base::NumberToString(value) + "\n";
    ASSERT_EQ(value_string.length(), base::WriteFile(path, value_string.c_str(),
                                                     value_string.length()));
  }

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;
  // The system time just before the daemon was initialized.
  base::TimeTicks test_start_;
  // The temporary directory for backing files.
  base::ScopedTempDir persistent_integer_backing_dir_;
  // File paths.
  base::FilePath backing_dir_path_;
  base::FilePath fake_disk_stats_;
  base::FilePath fake_vm_stats_;
  base::FilePath fake_scaling_max_freq_;
  base::FilePath fake_cpuinfo_max_freq_;
  base::FilePath fake_metrics_file_;
  base::FilePath fake_mm_stat_file_;

  // Mocks. They are strict mock so that all unexpected
  // calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;
  // These are assigned into unique_ptrs owned by daemon_, so they don't leak.
  StrictMock<PersistentIntegerMock>* daily_active_use_mock_;
  StrictMock<PersistentIntegerMock>* kernel_crash_interval_mock_;
  StrictMock<PersistentIntegerMock>* user_crash_interval_mock_;
  StrictMock<PersistentIntegerMock>* unclean_shutdown_interval_mock_;
};

TEST_F(MetricsDaemonTest, CheckSystemCrash) {
  static const char kKernelCrashDetected[] = "test-kernel-crash-detected";
  base::FilePath kernel_crash_detected =
      backing_dir_path_.Append(kKernelCrashDetected);
  EXPECT_FALSE(daemon_.CheckSystemCrash(kernel_crash_detected.value()));

  base::WriteFile(kernel_crash_detected, "", 0);
  EXPECT_TRUE(base::PathExists(kernel_crash_detected));
  EXPECT_TRUE(daemon_.CheckSystemCrash(kernel_crash_detected.value()));
  EXPECT_FALSE(base::PathExists(kernel_crash_detected));
  EXPECT_FALSE(daemon_.CheckSystemCrash(kernel_crash_detected.value()));
  EXPECT_FALSE(base::PathExists(kernel_crash_detected));
}

TEST_F(MetricsDaemonTest, MessageFilter) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AnyNumber());

  DBusMessage* msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
  DBusHandlerResult res =
      MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);

  IgnoreActiveUseUpdate();
  EXPECT_CALL(*user_crash_interval_mock_, GetAndClear())
      .Times(1)
      .RetiresOnSaturation();

  vector<string> signal_args;
  msg = NewDBusSignalString("/", "org.chromium.CrashReporter", "UserCrash",
                            signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  signal_args.push_back("randomstate");
  signal_args.push_back("bob");  // arbitrary username
  msg = NewDBusSignalString("/", "org.chromium.UnknownService.Manager",
                            "StateChanged", signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ nullptr, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);
}

TEST_F(MetricsDaemonTest, SendSample) {
  ExpectSample("Dummy.Metric", 3);
  daemon_.SendSample("Dummy.Metric",
                     /* sample */ 3,
                     /* min */ 1,
                     /* max */ 100,
                     /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, ReportDiskStats) {
  uint64_t read_sectors_now, write_sectors_now;
  CreateFakeDiskStatsFile(kFakeDiskStats1.c_str());
  daemon_.DiskStatsReadStats(&read_sectors_now, &write_sectors_now);
  EXPECT_EQ(read_sectors_now, kFakeReadSectors[1]);
  EXPECT_EQ(write_sectors_now, kFakeWriteSectors[1]);

  MetricsDaemon::StatsState s_state = daemon_.stats_state_;
  EXPECT_CALL(
      metrics_lib_,
      SendToUMA(_, (kFakeReadSectors[1] - kFakeReadSectors[0]) / 30, _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (kFakeWriteSectors[1] - kFakeWriteSectors[0]) / 30,
                        _, _, _));
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, _, _));  // SendCpuThrottleMetrics
  daemon_.StatsCallback();
  EXPECT_TRUE(s_state != daemon_.stats_state_);
}

TEST_F(MetricsDaemonTest, ProcessMeminfo) {
  string meminfo =
      "MemTotal:        2000000 kB\nMemFree:          500000 kB\n"
      "Buffers:         1000000 kB\nCached:           213652 kB\n"
      "SwapCached:            0 kB\nActive:           133400 kB\n"
      "Inactive:         183396 kB\nActive(anon):      92984 kB\n"
      "Inactive(anon):    58860 kB\nActive(file):      40416 kB\n"
      "Inactive(file):   124536 kB\nUnevictable:           0 kB\n"
      "Mlocked:               0 kB\nSwapTotal:             0 kB\n"
      "SwapFree:              0 kB\nDirty:                40 kB\n"
      "Writeback:             0 kB\nAnonPages:         92652 kB\n"
      "Mapped:            59716 kB\nShmem:             59196 kB\n"
      "Slab:              16656 kB\nSReclaimable:       6132 kB\n"
      "SUnreclaim:        10524 kB\nKernelStack:        1648 kB\n"
      "PageTables:         2780 kB\nNFS_Unstable:          0 kB\n"
      "Bounce:                0 kB\nWritebackTmp:          0 kB\n"
      "CommitLimit:      970656 kB\nCommitted_AS:    1260528 kB\n"
      "VmallocTotal:     122880 kB\nVmallocUsed:       12144 kB\n"
      "VmallocChunk:     103824 kB\nDirectMap4k:        9636 kB\n"
      "DirectMap2M:     1955840 kB\n";

  // All enum calls must report percents.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, _, 100)).Times(AtLeast(1));
  // Check that MemFree is correctly computed at 25%.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMemFree", 25, 100))
      .Times(AtLeast(1));
  // Check that we call SendToUma at least once (log histogram).
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(1));
  // Make sure we don't report fields not in the list.
  EXPECT_CALL(metrics_lib_, SendToUMA("Platform.MeminfoMlocked", _, _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMlocked", _, _))
      .Times(0);
  // Check that the total memory is reported.
  EXPECT_CALL(metrics_lib_,
              SendToUMA("Platform.MeminfoMemTotal", 2000000, 1, _, 100));
  EXPECT_TRUE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ProcessMeminfo2) {
  string meminfo = "MemTotal:        2000000 kB\nMemFree:         1000000 kB\n";
  // Not enough fields.
  EXPECT_FALSE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ReadFreqToInt) {
  const int fake_scaled_freq = 1666999;
  const int fake_max_freq = 2000000;
  int scaled_freq = 0;
  int max_freq = 0;
  CreateUint64ValueFile(fake_scaling_max_freq_, fake_scaled_freq);
  CreateUint64ValueFile(fake_cpuinfo_max_freq_, fake_max_freq);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_TRUE(
      daemon_.ReadFreqToInt(fake_scaling_max_freq_.value(), &scaled_freq));
  EXPECT_TRUE(daemon_.ReadFreqToInt(fake_cpuinfo_max_freq_.value(), &max_freq));
  EXPECT_EQ(fake_scaled_freq, scaled_freq);
  EXPECT_EQ(fake_max_freq, max_freq);
}

TEST_F(MetricsDaemonTest, SendCpuThrottleMetrics) {
  CreateUint64ValueFile(fake_cpuinfo_max_freq_, 2001000);
  // Test the 101% and 100% cases.
  CreateUint64ValueFile(fake_scaling_max_freq_, 2001000);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 101, 101));
  daemon_.SendCpuThrottleMetrics();
  CreateUint64ValueFile(fake_scaling_max_freq_, 2000000);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 100, 101));
  daemon_.SendCpuThrottleMetrics();
}

TEST_F(MetricsDaemonTest, SendZramMetrics) {
  EXPECT_TRUE(daemon_.testing_);

  // |compr_data_size| is the size in bytes of compressed data.
  const uint64_t compr_data_size = 40 * 1000 * 1000;
  // The constant '3' is a realistic but random choice.
  // |orig_data_size| does not include zero pages.
  const uint64_t orig_data_size = compr_data_size * 3;
  const uint64_t page_size = 4096;
  const uint64_t zero_pages = 10 * 1000 * 1000 / page_size;
  std::string value_string = "120000000 40000000 0 0 0 2441 0";

  ASSERT_TRUE(base::WriteFile(fake_mm_stat_file_, value_string));

  const uint64_t real_orig_size = orig_data_size + zero_pages * page_size;
  const uint64_t zero_ratio_percent =
      zero_pages * page_size * 100 / real_orig_size;
  // Ratio samples are in percents.
  const uint64_t actual_ratio_sample = real_orig_size * 100 / compr_data_size;

  EXPECT_CALL(metrics_lib_, SendToUMA(_, compr_data_size >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (real_orig_size - compr_data_size) >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, actual_ratio_sample, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_pages, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_ratio_percent, _, _, _));

  EXPECT_TRUE(daemon_.ReportZram(backing_dir_path_));
}

TEST_F(MetricsDaemonTest, SendZramMetricsOld) {
  EXPECT_TRUE(daemon_.testing_);

  // |compr_data_size| is the size in bytes of compressed data.
  const uint64_t compr_data_size = 50 * 1000 * 1000;
  // The constant '3' is a realistic but random choice.
  // |orig_data_size| does not include zero pages.
  const uint64_t orig_data_size = compr_data_size * 3;
  const uint64_t page_size = 4096;
  const uint64_t zero_pages = 20 * 1000 * 1000 / page_size;

  CreateUint64ValueFile(
      backing_dir_path_.Append(MetricsDaemon::kComprDataSizeName),
      compr_data_size);
  CreateUint64ValueFile(
      backing_dir_path_.Append(MetricsDaemon::kOrigDataSizeName),
      orig_data_size);
  CreateUint64ValueFile(backing_dir_path_.Append(MetricsDaemon::kZeroPagesName),
                        zero_pages);

  const uint64_t real_orig_size = orig_data_size + zero_pages * page_size;
  const uint64_t zero_ratio_percent =
      zero_pages * page_size * 100 / real_orig_size;
  // Ratio samples are in percents.
  const uint64_t actual_ratio_sample = real_orig_size * 100 / compr_data_size;
  const char uma_incompressible[] = "Platform.ZramIncompressiblePages";

  EXPECT_CALL(metrics_lib_, SendToUMA(_, compr_data_size >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (real_orig_size - compr_data_size) >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, actual_ratio_sample, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_pages, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_ratio_percent, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(uma_incompressible, _, _, _, _)).Times(0);

  EXPECT_TRUE(daemon_.ReportZram(backing_dir_path_));
}

TEST_F(MetricsDaemonTest, SendZramMetricsWithIncompressiblePageStats) {
  EXPECT_TRUE(daemon_.testing_);

  // |compr_data_size| is the size in bytes of compressed data.
  const uint64_t compr_data_size = 60 * 1000 * 1000;
  // The constant '3' is a realistic but random choice.
  // |orig_data_size| does not include zero pages.
  const uint64_t orig_data_size = compr_data_size * 3;
  const uint64_t page_size = 4096;
  const uint64_t zero_pages = 30 * 1000 * 1000 / page_size;
  const uint64_t incompr_pages = 5 * 1000 * 1000 / page_size;
  std::string value_string = "180000000 60000000 0 0 0 7324 0 1220";

  ASSERT_TRUE(base::WriteFile(fake_mm_stat_file_, value_string));

  const uint64_t real_orig_size = orig_data_size + zero_pages * page_size;
  const uint64_t zero_ratio_percent =
      zero_pages * page_size * 100 / real_orig_size;
  // Ratio samples are in percents.
  const uint64_t actual_ratio_sample = real_orig_size * 100 / compr_data_size;
  const uint64_t incompr_pages_ratio_pre =
      incompr_pages * page_size * 100 / real_orig_size;
  const uint64_t incompr_pages_ratio_post =
      incompr_pages * page_size * 100 / compr_data_size;

  EXPECT_CALL(metrics_lib_, SendToUMA(_, compr_data_size >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (real_orig_size - compr_data_size) >> 20, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, actual_ratio_sample, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_pages, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, zero_ratio_percent, _, _, _));
  EXPECT_CALL(metrics_lib_, SendToUMA(_, incompr_pages, _, _, _));
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, incompr_pages_ratio_pre, _));
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, incompr_pages_ratio_post, _));

  EXPECT_TRUE(daemon_.ReportZram(backing_dir_path_));
}

TEST_F(MetricsDaemonTest, GetDetachableBaseTimes) {
  EXPECT_TRUE(daemon_.testing_);

  base::FilePath temp_dir;
  EXPECT_TRUE(base::CreateNewTempDirectory("", &temp_dir));

  base::FilePath hammer_sysfs_path = temp_dir.Append("hammer_sysfs_path");
  base::FilePath level_path =
      temp_dir.Append(MetricsDaemon::kDetachableBaseSysfsLevelName);
  base::FilePath active_time_path =
      temp_dir.Append(MetricsDaemon::kDetachableBaseSysfsActiveTimeName);
  base::FilePath suspended_time_path =
      temp_dir.Append(MetricsDaemon::kDetachableBaseSysfsSuspendedTimeName);

  // Assume all sysfs files are located within the same subdirectory.
  EXPECT_TRUE(CreateDirectory(level_path.DirName()));

  uint64_t active_time, suspended_time;

  EXPECT_FALSE(daemon_.GetDetachableBaseTimes(hammer_sysfs_path, &active_time,
                                              &suspended_time));

  EXPECT_TRUE(base::WriteFile(hammer_sysfs_path, temp_dir.value().c_str(),
                              temp_dir.value().length()));
  EXPECT_TRUE(
      base::WriteFile(level_path, MetricsDaemon::kDetachableBaseSysfsLevelValue,
                      strlen(MetricsDaemon::kDetachableBaseSysfsLevelValue)));

  EXPECT_FALSE(daemon_.GetDetachableBaseTimes(hammer_sysfs_path, &active_time,
                                              &suspended_time));

  CreateUint64ValueFile(active_time_path, 10);
  CreateUint64ValueFile(suspended_time_path, 20);

  EXPECT_TRUE(daemon_.GetDetachableBaseTimes(hammer_sysfs_path, &active_time,
                                             &suspended_time));
  EXPECT_EQ(active_time, 10);
  EXPECT_EQ(suspended_time, 20);
}

TEST_F(MetricsDaemonTest, UpdateUsageStats) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AnyNumber());

  // Add an arbitrary amount to the test start.
  constexpr base::TimeDelta elapsed_time = base::Seconds(42);
  base::TimeTicks end = test_start_ + elapsed_time;
  ASSERT_EQ(elapsed_time, (end - test_start_));

  ExpectActiveUseUpdate(elapsed_time.InSeconds());

  daemon_.UpdateStats(end, base::Time::Now());
}

TEST_F(MetricsDaemonTest, UpdateUsageStatsTooBig) {
  // Ignore most calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AnyNumber());

  // Add an arbitrary amount to the test start.
  const int elapsed_seconds = 1'000'000'000;
  base::TimeTicks end = test_start_ + base::Seconds(elapsed_seconds);

  EXPECT_CALL(metrics_lib_,
              SendToUMA("Platform.UnaggregatedUsageTime", _, _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_lib_,
              SendToUMA("Platform.UnaggregatedUsageTimeTooBig",
                        Le(elapsed_seconds), 7200, INT_MAX / 2, 50));

  // Allow these calls since we're using strict mocks
  EXPECT_CALL(*daily_active_use_mock_, GetAndClear()).Times(AnyNumber());
  EXPECT_CALL(*daily_active_use_mock_, Add(Le(elapsed_seconds)))
      .Times(AnyNumber());
  EXPECT_CALL(*kernel_crash_interval_mock_, Add(Le(elapsed_seconds)))
      .Times(AnyNumber());
  EXPECT_CALL(*user_crash_interval_mock_, Add(Le(elapsed_seconds)))
      .Times(AnyNumber());

  daemon_.UpdateStats(end, base::Time::Now());
}

TEST_F(MetricsDaemonTest, RoundsDailyUseIfJustOverOneDay) {
  // Should round down daily use within 5 minutes of 24 hours...
  const int kSecondsPerDay = 24 * 60 * 60;
  const int kFiveMinutes = 5 * 60;
  EXPECT_CALL(*daily_active_use_mock_, GetAndClear())
      .WillOnce(Return(kSecondsPerDay + kFiveMinutes));
  EXPECT_CALL(*daily_active_use_mock_, Add(kFiveMinutes)).Times(1);
  ExpectSample("Platform.DailyUseTime", kSecondsPerDay);
  daemon_.SendAndResetDailyUseSample();

  // ... but not round down daily use above that...
  EXPECT_CALL(*daily_active_use_mock_, GetAndClear())
      .WillOnce(Return(kSecondsPerDay + kFiveMinutes + 1));
  ExpectSample("Platform.DailyUseTime", kSecondsPerDay + kFiveMinutes + 1);
  daemon_.SendAndResetDailyUseSample();

  // .. and not change times below that.
  EXPECT_CALL(*daily_active_use_mock_, GetAndClear())
      .WillOnce(Return(kSecondsPerDay - 1));
  ExpectSample("Platform.DailyUseTime", kSecondsPerDay - 1);
  daemon_.SendAndResetDailyUseSample();
}

}  // namespace chromeos_metrics

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
