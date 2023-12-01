// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_VMLOG_WRITER_H_
#define METRICS_VMLOG_WRITER_H_

#include <fstream>
#include <istream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace chromeos_metrics {

// Record for retrieving and reporting values from /proc/vmstat
struct VmstatRecord {
  uint64_t page_faults_ = 0;       // major faults
  uint64_t file_page_faults_ = 0;  // major faults for file-backed pages
  uint64_t anon_page_faults_ = 0;  // major faults for anonymous pages
  uint64_t swap_in_ = 0;           // pages swapped in
  uint64_t swap_out_ = 0;          // pages swapped out
};

struct CpuTimeRecord {
  uint64_t non_idle_time_ = 0;
  uint64_t total_time_ = 0;
};

struct PowerDomain {
  base::FilePath file_path;
  std::string name;
  uint64_t max_energy;
  uint64_t energy_before;
  uint64_t energy_after;
  base::TimeTicks ticks_before;
  base::TimeTicks ticks_after;

  bool operator<(const PowerDomain& that) const {
    return file_path < that.file_path;
  }
};

// Parse cumulative vm statistics from data read from /proc/vmstat.  Returns
// true for success.
bool VmStatsParseStats(std::istream* input, struct VmstatRecord* record);

// Parse cpu time from /proc/stat. Returns true for success.
bool ParseCpuTime(std::istream* input, CpuTimeRecord* record);

// Parse online CPU IDs from /proc/cpuinfo. Returns a vector of CPU ID on
// success or std::nullopt on failure.
std::optional<std::vector<int>> GetOnlineCpus(std::istream& proc_cpuinfo);

// Encapsulates the access to GPU information.
class GpuInfo {
 public:
  enum class GpuType { kAmd, kIntel, kUnknown };

  virtual ~GpuInfo() = default;

  // Detect and get an instance of GpuInfo to access GPU information from the
  // system.
  static std::unique_ptr<GpuInfo> Get();

  // Read the GPU frequency.  Returns true on success or an expected failure.
  // @param out:  A stream to output the discovered frequency, in MHz.
  bool GetCurrentFrequency(std::ostream& out);

  bool is_unknown() { return gpu_type_ == GpuType::kUnknown; }

 protected:
  GpuInfo(std::unique_ptr<std::istream> gpu_freq_stream, GpuType gpu_type);
  GpuInfo(const GpuInfo&) = delete;
  GpuInfo& operator=(const GpuInfo&) = delete;

 private:
  std::unique_ptr<std::istream> gpu_freq_stream_;
  GpuType gpu_type_;
};

// Encapsulates access to Intel RAPL information.
// Running Average Power Limit. See:
// https://www.kernel.org/doc/Documentation/power/powercap/powercap.txt
class RAPLInfo {
 public:
  enum class CpuType { kIntel, kUnknown };
  virtual ~RAPLInfo() = default;

  // Detect and get an instance of RAPLInfo to access RAPL information from the
  // system.
  static std::unique_ptr<RAPLInfo> Get();

  // Read the RAPL state. Returns true on success or an expected failure.
  // @param out:  A stream to output the discovered values, in watts.
  bool GetCurrentPower(std::ostream& out);

  // Print element headers.
  bool GetHeader(std::ostream& header);

  bool is_unknown() { return cpu_type_ == CpuType::kUnknown; }

 private:
  RAPLInfo(std::unique_ptr<std::vector<PowerDomain>> rapl_domains,
           CpuType cpu_type);
  RAPLInfo(const RAPLInfo&) = delete;
  RAPLInfo& operator=(const RAPLInfo&) = delete;

  static bool ReadUint64File(const base::FilePath& path, uint64_t* value_out);

  std::unique_ptr<std::vector<PowerDomain>> power_domains_;
  CpuType cpu_type_;
};

// Encapsulates the logic for writing to vmlog and rotating log files when
// necessary.
class VmlogFile {
 public:
  // Creates a new VmlogFile to manage vmlog logging. Output is written to
  // live_path, and rotated to rotated_path when the file would exceed max_size.
  // Output files always begin with the contents of header.
  VmlogFile(const base::FilePath& live_path,
            const base::FilePath& rotated_path,
            const uint64_t max_size,
            const std::string& header);
  VmlogFile(const VmlogFile&) = delete;
  VmlogFile& operator=(const VmlogFile&) = delete;

  ~VmlogFile();

  // Writes the requested data to the vmlog log file. Returns false on failure.
  bool Write(const std::string& data);

 private:
  friend class VmlogWriterTest;
  FRIEND_TEST(VmlogWriterTest, WriteCallbackSuccess);

  base::FilePath live_path_;
  base::FilePath rotated_path_;
  uint64_t max_size_;
  std::string header_;
  uint64_t cur_size_ = 0;
  int fd_ = -1;
};

// Reads information from /proc/vmstat periodically and writes summary data to
// vmlog. VmlogWriter manages output file and symlink creation and automatically
// rotates the underlying files to keep data fresh while keeping a small disk
// footprint.
class VmlogWriter {
 public:
  VmlogWriter(const base::FilePath& vmlog_dir,
              const base::TimeDelta& log_interval);
  VmlogWriter(const VmlogWriter&) = delete;
  VmlogWriter& operator=(const VmlogWriter&) = delete;

  ~VmlogWriter();

 private:
  friend class VmlogWriterTest;
  FRIEND_TEST(VmlogWriterTest, WriteCallbackSuccess);

  // Called by the constructor to initialize internals. May schedule itself on
  // valid_time_delay_timer_ if system clock doesn't look correct.
  void Init(const base::FilePath& vmlog_dir,
            const base::TimeDelta& log_interval);

  // Invoked every log_interval by timer_, this callback parses the contents of
  // /proc/vmstat and writes results to vmlog_.
  void WriteCallback();

  // Calculate the difference of Vmstat between two consecutive calls to this
  // function.
  bool GetDeltaVmStat(VmstatRecord* delta_out);

  // Calculate the CPU usage (a percentage of total CPU used) during consecutive
  // calls to this function.
  bool GetCpuUsage(double* cpu_usage_out);

  // Read the CPU frequencies.  Returns true on success.
  bool GetCpuFrequencies(std::ostream& out);

  // Read the GPU frequency.  Returns true on success or an expected failure.
  bool GetGpuFrequency(std::ostream& out);

  // Read the RAPL power.  Returns true on success or an expected failure.
  bool GetRAPL(std::ostream& out);

  std::unique_ptr<VmlogFile> vmlog_;
  // Stream used to read content in /proc/vmstat.
  std::ifstream vmstat_stream_;
  // Stream used to read content in /proc/stat.
  std::ifstream proc_stat_stream_;
  // Record (partial) content read in from /proc/vmstat last time.
  VmstatRecord prev_vmstat_record_;
  // Record cpu stat info read in from /proc/stat last time.
  CpuTimeRecord prev_cputime_record_;

  // A set of open entries to sysfs for cpu frequency information.  Each one
  // contains a single integer, in kHz.
  std::vector<std::ifstream> cpufreq_streams_;

  // |gpu_info_| is used to read GPU frequency.
  std::unique_ptr<GpuInfo> gpu_info_;

  // |rapl_info_| is used to read power state.
  std::unique_ptr<RAPLInfo> rapl_info_;

  base::RepeatingTimer timer_;
  base::OneShotTimer valid_time_delay_timer_;
};

}  // namespace chromeos_metrics

#endif  // METRICS_VMLOG_WRITER_H_
