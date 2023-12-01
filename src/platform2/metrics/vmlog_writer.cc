// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/vmlog_writer.h"

#include <algorithm>
#include <fcntl.h>
#include <inttypes.h>
#include <optional>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/cpu.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <brillo/daemons/daemon.h>
#include <re2/re2.h>

namespace chromeos_metrics {
namespace {

constexpr char kVmlogHeader[] =
    "time pgmajfault pgmajfault_f pgmajfault_a pswpin pswpout cpuusage";

// We limit the size of vmlog log files to keep frequent logging from wasting
// disk space.
constexpr int kMaxVmlogFileSize = 256 * 1024;

}  // namespace

bool VmStatsParseStats(std::istream* input_stream,
                       struct VmstatRecord* record) {
  // a mapping of string name to field in VmstatRecord and whether we found it
  struct Mapping {
    const std::string name;
    uint64_t* value_p;
    bool found;
    bool optional;
  } map[] = {
      {.name = "pgmajfault",
       .value_p = &record->page_faults_,
       .found = false,
       .optional = false},
      // pgmajfault_f and pgmajfault_a may not be present in all kernels.
      // Don't fuss if they are not.
      {.name = "pgmajfault_f",
       .value_p = &record->file_page_faults_,
       .found = false,
       .optional = true},
      {.name = "pgmajfault_a",
       .value_p = &record->anon_page_faults_,
       .found = false,
       .optional = true},
      {.name = "pswpin",
       .value_p = &record->swap_in_,
       .found = false,
       .optional = false},
      {.name = "pswpout",
       .value_p = &record->swap_out_,
       .found = false,
       .optional = false},
  };

  // Each line in the file has the form
  // <ID> <VALUE>
  // for instance:
  // nr_free_pages 213427
  std::string line;
  while (std::getline(*input_stream, line)) {
    std::vector<std::string> tokens = base::SplitString(
        line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    if (tokens.size() != 2u) {
      LOG(WARNING) << "Unexpected vmstat format in line: " << line;
      continue;
    }
    for (auto& mapping : map) {
      if (!tokens[0].compare(mapping.name)) {
        if (!base::StringToUint64(tokens[1], mapping.value_p))
          return false;
        mapping.found = true;
      }
    }
  }
  // Make sure we got all the stats, except the optional ones.
  for (const auto& mapping : map) {
    if (!mapping.found) {
      if (mapping.optional) {
        *mapping.value_p = 0;
      } else {
        LOG(WARNING) << "vmstat missing " << mapping.name;
        return false;
      }
    }
  }
  return true;
}

bool ParseCpuTime(std::istream* input, CpuTimeRecord* record) {
  std::string buf;
  if (!std::getline(*input, buf)) {
    PLOG(ERROR) << "Unable to read cpu time";
    return false;
  }
  // Expect the first line to be like
  // cpu  20126642 15102603 12415348 2330408305 11759657 0 355204 0 0 0
  // The number corresponds to cpu time for
  // #cpu user nice system idle iowait irq softirq  steal guest guest_nice
  std::vector<std::string> tokens = base::SplitString(
      buf, " \t\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (tokens[0] != "cpu") {
    LOG(WARNING) << "Expect the first line of /proc/stat to be \"cpu ...\"";
    return false;
  }
  uint64_t value;
  for (int i = 1; i < tokens.size(); ++i) {
    if (!base::StringToUint64(tokens[i], &value)) {
      LOG(WARNING) << "Unable to convert " << tokens[i] << " to int64";
      return false;
    }
    record->total_time_ += value;
    // Exclude idle or iowait.
    if (i != 4 && i != 5) {
      record->non_idle_time_ += value;
    }
  }
  return true;
}

std::optional<std::vector<int>> GetOnlineCpus(std::istream& proc_cpuinfo) {
  if (!proc_cpuinfo) {
    return std::nullopt;
  }

  // Search for lines like "processor : 0" in /proc/cpuinfo and add the CPU ID
  // part to the result list.
  std::vector<int> cpus;
  for (std::string line; std::getline(proc_cpuinfo, line);) {
    auto tokens = base::SplitString(line, ":", base::TRIM_WHITESPACE,
                                    base::SPLIT_WANT_ALL);
    if (tokens.size() != 2) {
      continue;
    }

    if (tokens[0] != "processor") {
      continue;
    }

    int cpu = 0;
    if (base::StringToInt(tokens[1], &cpu)) {
      cpus.push_back(cpu);
    }
  }

  return cpus;
}

GpuInfo::GpuInfo(std::unique_ptr<std::istream> gpu_freq_stream,
                 GpuInfo::GpuType gpu_type)
    : gpu_freq_stream_(std::move(gpu_freq_stream)), gpu_type_(gpu_type) {}

std::unique_ptr<GpuInfo> GpuInfo::Get() {
  std::unique_ptr<std::ifstream> gpu_freq_stream =
      std::make_unique<std::ifstream>();

  // Intel GPU detection.
  static const char* intel_gpu_freq_stream =
      "/sys/kernel/debug/dri/0/i915_frequency_info";
  gpu_freq_stream->open(intel_gpu_freq_stream);
  // Derefence |gpu_freq_stream| to check whether the file opens successfully.
  if (*gpu_freq_stream) {
    return base::WrapUnique(
        new GpuInfo(std::move(gpu_freq_stream), GpuInfo::GpuType::kIntel));
  }

  // AMD GPU detection.
  static const char* amd_gpu_freq_stream =
      "/sys/class/drm/card0/device/pp_dpm_sclk";
  gpu_freq_stream->open(amd_gpu_freq_stream);
  // Derefence |gpu_freq_stream| to check whether the file opens successfully.
  if (*gpu_freq_stream) {
    return base::WrapUnique(
        new GpuInfo(std::move(gpu_freq_stream), GpuInfo::GpuType::kAmd));
  }

  // Unknown GPU: return a null object with |gpu_freq_stream| unopened.
  return base::WrapUnique(
      new GpuInfo(std::move(gpu_freq_stream), GpuInfo::GpuType::kUnknown));
}

bool GpuInfo::GetCurrentFrequency(std::ostream& out) {
  if (is_unknown()) {
    PLOG(ERROR) << "Unable to parse frequency from unknown GPU type";
    return false;
  }

  DCHECK(*gpu_freq_stream_);
  if (!gpu_freq_stream_->seekg(0, std::ios_base::beg)) {
    PLOG(ERROR) << "Unable to seek GPU frequency info file";
    return false;
  }

  static const char* amdgpu_sclk_expression = R"(^\d: (\d{2,4})Mhz \*$)";
  static const char* intelgpu_curr_freq_expression =
      R"(^Actual freq: (\d{2,4}) MHz$)";
  const RE2 gpu_freq_matcher(gpu_type_ == GpuType::kAmd
                                 ? amdgpu_sclk_expression
                                 : intelgpu_curr_freq_expression);

  std::string line;
  while (std::getline(*gpu_freq_stream_, line)) {
    std::string frequency_mhz;
    if (RE2::FullMatch(line, gpu_freq_matcher, &frequency_mhz)) {
      out << " " << frequency_mhz;
      return true;
    }
  }

  PLOG(ERROR) << "Unable to recognize GPU frequency";
  return false;
}

/* ********************** RAPL **************************** */

bool RAPLInfo::ReadUint64File(const base::FilePath& path, uint64_t* value_out) {
  DCHECK(value_out);

  std::string str;
  if (!base::ReadFileToString(path, &str)) {
    PLOG(ERROR) << "Unable to read from " << path.value();
    return false;
  }

  base::TrimWhitespaceASCII(str, base::TRIM_TRAILING, &str);
  if (!base::StringToUint64(str, value_out)) {
    PLOG(ERROR) << "Unable to parse \"" << str << "\" from " << path.value();
    return false;
  }
  return true;
}

RAPLInfo::RAPLInfo(std::unique_ptr<std::vector<PowerDomain>> power_domains,
                   RAPLInfo::CpuType cpu_type)
    : power_domains_(std::move(power_domains)), cpu_type_(cpu_type) {}

std::unique_ptr<RAPLInfo> RAPLInfo::Get() {
  // TODO(b/168594119) Restore RAPL once access can be made secure.
  PLOG(ERROR) << "RAPL info disabled (b/168594119).";
  return base::WrapUnique(new RAPLInfo(0, RAPLInfo::CpuType::kUnknown));
}

bool RAPLInfo::GetHeader(std::ostream& header) {
  if (is_unknown()) {
    PLOG(ERROR) << "Unable to parse RAPL from this CPU";
    return false;
  }

  // List out the text name of each power domain.
  for (const auto& domain : *power_domains_)
    header << " " << domain.name;

  return true;
}

// Get the power delta from the last reading and output it to the stream.
bool RAPLInfo::GetCurrentPower(std::ostream& out) {
  if (is_unknown()) {
    PLOG(ERROR) << "Unable to parse RAPL from this CPU";
    return false;
  }
  // Cap of a maximal reasonable power in Watts
  constexpr const double kMaxWatts = 1e3;

  for (auto& domain : *power_domains_) {
    ReadUint64File(domain.file_path, &(domain.energy_after));
    domain.ticks_after = base::TimeTicks::Now();
  }

  for (auto& domain : *power_domains_) {
    uint64_t energy_delta =
        (domain.energy_after >= domain.energy_before)
            ? domain.energy_after - domain.energy_before
            : domain.max_energy - domain.energy_before + domain.energy_after;

    const base::TimeDelta time_delta = domain.ticks_after - domain.ticks_before;

    double average_power = energy_delta / (time_delta.InSecondsF() * 1e6);

    // Skip enormous sample if the counter is reset during suspend-to-RAM
    if (average_power > kMaxWatts) {
      out << " skip";
      continue;
    }
    out << " " << std::setprecision(3) << std::fixed << average_power;
  }

  for (auto& domain : *power_domains_) {
    domain.energy_before = domain.energy_after;
    domain.ticks_before = domain.ticks_after;
  }

  return true;
}

VmlogFile::VmlogFile(const base::FilePath& live_path,
                     const base::FilePath& rotated_path,
                     const uint64_t max_size,
                     const std::string& header)
    : live_path_(live_path),
      rotated_path_(rotated_path),
      max_size_(max_size),
      header_(header) {
  fd_ = open(live_path_.value().c_str(), O_CREAT | O_RDWR | O_EXCL, 0644);
  if (fd_ != -1) {
    Write(header_);
  } else {
    PLOG(ERROR) << "Failed to open file: " << live_path_.value();
  }
}

VmlogFile::~VmlogFile() = default;

bool VmlogFile::Write(const std::string& data) {
  if (fd_ == -1)
    return false;

  if (cur_size_ + data.size() > max_size_) {
    if (!base::CopyFile(live_path_, rotated_path_)) {
      PLOG(ERROR) << "Could not copy vmlog to: " << rotated_path_.value();
    }
    base::FilePath rotated_path_dir = rotated_path_.DirName();
    base::FilePath rotated_symlink = rotated_path_dir.Append("vmlog.1.LATEST");
    if (!base::PathExists(rotated_symlink)) {
      if (!base::CreateSymbolicLink(rotated_path_, rotated_symlink)) {
        PLOG(ERROR) << "Unable to create symbolic link from "
                    << rotated_symlink.value() << " to "
                    << rotated_path_.value();
      }
    }

    if (HANDLE_EINTR(ftruncate(fd_, 0)) != 0) {
      PLOG(ERROR) << "Could not ftruncate() file";
      return false;
    }
    if (HANDLE_EINTR(lseek(fd_, 0, SEEK_SET)) != 0) {
      PLOG(ERROR) << "Could not lseek() file";
      return false;
    }
    cur_size_ = 0;
    if (!Write(header_)) {
      return false;
    }
  }

  if (!base::WriteFileDescriptor(fd_, data)) {
    return false;
  }
  cur_size_ += data.size();
  return true;
}

VmlogWriter::VmlogWriter(const base::FilePath& vmlog_dir,
                         const base::TimeDelta& log_interval) {
  if (!base::DirectoryExists(vmlog_dir)) {
    if (!base::CreateDirectory(vmlog_dir)) {
      PLOG(ERROR) << "Couldn't create " << vmlog_dir.value();
      return;
    }
  }
  if (!base::SetPosixFilePermissions(vmlog_dir, 0755)) {
    PLOG(ERROR) << "Couldn't set permissions for " << vmlog_dir.value();
  }
  Init(vmlog_dir, log_interval);
}

void VmlogWriter::Init(const base::FilePath& vmlog_dir,
                       const base::TimeDelta& log_interval) {
  base::Time now = base::Time::Now();

  // If the current time is within a day of the epoch, we probably don't have a
  // good time set for naming files. Wait 5 minutes.
  //
  // See crbug.com/724175 for details.
  if (now - base::Time::UnixEpoch() < base::Days(1)) {
    LOG(WARNING) << "Time seems incorrect, too close to epoch: " << now;
    valid_time_delay_timer_.Start(
        FROM_HERE, base::Minutes(5),
        base::BindOnce(&VmlogWriter::Init, base::Unretained(this), vmlog_dir,
                       log_interval));
    return;
  }

  base::FilePath vmlog_current_path =
      vmlog_dir.Append("vmlog." + brillo::GetTimeAsLogString(now));
  base::FilePath vmlog_rotated_path =
      vmlog_dir.Append("vmlog.1." + brillo::GetTimeAsLogString(now));

  brillo::UpdateLogSymlinks(vmlog_dir.Append("vmlog.LATEST"),
                            vmlog_dir.Append("vmlog.PREVIOUS"),
                            vmlog_current_path);

  base::DeleteFile(vmlog_dir.Append("vmlog.1.PREVIOUS"));
  if (base::PathExists(vmlog_dir.Append("vmlog.1.LATEST"))) {
    base::Move(vmlog_dir.Append("vmlog.1.LATEST"),
               vmlog_dir.Append("vmlog.1.PREVIOUS"));
  }

  vmstat_stream_.open("/proc/vmstat", std::ifstream::in);
  if (vmstat_stream_.fail()) {
    PLOG(ERROR) << "Couldn't open /proc/vmstat";
    return;
  }

  proc_stat_stream_.open("/proc/stat", std::ifstream::in);
  if (proc_stat_stream_.fail()) {
    PLOG(ERROR) << "Couldn't open /proc/stat";
    return;
  }

  if (!log_interval.is_zero()) {
    timer_.Start(FROM_HERE, log_interval, this, &VmlogWriter::WriteCallback);
  }

  // The IDs of online CPUs are not necessarily in the set of [0,
  // sysconf(_SC_NPROCESSORS_ONLN) - 1]. Query the system to get the set of
  // online CPUs.
  std::ifstream proc_cpuinfo("/proc/cpuinfo");
  auto online_cpus = GetOnlineCpus(proc_cpuinfo);
  if (!online_cpus.has_value() || online_cpus->size() == 0) {
    PLOG(WARNING) << "Failed to get the list of online CPUs.";

    // Failed to parse online CPUs - fallback use the set of [0, n_cpus).
    const int n_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    for (int cpu = 0; cpu != n_cpus; ++cpu) {
      online_cpus->emplace_back(cpu);
    }
  }

  for (auto cpu : *online_cpus) {
    std::ostringstream path;
    path << "/sys/devices/system/cpu/cpu" << cpu << "/cpufreq/scaling_cur_freq";
    std::ifstream cpufreq_stream(path.str());
    if (cpufreq_stream) {
      cpufreq_streams_.push_back(std::move(cpufreq_stream));
    } else {
      PLOG(WARNING) << "Failed to open scaling_cur_freq for logical core "
                    << cpu;
    }
  }

  // Detect and open GPU frequency info stream.
  gpu_info_ = GpuInfo::Get();
  DCHECK(gpu_info_.get());

  std::ostringstream header(kVmlogHeader, std::ios_base::ate);
  if (!gpu_info_->is_unknown())
    header << " gpufreq";

  for (int cpu = 0; cpu != cpufreq_streams_.size(); ++cpu) {
    header << " cpufreq" << cpu;
  }

  rapl_info_ = RAPLInfo::Get();
  DCHECK(rapl_info_.get());

  if (!rapl_info_->is_unknown())
    rapl_info_->GetHeader(header);

  header << "\n";

  vmlog_.reset(new VmlogFile(vmlog_current_path, vmlog_rotated_path,
                             kMaxVmlogFileSize, header.str()));
}

VmlogWriter::~VmlogWriter() = default;

bool VmlogWriter::GetCpuUsage(double* cpu_usage_out) {
  proc_stat_stream_.clear();
  if (!proc_stat_stream_.seekg(0, std::ios_base::beg)) {
    PLOG(ERROR) << "Unable to seekg() /proc/stat";
    return false;
  }
  CpuTimeRecord cur;
  ParseCpuTime(&proc_stat_stream_, &cur);
  if (cur.total_time_ == prev_cputime_record_.total_time_) {
    LOG(WARNING) << "Same total time for two consecutive calls to GetCpuUsage";
    return false;
  }
  *cpu_usage_out =
      (cur.non_idle_time_ - prev_cputime_record_.non_idle_time_) /
      static_cast<double>(cur.total_time_ - prev_cputime_record_.total_time_);
  prev_cputime_record_ = cur;
  return true;
}

bool VmlogWriter::GetDeltaVmStat(VmstatRecord* delta_out) {
  // Reset the Vmstat stream.
  vmstat_stream_.clear();
  if (!vmstat_stream_.seekg(0, std::ios_base::beg)) {
    PLOG(ERROR) << "Unable to seekg() /proc/vmstat";
    return false;
  }

  // Get current Vmstat.
  VmstatRecord r;
  if (!VmStatsParseStats(&vmstat_stream_, &r)) {
    LOG(ERROR) << "Unable to parse vmstat data";
    return false;
  }

  delta_out->page_faults_ = r.page_faults_ - prev_vmstat_record_.page_faults_;
  delta_out->file_page_faults_ =
      r.file_page_faults_ - prev_vmstat_record_.file_page_faults_;
  delta_out->anon_page_faults_ =
      r.anon_page_faults_ - prev_vmstat_record_.anon_page_faults_;
  delta_out->swap_in_ = r.swap_in_ - prev_vmstat_record_.swap_in_;
  delta_out->swap_out_ = r.swap_out_ - prev_vmstat_record_.swap_out_;
  prev_vmstat_record_ = r;
  return true;
}

bool VmlogWriter::GetRAPL(std::ostream& out) {
  if (rapl_info_->is_unknown()) {
    // Nothing to do if the sysfs entry is not present.
    return true;
  }

  return rapl_info_->GetCurrentPower(out);
}

bool VmlogWriter::GetGpuFrequency(std::ostream& out) {
  if (gpu_info_->is_unknown()) {
    // Nothing to do if the sysfs entry is not present.
    return true;
  }

  return gpu_info_->GetCurrentFrequency(out);
}

bool VmlogWriter::GetCpuFrequencies(std::ostream& out) {
  for (std::ifstream& cpufreq_stream : cpufreq_streams_) {
    if (!cpufreq_stream.seekg(0, std::ios_base::beg)) {
      PLOG(ERROR) << "Unable to seek scaling_cur_freq";
      return false;
    }

    std::string result;
    cpufreq_stream >> result;
    out << " " << result;
  }
  return true;
}

void VmlogWriter::WriteCallback() {
  VmstatRecord delta_vmstat;
  double cpu_usage;
  if (!GetDeltaVmStat(&delta_vmstat) || !GetCpuUsage(&cpu_usage)) {
    LOG(ERROR) << "Stop timer because of error reading system info";
    timer_.Stop();
    return;
  }

  timeval tv;
  gettimeofday(&tv, nullptr);
  struct tm tm_time;
  localtime_r(&tv.tv_sec, &tm_time);
  std::ostringstream out_line;
  out_line << base::StringPrintf(
      "[%02d%02d/%02d%02d%02d]"
      " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %.2f",
      tm_time.tm_mon + 1, tm_time.tm_mday,              //
      tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec,  //
      delta_vmstat.page_faults_, delta_vmstat.file_page_faults_,
      delta_vmstat.anon_page_faults_, delta_vmstat.swap_in_,
      delta_vmstat.swap_out_, cpu_usage);

  if (!GetGpuFrequency(out_line) || !GetCpuFrequencies(out_line) ||
      !GetRAPL(out_line)) {
    LOG(ERROR) << "Stop timer because of error reading system info";
    timer_.Stop();
  }
  out_line << "\n";

  if (!vmlog_->Write(out_line.str())) {
    LOG(ERROR) << "Writing to vmlog failed.";
    timer_.Stop();
    return;
  }
}

}  // namespace chromeos_metrics
