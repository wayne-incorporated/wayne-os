// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vm_util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

#include <absl/strings/str_split.h>
#include <base/base64.h>
#include <base/containers/cxx20_erase.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/format_macros.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/safe_sprintf.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <brillo/files/file_util.h>
#include <brillo/process/process.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <vm_applications/apps.pb.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/concierge/crosvm_control.h"

namespace vm_tools::concierge {

const char kCrosvmBin[] = "/usr/bin/crosvm";

namespace {

constexpr char kFontsSharedDir[] = "/usr/share/fonts";
constexpr char kFontsSharedDirTag[] = "fonts";

// The maximum of CPU capacity is defined in include/linux/sched.h as
// SCHED_CAPACITY_SCALE. That is "1 << 10".
constexpr int kMaxCapacity = 1024;

constexpr char kUringAsyncExecutorString[] = "uring";
constexpr char kEpollAsyncExecutorString[] = "epoll";

constexpr char kSchedulerTunePath[] = "/scheduler-tune";
constexpr char kBoostTopAppProperty[] = "boost-top-app";
constexpr char kBoostArcVmProperty[] = "boost-arcvm";

std::string BooleanParameter(const char* parameter, bool value) {
  std::string result = base::StrCat({parameter, value ? "true" : "false"});
  return result;
}

}  // namespace

std::optional<AsyncExecutor> StringToAsyncExecutor(
    const std::string& async_executor) {
  if (async_executor == kUringAsyncExecutorString) {
    return std::optional{AsyncExecutor::kUring};
  } else if (async_executor == kEpollAsyncExecutorString) {
    return std::optional{AsyncExecutor::kEpoll};
  } else {
    LOG(ERROR) << "Failed to convert unknown string to AsyncExecutor"
               << async_executor;
    return std::nullopt;
  }
}

std::string AsyncExecutorToString(AsyncExecutor async_executor) {
  switch (async_executor) {
    case AsyncExecutor::kUring:
      return kUringAsyncExecutorString;
    case AsyncExecutor::kEpoll:
      return kEpollAsyncExecutorString;
  }
}

base::StringPairs Disk::GetCrosvmArgs() const {
  std::string first;
  if (writable)
    first = "--rwdisk";
  else
    first = "--disk";

  std::string sparse_arg;
  if (sparse) {
    sparse_arg = BooleanParameter(",sparse=", sparse.value());
  }
  std::string o_direct_arg;
  if (o_direct) {
    o_direct_arg = BooleanParameter(",o_direct=", o_direct.value());
  }
  std::string multiple_workers_arg;
  if (multiple_workers) {
    multiple_workers_arg =
        BooleanParameter(",multiple-workers=", multiple_workers.value());
  }
  std::string block_size_arg;
  if (block_size) {
    block_size_arg =
        base::StringPrintf(",block_size=%" PRIuS, block_size.value());
  }
  std::string async_executor_arg;
  if (async_executor) {
    async_executor_arg = base::StrCat(
        {",async_executor=", AsyncExecutorToString(async_executor.value())});
  }
  std::string block_id_arg;
  if (block_id) {
    // Virtio_blk can't handle more than 20 chars:
    // https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-2850006
    CHECK_LE(block_id.value().size(), 20);
    block_id_arg = base::StrCat({",id=", block_id.value()});
  }

  std::string second = base::StrCat({path.value(), sparse_arg, o_direct_arg,
                                     multiple_workers_arg, block_size_arg,
                                     async_executor_arg, block_id_arg});
  base::StringPairs result = {{std::move(first), std::move(second)}};
  return result;
}

int64_t GetVmMemoryMiB() {
  int64_t sys_memory_mb = base::SysInfo::AmountOfPhysicalMemoryMB();
  int64_t vm_memory_mb;
  if (sys_memory_mb >= 4096) {
    // On devices with >=4GB RAM, reserve 1GB for other processes.
    vm_memory_mb = sys_memory_mb - kHostReservedNumMiB;
  } else {
    vm_memory_mb = sys_memory_mb / 4 * 3;
  }

  // Limit guest memory size to avoid running out of host process address space.
  //
  // A 32-bit process has 4GB address space, and some parts are not usable for
  // various reasons including address space layout randomization (ASLR).
  // In 32-bit crosvm address space, only ~3370MB is usable:
  // - 256MB is not usable because of executable load bias ASLR.
  // - 4MB is used for crosvm executable.
  // - 32MB it not usable because of heap ASLR.
  // - 16MB is used for mapped shared libraries.
  // - 256MB is not usable because of mmap base address ASLR.
  // - 132MB is used for gaps in the memory layout.
  // - 30MB is used for other allocations.
  //
  // 3328 is chosen because it's a rounded number (i.e. 3328 % 256 == 0).
  // TODO(hashimoto): Remove this once crosvm becomes 64-bit on ARM.
  constexpr int64_t k32bitVmMemoryMaxMb = 3328;
  if (sizeof(uintptr_t) == 4) {
    vm_memory_mb = std::min(vm_memory_mb, k32bitVmMemoryMaxMb);
  }

  return vm_memory_mb;
}

std::optional<int32_t> ReadFileToInt32(const base::FilePath& filename) {
  std::string str;
  int int_val;
  if (base::ReadFileToString(filename, &str) &&
      base::StringToInt(
          base::TrimWhitespaceASCII(str, base::TrimPositions::TRIM_TRAILING),
          &int_val)) {
    return std::optional<int32_t>(int_val);
  }

  return std::nullopt;
}

std::optional<int32_t> GetCpuPackageId(int32_t cpu) {
  base::FilePath topology_path(base::StringPrintf(
      "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu));
  return ReadFileToInt32(topology_path);
}

std::optional<int32_t> GetCpuCapacity(int32_t cpu) {
  base::FilePath cpu_capacity_path(
      base::StringPrintf("/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu));
  return ReadFileToInt32(cpu_capacity_path);
}

std::optional<int32_t> GetCpuMaxFrequency(int32_t cpu) {
  base::FilePath cpu_max_freq_path(base::StringPrintf(
      "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu));
  return ReadFileToInt32(cpu_max_freq_path);
}

std::optional<std::string> GetCpuAffinityFromClusters(
    const std::vector<std::vector<std::string>>& cpu_clusters,
    const std::map<int32_t, std::vector<std::string>>& cpu_capacity_groups) {
  if (cpu_clusters.size() > 1) {
    // If more than one CPU cluster exists, generate CPU affinity groups based
    // on clusters. Each CPU from a given cluster will be pinned to the full
    // set of cores of that cluster, allowing some scheduling flexibility
    // while still ensuring vCPUs can only run on physical cores from the same
    // package.
    std::vector<std::string> cpu_affinities;
    for (const auto& cluster : cpu_clusters) {
      auto cpu_list = base::JoinString(cluster, ",");
      for (const auto& cpu : cluster) {
        cpu_affinities.push_back(
            base::StringPrintf("%s=%s", cpu.c_str(), cpu_list.c_str()));
      }
    }
    return base::JoinString(cpu_affinities, ":");
  } else if (cpu_capacity_groups.size() > 1) {
    // If only one cluster exists, group CPUs by capacity if there are at least
    // two distinct CPU capacity groups.
    std::vector<std::string> cpu_affinities;
    for (const auto& group : cpu_capacity_groups) {
      auto cpu_list = base::JoinString(group.second, ",");
      for (const auto& cpu : group.second) {
        cpu_affinities.push_back(
            base::StringPrintf("%s=%s", cpu.c_str(), cpu_list.c_str()));
      }
    }
    return base::JoinString(cpu_affinities, ":");
  } else {
    return std::nullopt;
  }
}

bool SetUpCrosvmProcess(const base::FilePath& cpu_cgroup) {
  // Note: This function is meant to be called after forking a process for
  // crosvm but before execve(). Since Concierge is multi-threaded, this
  // function should not call any functions that are not async signal safe
  // (see man signal-safety). Especially, don't call malloc/new or any functions
  // or constructors that may allocate heap memory. Calling malloc/new may
  // result in a dead-lock trying to lock a mutex that has already been locked
  // by one of the parent's threads.

  // Set up CPU cgroup. Note that FilePath::value() returns a const reference
  // to std::string without allocating a new object. c_str() doesn't do any copy
  // as long as we use C++11 or later.
  const int fd =
      HANDLE_EINTR(open(cpu_cgroup.value().c_str(), O_WRONLY | O_CLOEXEC));
  if (fd < 0) {
    // TODO(yusukes): Do logging here in an async safe way.
    return false;
  }

  char pid_str[32];
  const size_t len = base::strings::SafeSPrintf(pid_str, "%d", getpid());
  const ssize_t written = HANDLE_EINTR(write(fd, pid_str, len));
  close(fd);
  if (written != len) {
    // TODO(yusukes): Do logging here in an async safe way.
    return false;
  }

  // Set up process group ID.
  return SetPgid();
}

bool SetPgid() {
  // Note: This should only call async-signal-safe functions. Don't call
  // malloc/new. See SetUpCrosvmProcess() for more details.

  if (setpgid(0, 0) != 0) {
    // TODO(yusukes): Do logging here in an async safe way.
    return false;
  }

  return true;
}

bool WaitForChild(pid_t child, base::TimeDelta timeout) {
  const base::Time deadline = base::Time::Now() + timeout;
  while (true) {
    pid_t ret = waitpid(child, nullptr, WNOHANG);
    if (ret == child || (ret < 0 && errno == ECHILD)) {
      // Either the child exited or it doesn't exist anymore.
      return true;
    }

    // ret == 0 means that the child is still alive
    if (ret < 0) {
      PLOG(ERROR) << "Failed to wait for child process";
      return false;
    }

    base::Time now = base::Time::Now();
    if (deadline <= now) {
      // Timed out.
      return false;
    }
    usleep(100);
  }
}

bool CheckProcessExists(pid_t pid) {
  if (pid == 0)
    return false;

  // Try to reap child process in case it just exited.
  waitpid(pid, NULL, WNOHANG);

  // kill() with a signal value of 0 is explicitly documented as a way to
  // check for the existence of a process.
  return kill(pid, 0) >= 0 || errno != ESRCH;
}

std::optional<BalloonStats> GetBalloonStats(std::string socket_path) {
  BalloonStats stats;
  if (!CrosvmControl::Get()->BalloonStats(socket_path.c_str(), &stats.stats_ffi,
                                          &stats.balloon_actual)) {
    LOG(ERROR) << "Failed to retrieve balloon stats";
    return std::nullopt;
  }

  return stats;
}

std::optional<BalloonStats> ParseBalloonStats(
    const base::Value::Dict& balloon_stats) {
  auto additional_stats = balloon_stats.FindDict("stats");
  if (!additional_stats) {
    LOG(ERROR) << "stats dict not found";
    return std::nullopt;
  }

  BalloonStats stats;
  // Using FindDouble here since the value may exceeds 32bit integer range.
  // This is safe since double has 52bits of integer precision.
  stats.balloon_actual = static_cast<int64_t>(
      balloon_stats.FindDouble("balloon_actual").value_or(0));

  stats.stats_ffi.available_memory = static_cast<int64_t>(
      additional_stats->FindDouble("available_memory").value_or(0));
  stats.stats_ffi.disk_caches = static_cast<int64_t>(
      additional_stats->FindDouble("disk_caches").value_or(0));
  stats.stats_ffi.free_memory = static_cast<int64_t>(
      additional_stats->FindDouble("free_memory").value_or(0));
  stats.stats_ffi.major_faults = static_cast<int64_t>(
      additional_stats->FindDouble("major_faults").value_or(0));
  stats.stats_ffi.minor_faults = static_cast<int64_t>(
      additional_stats->FindDouble("minor_faults").value_or(0));
  stats.stats_ffi.swap_in =
      static_cast<int64_t>(additional_stats->FindDouble("swap_in").value_or(0));
  stats.stats_ffi.swap_out = static_cast<int64_t>(
      additional_stats->FindDouble("swap_out").value_or(0));
  stats.stats_ffi.total_memory = static_cast<int64_t>(
      additional_stats->FindDouble("total_memory").value_or(0));
  stats.stats_ffi.shared_memory = static_cast<int64_t>(
      additional_stats->FindDouble("shared_memory").value_or(0));
  stats.stats_ffi.unevictable_memory = static_cast<int64_t>(
      additional_stats->FindDouble("unevictable_memory").value_or(0));
  return stats;
}

bool AttachUsbDevice(std::string socket_path,
                     uint8_t bus,
                     uint8_t addr,
                     uint16_t vid,
                     uint16_t pid,
                     int fd,
                     uint8_t* out_port) {
  std::string device_path = "/proc/self/fd/" + std::to_string(fd);

  fcntl(fd, F_SETFD, 0);  // Remove the CLOEXEC

  return CrosvmControl::Get()->UsbAttach(socket_path.c_str(), bus, addr, vid,
                                         pid, device_path.c_str(), out_port);
}

bool DetachUsbDevice(std::string socket_path, uint8_t port) {
  return CrosvmControl::Get()->UsbDetach(socket_path.c_str(), port);
}

bool ListUsbDevice(std::string socket_path,
                   std::vector<UsbDeviceEntry>* device) {
  // Allocate enough slots for the max number of USB devices
  // This will never be more than 255
  const size_t max_usb_devices = CrosvmControl::Get()->MaxUsbDevices();
  device->resize(max_usb_devices);

  ssize_t dev_count = CrosvmControl::Get()->UsbList(
      socket_path.c_str(), device->data(), max_usb_devices);

  if (dev_count < 0) {
    return false;
  }

  device->resize(dev_count);

  return true;
}

bool CrosvmDiskResize(std::string socket_path,
                      int disk_index,
                      uint64_t new_size) {
  return CrosvmControl::Get()->ResizeDisk(socket_path.c_str(), disk_index,
                                          new_size);
}

bool UpdateCpuShares(const base::FilePath& cpu_cgroup, int cpu_shares) {
  const std::string cpu_shares_str = std::to_string(cpu_shares);
  if (base::WriteFile(cpu_cgroup.Append("cpu.shares"), cpu_shares_str.c_str(),
                      cpu_shares_str.size()) != cpu_shares_str.size()) {
    PLOG(ERROR) << "Failed to update " << cpu_cgroup.value() << " to "
                << cpu_shares;
    return false;
  }
  return true;
}

// This will limit the tasks in the CGroup to P @percent of CPU.
// Although P can be > 100, its maximum value depends on the number of CPUs.
// For now, limit to a certain percent of 1 CPU. @percent=-1 disables quota.
bool UpdateCpuQuota(const base::FilePath& cpu_cgroup, int percent) {
  LOG_ASSERT(percent <= 100 && (percent >= 0 || percent == -1));

  // Set period to 100000us and quota to percent * 1000us.
  const std::string cpu_period_str = std::to_string(100000);
  const base::FilePath cfs_period_us = cpu_cgroup.Append("cpu.cfs_period_us");
  if (base::WriteFile(cfs_period_us, cpu_period_str.c_str(),
                      cpu_period_str.size()) != cpu_period_str.size()) {
    PLOG(ERROR) << "Failed to update " << cfs_period_us.value() << " to "
                << cpu_period_str;
    return false;
  }

  int quota_int;
  if (percent == -1)
    quota_int = -1;
  else
    quota_int = percent * 1000;

  const std::string cpu_quota_str = std::to_string(quota_int);
  const base::FilePath cfs_quota_us = cpu_cgroup.Append("cpu.cfs_quota_us");
  if (base::WriteFile(cfs_quota_us, cpu_quota_str.c_str(),
                      cpu_quota_str.size()) != cpu_quota_str.size()) {
    PLOG(ERROR) << "Failed to update " << cfs_quota_us.value() << " to "
                << cpu_quota_str;
    return false;
  }

  return true;
}

bool UpdateCpuLatencySensitive(const base::FilePath& cpu_cgroup, bool enable) {
  std::string enable_str = std::to_string(static_cast<int>(enable));
  auto latency_sensitive = cpu_cgroup.Append("cpu.uclamp.latency_sensitive");
  if (base::WriteFile(latency_sensitive, enable_str.c_str(),
                      enable_str.size()) != enable_str.size()) {
    PLOG(ERROR) << "Failed to update " << latency_sensitive.value() << " to "
                << enable_str;
    return false;
  }
  return true;
}

bool UpdateCpuUclampMin(const base::FilePath& cpu_cgroup, double percent) {
  LOG_ASSERT(percent <= 100.0 && percent >= 0.0);

  std::string uclamp_min_str = std::to_string(percent);
  auto uclamp_min = cpu_cgroup.Append("cpu.uclamp.min");
  if (base::WriteFile(uclamp_min, uclamp_min_str.c_str(),
                      uclamp_min_str.size()) != uclamp_min_str.size()) {
    PLOG(ERROR) << "Failed to update " << uclamp_min.value() << " to "
                << uclamp_min_str;
    return false;
  }
  return true;
}

// Convert file path into fd path
// This will open the file and append SafeFD into provided container
std::string ConvertToFdBasedPath(brillo::SafeFD& parent_fd,
                                 base::FilePath* in_out_path,
                                 int flags,
                                 std::vector<brillo::SafeFD>& fd_storage) {
  static auto procSelfFd = base::FilePath("/proc/self/fd");
  if (procSelfFd.IsParent(*in_out_path)) {
    if (!base::PathExists(*in_out_path)) {
      return "Path does not exist";
    }
  } else {
    auto disk_fd = parent_fd.OpenExistingFile(*in_out_path, flags);
    if (brillo::SafeFD::IsError(disk_fd.second)) {
      LOG(ERROR) << "Could not open file: " << static_cast<int>(disk_fd.second);
      return "Could not open file";
    }
    *in_out_path = base::FilePath(kProcFileDescriptorsPath)
                       .Append(base::NumberToString(disk_fd.first.get()));
    fd_storage.push_back(std::move(disk_fd.first));
  }

  return "";
}

CustomParametersForDev::CustomParametersForDev(const std::string& data) {
  std::vector<base::StringPiece> lines = base::SplitStringPiece(
      data, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  for (auto& line : lines) {
    if (line.empty() || line[0] == '#')
      continue;

    // Split line with first = sign. --key=value and KEY=VALUE parameters both
    // use = to split. value will be an empty string in case of '--key'.
    std::pair<std::string_view, std::string_view> param_pair =
        absl::StrSplit(std::string_view(line), absl::MaxSplits('=', 1));
    base::StringPiece key =
        base::TrimWhitespaceASCII(param_pair.first, base::TRIM_ALL);
    base::StringPiece value =
        base::TrimWhitespaceASCII(param_pair.second, base::TRIM_ALL);

    switch (line[0]) {
      case '!':
        // Line contains a prefix key. Remove all args with this prefix.
        prefix_to_remove_.emplace_back(line.substr(1));
        break;
      case '^':
        // Parameter to be prepended before run, expected to be ^--key=value
        // format.
        params_to_prepend_.emplace_back(key.substr(1), std::move(value));
        break;
      case '-':
        // Parameter expected to be --key=value format.
        params_to_add_.emplace_back(std::move(key), std::move(value));
        break;
      default:
        // KEY=VALUE pair.
        special_parameters_.emplace(std::move(key), std::move(value));
        break;
    }
  }
  initialized_ = true;
}

void CustomParametersForDev::Apply(base::StringPairs* args) {
  if (!initialized_)
    return;
  for (const auto& prefix : prefix_to_remove_) {
    base::EraseIf(*args, [&prefix](const auto& pair) {
      return base::StartsWith(pair.first, prefix);
    });
  }
  for (const auto& param : params_to_prepend_) {
    args->emplace(args->begin(), param.first, param.second);
  }
  for (const auto& param : params_to_add_) {
    args->emplace_back(param.first, param.second);
  }
}

std::optional<const std::string> CustomParametersForDev::ObtainSpecialParameter(
    const std::string& key) {
  if (!initialized_)
    return std::nullopt;
  if (special_parameters_.find(key) != special_parameters_.end()) {
    return special_parameters_[key];
  } else {
    return std::nullopt;
  }
}

std::string SharedDataParam::to_string() const {
  // TODO(b/169446394): Go back to using "never" when caching is disabled
  // once we can switch /data/media to use 9p.

  // We can relax this condition later if we want to serve users which do not
  // set uid_map and gid_map, but today there is none.
  CHECK_NE(uid_map, "");
  CHECK_NE(gid_map, "");

  std::string result = base::StrCat(
      {data_dir.value(), ":", tag, ":type=fs:cache=",
       (enable_caches == SharedDataParam::Cache::kAlways)  ? "always"
       : (enable_caches == SharedDataParam::Cache::kNever) ? "never"
                                                           : "auto",
       ":uidmap=", uid_map, ":gidmap=", gid_map, ":timeout=",
       (enable_caches == SharedDataParam::Cache::kAlways) ? "3600" : "1",
       ":rewrite-security-xattrs=", rewrite_security_xattrs ? "true" : "false",
       ascii_casefold ? ":ascii_casefold=true" : "", ":writeback=",
       (enable_caches == SharedDataParam::Cache::kAlways) ? "true" : "false",
       posix_acl ? "" : ":posix_acl=false"});

  if (!privileged_quota_uids.empty()) {
    result += ":privileged_quota_uids=";
    for (size_t i = 0; i < privileged_quota_uids.size(); ++i) {
      if (i != 0)
        result += ' ';
      result += base::NumberToString(privileged_quota_uids[i]);
    }
  }
  return result;
}

SharedDataParam CreateFontsSharedDataParam() {
  return SharedDataParam{.data_dir = base::FilePath(kFontsSharedDir),
                         .tag = kFontsSharedDirTag,
                         .uid_map = kAndroidUidMap,
                         .gid_map = kAndroidGidMap,
                         .enable_caches = SharedDataParam::Cache::kAlways,
                         .ascii_casefold = false,
                         .posix_acl = true};
}

void ArcVmCPUTopology::CreateAffinity(void) {
  std::vector<std::string> cpu_list;
  std::vector<std::string> affinities;

  // Create capacity mask.
  int min_cap = -1;
  int max_cap = -1;
  int last_non_rt_cpu = -1;
  for (const auto& cap : capacity_) {
    for (const auto cpu : cap.second) {
      if (cap.first)
        cpu_list.push_back(base::StringPrintf("%d=%d", cpu, cap.first));
      // last_non_rt_cpu should be the last cpu with a lowest capacity.
      if (min_cap == -1 || min_cap >= cap.first) {
        min_cap = cap.first;
        last_non_rt_cpu = cpu;
      }
      max_cap = std::max(max_cap, static_cast<int>(cap.first));
    }
  }
  // Add RT VCPUs with a lowest capacity.
  if (min_cap) {
    for (int i = 0; i < num_rt_cpus_; i++) {
      cpu_list.push_back(base::StringPrintf("%d=%d", num_cpus_ + i, min_cap));
    }
    capacity_mask_ = base::JoinString(cpu_list, ",");
    cpu_list.clear();
  }
  // If there are heterogeneous cores, calculate uclamp.min value.
  if (min_cap != max_cap) {
    // Calculate a better uclamp.min for Android top-app tasks so that
    // those tasks will NOT be scheduled on the LITTLE cores.
    // If ARCVM kernel boots with different capacity CPUs, it enables Capacity
    // Aware Scheduler (CAS) which schedules the tasks to a CPU comparing with
    // its capacity and the task's expected CPU utilization.
    // Since the uclamp.min boosts up the minimum expected utilization to the
    // given percentage of maximum capacity, if that is bigger than the LITTLE
    // core capacity, CAS will schedule it on big core.
    // Thus its value must be *slightly* bigger than LITTLE core capacity.
    // Because of this reason, this adds 5% more than the LITTLE core capacity
    // rate. Note that the uclamp value must be a percentage of the maximum
    // capacity (~= utilization).
    top_app_uclamp_min_ = std::min(min_cap * 100 / kMaxCapacity + 5, 100);
  }
  // Allow boards to override the top_app_uclamp_min by scheduler-tune/
  // boost-top-app.
  brillo::CrosConfig cros_config;
  std::string boost;
  if (cros_config.GetString(kSchedulerTunePath, kBoostTopAppProperty, &boost)) {
    int uclamp_min;
    if (base::StringToInt(boost, &uclamp_min))
      top_app_uclamp_min_ = uclamp_min;
    else
      LOG(WARNING) << "Failed to convert value of " << kSchedulerTunePath << "/"
                   << kBoostTopAppProperty << " to number";
  }

  // The board may request to boost the whole ARCVM globally, in order to reduce
  // the latency and improve general experience of the ARCVM, especially on the
  // little.BIG CPU architecture.
  // If the global boost wasn't defined, it won't be used at all. b/217825939
  global_vm_boost_ = 0.0;
  if (cros_config.GetString(kSchedulerTunePath, kBoostArcVmProperty, &boost)) {
    double boost_factor;
    if (base::StringToDouble(boost, &boost_factor)) {
      int32_t little_max_freq = std::numeric_limits<int32_t>::max();
      int32_t big_max_freq = 0;

      // The global boost factor is defined as:
      // max_freq(little_core) / max_freq(big_core) * boost_factor
      for (int32_t cpu = 0; cpu < num_cpus_; cpu++) {
        auto max_freq = GetCpuMaxFrequency(cpu);
        if (max_freq) {
          little_max_freq = std::min(little_max_freq, *max_freq);
          big_max_freq = std::max(big_max_freq, *max_freq);
        }
      }

      if (little_max_freq <= big_max_freq && little_max_freq != 0 &&
          big_max_freq != 0) {
        double freq_ratio = static_cast<double>(little_max_freq) / big_max_freq;
        global_vm_boost_ = freq_ratio * boost_factor * 100.0;
        if (global_vm_boost_ > 100.0) {
          LOG(INFO) << "Clamping global VM boost from " << global_vm_boost_
                    << "% to 100%";
          global_vm_boost_ = 100.0;
        }

        LOG(INFO) << "Calculated global VM boost: " << global_vm_boost_ << "%";
      } else {
        LOG(WARNING) << "VM cannot be boosted - invalid frequencies detected "
                     << "little: " << little_max_freq
                     << " big: " << big_max_freq;
      }
    }
  }

  for (const auto& pkg : package_) {
    bool is_rt_vcpu_package = false;
    for (auto cpu : pkg.second) {
      cpu_list.push_back(std::to_string(cpu));
      // Add RT VCPUs as a package with a lowest capacity.
      is_rt_vcpu_package = is_rt_vcpu_package || (cpu == last_non_rt_cpu);
    }
    if (is_rt_vcpu_package) {
      for (int i = 0; i < num_rt_cpus_; i++) {
        cpu_list.push_back(std::to_string(num_cpus_ + i));
      }
    }
    package_mask_.push_back(base::JoinString(cpu_list, ","));
    cpu_list.clear();
  }

  // Add RT VCPUs after non RT VCPUs.
  for (int i = 0; i < num_rt_cpus_; i++) {
    rt_cpus_.insert(num_cpus_ + i);
  }
  for (auto cpu : rt_cpus_) {
    cpu_list.push_back(std::to_string(cpu));
  }
  rt_cpu_mask_ = base::JoinString(cpu_list, ",");
  cpu_list.clear();

  for (int i = 0; i < num_cpus_ + num_rt_cpus_; i++) {
    if (rt_cpus_.find(i) == rt_cpus_.end()) {
      cpu_list.push_back(std::to_string(i));
    }
  }
  non_rt_cpu_mask_ = base::JoinString(cpu_list, ",");
  cpu_list.clear();

  // Try to group VCPUs based on physical CPUs topology.
  if (package_.size() > 1) {
    for (const auto& pkg : package_) {
      bool is_rt_vcpu_package = false;
      for (auto cpu : pkg.second) {
        cpu_list.push_back(std::to_string(cpu));
        // Add RT VCPUs as a package with a lowest capacity.
        is_rt_vcpu_package = is_rt_vcpu_package || (cpu == last_non_rt_cpu);
      }
      std::string cpu_mask = base::JoinString(cpu_list, ",");
      cpu_list.clear();
      for (auto cpu : pkg.second) {
        affinities.push_back(
            base::StringPrintf("%d=%s", cpu, cpu_mask.c_str()));
      }
      if (is_rt_vcpu_package) {
        for (int i = 0; i < num_rt_cpus_; i++) {
          affinities.push_back(
              base::StringPrintf("%d=%s", num_cpus_ + i, cpu_mask.c_str()));
        }
      }
    }
  } else {
    // Try to group VCPUs based on physical CPUs capacity values.
    for (const auto& cap : capacity_) {
      bool is_rt_vcpu_cap = false;
      for (auto cpu : cap.second) {
        cpu_list.push_back(std::to_string(cpu));
        is_rt_vcpu_cap = is_rt_vcpu_cap || (cpu == last_non_rt_cpu);
      }

      std::string cpu_mask = base::JoinString(cpu_list, ",");
      cpu_list.clear();
      for (auto cpu : cap.second) {
        affinities.push_back(
            base::StringPrintf("%d=%s", cpu, cpu_mask.c_str()));
      }
      if (is_rt_vcpu_cap) {
        for (int i = 0; i < num_rt_cpus_; i++) {
          affinities.push_back(
              base::StringPrintf("%d=%s", num_cpus_ + i, cpu_mask.c_str()));
        }
      }
    }
  }
  affinity_mask_ = base::JoinString(affinities, ":");

  num_cpus_ += num_rt_cpus_;
}

// Creates CPU grouping by cpu_capacity.
void ArcVmCPUTopology::CreateTopology(void) {
  for (uint32_t cpu = 0; cpu < num_cpus_; cpu++) {
    auto capacity = GetCpuCapacity(cpu);
    auto package = GetCpuPackageId(cpu);

    // Do not fail, carry on, but use an aritifical capacity group.
    if (!capacity)
      capacity_[0].push_back(cpu);
    else
      capacity_[*capacity].push_back(cpu);

    // Ditto.
    if (!package)
      package_[0].push_back(cpu);
    else
      package_[*package].push_back(cpu);
  }
}

// Check whether the host processor is symmetric.
// TODO(kansho): Support ADL. IsSymmetricCPU() would return true even though
//               it's heterogeneous.
bool ArcVmCPUTopology::IsSymmetricCPU() {
  return capacity_.size() == 1 && package_.size() == 1;
}

void ArcVmCPUTopology::CreateCPUAffinity() {
  CreateTopology();
  CreateAffinity();
}

void ArcVmCPUTopology::AddCpuToCapacityGroupForTesting(uint32_t cpu,
                                                       uint32_t capacity) {
  capacity_[capacity].push_back(cpu);
}

void ArcVmCPUTopology::AddCpuToPackageGroupForTesting(uint32_t cpu,
                                                      uint32_t package) {
  package_[package].push_back(cpu);
}

void ArcVmCPUTopology::CreateCPUAffinityForTesting() {
  CreateAffinity();
}

uint32_t ArcVmCPUTopology::NumCPUs() {
  return num_cpus_;
}

uint32_t ArcVmCPUTopology::NumRTCPUs() {
  return num_rt_cpus_;
}

void ArcVmCPUTopology::SetNumRTCPUs(uint32_t num_rt_cpus) {
  num_rt_cpus_ = num_rt_cpus;
}

const std::string& ArcVmCPUTopology::AffinityMask() {
  return affinity_mask_;
}

const std::string& ArcVmCPUTopology::RTCPUMask() {
  return rt_cpu_mask_;
}

const std::string& ArcVmCPUTopology::NonRTCPUMask() {
  return non_rt_cpu_mask_;
}

const std::string& ArcVmCPUTopology::CapacityMask() {
  return capacity_mask_;
}

const std::vector<std::string>& ArcVmCPUTopology::PackageMask() {
  return package_mask_;
}

int ArcVmCPUTopology::TopAppUclampMin() {
  return top_app_uclamp_min_;
}

double ArcVmCPUTopology::GlobalVMBoost() {
  return global_vm_boost_;
}

ArcVmCPUTopology::ArcVmCPUTopology(uint32_t num_cpus, uint32_t num_rt_cpus) {
  num_cpus_ = num_cpus;
  num_rt_cpus_ = num_rt_cpus;
}

std::ostream& operator<<(std::ostream& os, const VmStartChecker::Status& e) {
  switch (e) {
    case VmStartChecker::Status::READY:
      os << "VM is ready";
      break;
    case VmStartChecker::Status::EPOLL_INVALID_EVENT:
      os << "Received invalid event while waiting for VM to start";
      break;
    case VmStartChecker::Status::EPOLL_INVALID_FD:
      os << "Received invalid fd while waiting for VM to start";
      break;
    case VmStartChecker::Status::TIMEOUT:
      os << "Timed out while waiting for VM to start";
      break;
    case VmStartChecker::Status::INVALID_SIGNAL_INFO:
      os << "Received invalid signal info while waiting for VM to start";
      break;
    case VmStartChecker::Status::SIGNAL_RECEIVED:
      os << "Received signal while waiting for VM to start";
      break;
    default:
      os << "Invalid enum value";
      break;
  }
  return os;
}

std::unique_ptr<VmStartChecker> VmStartChecker::Create(int32_t signal_fd) {
  // Create an event fd that will  be signalled when a VM is ready.
  base::ScopedFD vm_start_event_fd(eventfd(0, EFD_CLOEXEC));
  if (!vm_start_event_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create eventfd for VM start notification";
    return nullptr;
  }

  // We need to add it to the epoll set so that |Wait| can use it successfully.
  // This fd shouldn't be used across child processes but still pass
  // EPOLL_CLOEXEC as good hygiene.
  base::ScopedFD vm_start_epoll_fd(epoll_create1(EPOLL_CLOEXEC));
  if (!vm_start_epoll_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create epoll fd for the VM start event";
    return nullptr;
  }

  struct epoll_event ep_event {
    .events = EPOLLIN,
    .data.u32 = static_cast<uint32_t>(vm_start_event_fd.get()),
  };
  if (HANDLE_EINTR(epoll_ctl(vm_start_epoll_fd.get(), EPOLL_CTL_ADD,
                             vm_start_event_fd.get(), &ep_event)) < 0) {
    PLOG(ERROR) << "Failed to epoll add VM start event fd";
    return nullptr;
  }

  // Add the signal fd to the epoll set to see if a signal is received while
  // waiting for the VM.
  ep_event = {
      .events = EPOLLIN,
      .data.u32 = static_cast<uint32_t>(signal_fd),
  };
  if (HANDLE_EINTR(epoll_ctl(vm_start_epoll_fd.get(), EPOLL_CTL_ADD, signal_fd,
                             &ep_event)) < 0) {
    PLOG(ERROR) << "Failed to epoll add signal fd";
    return nullptr;
  }

  return base::WrapUnique(new VmStartChecker(
      signal_fd, std::move(vm_start_event_fd), std::move(vm_start_epoll_fd)));
}

VmStartChecker::Status VmStartChecker::Wait(base::TimeDelta timeout) {
  struct epoll_event ep_event;
  if (HANDLE_EINTR(epoll_wait(epoll_fd_.get(), &ep_event, 1,
                              timeout.InMilliseconds())) <= 0) {
    PLOG(ERROR) << "Timed out waiting for VM to start";
    return Status::TIMEOUT;
  }

  // We've only registered for input events.
  if ((ep_event.events & EPOLLIN) == 0) {
    LOG(ERROR) << "Got invalid event while waiting for VM to start: "
               << ep_event.events;
    return Status::EPOLL_INVALID_EVENT;
  }

  if ((ep_event.data.u32 != static_cast<uint32_t>(event_fd_.get())) &&
      (ep_event.data.u32 != static_cast<uint32_t>(signal_fd_))) {
    LOG(ERROR) << "Got invalid fd while waiting for VM to start: "
               << ep_event.data.u32;
    return Status::EPOLL_INVALID_FD;
  }

  if (ep_event.data.u32 == static_cast<uint32_t>(signal_fd_)) {
    struct signalfd_siginfo siginfo;
    if (read(signal_fd_, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
      PLOG(ERROR) << "Failed to read signal info";
      return Status::INVALID_SIGNAL_INFO;
    }

    LOG(ERROR) << "Received signal: " << siginfo.ssi_signo
               << " while waiting to start the VM";
    return Status::SIGNAL_RECEIVED;
  }

  // At this point |event_fd_| has been successfully signalled.
  return Status::READY;
}

int32_t VmStartChecker::GetEventFd() const {
  return event_fd_.get();
}

VmStartChecker::VmStartChecker(int32_t signal_fd,
                               base::ScopedFD event_fd,
                               base::ScopedFD epoll_fd)
    : signal_fd_(signal_fd),
      event_fd_(std::move(event_fd)),
      epoll_fd_(std::move(epoll_fd)) {}

VmInfo_VmType ToLegacyVmType(apps::VmType type) {
  switch (type) {
    case apps::VmType::TERMINA:
      return VmInfo::TERMINA;
    case apps::PLUGIN_VM:
      return VmInfo::PLUGIN_VM;
    case apps::BOREALIS:
      return VmInfo::BOREALIS;
    case apps::ARCVM:
      return VmInfo::ARC_VM;
    case apps::BRUSCHETTA:
      return VmInfo::BRUSCHETTA;
    default:
      return VmInfo::UNKNOWN;
  }
}

}  // namespace vm_tools::concierge
