// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/process_cache.h"

#include <unistd.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "base/containers/lru_cache.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/hash/md5.h"
#include "base/logging.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece_forward.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "openssl/sha.h"
#include "re2/re2.h"
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/metrics_sender.h"
#include "secagentd/proto/security_xdr_events.pb.h"

namespace {

namespace bpf = secagentd::bpf;
namespace pb = cros_xdr::reporting;
using secagentd::ProcessCache;

static const char kErrorFailedToStat[] = "Failed to stat ";
static const char kErrorFailedToResolve[] = "Failed to resolve ";
static const char kErrorFailedToRead[] = "Failed to read ";
static const char kErrorFailedToParse[] = "Failed to parse ";
static const char kErrorSslSha[] = "SSL SHA error";

std::string StableUuid(ProcessCache::InternalProcessKeyType seed) {
  base::MD5Digest md5;
  base::MD5Sum(&seed, sizeof(seed), &md5);
  // Convert the hash to a UUID string. Pretend to be version 4, variant 1.
  md5.a[4] = (md5.a[4] & 0x0f) | 0x40;
  md5.a[6] = (md5.a[6] & 0x3f) | 0x80;
  return base::StringPrintf(
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      md5.a[0], md5.a[1], md5.a[2], md5.a[3], md5.a[4], md5.a[5], md5.a[6],
      md5.a[7], md5.a[8], md5.a[9], md5.a[10], md5.a[11], md5.a[12], md5.a[13],
      md5.a[14], md5.a[15]);
}

// Kernel arg and env lists use '\0' to delimit elements. Tokenize the string
// and use single quotes (') to designate atomic elements.
// bufsize is the total capacity of buf (used for bounds checking).
// payload_len is the length of actual payload including the final '\0'.
std::string SafeTransformArgvEnvp(const char* buf,
                                  size_t bufsize,
                                  size_t payload_len) {
  std::string str;
  if (payload_len <= 0 || payload_len > bufsize) {
    return str;
  }
  base::CStringTokenizer t(buf, buf + payload_len, std::string("\0", 1));
  while (t.GetNext()) {
    str.append(base::StringPrintf("'%s' ", t.token().c_str()));
  }
  if (str.length() > 0) {
    str.pop_back();
  }
  return str;
}

// Fills a FileImage proto with contents from bpf image_info.
void FillImageFromBpf(const bpf::cros_image_info& image_info,
                      pb::FileImage* file_image_proto) {
  file_image_proto->set_pathname(std::string(image_info.pathname));
  file_image_proto->set_mnt_ns(image_info.mnt_ns);
  file_image_proto->set_inode_device_id(image_info.inode_device_id);
  file_image_proto->set_inode(image_info.inode);
  file_image_proto->set_canonical_uid(image_info.uid);
  file_image_proto->set_canonical_gid(image_info.gid);
  file_image_proto->set_mode(image_info.mode);
}

void FillProcessFromBpf(const bpf::cros_process_start& process_start,
                        pb::Process* process_proto) {
  ProcessCache::PartiallyFillProcessFromBpfTaskInfo(process_start.task_info,
                                                    process_proto);
  FillImageFromBpf(process_start.image_info, process_proto->mutable_image());
}

absl::Status GetNsFromPath(const base::FilePath& ns_symlink_path,
                           uint64_t* ns) {
  // mnt_ns_symlink is not actually pathlike. E.g: "mnt:[4026531840]".
  constexpr char kMntNsPattern[] = R"(mnt:\[(\d+)\])";
  static const LazyRE2 kMntNsRe = {kMntNsPattern};
  base::FilePath ns_symlink;
  if (!base::ReadSymbolicLink(ns_symlink_path, &ns_symlink)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToResolve, ns_symlink_path.value()}));
  }
  if (!RE2::FullMatch(ns_symlink.value(), *kMntNsRe, ns)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToParse, ns_symlink.value()}));
  }
  return absl::OkStatus();
}

absl::Status GetStatFromProcfs(const base::FilePath& stat_path,
                               uint64_t* ppid,
                               uint64_t* starttime_t,
                               std::string* set_comm_if_kthread) {
  std::string proc_stat_contents;
  if (!base::ReadFileToString(stat_path, &proc_stat_contents)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToRead, stat_path.value()}));
  }

  // See https://man7.org/linux/man-pages/man5/proc.5.html for
  // /proc/[pid]/stat format. All tokens are delimited with a whitespace. One
  // major caveat is that comm (field 2) token may have an embedded whitespace
  // and is so delimited by parentheses. The token may also have embedded
  // parentheses though so we just ignore everything until the final ')'.
  // StringTokenizer::set_quote_chars does not help with this. It accepts
  // multiple quote chars but does not work for asymmetric quoting.
  size_t end_of_comm = proc_stat_contents.rfind(')');
  if (end_of_comm == std::string::npos) {
    return absl::OutOfRangeError(
        base::StrCat({kErrorFailedToParse, stat_path.value()}));
  }
  base::StringTokenizer t(proc_stat_contents.begin() + end_of_comm,
                          proc_stat_contents.end(), " ");
  // We could avoid a separate loop here but the tokenizer API is awkward for
  // random access.
  std::vector<base::StringPiece> stat_tokens;
  while (t.GetNext()) {
    stat_tokens.push_back(t.token_piece());
  }

  // We need the following fields (1-indexed in man page):
  // (4) ppid  %d
  // (9) flags  %u
  // (22) starttime  %llu
  // And remember that we started tokenizing at (2) comm.
  static const size_t kPpidField = 2;
  static const size_t kFlagsField = 7;
  static const size_t kStarttimeField = 20;
  uint32_t flags;
  if ((stat_tokens.size() <= kStarttimeField) ||
      (!base::StringToUint64(stat_tokens[kPpidField], ppid)) ||
      (!base::StringToUint(stat_tokens[kFlagsField], &flags)) ||
      (!base::StringToUint64(stat_tokens[kStarttimeField], starttime_t))) {
    return absl::OutOfRangeError(
        base::StrCat({kErrorFailedToParse, stat_path.value()}));
  }
  constexpr uint32_t kPfKthread = 0x00200000;  // Defined in linux/sched.h.
  if (flags & kPfKthread) {
    size_t start_of_comm = proc_stat_contents.find('(');
    if (start_of_comm != std::string::npos &&
        (start_of_comm + 1 <= end_of_comm)) {
      *set_comm_if_kthread = base::StrCat(
          {"[",
           base::MakeStringPiece(proc_stat_contents.begin() + start_of_comm + 1,
                                 proc_stat_contents.begin() + end_of_comm),
           "]"});
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> GenerateImageHash(
    const base::FilePath& image_path_in_current_ns) {
  base::File image(image_path_in_current_ns,
                   base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!image.IsValid()) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToRead, image_path_in_current_ns.value()}));
  }
  SHA256_CTX ctx;
  if (!SHA256_Init(&ctx)) {
    return absl::InternalError(kErrorSslSha);
  }
  std::array<char, 4096> buf;
  int bytes_read = 0;
  while ((bytes_read = image.ReadAtCurrentPos(buf.data(), buf.size())) > 0) {
    if (!SHA256_Update(&ctx, buf.data(), bytes_read)) {
      return absl::InternalError(kErrorSslSha);
    }
  }
  if (bytes_read < 0) {
    return absl::AbortedError(
        base::StrCat({kErrorFailedToRead, image_path_in_current_ns.value()}));
  }
  static_assert(sizeof(buf) >= SHA256_DIGEST_LENGTH);
  if (!SHA256_Final(reinterpret_cast<unsigned char*>(buf.data()), &ctx)) {
    return absl::InternalError(kErrorSslSha);
  }
  return base::HexEncode(buf.data(), SHA256_DIGEST_LENGTH);
}

absl::StatusOr<ProcessCache::InternalImageValueType>
VerifyStatAndGenerateImageHash(
    const ProcessCache::InternalImageKeyType& image_key,
    const base::FilePath& image_path_in_current_ns) {
  auto hash = GenerateImageHash(image_path_in_current_ns);
  if (!hash.ok()) {
    return hash.status();
  }
  base::stat_wrapper_t image_stat;
  if (base::File::Stat(image_path_in_current_ns.value().c_str(), &image_stat) ||
      (image_stat.st_dev != image_key.inode_device_id) ||
      (image_stat.st_ino != image_key.inode) ||
      (image_stat.st_mtim.tv_sec != image_key.mtime.tv_sec) ||
      (image_stat.st_mtim.tv_nsec != image_key.mtime.tv_nsec) ||
      (image_stat.st_ctim.tv_sec != image_key.ctime.tv_sec) ||
      (image_stat.st_ctim.tv_nsec != image_key.ctime.tv_nsec)) {
    return absl::NotFoundError(
        base::StrCat({"Failed to match stat of image hashed at ",
                      image_path_in_current_ns.value()}));
  }
  return ProcessCache::InternalImageValueType{.sha256 = hash.value()};
}

// Safely initialized and trivially destructible static value of SC_CLK_TCK.
const uint64_t GetScClockTck() {
  static const uint64_t kScClockTck = sysconf(_SC_CLK_TCK);
  return kScClockTck;
}

}  // namespace

namespace secagentd {

constexpr ProcessCache::InternalProcessCacheType::size_type
    kProcessCacheMaxSize = 256;
constexpr ProcessCache::InternalImageCacheType::size_type kImageCacheMaxSize =
    256;

uint64_t ProcessCache::LossyNsecToClockT(bpf::time_ns_t ns) {
  static constexpr uint64_t kNsecPerSec = 1000000000;
  const uint64_t sc_clock_tck = GetScClockTck();
  // Copied from the kernel procfs code though we unfortunately cannot use
  // ifdefs and need to do comparisons live.
  if ((kNsecPerSec % sc_clock_tck) == 0) {
    return ns / (kNsecPerSec / sc_clock_tck);
  } else if ((sc_clock_tck % 512) == 0) {
    return (ns * sc_clock_tck / 512) / (kNsecPerSec / 512);
  } else {
    return (ns * 9) /
           ((9ull * kNsecPerSec + (sc_clock_tck / 2)) / sc_clock_tck);
  }
}

// Converts clock_t to seconds.
int64_t ProcessCache::ClockTToSeconds(uint64_t clock_t) {
  return clock_t / GetScClockTck();
}

void ProcessCache::PartiallyFillProcessFromBpfTaskInfo(
    const bpf::cros_process_task_info& task_info, pb::Process* process_proto) {
  ProcessCache::InternalProcessKeyType key{
      LossyNsecToClockT(task_info.start_time), task_info.pid};
  process_proto->set_process_uuid(StableUuid(key));
  process_proto->set_canonical_pid(task_info.pid);
  process_proto->set_canonical_uid(task_info.uid);
  process_proto->set_commandline(SafeTransformArgvEnvp(
      task_info.commandline, sizeof(task_info.commandline),
      task_info.commandline_len));
  process_proto->set_rel_start_time_s(ClockTToSeconds(key.start_time_t));
}

absl::StatusOr<base::FilePath> ProcessCache::SafeAppendAbsolutePath(
    const base::FilePath& path, const base::FilePath& abs_component) {
  // TODO(b/279213783): abs_component is expected to be an absolute and
  // resolved path. But that's sometimes not the case. If the path references
  // parent it likely won't resolve and possibly may attempt to escape the
  // pid_mnt_root namespace. So err on the side of safety. Similarly, if the
  // path is not absolute, it likely won't resolve because we don't have its
  // CWD.
  if (!abs_component.IsAbsolute() || abs_component.ReferencesParent()) {
    return absl::InvalidArgumentError(base::StrCat(
        {"Refusing to translate relative or parent-referencing path ",
         abs_component.value()}));
  }
  return path.Append(
      base::StrCat({base::FilePath::kCurrentDirectory, abs_component.value()}));
}

ProcessCache::ProcessCache(const base::FilePath& root_path)
    : weak_ptr_factory_(this),
      process_cache_(
          std::make_unique<InternalProcessCacheType>(kProcessCacheMaxSize)),
      image_cache_(
          std::make_unique<InternalImageCacheType>(kImageCacheMaxSize)),
      root_path_(root_path),
      earliest_seen_exec_rel_s_(INT64_MAX) {}

ProcessCache::ProcessCache() : ProcessCache(base::FilePath("/")) {}

void ProcessCache::PutFromBpfExec(
    const bpf::cros_process_start& process_start) {
  // Starts reporting of the cache fullness metric.
  static bool started_reporting_cache_fullness = false;
  if (!started_reporting_cache_fullness) {
    MetricsSender::GetInstance().RegisterMetricOnFlushCallback(
        base::BindRepeating(&ProcessCache::SendPolledMetrics,
                            weak_ptr_factory_.GetWeakPtr()));
    started_reporting_cache_fullness = true;
  }

  InternalProcessKeyType key{
      LossyNsecToClockT(process_start.task_info.start_time),
      process_start.task_info.pid};
  auto process_proto = std::make_unique<pb::Process>();
  FillProcessFromBpf(process_start, process_proto.get());
  InternalProcessKeyType parent_key{
      LossyNsecToClockT(process_start.task_info.parent_start_time),
      process_start.task_info.ppid};
  InternalImageKeyType image_key{
      process_start.image_info.inode_device_id, process_start.image_info.inode,
      process_start.image_info.mtime, process_start.image_info.ctime};
  {
    base::AutoLock cache_lock(image_cache_lock_);
    auto it =
        InclusiveGetImage(image_key, process_start.image_info.pid_for_setns,
                          base::FilePath(process_start.image_info.pathname));
    if (it != image_cache_->end()) {
      process_proto->mutable_image()->set_sha256(it->second.sha256);
    }
  }
  // Execs from eBPF are always new processes.
  process_proto->set_meta_first_appearance(true);
  if (earliest_seen_exec_rel_s_ > process_proto->rel_start_time_s()) {
    earliest_seen_exec_rel_s_ = process_proto->rel_start_time_s();
    LOG(INFO) << "Set first seen process exec time to "
              << earliest_seen_exec_rel_s_;
  }

  base::AutoLock lock(process_cache_lock_);
  process_cache_->Put(
      key, InternalProcessValueType({std::move(process_proto), parent_key}));
}

void ProcessCache::EraseProcess(uint64_t pid, bpf::time_ns_t start_time_ns) {
  InternalProcessKeyType key{LossyNsecToClockT(start_time_ns), pid};
  base::AutoLock lock(process_cache_lock_);
  auto it = process_cache_->Peek(key);
  if (it != process_cache_->end()) {
    process_cache_->Erase(it);
  }
}

std::pair<ProcessCache::InternalProcessCacheType::iterator, metrics::Cache>
ProcessCache::InclusiveGetProcess(const InternalProcessKeyType& key) {
  process_cache_lock_.AssertAcquired();
  // PID 0 doesn't exist and is also used to signify the end of the process
  // "linked list".
  if (key.pid == 0) {
    // Metric will not be logged.
    return std::make_pair(process_cache_->end(), metrics::Cache(-1));
  }
  auto it = process_cache_->Get(key);
  if (it != process_cache_->end()) {
    return std::make_pair(it, metrics::Cache::kCacheHit);
  }

  absl::StatusOr<InternalProcessValueType> statusor;
  {
    base::AutoUnlock unlock(process_cache_lock_);
    statusor = MakeFromProcfs(key);
    if (!statusor.ok()) {
      LOG(ERROR) << statusor.status();
      return std::make_pair(process_cache_->end(), metrics::Cache::kCacheMiss);
    }
  }

  it = process_cache_->Put(key, std::move(*statusor));
  return std::make_pair(it, metrics::Cache::kProcfsFilled);
}

ProcessCache::InternalImageCacheType::const_iterator
ProcessCache::InclusiveGetImage(const InternalImageKeyType& image_key,
                                uint64_t pid_for_setns,
                                const base::FilePath& image_path_in_pids_ns) {
  image_cache_lock_.AssertAcquired();
  auto it = image_cache_->Get(image_key);
  if (it != image_cache_->end()) {
    if (it->first.mtime.tv_sec == 0 || it->first.ctime.tv_sec == 0) {
      // Invalidate entry and force checksum if its cached ctime or mtime seems
      // missing.
      image_cache_->Erase(it);
      it = image_cache_->end();
    } else {
      return it;
    }
  }

  absl::StatusOr<InternalImageValueType> statusorhash;
  {
    base::AutoUnlock unlock(image_cache_lock_);
    // First try our own (i.e root) namespace. This will almost always work
    // because minijail mounts are 1:1. Stat will save us from false positive
    // matches.
    auto statusorpath =
        SafeAppendAbsolutePath(root_path_, image_path_in_pids_ns);
    if (statusorpath.ok()) {
      statusorhash = VerifyStatAndGenerateImageHash(image_key, *statusorpath);
    }
    // If !statusorpath.ok() then GetPathInCurrentMountNs will call
    // SafeAppendAbsolutePath with the same image_path_in_pids_ns which will
    // return the same status. No point in trying.
    if (statusorpath.ok() && !statusorhash.ok()) {
      statusorpath =
          GetPathInCurrentMountNs(pid_for_setns, image_path_in_pids_ns);
      if (statusorpath.ok()) {
        statusorhash = VerifyStatAndGenerateImageHash(image_key, *statusorpath);
      }
    }

    if (!statusorpath.ok() || !statusorhash.ok()) {
      LOG(ERROR) << "Failed to hash " << image_path_in_pids_ns
                 << " in mnt ns of pid " << pid_for_setns << ": "
                 << (!statusorpath.ok() ? statusorpath.status()
                                        : statusorhash.status());
      return image_cache_->end();
    }
  }

  it = image_cache_->Put(image_key, std::move(*statusorhash));
  return it;
}

std::vector<std::unique_ptr<pb::Process>> ProcessCache::GetProcessHierarchy(
    uint64_t pid, bpf::time_ns_t start_time_ns, int num_generations) {
  std::vector<std::unique_ptr<pb::Process>> processes;
  InternalProcessKeyType lookup_key{LossyNsecToClockT(start_time_ns), pid};
  base::AutoLock lock(process_cache_lock_);
  for (int i = 0; i < num_generations; ++i) {
    auto pair = InclusiveGetProcess(lookup_key);
    auto it = pair.first;
    if (lookup_key.pid != 0) {
      MetricsSender::GetInstance().IncrementBatchedMetric(metrics::kCache,
                                                          pair.second);
    }
    if (it != process_cache_->end()) {
      auto process_proto = std::make_unique<pb::Process>();
      process_proto->CopyFrom(*it->second.process_proto);
      processes.push_back(std::move(process_proto));
      if (it->second.process_proto->meta_first_appearance()) {
        it->second.process_proto->set_meta_first_appearance(false);
      }
      lookup_key = it->second.parent_key;
    } else {
      // Process no longer exists or we've reached init. Break and best-effort
      // return what we were able to retrieve.
      break;
    }
  }
  return processes;
}

absl::StatusOr<ProcessCache::InternalProcessValueType>
ProcessCache::MakeFromProcfs(const ProcessCache::InternalProcessKeyType& key) {
  InternalProcessKeyType parent_key;
  auto process_proto = std::make_unique<pb::Process>();
  process_proto->set_canonical_pid(key.pid);
  process_proto->set_process_uuid(StableUuid(key));
  process_proto->set_rel_start_time_s(ClockTToSeconds(key.start_time_t));

  const base::FilePath proc_pid_dir =
      root_path_.Append(base::StringPrintf("proc/%" PRIu64, key.pid));
  base::stat_wrapper_t pid_dir_stat;
  if (base::File::Stat(proc_pid_dir.value().c_str(), &pid_dir_stat)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToStat, proc_pid_dir.value()}));
  }
  process_proto->set_canonical_uid(pid_dir_stat.st_uid);

  const base::FilePath cmdline_path = proc_pid_dir.Append("cmdline");
  std::string cmdline_contents;
  if (!base::ReadFileToString(cmdline_path, &cmdline_contents)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToRead, cmdline_path.value()}));
  }
  process_proto->set_commandline(
      SafeTransformArgvEnvp(cmdline_contents.c_str(), cmdline_contents.size(),
                            cmdline_contents.size()));

  auto status = FillImageFromProcfs(proc_pid_dir, key.pid,
                                    process_proto->mutable_image());
  if (!status.ok()) {
    // It's okay if we don't get the image. Report everything else.
    LOG(ERROR) << "Failed to fill process image info from procfs "
               << status.ToString();
  }

  // This must be the last file that we read for this process because process
  // starttime is used as a key against pid reuse.
  const base::FilePath stat_path = proc_pid_dir.Append("stat");
  uint64_t procfs_start_time_t;
  // mutable_commandline is already empty if this process is a kthread. So put
  // in the comm instead.
  status = GetStatFromProcfs(stat_path, &parent_key.pid, &procfs_start_time_t,
                             process_proto->mutable_commandline());
  if (!status.ok()) {
    return status;
  }

  // TODO(b/254291026): Incoming ns is currently not derived using
  // timens_add_boottime_ns.
  if (key.start_time_t != procfs_start_time_t) {
    return absl::AbortedError(
        base::StringPrintf("Detected PID reuse on %" PRIu64
                           " (want time %" PRIu64 ", got time %" PRIu64 ")",
                           key.pid, key.start_time_t, procfs_start_time_t));
  }

  // parent_key.pid is filled in by this point but we also need start_time.
  // parent_key.pid == 0 implies current process is init or a kthread. No need
  // to traverse further.
  if (parent_key.pid != 0) {
    const base::FilePath parent_stat_path = root_path_.Append(
        base::StringPrintf("proc/%" PRIu64 "/stat", parent_key.pid));
    uint64_t unused_ppid;
    std::string unused_comm;
    status = GetStatFromProcfs(parent_stat_path, &unused_ppid,
                               &parent_key.start_time_t, &unused_comm);
    if (!status.ok() || key.start_time_t < parent_key.start_time_t) {
      LOG(WARNING) << "Failed to establish parent linkage for PID " << key.pid;
      // Signifies end of our "linked list".
      parent_key.pid = 0;
    }
  }

  // Heuristically determine if the scraped process would have been seen before.
  // False positives are expected and acceptable.
  process_proto->set_meta_first_appearance(process_proto->rel_start_time_s() <=
                                           earliest_seen_exec_rel_s_);

  return InternalProcessValueType{std::move(process_proto), parent_key};
}

bool ProcessCache::IsEventFiltered(
    const cros_xdr::reporting::Process* parent_process,
    const cros_xdr::reporting::Process* process) {
  const auto& parent_filter = filter_rules_parent_;
  const auto& image_filter = filter_rules_process_;
  const auto& should_filter = [](const cros_xdr::reporting::Process& p,
                                 const InternalFilterRuleSetType& filters,
                                 const std::string& type) -> bool {
    const auto& matching_filter = filters.find(p.image().sha256());
    if (matching_filter == filters.end()) {
      return false;
    }
    if (matching_filter->second.commandline.empty()) {
      // Commands match and there is no shell script to match.
      return true;
    }
    for (const auto& commandline : matching_filter->second.commandline) {
      if (p.commandline() == commandline) {
        // Exact commandline match.
        return true;
      }
    }
    // Commands match but no matching shell script.
    return false;
  };

  if (parent_process &&
      should_filter(*parent_process, parent_filter, "parent_process")) {
    return true;
  }
  if (process && should_filter(*process, image_filter, "process")) {
    return true;
  }

  return false;
}

void ProcessCache::SendPolledMetrics() {
  MetricsSender::GetInstance().SendPercentageMetricToUMA(
      metrics::kCacheFullness,
      trunc(100 * (static_cast<double>(process_cache_->size()) /
                   static_cast<double>(process_cache_->max_size()))));
}

void ProcessCache::InitializeFilter(bool underscorify) {
  // Image pathnames are adjusted by root_path_ for testing. Also they need
  // to be underscorified for the unit test framework to function correctly.

  // Since shell scripts just look at commandline they don't need to
  // be underscorified or adjusted by root_path_ for testing.

  std::vector<InternalFilterRule> parent_filter_seeds = {
      // Shell rules
      // TODO(b:267391331): make temp logger into a real application.
      {
          .image_pathname = "bin/sh",
          .commandline =
              {"'/bin/sh' '/usr/share/cros/init/temp_logger.sh'",
               "'/bin/sh' '/usr/local/libexec/recover-duts/recover_duts'",
               "'/bin/sh' "
               "'/usr/local/libexec/recover-duts/hooks/check_ethernet.hook'"},
      }};

  std::vector<InternalFilterRule> process_filter_seeds = {
      // Command rules
      // TODO(b:267391049): We think this is being execve by some base library
      // to determine how much space is left on the system. This spams the event
      // logs so we add a filter. The base library should really be fixed.
      {.image_pathname = "usr/sbin/spaced_cli"},
      // TODO(b:274925855): dmsetup is called at 1 Hz by spaced. Evaluate
      // if spaced needs to call it that often.
      {.image_pathname = "sbin/dmsetup"}};

  std::vector<
      std::pair<InternalFilterRuleSetType&, std::vector<InternalFilterRule>&>>
      filter_seeds = {{filter_rules_parent_, parent_filter_seeds},
                      {filter_rules_process_, process_filter_seeds}};

  for (auto& v : filter_seeds) {
    for (auto& k : v.second) {
      if (underscorify) {
        std::replace(k.image_pathname.begin(), k.image_pathname.end(), '/',
                     '_');
      }
      k.image_pathname = root_path_.Append(k.image_pathname).value();
      auto result = GenerateImageHash(base::FilePath(k.image_pathname));
      if (!result.ok()) {
        LOG(ERROR) << "XdrProcessEvent filter failed to create rule for "
                   << "image_path_name:" << k.image_pathname
                   << " error:" << result.status();
        continue;
      }

      v.first.emplace(std::make_pair(result.value(), std::move(k)));
    }
  }
  LOG(INFO) << "Process filter rules created:";
  for (const auto& key : filter_rules_parent_) {
    LOG(INFO) << "PARENT: SHA256:" << key.first
              << " pathname:" << key.second.image_pathname;
    if (!key.second.commandline.empty())
      LOG(INFO) << "Commands:";
    for (auto commandline : key.second.commandline) {
      LOG(INFO) << commandline;
    }
  }

  for (const auto& key : filter_rules_process_) {
    LOG(INFO) << "PROCESS: SHA256:" << key.first
              << " pathname:" << key.second.image_pathname;
    if (!key.second.commandline.empty())
      LOG(INFO) << "Commands:";
    for (auto commandline : key.second.commandline) {
      LOG(INFO) << commandline;
    }
  }
}

absl::StatusOr<base::FilePath> ProcessCache::GetPathInCurrentMountNs(
    uint64_t pid_for_setns, const base::FilePath& image_path_in_pids_ns) const {
  const base::FilePath pid_mnt_root =
      root_path_.Append(base::StringPrintf("proc/%" PRIu64, pid_for_setns))
          .Append("root");
  return SafeAppendAbsolutePath(pid_mnt_root, image_path_in_pids_ns);
}

absl::Status ProcessCache::FillImageFromProcfs(
    const base::FilePath& proc_pid_dir,
    uint64_t pid_for_setns,
    pb::FileImage* file_image_proto) {
  const base::FilePath exe_symlink_path = proc_pid_dir.Append("exe");
  base::FilePath exe_path;
  if (!base::ReadSymbolicLink(exe_symlink_path, &exe_path)) {
    // Likely a kthread and there's no image to report.
    return absl::OkStatus();
  }
  base::stat_wrapper_t exe_stat;
  auto statusorpath = GetPathInCurrentMountNs(pid_for_setns, exe_path);
  if (!statusorpath.ok()) {
    return statusorpath.status();
  }
  if (base::File::Stat(statusorpath->value().c_str(), &exe_stat)) {
    return absl::NotFoundError(
        base::StrCat({kErrorFailedToStat, statusorpath->value()}));
  }
  const base::FilePath mnt_ns_symlink_path =
      proc_pid_dir.Append("ns").Append("mnt");
  uint64_t mnt_ns;
  auto status = GetNsFromPath(mnt_ns_symlink_path, &mnt_ns);
  if (!status.ok()) {
    return status;
  }
  file_image_proto->set_pathname(exe_path.value());
  file_image_proto->set_mnt_ns(mnt_ns);
  file_image_proto->set_inode_device_id(exe_stat.st_dev);
  file_image_proto->set_inode(exe_stat.st_ino);
  file_image_proto->set_canonical_uid(exe_stat.st_uid);
  file_image_proto->set_canonical_gid(exe_stat.st_gid);
  file_image_proto->set_mode(exe_stat.st_mode);

  InternalImageKeyType image_key{
      exe_stat.st_dev,
      exe_stat.st_ino,
      {exe_stat.st_mtim.tv_sec, exe_stat.st_mtim.tv_nsec},
      {exe_stat.st_ctim.tv_sec, exe_stat.st_ctim.tv_nsec}};
  {
    base::AutoLock lock(image_cache_lock_);
    auto it = InclusiveGetImage(image_key, pid_for_setns, exe_path);
    if (it != image_cache_->end()) {
      file_image_proto->set_sha256(it->second.sha256);
    }
  }
  return absl::OkStatus();
}

}  // namespace secagentd
