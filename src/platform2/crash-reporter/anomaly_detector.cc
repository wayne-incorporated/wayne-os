// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/anomaly_detector.h"

#include <memory>
#include <optional>
#include <unordered_set>
#include <utility>

#include <anomaly_detector/proto_bindings/anomaly_detector.pb.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/strcat.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <metrics/metrics_library.h>
#include <re2/re2.h>

#include "crash-reporter/util.h"

namespace {

// This hashing algorithm dates back to before this was migrated from C to C++.
// We're stuck with it now because we would like the hashes to remain the same
// over time for a given crash as the hashes are used in the crash signatures.
uint32_t StringHash(const std::string& input) {
  uint32_t hash = 0;
  for (auto& c : input) {
    hash = (hash << 5) + hash + c;
  }
  return hash;
}

std::string OnlyAsciiAlpha(std::string s) {
  s.erase(std::remove_if(s.begin(), s.end(),
                         [](char c) -> bool { return !base::IsAsciiAlpha(c); }),
          s.end());
  return s;
}

}  // namespace

namespace anomaly {

CrashReport::CrashReport(std::string t, std::vector<std::string> f)
    : text(std::move(t)), flags(std::move(f)) {}

bool operator==(const CrashReport& lhs, const CrashReport& rhs) {
  return lhs.text == rhs.text && lhs.flags == rhs.flags;
}

std::ostream& operator<<(std::ostream& out, const CrashReport& cr) {
  out << "{.text='" << cr.text << "', .flags={"
      << base::JoinString(cr.flags, " ") << "}}";
  return out;
}

Parser::~Parser() {}

// We expect only a handful of different anomalies per boot session, so the
// probability of a collision is very low, and statistically it won't matter
// (unless anomalies with the same hash also happens in tandem, which is even
// rarer).
bool Parser::WasAlreadySeen(uint32_t hash) {
  size_t bit_index = hash % HASH_BITMAP_SIZE;
  bool return_val = hash_bitmap_[bit_index];
  hash_bitmap_.set(bit_index, true);
  return return_val;
}

MaybeCrashReport Parser::PeriodicUpdate() {
  return std::nullopt;
}

constexpr LazyRE2 service_failure = {
    R"((\S+) \S+ process \(\d+\) terminated with status (\d+))"};

ServiceParser::ServiceParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

MaybeCrashReport ServiceParser::ParseLogEntry(const std::string& line) {
  std::string service_name;
  std::string exit_status;
  if (!RE2::FullMatch(line, *service_failure, &service_name, &exit_status))
    return std::nullopt;

  if (service_name == "cros-camera") {
    // cros-camera uses non-zero exit status to indicate transient failures and
    // to request that the service be re-started. This is 'nominal' and should
    // not be reported. (It's also flooding our servers.)
    return std::nullopt;
  }

  // We only want to report a limited number of service failures due to noise.
  if (!testonly_send_all_ &&
      base::RandGenerator(util::GetServiceFailureWeight()) != 0) {
    return std::nullopt;
  }

  uint32_t hash = StringHash(service_name.c_str());

  if (WasAlreadySeen(hash))
    return std::nullopt;

  std::string text = base::StringPrintf(
      "%08x-exit%s-%s\n", hash, exit_status.c_str(), service_name.c_str());
  std::string flag;
  if (base::StartsWith(service_name, "arc-", base::CompareCase::SENSITIVE))
    flag = "--arc_service_failure=" + service_name;
  else
    flag = "--service_failure=" + service_name;
  return CrashReport(std::move(text), {std::move(flag)});
}

std::string GetField(const std::string& line, std::string pattern) {
  std::string field_value;
  RE2::PartialMatch(line, pattern, &field_value);
  // This will return the empty string if there wasn't a match.
  return field_value;
}

// Make cursory checks on specific fields in the selinux audit report to see if
// the content is a CrOS selinux violation.
bool IsCrosSelinuxViolation(const std::vector<std::string>& contents) {
  for (const std::string& s : contents) {
    if (s.find("cros") != std::string::npos) {
      return true;
    }
    if (s.find("minijail") != std::string::npos) {
      return true;
    }
  }
  return false;
}

constexpr LazyRE2 granted = {"avc:[ ]*granted"};

SELinuxParser::SELinuxParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

MaybeCrashReport SELinuxParser::ParseLogEntry(const std::string& line) {
  // Ignore permissive "errors". These are extremely common and don't have any
  // real impact. The noise from them would crowd out other crashes that have
  // a more significant impact.
  if (line.find("permissive=1") != std::string::npos) {
    return std::nullopt;
  }

  // We only want to report a limited number of selinux violations due to noise.
  if (!testonly_send_all_ &&
      base::RandGenerator(util::GetSelinuxWeight()) != 0) {
    return std::nullopt;
  }

  std::string only_alpha = OnlyAsciiAlpha(line);
  uint32_t hash = StringHash(only_alpha.c_str());
  if (WasAlreadySeen(hash))
    return std::nullopt;

  std::string signature;

  // This case is strange: the '-' is only added if 'granted' was present.
  if (RE2::PartialMatch(line, *granted))
    signature += "granted-";

  std::string scontext = GetField(line, R"(scontext=(\S*))");
  std::string tcontext = GetField(line, R"(tcontext=(\S*))");
  std::string permission = GetField(line, R"(\{ (\S*) \})");
  std::string comm = GetField(line, R"'(comm="([^"]*)")'");
  std::string name = GetField(line, R"'(name="([^"]*)")'");

  // Ignore ARC++, and other non-CrOS, errors. They are extremely common and
  // largely not used anyway, providing a lot of noise.
  // (We do this by checking scontext, tcontext, and comm for certain known-CrOS
  // strings.)
  if (!IsCrosSelinuxViolation({scontext, tcontext, comm})) {
    if (testonly_send_all_) {
      // For tests, log something that we can match on to make sure
      // anomaly_detector saw the line and ignored it.
      LOG(INFO) << "Skipping non-CrOS selinux violation: " << line;
    }
    return std::nullopt;
  }

  signature += base::JoinString({scontext, tcontext, permission,
                                 OnlyAsciiAlpha(comm), OnlyAsciiAlpha(name)},
                                "-");
  std::string text =
      base::StringPrintf("%08x-selinux-%s\n", hash, signature.c_str());

  if (!comm.empty())
    text += "comm\x01" + comm + "\x02";
  if (!name.empty())
    text += "name\x01" + name + "\x02";
  if (!scontext.empty())
    text += "scontext\x01" + scontext + "\x02";
  if (!tcontext.empty())
    text += "tcontext\x01" + tcontext + "\x02";
  text += "\n";
  text += line;

  return CrashReport(
      std::move(text),
      {"--selinux_violation",
       base::StringPrintf("--weight=%d", util::GetSelinuxWeightForCrash())});
}

static constexpr LazyRE2 kernel_suspend_warning = {
    // Intel - PMT - failure to transition to S0ix detected on resume
    "drivers/idle|"  // <= v4.14
    // Intel - EC - detected failure to transition to S0ix
    "drivers/platform/chrome/cros_ec"};

std::string DetermineFlag(const std::string& info) {
  // Paths like:
  //   drivers/net/wireless/...
  //   net/wireless/...
  //   net/mac80211/...
  if (info.find("net/wireless") != std::string::npos ||
      info.find("net/mac80211") != std::string::npos)
    return "--kernel_wifi_warning";
  if (RE2::PartialMatch(info, *kernel_suspend_warning))
    return "--kernel_suspend_warning";

  return "--kernel_warning";
}

constexpr LazyRE2 start_ath10k_dump = {R"(ath10k_.*firmware crashed!)"};
constexpr LazyRE2 end_ath10k_dump = {R"(ath10k_.*htt-ver)"};
constexpr LazyRE2 tag_ath10k_dump = {R"(ath10k_)"};

// Older wifi chips have lmac dump only and newer wifi chips have lmac followed
// by umac dumps. The KernelParser should parse the dumps accordingly.
// The following regexp identify the beginning of the iwlwifi dump.
constexpr LazyRE2 start_iwlwifi_dump = {R"(iwlwifi.*Loaded firmware version:)"};

// The following regexp separates the umac and lmac.
constexpr LazyRE2 start_iwlwifi_dump_umac = {R"(Start IWL Error Log Dump(.+))"};
// The following regexps identify the iwlwifi error dump end.
constexpr LazyRE2 end_iwlwifi_dump_umac = {R"((.+)isr status reg)"};
constexpr LazyRE2 end_iwlwifi_dump_lmac = {R"((.+)flow_handler)"};

constexpr char cut_here[] = "------------[ cut here";
constexpr char end_trace[] = "---[ end trace";
constexpr char crash_report_rlimit[] =
    "(crash_reporter) has RLIMIT_CORE set to";

// The CPU and PID information got added in the 3.11 kernel development cycle
// per commit dcb6b45254e2281b6f99ea7f2d51343954aa3ba8. That part is marked
// optional to make sure the old format still gets accepted. Once we no longer
// care about kernel version 3.10 and earlier, we can update the code to require
// CPU and PID to be present unconditionally.
constexpr LazyRE2 header = {
    R"(^\[\s*\S+\] WARNING:(?: CPU: \d+ PID: \d+)? at (.+))"};

constexpr LazyRE2 smmu_fault = {R"(Unhandled context fault: fsr=0x)"};

static constexpr LazyRE2 kernel_lc_suspend_warning = {
    R"((intel_pmc_core.+CPU did not enter SLP_S0!!!))"};

KernelParser::KernelParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

MaybeCrashReport KernelParser::ParseLogEntry(const std::string& line) {
  if (last_line_ == LineType::None) {
    if (line.find(cut_here) != std::string::npos)
      last_line_ = LineType::Start;
  } else if (last_line_ == LineType::Start || last_line_ == LineType::Header) {
    std::string info;
    if (RE2::FullMatch(line, *header, &info)) {
      // The info string looks like: "file:line func+offset/offset() [mod]".
      // The [mod] suffix is only present if the address is located within a
      // kernel module.
      uint32_t hash = StringHash(info.c_str());
      if (WasAlreadySeen(hash)) {
        last_line_ = LineType::None;
        return std::nullopt;
      }
      flag_ = DetermineFlag(info);

      size_t spacep = info.find(" ");
      bool found = spacep != std::string::npos;
      auto function = found ? info.substr(spacep + 1) : "unknown-function";

      text_ += base::StringPrintf("%08x-%s\n", hash, function.c_str());
      text_ += base::StringPrintf("%s\n", info.c_str());
      last_line_ = LineType::Body;
    } else if (last_line_ == LineType::Start) {
      // Allow for a single header line between the "cut here" and the "WARNING"
      last_line_ = LineType::Header;
      text_ += line + "\n";
    } else {
      last_line_ = LineType::None;
    }
  } else if (last_line_ == LineType::Body) {
    if (line.find(end_trace) != std::string::npos) {
      last_line_ = LineType::None;
      std::string text_tmp;
      text_tmp.swap(text_);

      // Sample kernel warnings since they are too noisy and overload the crash
      // server. (See http://b/185156234.)
      const int kWeight = util::GetKernelWarningWeight(flag_);
      if (!testonly_send_all_ && base::RandGenerator(kWeight) != 0) {
        return std::nullopt;
      }
      return CrashReport(
          std::move(text_tmp),
          {std::move(flag_), base::StringPrintf("--weight=%d", kWeight)});
    }
    text_ += line + "\n";
  }

  // Intel kernels >= v4.19 generate suspend warnings using lower-case warning
  // macros, e.g. `pr_warn()`. These do not generate a signature or stack dump,
  // so they are not caught by the kernel warning matching code above. Look for
  // them here, and make sure they are sampled identically to kernel_warning.
  std::string sig;
  if (RE2::PartialMatch(line, *kernel_lc_suspend_warning, &sig)) {
    uint32_t hash = StringHash(sig.c_str());
    if (WasAlreadySeen(hash)) {
      return std::nullopt;
    }
    const std::string flag = "--kernel_suspend_warning";
    // Sample kernel warnings since they are too noisy and overload the crash
    // server. (See http://b/185156234.)
    const int kWeight = util::GetKernelWarningWeight(flag);
    if (!testonly_send_all_ && base::RandGenerator(kWeight) != 0) {
      return std::nullopt;
    }
    return CrashReport(
        sig + "\n",
        {std::move(flag), base::StringPrintf("--weight=%d", kWeight)});
  }

  if (ath10k_last_line_ == Ath10kLineType::None) {
    if (RE2::PartialMatch(line, *start_ath10k_dump)) {
      ath10k_last_line_ = Ath10kLineType::Start;
      ath10k_text_ += line + "\n";
    }
  } else if (ath10k_last_line_ == Ath10kLineType::Start) {
    // Return if the end_ath10k_dump is reached or the log tag doesn't match
    // tag_ath10k_dump.
    if (RE2::PartialMatch(line, *end_ath10k_dump) ||
        !RE2::PartialMatch(line, *tag_ath10k_dump)) {
      ath10k_last_line_ = Ath10kLineType::None;
      if (RE2::PartialMatch(line, *end_ath10k_dump)) {
        ath10k_text_ += line + "\n";
      }
      std::string ath10k_text_tmp;
      ath10k_text_tmp.swap(ath10k_text_);

      const std::string kFlag = "--kernel_ath10k_error";
      const int kWeight = util::GetKernelWarningWeight(kFlag);
      if (!testonly_send_all_ && base::RandGenerator(kWeight) != 0) {
        return std::nullopt;
      }

      return CrashReport(
          std::move(ath10k_text_tmp),
          {std::move(kFlag), base::StringPrintf("--weight=%d", kWeight)});
    }

    ath10k_text_ += line + "\n";
  }

  if (iwlwifi_last_line_ == IwlwifiLineType::None) {
    if (RE2::PartialMatch(line, *start_iwlwifi_dump)) {
      iwlwifi_last_line_ = IwlwifiLineType::Start;
      iwlwifi_text_ += line + "\n";
    }
  } else if (iwlwifi_last_line_ == IwlwifiLineType::Start) {
    if (RE2::PartialMatch(line, *end_iwlwifi_dump_lmac)) {
      iwlwifi_last_line_ = IwlwifiLineType::Lmac;
    } else if (RE2::PartialMatch(line, *end_iwlwifi_dump_umac)) {
      // Return if the line is equal to the umac end. There is never anything
      // after the umac end.
      iwlwifi_last_line_ = IwlwifiLineType::None;
      iwlwifi_text_ += line + "\n";
      std::string iwlwifi_text_tmp;
      iwlwifi_text_tmp.swap(iwlwifi_text_);

      const std::string kFlag = "--kernel_iwlwifi_error";
      const int kWeight = util::GetKernelWarningWeight(kFlag);
      if (!testonly_send_all_ && base::RandGenerator(kWeight) != 0) {
        return std::nullopt;
      }

      return CrashReport(
          std::move(iwlwifi_text_tmp),
          {std::move(kFlag), base::StringPrintf("--weight=%d", kWeight)});
    }
    iwlwifi_text_ += line + "\n";
  } else if (iwlwifi_last_line_ == IwlwifiLineType::Lmac) {
    // Check if there is an umac dump.
    if (RE2::PartialMatch(line, *start_iwlwifi_dump_umac)) {
      iwlwifi_last_line_ = IwlwifiLineType::Start;
      iwlwifi_text_ += line + "\n";
    } else {
      // Return if there is no umac.
      iwlwifi_last_line_ = IwlwifiLineType::None;
      std::string iwlwifi_text_tmp;
      iwlwifi_text_tmp.swap(iwlwifi_text_);

      const std::string kFlag = "--kernel_iwlwifi_error";
      const int kWeight = util::GetKernelWarningWeight(kFlag);
      if (!testonly_send_all_ && base::RandGenerator(kWeight) != 0) {
        return std::nullopt;
      }

      return CrashReport(
          std::move(iwlwifi_text_tmp),
          {std::move(kFlag), base::StringPrintf("--weight=%d", kWeight)});
    }
  }

  if (RE2::PartialMatch(line, *smmu_fault)) {
    std::string smmu_text_tmp = line + "\n";
    return CrashReport(std::move(smmu_text_tmp),
                       {std::move("--kernel_smmu_fault")});
  }

  if (line.find(crash_report_rlimit) != std::string::npos) {
    LOG(INFO) << "crash_reporter crashed!";
    // Rate limit reporting crash_reporter failures to prevent crash loops.
    if (crash_reporter_last_crashed_.is_null() ||
        (base::TimeTicks::Now() - crash_reporter_last_crashed_) >
            base::Hours(1)) {
      crash_reporter_last_crashed_ = base::TimeTicks::Now();
      return CrashReport("", {std::move("--crash_reporter_crashed")});
    }
  }

  return std::nullopt;
}

constexpr char begin_suspend_error_stats[] =
    "Error writing to /sys/power/state: ";
constexpr char end_suspend_error_stats[] =
    "--- end /sys/kernel/debug/suspend_stats ---";
constexpr LazyRE2 last_failed_dev = {R"(\s*last_failed_dev: (.+))"};
constexpr LazyRE2 last_failed_errno = {R"(\s*last_failed_errno: (.+))"};
constexpr LazyRE2 last_failed_step = {R"(\s*last_failed_step: (.+))"};

SuspendParser::SuspendParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

MaybeCrashReport SuspendParser::ParseLogEntry(const std::string& line) {
  // We only want to report a fraction of suspend failures due to noise.
  if (!testonly_send_all_ &&
      base::RandGenerator(util::GetSuspendFailureWeight()) != 0) {
    return std::nullopt;
  }

  if (last_line_ == LineType::None &&
      line.find(begin_suspend_error_stats) == 0) {
    last_line_ = LineType::Start;
    dev_str_ = "none";
    errno_str_ = "unknown";
    step_str_ = "unknown";
    return std::nullopt;
  }

  if (last_line_ != LineType::Start && last_line_ != LineType::Body) {
    return std::nullopt;
  }

  if (line.find(end_suspend_error_stats) != 0) {
    std::string info;
    if (RE2::FullMatch(line, *last_failed_dev, &info)) {
      dev_str_ = info;
    } else if (RE2::FullMatch(line, *last_failed_errno, &info)) {
      errno_str_ = info;
    } else if (RE2::FullMatch(line, *last_failed_step, &info)) {
      step_str_ = info;
    }

    last_line_ = LineType::Body;
    return std::nullopt;
  }

  uint32_t hash = StringHash((dev_str_ + errno_str_ + step_str_).c_str());
  std::string text = base::StringPrintf(
      "%08x-suspend failure: device: %s step: %s errno: %s\n", hash,
      dev_str_.c_str(), step_str_.c_str(), errno_str_.c_str());
  return CrashReport(std::move(text), {"--suspend_failure"});
}

TerminaParser::TerminaParser(
    scoped_refptr<dbus::Bus> dbus,
    std::unique_ptr<MetricsLibraryInterface> metrics_lib,
    bool testonly_send_all)
    : dbus_(dbus),
      metrics_lib_(std::move(metrics_lib)),
      testonly_send_all_(testonly_send_all) {}

constexpr LazyRE2 btrfs_extent_corruption = {
    R"(BTRFS warning \(device .*\): csum failed root [[:digit:]]+ )"
    R"(ino [[:digit:]]+ off [[:digit:]]+ csum 0x[[:xdigit:]]+ expected )"
    R"(csum 0x[[:xdigit:]]+ mirror [[:digit:]]+)"};
constexpr LazyRE2 btrfs_tree_node_corruption = {
    R"(BTRFS warning \(device .*\): .*checksum verify failed on )"
    R"([[:digit:]]+ wanted (0x)?[[:xdigit:]]+ found (0x)?[[:xdigit:]]+ level )"
    R"([[:digit:]]+)"};

MaybeCrashReport TerminaParser::ParseLogEntryForBtrfs(int cid,
                                                      const std::string& line) {
  if (!RE2::PartialMatch(line, *btrfs_extent_corruption) &&
      !RE2::PartialMatch(line, *btrfs_tree_node_corruption)) {
    return std::nullopt;
  }

  anomaly_detector::GuestFileCorruptionSignal message;
  message.set_vsock_cid(cid);
  dbus::Signal signal(anomaly_detector::kAnomalyEventServiceInterface,
                      anomaly_detector::kAnomalyGuestFileCorruptionSignalName);

  dbus::MessageWriter writer(&signal);
  writer.AppendProtoAsArrayOfBytes(message);

  dbus::ExportedObject* exported_object = dbus_->GetExportedObject(
      dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath));
  exported_object->SendSignal(&signal);

  // Don't send a crash report here, because the gap between when the
  // corruption occurs and when we detect it can be arbitrarily large.
  return std::nullopt;
}

constexpr LazyRE2 crostini_oom_event = {
    R"(Out of memory: Killed process [[:digit:]]+ \((.*)\) total-vm:)"
    R"([[:digit:]]+kB, anon-rss:[[:digit:]]+kB, file-rss:[[:digit:]]+kB, )"
    R"(shmem-rss:[[:digit:]]+kB, UID:[[:digit:]]+ pgtables:[[:digit:]]+kB )"
    R"(oom_score_adj:[[:digit:]]+)"};
constexpr char kUMAOomEvent[] = "Crostini.OomEvent";

MaybeCrashReport TerminaParser::ParseLogEntryForOom(int cid,
                                                    const std::string& line) {
  if (!testonly_send_all_ &&
      base::RandGenerator(util::GetOomEventWeight()) != 0) {
    // We only want to report a limited number of oom events due to noise.
    return std::nullopt;
  }
  std::string app_name;
  if (!RE2::PartialMatch(line, *crostini_oom_event, &app_name)) {
    return std::nullopt;
  }

  anomaly_detector::GuestOomEventSignal message;
  message.set_vsock_cid(cid);
  dbus::Signal signal(anomaly_detector::kAnomalyEventServiceInterface,
                      anomaly_detector::kAnomalyGuestOomEventSignalName);

  dbus::MessageWriter writer(&signal);
  writer.AppendProtoAsArrayOfBytes(message);

  dbus::ExportedObject* exported_object = dbus_->GetExportedObject(
      dbus::ObjectPath(anomaly_detector::kAnomalyEventServicePath));
  exported_object->SendSignal(&signal);

  if (!metrics_lib_->SendCrosEventToUMA(kUMAOomEvent)) {
    LOG(WARNING) << "Could not send OomEvent metric to UMA";
  }

  // replace any non-alphanumeric characters with underscores for signature
  RE2::GlobalReplace(&app_name, "[^a-zA-Z0-9_-]", "_");
  std::string text = "guest-oom-event-" + app_name + "\n" + line + '\n';

  return CrashReport(std::move(text), {std::move("--guest_oom_event")});
}

constexpr LazyRE2 cryptohome_mount_failure = {
    R"(Failed to mount cryptohome, error = (\d+))"};

constexpr LazyRE2 cryptohome_recovery_failure = {
    R"(Cryptohome Recovery (.+) failure, error = (.*))"};

CryptohomeParser::CryptohomeParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

MaybeCrashReport CryptohomeParser::ParseLogEntry(const std::string& line) {
  uint64_t error_code;
  if (RE2::PartialMatch(line, *cryptohome_mount_failure, &error_code)) {
    // Avoid creating crash reports if the user doesn't exist or if cryptohome
    // can't authenticate the user's password.
    if (error_code == cryptohome::MOUNT_ERROR_USER_DOES_NOT_EXIST ||
        error_code == cryptohome::MOUNT_ERROR_KEY_FAILURE)
      return std::nullopt;

    return CrashReport("", {std::move("--mount_failure"),
                            std::move("--mount_device=cryptohome")});
  }

  std::string recovery_error_source, recovery_error;
  if (RE2::PartialMatch(line, *cryptohome_recovery_failure,
                        &recovery_error_source, &recovery_error)) {
    if (!testonly_send_all_ &&
        base::RandGenerator(util::GetRecoveryFailureWeight()) != 0) {
      return std::nullopt;
    }
    std::string signature = base::StringPrintf("%s-%s-recovery-failure\n",
                                               recovery_error_source.c_str(),
                                               recovery_error.c_str());
    return CrashReport(signature, {std::move("--cryptohome_recovery_failure")});
  }

  // The line didn't match anything.
  return std::nullopt;
}

constexpr LazyRE2 auth_failure = {
    R"(Found auth failure in the last life cycle. \(0x(.+)\))"};

const std::unordered_set<uint32_t> auth_failure_blocklist = {
    0x2010c9ae,  // wrong password attempts
};

MaybeCrashReport TcsdParser::ParseLogEntry(const std::string& line) {
  uint32_t hash;
  if (!RE2::PartialMatch(line, *auth_failure, RE2::Hex(&hash))) {
    return std::nullopt;
  }
  if (auth_failure_blocklist.count(hash)) {
    LOG(INFO) << "Ignoring auth_failure 0x" << std::hex << hash;
    return std::nullopt;
  }
  std::string text = base::StringPrintf("%08x-auth failure\n", hash);

  return CrashReport(std::move(text), {std::move("--auth_failure")});
}

HermesParser::HermesParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

constexpr LazyRE2 esim_installation_failure = {
    R"(Domain=dbus, Code=org.chromium.Hermes.Error.(\S+), Message=(.*))"};

MaybeCrashReport HermesParser::ParseLogEntry(const std::string& line) {
  std::string error_code;
  std::string error_message;

  int weight = 1;
  if (!RE2::PartialMatch(line, *esim_installation_failure, &error_code,
                         &error_message)) {
    return std::nullopt;
  }

  if (error_code != "SendHttpsFailure" && error_code != "Unknown" &&
      error_code != "ModemMessageProcessing" &&
      error_code != "UnexpectedModemManagerState") {
    return std::nullopt;
  }

  if (error_code == "SendHttpsFailure") {
    weight = 5;
  }

  if (!testonly_send_all_ && base::RandGenerator(weight) != 0) {
    return std::nullopt;
  }

  uint32_t hash = StringHash(error_message.c_str());
  if (WasAlreadySeen(hash)) {
    return std::nullopt;
  }

  std::string text = base::StringPrintf("%08x-%s\n", hash, error_code.c_str());
  const std::string kFlag = "--hermes_failure";
  return CrashReport(std::move(text),
                     {std::move("--hermes_failure"),
                      base::StringPrintf("--weight=%d", weight)});
}

ShillParser::ShillParser(bool testonly_send_all)
    : testonly_send_all_(testonly_send_all) {}

constexpr LazyRE2 mm_failure = {
    R"(dbus.*org.freedesktop.ModemManager1.Error.(\S+), (.*))"};
// logged by shill/manager.cc if cellular fails to enable
constexpr LazyRE2 enable_failure = {
    R"(dbus.*flimflam.Error.(\S+), Message=Enable cellular failed: (.*))"};
// logged by shill/cellular.cc after a connection attempt fails
constexpr LazyRE2 connect_failure = {
    R"((\S+) could not connect \(trigger=(\S+)\) to mccmnc=(\S+): (.*))"};
constexpr LazyRE2 sim_not_inserted_failure = {
    R"(dbus.*org.freedesktop.ModemManager1.Error.Core.WrongState.*)"};
// logged by shill/cellular.cc after an entitlement check fails
constexpr LazyRE2 entitlement_check_failure = {R"(Entitlement check failed:)"};

MaybeCrashReport ShillParser::ParseLogEntry(const std::string& line) {
  std::string error_code;
  std::string error_message;
  std::string carrier;
  std::string modem;
  std::string trigger_mode;
  int weight = 1;
  if (RE2::PartialMatch(line, *connect_failure, &modem, &trigger_mode, &carrier,
                        &error_message)) {
    error_code = modem + "-" + carrier + "-" + trigger_mode + "-connect";
    weight = 5;
  } else if (RE2::PartialMatch(line, *enable_failure, &error_code,
                               &error_message)) {
    error_code = error_code + "-enable";
    weight = 200;
  } else if (RE2::PartialMatch(line, *mm_failure, &error_code,
                               &error_message)) {
    weight = 50;
  } else if (RE2::PartialMatch(line, *entitlement_check_failure)) {
    error_code = "EntitlementCheckFailure";
    weight = 50;
  }
  if (error_code.empty()) {
    return std::nullopt;
  }
  if (RE2::PartialMatch(line, *sim_not_inserted_failure)) {
    return std::nullopt;
  }

  // Writing an integration test for cellular anomalies would require hacks in
  // production code to deterministically trigger an error path, and currently,
  // most anomalies in the field occur due to network, modem, or ChromeOS quirks
  // that need fixing. Such tests would also need to run in a separate cellular
  // pool. Given the complexity of writing and maintaining a cellular
  // integration test for anomaly detector, we prefer to rely on unit tests for
  // current cellular anomalies. ref: b/243522072

  if (!testonly_send_all_ && base::RandGenerator(weight) != 0) {
    return std::nullopt;
  }

  uint32_t hash = StringHash((error_code + error_message).c_str());
  if (WasAlreadySeen(hash)) {
    return std::nullopt;
  }

  std::string text = base::StringPrintf("%08x-%s\n", hash, error_code.c_str());
  const std::string kFlag = "--modem_failure";
  return CrashReport(std::move(text),
                     {std::move("--modem_failure"),
                      base::StringPrintf("--weight=%d", weight)});
}

}  // namespace anomaly
