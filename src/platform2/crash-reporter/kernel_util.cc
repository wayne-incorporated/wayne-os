// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_util.h"

#include <algorithm>
#include <iterator>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "crash-reporter/util.h"

using base::StringPiece;
using base::StringPrintf;

namespace {

constexpr char kDefaultKernelStackSignature[] =
    "kernel-UnspecifiedStackSignature";

// Byte length of maximum human readable portion of a kernel crash signature.
constexpr size_t kMaxHumanStringLength = 40;
// Time in seconds from the final kernel log message for a call stack
// to count towards the signature of the kcrash.
constexpr int kSignatureTimestampWindow = 2;
// Kernel log timestamp regular expression.
// Specify the multiline option so that ^ matches the start of lines, not just
// the start of the text.
constexpr char kTimestampRegex[] = "(?m)^<.*>\\[\\s*(\\d+\\.\\d+)\\]";

//
// These regular expressions enable to us capture the function name of
// the PC in a backtrace.
// The backtrace is obtained through dmesg or the kernel's preserved/kcrashmem
// feature.
//
// For ARM we see:
//   "<5>[   39.458982] PC is at write_breakme+0xd0/0x1b4" (arm32)
//   "<4>[  263.857834] pc : lkdtm_BUG+0xc/0x10" (arm64)
// For MIPS we see:
//   "<5>[ 3378.552000] epc   : 804010f0 lkdtm_do_action+0x68/0x3f8"
// For x86:
//   "<0>[   37.474699] EIP: [<790ed488>] write_breakme+0x80/0x108
//    SS:ESP 0068:e9dd3efc"
// For x86_64:
//   "<5>[ 1505.853254] RIP: 0010:[<ffffffff94fb0c27>] [<ffffffff94fb0c27>]
//   list_del_init+0x8/0x1b" (v4.10-)
//   "<4>[ 2358.194253] RIP: 0010:pick_task_fair+0x55/0x77" (v4.10+)
//
const char* const kPCFuncNameRegex[] = {
    nullptr, R"( (?:PC is at |pc : )([^\+\[ ]+).*)",
    R"( epc\s+:\s+\S+\s+([^\+ ]+).*)",  // MIPS has an exception
                                        // program counter
    R"( EIP: \[<.*>\] ([^\+ ]+).*)",    // X86 uses EIP for the
                                        // program counter
    R"( RIP: [[:xdigit:]]{4}:(?:\[<[[:xdigit:]]+>\] \[<[[:xdigit:]]+>\] )?)"
    R"(([^\+ ]+)\+0x.*)",  // X86_64 uses RIP
};

static_assert(std::size(kPCFuncNameRegex) == kernel_util::kArchCount,
              "Missing Arch PC func_name RegExp");

void ProcessStackTrace(re2::StringPiece kernel_dump,
                       unsigned* hash,
                       float* last_stack_timestamp,
                       bool* is_watchdog_crash) {
  RE2 line_re("(.+)");

  RE2::Options opt;
  opt.set_case_sensitive(false);
  RE2 stack_trace_start_re(
      std::string(kTimestampRegex) + " (Call Trace|Backtrace):$", opt);

  // Match lines such as the following and grab out "function_name".
  // The ? may or may not be present.
  //
  // For ARM:
  // <4>[ 3498.731164] [<c0057220>] ? (function_name+0x20/0x2c) from
  // [<c018062c>] (foo_bar+0xdc/0x1bc) (arm32 older)
  // <4>[  263.956936]  lkdtm_do_action+0x24/0x40 (arm64 / arm32 newer)
  //
  // For MIPS:
  // <5>[ 3378.656000] [<804010f0>] lkdtm_do_action+0x68/0x3f8
  //
  // For X86:
  // <4>[ 6066.849504]  [<7937bcee>] ? function_name+0x66/0x6c
  // <4>[ 2358.194379]  __schedule+0x83f/0xf92 (newer) like arm64 above
  //
  RE2 stack_entry_re(
      std::string(kTimestampRegex) +
      R"(\s+(?:\[<[[:xdigit:]]+>\])?)"  // Matches "  [<7937bcee>]" (if any)
      R"(([\s?(]+))"                    // Matches " ? (" (ARM) or " ? " (X86)
      R"(([^\+ )]+))");                 // Matches until delimiter reached
  std::string line;
  std::string hashable;
  std::string previous_hashable;
  bool is_watchdog = false;

  *hash = 0;
  *last_stack_timestamp = 0;

  // Find the last and second-to-last stack traces.  The latter is used when
  // the panic is from a watchdog timeout.
  while (RE2::FindAndConsume(&kernel_dump, line_re, &line)) {
    std::string certainty;
    std::string function_name;
    if (RE2::PartialMatch(line, stack_trace_start_re, last_stack_timestamp)) {
      previous_hashable = hashable;
      hashable.clear();
      is_watchdog = false;
    } else if (RE2::PartialMatch(line, stack_entry_re, last_stack_timestamp,
                                 &certainty, &function_name)) {
      bool is_certain = certainty.find('?') == std::string::npos;
      // Do not include any uncertain (prefixed by '?') frames in our hash.
      if (!is_certain)
        continue;
      if (!hashable.empty())
        hashable.append("|");
      if (function_name == "watchdog_timer_fn" || function_name == "watchdog") {
        is_watchdog = true;
      }
      hashable.append(function_name);
    }
  }

  // If the last stack trace contains a watchdog function we assume the panic
  // is from the watchdog timer, and we hash the previous stack trace rather
  // than the last one, assuming that the previous stack is that of the hung
  // thread.
  //
  // In addition, if the hashable is empty (meaning all frames are uncertain,
  // for whatever reason) also use the previous frame, as it cannot be any
  // worse.
  if (is_watchdog || hashable.empty()) {
    hashable = previous_hashable;
  }

  *hash = util::HashString(StringPiece(hashable));
  *is_watchdog_crash = is_watchdog;
}

bool FindCrashingFunction(re2::StringPiece kernel_dump,
                          float stack_trace_timestamp,
                          kernel_util::ArchKind arch,
                          std::string* crashing_function) {
  float timestamp = 0;

  // Use the correct regex for this architecture.
  if (kPCFuncNameRegex[arch] == nullptr) {
    LOG(WARNING) << "PC func_name RegExp is not defined for this architecture";
    return false;
  }
  RE2 func_re(std::string(kTimestampRegex) + kPCFuncNameRegex[arch]);

  while (RE2::FindAndConsume(&kernel_dump, func_re, &timestamp,
                             crashing_function)) {
  }
  if (timestamp == 0) {
    LOG(WARNING) << "Found no crashing function";
    return false;
  }
  if (stack_trace_timestamp != 0 &&
      abs(static_cast<int>(stack_trace_timestamp - timestamp)) >
          kSignatureTimestampWindow) {
    LOG(WARNING) << "Found crashing function but not within window";
    return false;
  }
  return true;
}

bool FindPanicMessage(re2::StringPiece kernel_dump,
                      std::string* panic_message) {
  // Match lines such as the following and grab out "Fatal exception"
  // <0>[  342.841135] Kernel panic - not syncing: Fatal exception
  RE2 kernel_panic_re(std::string(kTimestampRegex) +
                      " Kernel panic[^\\:]*\\:\\s*(.*)");
  float timestamp = 0;
  while (RE2::FindAndConsume(&kernel_dump, kernel_panic_re, &timestamp,
                             panic_message)) {
  }
  if (timestamp == 0) {
    LOG(WARNING) << "Found no panic message";
    return false;
  }
  return true;
}

}  // namespace

namespace kernel_util {

const char kKernelExecName[] = "kernel";
const char kHypervisorExecName[] = "hypervisor";

bool IsHypervisorCrash(const std::string& kernel_dump) {
  RE2 hypervisor_re("Linux version [0-9.]+-manatee");
  return RE2::PartialMatch(kernel_dump, hypervisor_re);
}

ArchKind GetCompilerArch() {
#if defined(COMPILER_GCC) && defined(ARCH_CPU_ARM_FAMILY)
  return kArchArm;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_MIPS_FAMILY)
  return kArchMips;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_X86_64)
  return kArchX86_64;
#elif defined(COMPILER_GCC) && defined(ARCH_CPU_X86_FAMILY)
  return kArchX86;
#else
  return kArchUnknown;
#endif
}

std::string ComputeKernelStackSignature(const std::string& kernel_dump,
                                        ArchKind arch) {
  unsigned stack_hash = 0;
  float last_stack_timestamp = 0;
  std::string human_string;
  bool is_watchdog_crash;

  ProcessStackTrace(kernel_dump, &stack_hash, &last_stack_timestamp,
                    &is_watchdog_crash);

  if (!FindCrashingFunction(kernel_dump, last_stack_timestamp, arch,
                            &human_string)) {
    if (!FindPanicMessage(kernel_dump, &human_string)) {
      LOG(WARNING) << "Found no human readable string, using empty string";
      human_string.clear();
    }
  }

  if (human_string.empty() && stack_hash == 0) {
    LOG(WARNING) << "Cannot find a stack or a human readable string";
    return kDefaultKernelStackSignature;
  }

  human_string = human_string.substr(0, kMaxHumanStringLength);
  return StringPrintf("%s-%s%s-%08X", kKernelExecName,
                      (is_watchdog_crash ? "(HANG)-" : ""),
                      human_string.c_str(), stack_hash);
}

std::string BiosCrashSignature(const std::string& dump) {
  const char* type = "";

  if (RE2::PartialMatch(dump, RE2("PANIC in EL3")))
    type = "PANIC";
  else if (RE2::PartialMatch(dump, RE2("Unhandled Exception in EL3")))
    type = "EXCPT";
  else if (RE2::PartialMatch(dump, RE2("Unhandled Interrupt Exception in")))
    type = "INTR";

  std::string elr;
  RE2::PartialMatch(dump, RE2("x30 =\\s+(0x[0-9a-fA-F]+)"), &elr);

  return StringPrintf("bios-(%s)-%s", type, elr.c_str());
}

std::string ComputeNoCErrorSignature(const std::string& dump) {
  RE2 line_re("(.+)");
  re2::StringPiece dump_piece = dump;

  // Match lines such as the following and grab out the type of NoC (MMSS)
  // and the register contents
  //
  // QTISECLIB [1727120e379]MMSS_NOC ERROR: ERRLOG0_LOW = 0x00000105
  //
  RE2 noc_entry_re(R"(QTISECLIB \[[[:xdigit:]]+\]([a-zA-Z]+)_NOC ERROR: )"
                   R"(ERRLOG[0-9]_(?:(LOW|HIGH)) = ([[:xdigit:]]+))");
  std::string line;
  std::string hashable;
  std::string noc_name;
  std::string first_noc;
  std::string regval;

  // Look at each line of the bios log for the NOC errors and compute a hash
  // of all the registers
  while (RE2::FindAndConsume(&dump_piece, line_re, &line)) {
    if (RE2::PartialMatch(line, noc_entry_re, &noc_name, &regval)) {
      if (!hashable.empty())
        hashable.append("|");
      if (first_noc.empty())
        first_noc = noc_name;
      hashable.append(noc_name);
      hashable.append("|");
      hashable.append(regval);
    }
  }

  unsigned hash = util::HashString(StringPiece(hashable));

  return StringPrintf("%s-(NOC-Error)-%s-%08X", kKernelExecName,
                      first_noc.c_str(), hash);
}

// Watchdog reboots leave no stack trace. Generate a poor man's signature out
// of the last log line instead (minus the timestamp ended by ']').
std::string WatchdogSignature(const std::string& console_ramoops,
                              const std::string& watchdogRebootReason) {
  StringPiece line(console_ramoops);
  constexpr char kTimestampEnd[] = "] ";
  size_t timestamp_end_pos = line.rfind(kTimestampEnd);
  if (timestamp_end_pos != StringPiece::npos) {
    line = line.substr(timestamp_end_pos + strlen(kTimestampEnd));
  }
  size_t newline_pos = line.find("\n");
  size_t end = (newline_pos == StringPiece::npos
                    ? StringPiece::npos
                    : std::min(newline_pos, kMaxHumanStringLength));
  return StringPrintf(
      "%s%s-%s-%08X", kKernelExecName, watchdogRebootReason.c_str(),
      std::string(line.substr(0, end)).c_str(), util::HashString(line));
}

bool ExtractHypervisorLog(std::string& console_ramoops,
                          std::string& hypervisor_log) {
  RE2 hypervisor_log_re("(?s)(\\n-*\\[ hypervisor log \\]-*\\n)(.*)$");
  re2::StringPiece header;
  if (RE2::PartialMatch(console_ramoops, hypervisor_log_re, &header,
                        &hypervisor_log)) {
    console_ramoops.resize(console_ramoops.size() - hypervisor_log.size() -
                           header.size());
    return true;
  }
  return false;
}

}  // namespace kernel_util
