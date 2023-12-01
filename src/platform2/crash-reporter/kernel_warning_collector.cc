// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_warning_collector.h"

#include <memory>
#include <utility>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/util.h"

namespace {
const char kGenericWarningExecName[] = "kernel-warning";
const char kWifiWarningExecName[] = "kernel-wifi-warning";
const char kSMMUFaultExecName[] = "kernel-smmu-fault";
const char kSuspendWarningExecName[] = "kernel-suspend-warning";
const char kKernelIwlwifiErrorExecName[] = "kernel-iwlwifi-error";
const char kKernelAth10kErrorExecName[] = "kernel-ath10k-error";
const char kKernelWarningSignatureKey[] = "sig";
const pid_t kKernelPid = 0;
}  // namespace

using base::FilePath;
using base::StringPrintf;

KernelWarningCollector::KernelWarningCollector()
    : CrashCollector("kernel_warning"), warning_report_path_("/dev/stdin") {}

KernelWarningCollector::~KernelWarningCollector() {}

bool KernelWarningCollector::LoadKernelWarning(std::string* content,
                                               std::string* signature,
                                               std::string* func_name,
                                               WarningType type) {
  FilePath kernel_warning_path(warning_report_path_.c_str());
  if (!base::ReadFileToString(kernel_warning_path, content)) {
    PLOG(ERROR) << "Could not open " << kernel_warning_path.value();
    return false;
  }

  if (type == kIwlwifi) {
    if (!ExtractIwlwifiSignature(*content, signature, func_name)) {
      return false;
    } else if (signature->length() > 0) {
      return true;
    }
  } else if (type == kSMMUFault) {
    if (!ExtractSMMUFaultSignature(*content, signature, func_name)) {
      return false;
    } else if (signature->length() > 0) {
      return true;
    }
  } else if (type == kAth10k) {
    if (!ExtractAth10kSignature(*content, signature, func_name)) {
      return false;
    } else if (signature->length() > 0) {
      return true;
    }
  } else {
    if (!ExtractSignature(*content, signature, func_name)) {
      return false;
    } else if (signature->length() > 0) {
      return true;
    }
  }

  LOG(WARNING) << "Couldn't find match for signature line. "
               << "Falling back to first line of warning.";
  *signature = content->substr(0, content->find('\n'));
  return true;
}

// Extract the crashing function name from the signature.
// Signature example: 6a839c19-lkdtm_do_action+0x225/0x5bc
// Signature example2: 6a839c19-unknown-function+0x161/0x344 [iwlmvm]
constexpr LazyRE2 sig_re = {R"(^[0-9a-fA-F]+-([0-9a-zA-Z_-]+)\+.*$)"};

bool KernelWarningCollector::ExtractSignature(const std::string& content,
                                              std::string* signature,
                                              std::string* func_name) {
  // The signature is in the first or second line.
  // First, try the first, and if it's not there, try the second.
  std::string::size_type end_position = content.find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected kernel warning format";
    return false;
  }
  size_t start = 0;
  for (int i = 0; i < 2; i++) {
    *signature = content.substr(start, end_position - start);

    if (RE2::FullMatch(*signature, *sig_re, func_name)) {
      return true;
    } else {
      LOG(INFO) << *signature << " does not match regex";
      signature->clear();
      func_name->clear();
    }

    // Else, try the next line.
    start = end_position + 1;
    end_position = content.find('\n', start);
  }

  return true;
}

// Extract the crashing function name from the signature.
// The crashing function for the lmac appears after the line:
// Loaded firmware version: 46.b20aefee.0
// Signature example: 0x00000084 | NMI_INTERRUPT_UNKNOWN
// The crashing function for the umac appears after the line:
// iwlwifi 0000:00:0c.0: Status: 0x00000100, count: 7
// Signature example: 0x20000066 | NMI_INTERRUPT_HOST
constexpr LazyRE2 before_iwlwifi_assert_lmac = {
    R"(iwlwifi (?:.+): Loaded firmware version:)"};
constexpr LazyRE2 before_iwlwifi_assert_umac = {R"(iwlwifi (?:.+): Status:)"};
constexpr LazyRE2 iwlwifi_sig_re = {
    R"((iwlwifi (?:.+): \b(\w+)\b \| \b(\w+)\b))"};

enum class LineType {
  Umac,
  Lmac,
  None,
  CheckUmac,
};

bool KernelWarningCollector::ExtractIwlwifiSignature(const std::string& content,
                                                     std::string* signature,
                                                     std::string* func_name) {
  LineType last_line = LineType::None;
  // Extracting the function name depends on where the assert occurs in
  // lmac/umac:
  // 1- Assert in lmac:
  //       The umac have the default assert value in its signature
  //       (0x20000070).
  // 2- Assert in umac:
  //       The lmac have the default assert value in its signature
  //       (0x00000071).
  // Based on that, the function name in lmac/umac should be ignored if the
  // assert number in the signature is equal to 0x00000071 in lmac or 0x20000070
  // in umac.
  const std::string default_lmac_assert = "0x00000071";
  const std::string default_umac_assert = "0x20000070";
  // The signature is reported as unknown in the case of parsing error.
  const std::string unknown_iwlwifi_signature = "iwlwifi unknown signature";
  std::string assert_number;
  std::string iwlwifi_signature;
  std::string::size_type end_position = content.find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected kernel iwlwifi error format";
    return false;
  }

  // Look for the signature in the lmac and check the assert number. if the lmac
  // assert number not equal (0x00000071), then return that as the signature.
  // Otherwise, check the signature of the umac. if the umac assert number not
  // equal (0x20000070), then return that as the signature. Otherwise, break.
  size_t start = 0;
  size_t end = content.size();
  while (start < end && end_position != std::string::npos) {
    *signature = content.substr(start, end_position - start);

    if (last_line == LineType::None) {
      if (RE2::PartialMatch(*signature, *before_iwlwifi_assert_lmac)) {
        last_line = LineType::Lmac;
      }
    } else if (last_line == LineType::Lmac) {
      // Check the signature of the lmac.
      if (RE2::PartialMatch(*signature, *iwlwifi_sig_re, &iwlwifi_signature,
                            &assert_number, func_name)) {
        if (default_lmac_assert != assert_number) {
          *signature = iwlwifi_signature;
          return true;
        } else {
          // Check umac if the lmac assertion number == default_lmac_assert.
          last_line = LineType::CheckUmac;
          signature->clear();
          func_name->clear();
        }
      } else {
        // Break if the signature of the lmac didn't match.
        LOG(INFO) << *signature << " does not match lmac regex";
        *signature = unknown_iwlwifi_signature;
        func_name->clear();
        break;
      }
    } else if (last_line == LineType::CheckUmac) {
      // Check the line before the umac signature.
      if (RE2::PartialMatch(*signature, *before_iwlwifi_assert_umac)) {
        last_line = LineType::Umac;
      }
    } else if (last_line == LineType::Umac) {
      // Check the signature of the umac.
      if (RE2::PartialMatch(*signature, *iwlwifi_sig_re, &iwlwifi_signature,
                            &assert_number, func_name)) {
        if (default_umac_assert != assert_number) {
          *signature = iwlwifi_signature;
          return true;
        } else {
          // Break if the umac assertion number == default_umac_assert.
          LOG(ERROR) << "unexpected kernel iwlwifi error format. "
                        "Both umac/lmac dumps have the default assert numbers.";
          *signature = unknown_iwlwifi_signature;
          func_name->clear();
          break;
        }
      } else {
        // Break if the signature of the umac didn't match.
        LOG(INFO) << *signature << " does not match umac regex";
        *signature = unknown_iwlwifi_signature;
        func_name->clear();
        break;
      }
    }

    // Else, try the next line.
    start = end_position + 1;
    end_position = content.find('\n', start);
  }

  return true;
}

constexpr LazyRE2 smmu_sig_re = {R"((\S+): Unhandled context fault: (.*))"};

bool KernelWarningCollector::ExtractSMMUFaultSignature(
    const std::string& content,
    std::string* signature,
    std::string* func_name) {
  // The signature is the part of the line after "Unhandled context fault:"
  std::string line;
  std::string::size_type end_position = content.find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected smmu fault warning format";
    return false;
  }

  line = content.substr(0, end_position);
  if (RE2::PartialMatch(line, *smmu_sig_re, func_name, signature)) {
    return true;
  }
  LOG(INFO) << line << " does not match regex";
  signature->clear();
  func_name->clear();
  return false;
}

constexpr LazyRE2 ath10k_sig_re = {R"((ath10k_.*firmware crashed))"};

bool KernelWarningCollector::ExtractAth10kSignature(const std::string& content,
                                                    std::string* signature,
                                                    std::string* func_name) {
  std::string line;
  std::string::size_type end_position = content.find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected ath10k crash format";
    return false;
  }

  line = content.substr(0, end_position);
  if (RE2::PartialMatch(line, *ath10k_sig_re, signature)) {
    *func_name = "firmware crashed";
    return true;
  }
  LOG(INFO) << line << " does not match regex";
  signature->clear();
  func_name->clear();
  return false;
}

bool KernelWarningCollector::Collect(int weight, WarningType type) {
  LOG(INFO) << "Processing kernel warning";

  if (weight != 1) {
    AddCrashMetaUploadData("weight", StringPrintf("%d", weight));
  }

  std::string kernel_warning;
  std::string warning_signature;
  std::string func_name;
  if (!LoadKernelWarning(&kernel_warning, &warning_signature, &func_name,
                         type)) {
    return false;
  }

  FilePath root_crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(constants::kRootUid,
                                      &root_crash_directory, nullptr)) {
    return false;
  }

  const char* exec_name;
  if (type == kWifi)
    exec_name = kWifiWarningExecName;
  else if (type == kSMMUFault)
    exec_name = kSMMUFaultExecName;
  else if (type == kSuspend)
    exec_name = kSuspendWarningExecName;
  else if (type == kGeneric)
    exec_name = kGenericWarningExecName;
  else if (type == kAth10k)
    exec_name = kKernelAth10kErrorExecName;
  else
    exec_name = kKernelIwlwifiErrorExecName;

  // Attempt to make the exec_name more unique to avoid collisions.
  if (!func_name.empty()) {
    func_name.insert(func_name.begin(), '_');
  } else {
    LOG(WARNING) << "Couldn't extract function name from signature. "
                    "Going on without it.";
  }

  std::string dump_basename = FormatDumpBasename(
      base::StrCat({exec_name, func_name}), time(nullptr), kKernelPid);
  FilePath log_path =
      GetCrashPath(root_crash_directory, dump_basename, "log.gz");
  FilePath meta_path =
      GetCrashPath(root_crash_directory, dump_basename, "meta");
  FilePath kernel_crash_path = root_crash_directory.Append(
      StringPrintf("%s.kcrash", dump_basename.c_str()));

  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(kernel_crash_path, kernel_warning) !=
      static_cast<int>(kernel_warning.length())) {
    LOG(INFO) << "Failed to write kernel warning to "
              << kernel_crash_path.value().c_str();
    return true;
  }

  AddCrashMetaData(kKernelWarningSignatureKey, warning_signature);

  // Get the log contents, compress, and attach to crash report.
  bool result = GetLogContents(log_config_path_, exec_name, log_path);
  if (result) {
    AddCrashMetaUploadFile("log", log_path.BaseName().value());
  }

  FinishCrash(meta_path, exec_name, kernel_crash_path.BaseName().value());

  return true;
}

// static
CollectorInfo KernelWarningCollector::GetHandlerInfo(
    int32_t weight,
    bool kernel_warning,
    bool kernel_wifi_warning,
    bool kernel_smmu_fault,
    bool kernel_suspend_warning,
    bool kernel_iwlwifi_error,
    bool kernel_ath10k_error) {
  auto collector = std::make_shared<KernelWarningCollector>();
  base::RepeatingCallback<bool(KernelWarningCollector::WarningType)>
      kernel_warn_cb = base::BindRepeating(&KernelWarningCollector::Collect,
                                           collector, weight);
  return {
      .collector = collector,
      .handlers =
          {{
               .should_handle = kernel_warning,
               .cb = base::BindRepeating(kernel_warn_cb, WarningType::kGeneric),
           },
           {
               .should_handle = kernel_wifi_warning,
               .cb = base::BindRepeating(kernel_warn_cb, WarningType::kWifi),
           },
           {
               .should_handle = kernel_smmu_fault,
               .cb =
                   base::BindRepeating(kernel_warn_cb, WarningType::kSMMUFault),
           },
           {
               .should_handle = kernel_suspend_warning,
               .cb = base::BindRepeating(kernel_warn_cb, WarningType::kSuspend),
           },
           {
               .should_handle = kernel_iwlwifi_error,
               .cb = base::BindRepeating(kernel_warn_cb, WarningType::kIwlwifi),
           },
           {
               .should_handle = kernel_ath10k_error,
               .cb = base::BindRepeating(kernel_warn_cb, WarningType::kAth10k),
           }},
  };
}
