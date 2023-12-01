// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/memory_fetcher.h"

#include <optional>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/cros_healthd/utils/memory_info.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using OptionalProbeErrorPtr = std::optional<mojom::ProbeErrorPtr>;

// Path to procfs, relative to the root directory.
constexpr char kRelativeProcCpuInfoPath[] = "proc/cpuinfo";
constexpr char kRelativeProcPath[] = "proc";
constexpr char kRelativeMktmePath[] = "sys/kernel/mm/mktme";
constexpr char kMktmeActiveFile[] = "active";
constexpr char kMktmeActiveAlgorithmFile[] = "active_algo";
constexpr char kMktmeKeyCountFile[] = "keycnt";
constexpr char kMktmeKeyLengthFile[] = "keylen";
constexpr uint64_t kTmeBypassAllowBit = (uint64_t)1 << 31;
constexpr uint64_t kTmeAllowAesXts128 = 1;
constexpr uint64_t kTmeAllowAesXts256 = (uint64_t)1 << 2;
constexpr uint64_t kTmeEnableBit = (uint64_t)1 << 1;
constexpr uint64_t kTmeBypassBit = (uint64_t)1 << 31;
// tme agorithm mask bits[7:4].
constexpr uint64_t kTmeAlgorithmMask = ((uint64_t)1 << 8) - ((uint64_t)1 << 4);
// AES_XTS_128: bits[7:4] == 0
constexpr uint64_t kTmeAlgorithmAesXts128 = 0;
// AES_XTS_128: bits[7:4] == 2
constexpr uint64_t kTmeAlgorithmAesXts256 = (uint64_t)2 << 4;

}  // namespace

// Sets the total_memory_kib, free_memory_kib and available_memory_kib fields of
// |info| with information read from proc/meminfo. Returns any error
// encountered probing the memory information. |info| is valid iff no error
// occurred.
void MemoryFetcher::ParseProcMemInfo(mojom::MemoryInfo* info) {
  auto memory_info = MemoryInfo::ParseFrom(context_->root_dir());
  if (!memory_info.has_value()) {
    CreateErrorAndSendBack(mojom::ErrorType::kParseError,
                           "Error parsing /proc/meminfo");
    return;
  }
  info->total_memory_kib = memory_info.value().total_memory_kib;
  info->free_memory_kib = memory_info.value().free_memory_kib;
  info->available_memory_kib = memory_info.value().available_memory_kib;
}

// Sets the page_faults_per_second field of |info| with information read from
// /proc/vmstat. Returns any error encountered probing the memory information.
// |info| is valid iff no error occurred.
void MemoryFetcher::ParseProcVmStat(mojom::MemoryInfo* info) {
  std::string file_contents;
  if (!ReadAndTrimString(context_->root_dir().Append(kRelativeProcPath),
                         "vmstat", &file_contents)) {
    CreateErrorAndSendBack(mojom::ErrorType::kFileReadError,
                           "Unable to read /proc/vmstat");
    return;
  }

  // Parse the vmstat contents for pgfault.
  base::StringPairs keyVals;
  if (!base::SplitStringIntoKeyValuePairs(file_contents, ' ', '\n', &keyVals)) {
    CreateErrorAndSendBack(mojom::ErrorType::kParseError,
                           "Incorrectly formatted /proc/vmstat");
    return;
  }

  bool pgfault_found = false;
  for (int i = 0; i < keyVals.size(); i++) {
    if (keyVals[i].first == "pgfault") {
      uint64_t num_page_faults;
      if (base::StringToUint64(keyVals[i].second, &num_page_faults)) {
        info->page_faults_since_last_boot = num_page_faults;
        pgfault_found = true;
        break;
      } else {
        CreateErrorAndSendBack(mojom::ErrorType::kParseError,
                               "Incorrectly formatted pgfault");
        return;
      }
    }
  }

  if (!pgfault_found) {
    CreateErrorAndSendBack(mojom::ErrorType::kParseError,
                           "pgfault not found in /proc/vmstat");
    return;
  }
}

void MemoryFetcher::CreateResultAndSendBack() {
  SendBackResult(mojom::MemoryResult::NewMemoryInfo(mem_info_.Clone()));
}

void MemoryFetcher::CreateErrorAndSendBack(mojom::ErrorType error_type,
                                           const std::string& message) {
  SendBackResult(mojom::MemoryResult::NewError(
      CreateAndLogProbeError(error_type, message)));
}

void MemoryFetcher::SendBackResult(mojom::MemoryResultPtr result) {
  // Invalid all weak ptrs to prevent other callbacks to be run.
  weak_factory_.InvalidateWeakPtrs();
  if (pending_callbacks_.empty())
    return;
  for (size_t i = 1; i < pending_callbacks_.size(); ++i) {
    std::move(pending_callbacks_[i]).Run(result.Clone());
  }
  std::move(pending_callbacks_[0]).Run(std::move(result));
  pending_callbacks_.clear();
}

// Parse mktme information.
void MemoryFetcher::FetchMktmeInfo() {
  auto mktme_path = context_->root_dir().Append(kRelativeMktmePath);
  // Directory /sys/kernel/mktme existence indicates mktme support.
  if (!base::PathExists(mktme_path)) {
    CreateResultAndSendBack();
    return;
  }
  auto memory_encryption_info = mojom::MemoryEncryptionInfo::New();
  std::string file_contents;

  // Check if mktme enabled or not.
  if (!ReadAndTrimString(mktme_path, kMktmeActiveFile, &file_contents)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kFileReadError,
        "Unable to read " + mktme_path.Append(kMktmeActiveFile).value());
    return;
  }
  uint32_t value;
  if (!base::StringToUint(file_contents, &value)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kParseError,
        "Failed to convert mktme enable state to integer: " + file_contents);
    return;
  }
  memory_encryption_info->encryption_state =
      (value != 0) ? mojom::EncryptionState::kMktmeEnabled
                   : mojom::EncryptionState::kEncryptionDisabled;

  // Get max number of key support.
  if (!ReadAndTrimString(mktme_path, kMktmeKeyCountFile, &file_contents)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kFileReadError,
        "Unable to read " + mktme_path.Append(kMktmeKeyCountFile).value());
    return;
  }
  if (!base::StringToUint(file_contents,
                          &memory_encryption_info->max_key_number)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kParseError,
        "Failed to convert mktme maximum key number to integer: " +
            file_contents);
    return;
  }

  // Get key length.
  if (!ReadAndTrimString(mktme_path, kMktmeKeyLengthFile, &file_contents)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kFileReadError,
        "Unable to read " + mktme_path.Append(kMktmeKeyLengthFile).value());
    return;
  }
  if (!base::StringToUint(file_contents, &memory_encryption_info->key_length)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kParseError,
        "Failed to convert mktme key length to integer: " + file_contents);
    return;
  }

  // Get active algorithm.
  if (!ReadAndTrimString(mktme_path, kMktmeActiveAlgorithmFile,
                         &file_contents)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kFileReadError,
        "Unable to read " +
            mktme_path.Append(kMktmeActiveAlgorithmFile).value());
    return;
  }
  if (file_contents == "AES_XTS_256") {
    memory_encryption_info->active_algorithm =
        mojom::CryptoAlgorithm::kAesXts256;
  } else if (file_contents == "AES_XTS_128") {
    memory_encryption_info->active_algorithm =
        mojom::CryptoAlgorithm::kAesXts128;
  } else {
    memory_encryption_info->active_algorithm = mojom::CryptoAlgorithm::kUnknown;
  }
  mem_info_.memory_encryption_info = std::move(memory_encryption_info);
  CreateResultAndSendBack();
}

void MemoryFetcher::ExtractTmeInfoFromMsr() {
  mojom::MemoryEncryptionInfo info;
  // tme enabled when hardware tme enabled and tme encryption not bypassed.
  bool tme_enable = ((tme_activate_value_ & kTmeEnableBit) &&
                     (!(tme_capability_value_ & kTmeBypassAllowBit) ||
                      !(tme_activate_value_ & kTmeBypassBit)));
  info.encryption_state = tme_enable
                              ? mojom::EncryptionState::kTmeEnabled
                              : mojom::EncryptionState::kEncryptionDisabled;
  info.max_key_number = 1;

  if (((tme_activate_value_ & kTmeAlgorithmMask) == kTmeAlgorithmAesXts128) &&
      (tme_capability_value_ & kTmeAllowAesXts128)) {
    info.active_algorithm = mojom::CryptoAlgorithm::kAesXts128;
    info.key_length = 128;
  } else if (((tme_activate_value_ & kTmeAlgorithmMask) ==
              kTmeAlgorithmAesXts256) &&
             (tme_capability_value_ & kTmeAllowAesXts256)) {
    info.active_algorithm = mojom::CryptoAlgorithm::kAesXts256;
    info.key_length = 256;
  } else {
    info.active_algorithm = mojom::CryptoAlgorithm::kUnknown;
    info.key_length = 0;
  }
  mem_info_.memory_encryption_info = info.Clone();
  CreateResultAndSendBack();
}

void MemoryFetcher::HandleReadTmeActivateMsr(mojom::NullableUint64Ptr val) {
  DCHECK(mem_info_.memory_encryption_info);
  if (val.is_null()) {
    CreateErrorAndSendBack(mojom::ErrorType::kFileReadError,
                           "Error while reading tme activate msr");
    return;
  }
  tme_activate_value_ = val->value;
  ExtractTmeInfoFromMsr();
}

void MemoryFetcher::HandleReadTmeCapabilityMsr(mojom::NullableUint64Ptr val) {
  DCHECK(mem_info_.memory_encryption_info);
  if (val.is_null()) {
    CreateErrorAndSendBack(mojom::ErrorType::kFileReadError,
                           "Error while reading tme capability msr");
    return;
  }
  tme_capability_value_ = val->value;
  // Values of MSR registers IA32_TME_ACTIVATE_MSR (0x982) will be the same in
  // all CPU cores. Therefore, we are only interested in reading the values in
  // CPU0.
  context_->executor()->ReadMsr(
      cpu_msr::kIA32TmeActivate, 0,
      base::BindOnce(&MemoryFetcher::HandleReadTmeActivateMsr,
                     weak_factory_.GetWeakPtr()));
}

void MemoryFetcher::FetchTmeInfo() {
  std::string file_content;
  // First check tme flag in /proc/cpuinfo to see tme support by the CPU or not.
  if (!ReadAndTrimString(context_->root_dir().Append(kRelativeProcCpuInfoPath),
                         &file_content)) {
    CreateErrorAndSendBack(
        mojom::ErrorType::kFileReadError,
        "Unable to read " +
            context_->root_dir().Append(kRelativeProcCpuInfoPath).value());
    return;
  }

  std::vector<std::string> lines = base::SplitString(
      file_content, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  std::string flags_line;
  // Parse for the line starting with "flags" in /proc/cpuinfo for CPU 0 only
  // (until first empty line).
  for (const auto& line : lines) {
    if (line.empty()) {
      break;
    }
    if ("flags" == line.substr(0, line.find('\t'))) {
      flags_line = line;
      break;
    }
  }
  // "tme" flag indicates tme supported by CPU.
  if (flags_line.find("tme") == std::string::npos) {
    CreateResultAndSendBack();
    return;
  }

  mem_info_.memory_encryption_info = mojom::MemoryEncryptionInfo::New();
  // Values of MSR registers IA32_TME_CAPABILITY (0x981) will be the same in all
  // CPU cores. Therefore, we are only interested in reading the values in CPU0.
  context_->executor()->ReadMsr(
      cpu_msr::kIA32TmeCapability, 0,
      base::BindOnce(&MemoryFetcher::HandleReadTmeCapabilityMsr,
                     weak_factory_.GetWeakPtr()));
}

void MemoryFetcher::FetchMemoryEncryptionInfo() {
  auto mktme_path = context_->root_dir().Append(kRelativeMktmePath);
  // If mktme support on the platform, fetch mktme telemetry. Otherwise, fetch
  // tme telemery.
  if (base::PathExists(mktme_path)) {
    // Existence of /sys/kernel/mm/mktme folder indicates mktme support on
    // platform.
    FetchMktmeInfo();
    return;
  }
  // Fetches tme info.
  FetchTmeInfo();
}

void MemoryFetcher::FetchMemoryInfo(FetchMemoryInfoCallback callback) {
  pending_callbacks_.push_back(std::move(callback));
  if (pending_callbacks_.size() > 1)
    return;
  ParseProcMemInfo(&mem_info_);
  ParseProcVmStat(&mem_info_);
  FetchMemoryEncryptionInfo();
}

}  // namespace diagnostics
