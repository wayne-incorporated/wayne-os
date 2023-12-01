// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/cpu_fetcher.h"

#include <sys/utsname.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <re2/re2.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/system/system_utilities_constants.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/cros_healthd/utils/procfs_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using PhysicalCpuMap = std::map<int, mojom::PhysicalCpuInfoPtr>;
using VulnerabilityInfoMap =
    base::flat_map<std::string, mojom::VulnerabilityInfoPtr>;

// Regex used to parse kPresentFileName.
constexpr char kPresentFileRegex[] = R"((\d+)-(\d+))";

// Pattern that all C-state directories follow.
constexpr char kCStateDirectoryMatcher[] = "state*";

// Keys used to parse information from /proc/cpuinfo.
constexpr char kModelNameKey[] = "model name";
constexpr char kProcessorIdKey[] = "processor";
constexpr char kX86CpuFlagsKey[] = "flags";
constexpr char kArmCpuFlagsKey[] = "Features";

// Regex used to parse /proc/stat.
constexpr char kRelativeStatFileRegex[] = R"(cpu(\d+)\s+(\d+) \d+ (\d+) (\d+))";

// Directory containing all CPU temperature subdirectories.
const char kHwmonDir[] = "sys/class/hwmon/";
// Subdirectory of sys/class/hwmon/hwmon*/ which sometimes contains the CPU
// temperature files.
const char kDeviceDir[] = "device";
// Matches all CPU temperature subdirectories of |kHwmonDir|.
const char kHwmonDirectoryPattern[] = "hwmon*";
// Matches all files containing CPU temperatures.
const char kCPUTempFilePattern[] = "temp*_input";
// String "aeskl" indicates keylocker support.
const char kKeylockerAeskl[] = "aeskl";

namespace vulnerability {

// Strings used to match the status of CPU vulnerability.
// The possible output formats can be found here:
// https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln
constexpr char kNotAffectedContent[] = "Not affected";
constexpr char kVulnerablePrefix[] = "Vulnerable";
constexpr char kKvmVulnerablePrefix[] = "KVM: Vulnerable";
// https://github.com/torvalds/linux/blob/df0cc57e057f18e44dac8e6c18aba47ab53202f9/arch/x86/kernel/cpu/bugs.c#L1649
constexpr char kProcessorVulnerableContent[] = "Processor vulnerable";
constexpr char kMitigationPrefix[] = "Mitigation";
constexpr char kKvmMitigationPrefix[] = "KVM: Mitigation";
constexpr char kUnknownPrefix[] = "Unknown";

}  // namespace vulnerability

// The different SMT control file content that indicates the state of SMT
// control.
constexpr char kSmtControlOnContent[] = "on";
constexpr char kSmtControlOffContent[] = "off";
constexpr char kSmtControlForceOffContent[] = "forceoff";
constexpr char kSmtControlNotSupportedContent[] = "notsupported";
constexpr char kSmtControlNotImplementedContent[] = "notimplemented";

// Contains the values parsed from /proc/stat for a single logical CPU.
struct ParsedStatContents {
  uint64_t user_time_user_hz;
  uint64_t system_time_user_hz;
  uint64_t idle_time_user_hz;
};

// Read system temperature sensor data and appends it to |out_contents|. Returns
// |true| iff there was at least one sensor value in given |sensor_dir|.
bool ReadTemperatureSensorInfo(
    const base::FilePath& sensor_dir,
    std::vector<mojom::CpuTemperatureChannelPtr>* out_contents) {
  bool has_data = false;

  base::FileEnumerator enumerator(
      sensor_dir, false, base::FileEnumerator::FILES, kCPUTempFilePattern);
  for (base::FilePath temperature_path = enumerator.Next();
       !temperature_path.empty(); temperature_path = enumerator.Next()) {
    // Get appropriate temp*_label file.
    std::string label_path = temperature_path.MaybeAsASCII();
    if (label_path.empty()) {
      LOG(WARNING) << "Unable to parse a path to temp*_input file as ASCII";
      continue;
    }
    base::ReplaceSubstringsAfterOffset(&label_path, 0, "input", "label");
    base::FilePath name_path = sensor_dir.Append("name");

    // Get the label describing this temperature. Use temp*_label
    // if present, fall back on name file.
    std::string label;
    if (base::PathExists(base::FilePath(label_path))) {
      ReadAndTrimString(base::FilePath(label_path), &label);
    } else if (base::PathExists(base::FilePath(name_path))) {
      ReadAndTrimString(name_path, &label);
    }

    // Read temperature in millidegree Celsius.
    int32_t temperature = 0;
    if (ReadInteger(temperature_path, base::StringToInt, &temperature)) {
      has_data = true;
      // Convert from millidegree Celsius to Celsius.
      temperature /= 1000;

      mojom::CpuTemperatureChannel channel;
      if (!label.empty())
        channel.label = label;
      channel.temperature_celsius = temperature;
      out_contents->push_back(channel.Clone());
    } else {
      LOG(WARNING) << "Unable to read CPU temp from "
                   << temperature_path.MaybeAsASCII();
    }
  }
  return has_data;
}

// Gets the time spent in each C-state for the logical processor whose ID is
// |logical_id|. Returns std::nullopt if a required sysfs node was not found.
std::optional<std::vector<mojom::CpuCStateInfoPtr>> GetCStates(
    const base::FilePath& root_dir, int logical_id) {
  std::vector<mojom::CpuCStateInfoPtr> c_states;
  // Find all directories matching /sys/devices/system/cpu/cpuN/cpudidle/stateX.
  base::FileEnumerator c_state_it(
      GetCStateDirectoryPath(root_dir, logical_id), false,
      base::FileEnumerator::SHOW_SYM_LINKS | base::FileEnumerator::FILES |
          base::FileEnumerator::DIRECTORIES,
      kCStateDirectoryMatcher);
  for (base::FilePath c_state_dir = c_state_it.Next(); !c_state_dir.empty();
       c_state_dir = c_state_it.Next()) {
    mojom::CpuCStateInfo c_state;
    if (!ReadAndTrimString(c_state_dir, kCStateNameFileName, &c_state.name) ||
        !ReadInteger(c_state_dir, kCStateTimeFileName, &base::StringToUint64,
                     &c_state.time_in_state_since_last_boot_us)) {
      return std::nullopt;
    }
    c_states.push_back(c_state.Clone());
  }

  return c_states;
}

// Parses the contents of /proc/stat into a map of logical IDs to
// ParsedStatContents. Returns std::nullopt if an error was encountered while
// parsing.
std::optional<std::map<int, ParsedStatContents>> ParseStatContents(
    const std::string& stat_contents) {
  std::stringstream stat_sstream(stat_contents);

  // Ignore the first line, since it's aggregated data for the individual
  // logical CPUs.
  std::string line;
  std::getline(stat_sstream, line);

  // Parse lines of the format "cpu%d %d %d %d %d ...", where each line
  // corresponds to a separate logical CPU.
  std::map<int, ParsedStatContents> parsed_contents;
  int logical_cpu_id;
  std::string logical_cpu_id_str;
  std::string user_time_str;
  std::string system_time_str;
  std::string idle_time_str;
  while (std::getline(stat_sstream, line) &&
         RE2::PartialMatch(line, kRelativeStatFileRegex, &logical_cpu_id_str,
                           &user_time_str, &system_time_str, &idle_time_str)) {
    ParsedStatContents contents;
    if (!base::StringToUint64(user_time_str, &contents.user_time_user_hz) ||
        !base::StringToUint64(system_time_str, &contents.system_time_user_hz) ||
        !base::StringToUint64(idle_time_str, &contents.idle_time_user_hz) ||
        !base::StringToInt(logical_cpu_id_str, &logical_cpu_id)) {
      return std::nullopt;
    }
    DCHECK_EQ(parsed_contents.count(logical_cpu_id), 0);
    parsed_contents[logical_cpu_id] = std::move(contents);
  }

  return parsed_contents;
}

std::optional<std::map<int, ParsedStatContents>> GetParsedStatContents(
    const base::FilePath& root_dir) {
  std::string stat_contents;
  auto stat_file = GetProcStatPath(root_dir);
  if (!ReadFileToString(stat_file, &stat_contents)) {
    LOG(ERROR) << "Unable to read stat file: " << stat_file.value();
    return std::nullopt;
  }

  std::optional<std::map<int, ParsedStatContents>> parsed_stat_contents =
      ParseStatContents(stat_contents);
  if (!parsed_stat_contents.has_value()) {
    LOG(ERROR) << "Unable to parse stat contents: " << stat_contents;
    return std::nullopt;
  }
  return parsed_stat_contents;
}

std::optional<std::vector<std::string>> GetProcCpuInfoContent(
    const base::FilePath& root_dir) {
  std::string cpu_info_contents;
  auto cpu_info_file = GetProcCpuInfoPath(root_dir);
  if (!ReadFileToString(cpu_info_file, &cpu_info_contents)) {
    return std::nullopt;
  }

  return base::SplitStringUsingSubstr(cpu_info_contents, "\n\n",
                                      base::KEEP_WHITESPACE,
                                      base::SPLIT_WANT_NONEMPTY);
}

// Parses |block| to determine if the block parsed from /proc/cpuinfo is a
// processor block.
bool IsProcessorBlock(const std::string& block) {
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(block, ':', '\n', &pairs);

  if (pairs.size() &&
      pairs[0].first.find(kProcessorIdKey) != std::string::npos) {
    return true;
  }

  return false;
}

// Parses |processor| to obtain |processor_id|, |physical_id|, |model_name| and
// |cpu_flags| if applicable. Returns true on success. |model_name| may be empty
// depending on the CPU architecture, and it is considered as success.
bool ParseProcessor(const std::string& processor,
                    int& processor_id,
                    std::string& model_name,
                    std::vector<std::string>& cpu_flags) {
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(processor, ':', '\n', &pairs);
  std::string processor_id_str;
  std::string physical_id_str;
  bool flags_found = false;
  for (const auto& key_value : pairs) {
    std::string key;
    std::string value;
    base::TrimWhitespaceASCII(key_value.first, base::TRIM_ALL, &key);
    base::TrimWhitespaceASCII(key_value.second, base::TRIM_ALL, &value);
    if (key == kProcessorIdKey) {
      processor_id_str = value;
    } else if (key == kModelNameKey) {
      model_name = value;
    } else if (key == kX86CpuFlagsKey || key == kArmCpuFlagsKey) {
      cpu_flags = base::SplitString(value, " ", base::TRIM_WHITESPACE,
                                    base::SPLIT_WANT_NONEMPTY);
      flags_found = true;
    }
  }

  if (!base::StringToInt(processor_id_str, &processor_id)) {
    LOG(ERROR) << "processor id cannot be converted to integer: "
               << processor_id_str;
    return false;
  }

  if (!flags_found) {
    LOG(ERROR) << "no cpu flags found";
    return false;
  }

  return true;
}

void ParseSocID(const base::FilePath& root_dir, std::string* model_name) {
  // Currently, only Mediatek and Qualcomm with newer kernel support this
  // feature.
  std::string content;
  base::FileEnumerator file_enum(
      root_dir.Append(kRelativeSoCDevicesDir), false,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS);
  for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
    if (!base::ReadFileToString(path.Append("soc_id"), &content)) {
      continue;
    }
    // The soc_id content should be "jep106:XXYY:ZZZZ".
    // XX represents identity code.
    // YY represents continuation code.
    // ZZZZ represents SoC ID.
    // We can use XXYY to distinguish vendor.
    //
    // https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-devices-soc
    const std::string kSoCIDPrefix = "jep106:";
    if (content.find(kSoCIDPrefix) != 0) {
      continue;
    }
    content.erase(0, kSoCIDPrefix.length());

    std::string vendor_id = content.substr(0, 4);
    std::string soc_id = content.substr(5, 4);
    // pair.first: Vendor ID.
    // pair.second: The string that we return from our API.
    const std::map<std::string, std::string> vendors{{"0426", "MediaTek"},
                                                     {"0070", "Qualcomm"}};
    auto vendor = vendors.find(vendor_id);
    if (vendor != vendors.end()) {
      *model_name = vendor->second + " " + soc_id;
    }
  }
}

void ParseCompatibleString(const base::FilePath& root_dir,
                           std::string* model_name) {
  std::string content;
  if (!base::ReadFileToString(root_dir.Append(kRelativeCompatibleFile),
                              &content)) {
    return;
  }

  // pair.first: Vendor string in compatible string.
  // pair.second: The string that we return from our API.
  const std::map<std::string, std::string> vendors{{"mediatek", "MediaTek"},
                                                   {"qualcomm", "Qualcomm"},
                                                   {"rockchip", "Rockchip"}};
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(content, ',', '\0', &pairs);
  for (const auto& key_value : pairs) {
    auto vendor = vendors.find(key_value.first);
    if (vendor != vendors.end()) {
      *model_name = vendor->second + " " + key_value.second;
      return;
    }
  }
}

void GetArmSoCModelName(const base::FilePath& root_dir,
                        std::string* model_name) {
  ParseSocID(root_dir, model_name);
  if (!model_name->empty()) {
    return;
  }
  ParseCompatibleString(root_dir, model_name);
}

// The State class is responsible storing the state when fetching CPU info.
class State {
 public:
  explicit State(Context* context);
  State(const State&) = delete;
  State& operator=(const State&) = delete;
  ~State();

  static void Fetch(Context* context, FetchCpuInfoCallback callback);

 private:
  // Read and parse physical cpus and store into |physical_cpus|. Returns true
  // on success and false otherwise.
  bool FetchPhysicalCpus();

  // Reads and parses the total number of threads available on the device and
  // store into |num_total_threads|. Returns true on success and false
  // otherwise.
  bool FetchNumTotalThreads();

  // Record the cpu architecture into |architecture|. Returns true on success
  // and false otherwise.
  bool FetchArchitecture();

  // Record the keylocker information into |architecture|. Returns true on
  // success and false otherwise.
  bool FetchKeylockerInfo();

  // Fetch cpu temperature channels and store into |temperature_channels|.
  // Returns true on success and false otherwise.
  bool FetchCpuTemperatures();

  // Read and parse general virtualization info and store into |virtualization|.
  // Returns true on success and false otherwise.
  bool FetchVirtualization();

  // Read and parse cpu vulnerabilities and store into |vulnerabilities|.
  // Returns true on success and false otherwise.
  bool FetchVulnerabilities();

  // Calls |callback_| and passes the result. If |all_callback_called| or
  // |error_| is set, the result is a ProbeError, otherwise it is |cpu_info_|.
  void HandleCallbackComplete(FetchCpuInfoCallback callback,
                              bool is_all_callback_called);

  // Callback function to handle ReadMsr() call reading vmx registers.
  void HandleVmxReadMsr(uint32_t index, mojom::NullableUint64Ptr val);

  // Callback function to handle ReadMsr() call reading svm registers.
  void HandleSvmReadMsr(uint32_t index, mojom::NullableUint64Ptr val);

  // Calls ReadMsr based on the virtualization capability of each physical cpu.
  void FetchPhysicalCpusVirtualizationInfo(CallbackBarrier& barrier);

  // Logs |message| and sets |error_|. Only do the logging if |error_| has been
  // set.
  void LogAndSetError(mojom::ErrorType type, const std::string& message);

  // Stores the context received from Fetch.
  Context* const context_;
  // Stores the error that will be returned. HandleCallbackComplete will report
  // error if this is set.
  mojom::ProbeErrorPtr error_;
  // Stores the final cpu info that will be returned.
  mojom::CpuInfoPtr cpu_info_;

  // Maintains a map that maps each physical cpu id to its first corresponding
  // logical cpu id.
  std::map<uint32_t, uint32_t> physical_id_to_first_logical_id_;
  // Must be the last member of the class.
  base::WeakPtrFactory<State> weak_factory_{this};
};

State::State(Context* context)
    : context_(context), cpu_info_(mojom::CpuInfo::New()) {}

State::~State() = default;

bool State::FetchNumTotalThreads() {
  base::FilePath root_dir = context_->root_dir();

  std::string cpu_present;
  auto cpu_dir = root_dir.Append(kRelativeCpuDir);
  if (!ReadAndTrimString(cpu_dir, kPresentFileName, &cpu_present)) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Unable to read CPU present file: " +
                       cpu_dir.Append(kPresentFileName).value());
    return false;
  }

  // Expect |cpu_present| to contain a comma separated list of values either in
  // the pattern of "%d" or "%d-%d". In the case of "%d-%d", the first integer
  // is strictly smaller than the second. The total number of threads is the
  // sum of the number of threads calculated in each individual pattern.
  //
  // https://www.kernel.org/doc/html/v5.5/admin-guide/cputopology.html

  std::vector<std::string> cpu_threads = base::SplitString(
      cpu_present, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  uint32_t total_thread_count = 0;

  for (auto& thread : cpu_threads) {
    std::string low_thread_num;
    std::string high_thread_num;
    uint32_t low_thread_int;
    uint32_t high_thread_int;
    // Check if is in the form of "%d".
    if (base::StringToUint(thread, &low_thread_int)) {
      total_thread_count++;
      continue;
    }
    // Check if is in the form of "%d-%d".
    if (RE2::FullMatch(thread, kPresentFileRegex, &low_thread_num,
                       &high_thread_num) &&
        base::StringToUint(low_thread_num, &low_thread_int) &&
        base::StringToUint(high_thread_num, &high_thread_int)) {
      DCHECK_GT(high_thread_int, low_thread_int);
      total_thread_count += high_thread_int - low_thread_int + 1;
      continue;
    }

    LogAndSetError(mojom::ErrorType::kParseError,
                   "Unable to parse CPU present file: " + cpu_present);
    return false;
  }

  cpu_info_->num_total_threads = total_thread_count;

  return true;
}

bool State::FetchArchitecture() {
  struct utsname buf;
  if (context_->system_utils()->Uname(&buf)) {
    cpu_info_->architecture = mojom::CpuArchitectureEnum::kUnknown;
    return true;
  }

  std::string machine(buf.machine);
  if (machine == kUnameMachineX86_64) {
    cpu_info_->architecture = mojom::CpuArchitectureEnum::kX86_64;
    return true;
  }
  if (machine == kUnameMachineAArch64) {
    cpu_info_->architecture = mojom::CpuArchitectureEnum::kAArch64;
    return true;
  }
  if (machine == kUnameMachineArmv7l) {
    cpu_info_->architecture = mojom::CpuArchitectureEnum::kArmv7l;
    return true;
  }

  cpu_info_->architecture = mojom::CpuArchitectureEnum::kUnknown;
  return true;
}

// Fetch Keylocker information.
bool State::FetchKeylockerInfo() {
  base::FilePath root_dir = context_->root_dir();

  std::string file_contents;
  // Crypto file is common for all CPU architects. However, crypto algorithms
  // populated in crypto file could be hardware dependent.
  if (!ReadAndTrimString(root_dir, kRelativeCryptoFilePath, &file_contents)) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Unable to read file: " +
                       root_dir.Append(kRelativeCryptoFilePath).value());
    return false;
  }
  // aeskl algorithm populated in crypto file is the indication that keylocker
  // driver had been loaded, the hardware had been configured and ready for use.
  std::size_t found = file_contents.find(kKeylockerAeskl);
  if (found == std::string::npos) {
    cpu_info_->keylocker_info = nullptr;
    return true;
  }
  auto info = mojom::KeylockerInfo::New();
  info->keylocker_configured = true;
  cpu_info_->keylocker_info = std::move(info);

  return true;
}

// Fetches and returns information about the device's CPU temperature channels.
bool State::FetchCpuTemperatures() {
  base::FilePath root_dir = context_->root_dir();

  std::vector<mojom::CpuTemperatureChannelPtr> temps;
  // Get directories |/sys/class/hwmon/hwmon*|
  base::FileEnumerator hwmon_enumerator(root_dir.AppendASCII(kHwmonDir), false,
                                        base::FileEnumerator::DIRECTORIES,
                                        kHwmonDirectoryPattern);
  for (base::FilePath hwmon_path = hwmon_enumerator.Next(); !hwmon_path.empty();
       hwmon_path = hwmon_enumerator.Next()) {
    // First try to get |temp*_input| files from |hwmon*/device/|. If the values
    // cannot be read, fallback to |hwmon*/| instead.
    base::FilePath device_path = hwmon_path.Append(kDeviceDir);
    if (base::PathExists(device_path) &&
        ReadTemperatureSensorInfo(device_path, &temps)) {
      continue;
    }
    ReadTemperatureSensorInfo(hwmon_path, &temps);
  }

  cpu_info_->temperature_channels = std::move(temps);

  return true;
}

bool State::FetchPhysicalCpus() {
  base::FilePath root_dir = context_->root_dir();

  std::optional<std::map<int, ParsedStatContents>> parsed_stat_contents =
      GetParsedStatContents(root_dir);
  if (parsed_stat_contents == std::nullopt) {
    LogAndSetError(
        mojom::ErrorType::kParseError,
        "Unable to parse stat file: " + GetProcStatPath(root_dir).value());
    return false;
  }
  std::map<int, ParsedStatContents> logical_ids_to_stat_contents =
      parsed_stat_contents.value();

  std::optional<std::vector<std::string>> processor_info_opt =
      GetProcCpuInfoContent(root_dir);
  if (processor_info_opt == std::nullopt) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Unable to read CPU info file: " +
                       GetProcCpuInfoPath(root_dir).value());
    return false;
  }
  const std::vector<std::string>& processor_info = processor_info_opt.value();

  PhysicalCpuMap physical_cpus;
  for (const auto& processor : processor_info) {
    if (!IsProcessorBlock(processor))
      continue;

    int processor_id;
    std::string model_name;
    std::vector<std::string> cpu_flags;
    if (!ParseProcessor(processor, processor_id, model_name, cpu_flags)) {
      LogAndSetError(mojom::ErrorType::kParseError,
                     "Unable to parse processor string: " + processor);
      return false;
    }

    int physical_id;
    if (!ReadInteger(GetPhysicalPackageIdPath(root_dir, processor_id),
                     &base::StringToInt, &physical_id)) {
      LogAndSetError(mojom::ErrorType::kParseError,
                     "Unable to parse physical ID for cpu " +
                         base::NumberToString(processor_id));
      return false;
    }

    // Find the physical CPU corresponding to this logical CPU, if it already
    // exists. If not, make one.
    auto itr = physical_cpus.find(physical_id);
    if (itr == physical_cpus.end()) {
      physical_id_to_first_logical_id_[physical_id] = processor_id;
      mojom::PhysicalCpuInfoPtr physical_cpu = mojom::PhysicalCpuInfo::New();
      if (model_name.empty()) {
        // It may be Arm CPU. We will return SoC model name instead.
        GetArmSoCModelName(root_dir, &model_name);
      }
      if (!model_name.empty())
        physical_cpu->model_name = std::move(model_name);

      physical_cpu->flags = std::move(cpu_flags);

      const auto result =
          physical_cpus.insert({physical_id, std::move(physical_cpu)});
      DCHECK(result.second);
      itr = result.first;
    }

    // Populate the logical CPU info values.
    mojom::LogicalCpuInfo logical_cpu;
    const auto parsed_stat_itr =
        logical_ids_to_stat_contents.find(processor_id);
    if (parsed_stat_itr == logical_ids_to_stat_contents.end()) {
      LogAndSetError(mojom::ErrorType::kParseError,
                     "No parsed stat contents for logical ID: " +
                         base::NumberToString(processor_id));
      return false;
    }
    logical_cpu.user_time_user_hz = parsed_stat_itr->second.user_time_user_hz;
    logical_cpu.system_time_user_hz =
        parsed_stat_itr->second.system_time_user_hz;
    logical_cpu.idle_time_user_hz = parsed_stat_itr->second.idle_time_user_hz;

    auto c_states = GetCStates(root_dir, processor_id);
    if (c_states == std::nullopt) {
      LogAndSetError(mojom::ErrorType::kFileReadError,
                     "Unable to read C States.");
      return false;
    }
    logical_cpu.c_states = std::move(c_states.value());

    auto cpufreq_dir = GetCpuFreqDirectoryPath(root_dir, processor_id);
    // Not every CPU support CPU frequency scaling. Set the frequency to 0 if
    // the CPU doesn't support and relevant files does not exist.
    if (!base::PathExists(cpufreq_dir)) {
      logical_cpu.max_clock_speed_khz = 0;
      logical_cpu.scaling_max_frequency_khz = 0;
      logical_cpu.scaling_current_frequency_khz = 0;
    } else {
      if (!ReadInteger(cpufreq_dir, kCpuinfoMaxFreqFileName,
                       &base::StringToUint, &logical_cpu.max_clock_speed_khz)) {
        LogAndSetError(mojom::ErrorType::kFileReadError,
                       "Unable to read max CPU frequency file to integer: " +
                           cpufreq_dir.Append(kCpuinfoMaxFreqFileName).value());
        return false;
      }

      if (!ReadInteger(cpufreq_dir, kScalingMaxFreqFileName,
                       &base::StringToUint,
                       &logical_cpu.scaling_max_frequency_khz)) {
        LogAndSetError(
            mojom::ErrorType::kFileReadError,
            "Unable to read scaling max frequency file to integer: " +
                cpufreq_dir.Append(kScalingMaxFreqFileName).value());
        return false;
      }

      if (!ReadInteger(cpufreq_dir, kScalingCurFreqFileName,
                       &base::StringToUint,
                       &logical_cpu.scaling_current_frequency_khz)) {
        LogAndSetError(
            mojom::ErrorType::kFileReadError,
            "Unable to read scaling current frequency file to integer: " +
                cpufreq_dir.Append(kScalingCurFreqFileName).value());
        return false;
      }
    }

    if (!ReadInteger(GetCoreIdPath(root_dir, processor_id), &base::StringToUint,
                     &logical_cpu.core_id)) {
      LogAndSetError(mojom::ErrorType::kParseError,
                     "Unable to parse core ID for cpu " +
                         base::NumberToString(processor_id));
      return false;
    }

    // Add this logical CPU to the corresponding physical CPU.
    itr->second->logical_cpus.push_back(logical_cpu.Clone());
  }

  for (auto& key_value : physical_cpus) {
    cpu_info_->physical_cpus.push_back(std::move(key_value.second));
  }

  return true;
}

bool State::FetchVirtualization() {
  base::FilePath root_dir = context_->root_dir();

  cpu_info_->virtualization = mojom::VirtualizationInfo::New();
  cpu_info_->virtualization->has_kvm_device =
      base::PathExists(root_dir.Append(kRelativeKvmFilePath));

  base::FilePath smt_dir = root_dir.Append(kRelativeCpuDir).Append(kSmtDirName);
  // If smt control directory does not exist, this means the linux kernel
  // version does not support smt and we mark it as kNotImplemented.
  if (!base::PathExists(smt_dir)) {
    cpu_info_->virtualization->is_smt_active = false;
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kNotImplemented;
    return true;
  }

  base::FilePath smt_active_path = smt_dir.Append(kSmtActiveFileName);

  uint32_t active;
  if (!ReadInteger(smt_active_path, base::StringToUint, &active) ||
      active > 1) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Unable to read smt active file.");
    return false;
  }

  cpu_info_->virtualization->is_smt_active = active == 1;

  std::string control;
  base::FilePath smt_control_path = smt_dir.Append(kSmtControlFileName);

  if (!ReadAndTrimString(smt_control_path, &control)) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Unable to read smt control file.");
    return false;
  }

  if (control == kSmtControlOnContent) {
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kOn;
  } else if (control == kSmtControlOffContent) {
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kOff;
  } else if (control == kSmtControlForceOffContent) {
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kForceOff;
  } else if (control == kSmtControlNotSupportedContent) {
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kNotSupported;
  } else if (control == kSmtControlNotImplementedContent) {
    cpu_info_->virtualization->smt_control =
        mojom::VirtualizationInfo::SMTControl::kNotImplemented;
  } else {
    LogAndSetError(mojom::ErrorType::kParseError,
                   "Unable to parse smt control file.");
    return false;
  }

  return true;
}

bool State::FetchVulnerabilities() {
  base::FilePath root_dir = context_->root_dir();
  base::FilePath vulnerability_dir =
      root_dir.Append(kRelativeCpuDir).Append(kVulnerabilityDirName);
  // If vulnerabilities directory does not exist, this means the linux kernel
  // version does not support vulnerability detection yet and we will return
  // an empty map.
  std::vector<VulnerabilityInfoMap::value_type> vulnerabilities_vec;
  base::FileEnumerator it(vulnerability_dir,
                          /*recursive=*/false, base::FileEnumerator::FILES);
  for (base::FilePath vulnerability_file = it.Next();
       !vulnerability_file.empty(); vulnerability_file = it.Next()) {
    auto vulnerability = mojom::VulnerabilityInfo::New();

    if (!ReadAndTrimString(vulnerability_file, &vulnerability->message)) {
      LogAndSetError(
          mojom::ErrorType::kFileReadError,
          "Unable to read vulnerability file: " + vulnerability_file.value());
      return false;
    }

    vulnerability->status =
        GetVulnerabilityStatusFromMessage(vulnerability->message);

    vulnerabilities_vec.push_back(
        {vulnerability_file.BaseName().value(), std::move(vulnerability)});
  }

  cpu_info_->vulnerabilities =
      VulnerabilityInfoMap(std::move(vulnerabilities_vec));
  return true;
}

void State::FetchPhysicalCpusVirtualizationInfo(CallbackBarrier& barrier) {
  for (uint32_t physical_id = 0; physical_id < cpu_info_->physical_cpus.size();
       ++physical_id) {
    uint32_t logical_id = physical_id_to_first_logical_id_[physical_id];
    mojom::PhysicalCpuInfoPtr& physical_cpu =
        cpu_info_->physical_cpus[physical_id];

    physical_cpu->virtualization = mojom::CpuVirtualizationInfo::New();
    const std::vector<std::string>& flags = physical_cpu->flags.value();
    if (std::find(flags.begin(), flags.end(), "vmx") != flags.end()) {
      physical_cpu->virtualization->type =
          mojom::CpuVirtualizationInfo::Type::kVMX;
      context_->executor()->ReadMsr(
          cpu_msr::kIA32FeatureControl, logical_id,
          barrier.Depend(base::BindOnce(&State::HandleVmxReadMsr,
                                        weak_factory_.GetWeakPtr(),
                                        physical_id)));
    } else if (std::find(flags.begin(), flags.end(), "svm") != flags.end()) {
      physical_cpu->virtualization->type =
          mojom::CpuVirtualizationInfo::Type::kSVM;
      context_->executor()->ReadMsr(
          cpu_msr::kVmCr, logical_id,
          barrier.Depend(base::BindOnce(&State::HandleSvmReadMsr,
                                        weak_factory_.GetWeakPtr(),
                                        physical_id)));
    } else {
      physical_cpu->virtualization = nullptr;
      continue;
    }
  }
}

void State::HandleSvmReadMsr(uint32_t physical_id,
                             mojom::NullableUint64Ptr val) {
  if (val.is_null()) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Error while reading svm msr register");
    return;
  }
  cpu_info_->physical_cpus[physical_id]->virtualization->is_enabled =
      !(val->value & kVmCrSvmeDisabledBit);
  cpu_info_->physical_cpus[physical_id]->virtualization->is_locked =
      val->value & kVmCrLockedBit;
}

void State::HandleVmxReadMsr(uint32_t physical_id,
                             mojom::NullableUint64Ptr val) {
  if (val.is_null()) {
    LogAndSetError(mojom::ErrorType::kFileReadError,
                   "Error while reading vmx msr register");
    return;
  }
  cpu_info_->physical_cpus[physical_id]->virtualization->is_enabled =
      (val->value & kIA32FeatureEnableVmxInsideSmx) ||
      (val->value & kIA32FeatureEnableVmxOutsideSmx);
  cpu_info_->physical_cpus[physical_id]->virtualization->is_locked =
      val->value & kIA32FeatureLocked;
}

void State::HandleCallbackComplete(FetchCpuInfoCallback callback,
                                   bool is_all_callback_called) {
  if (!is_all_callback_called) {
    LogAndSetError(mojom::ErrorType::kServiceUnavailable,
                   "Not all Fetch Cpu Virtualization Callbacks "
                   "have been sucessfully called");
  }
  std::move(callback).Run(
      error_ ? mojom::CpuResult::NewError(std::move(error_))
             : mojom::CpuResult::NewCpuInfo(std::move(cpu_info_)));
}

void State::LogAndSetError(mojom::ErrorType type, const std::string& message) {
  LOG(ERROR) << message;
  if (error_.is_null())
    error_ = mojom::ProbeError::New(type, message);
}

void State::Fetch(Context* context, FetchCpuInfoCallback callback) {
  auto state = std::make_unique<State>(context);
  State* state_ptr = state.get();

  CallbackBarrier barrier{base::BindOnce(
      &State::HandleCallbackComplete, std::move(state), std::move(callback))};

  if (!state_ptr->FetchNumTotalThreads() || !state_ptr->FetchArchitecture() ||
      !state_ptr->FetchKeylockerInfo() || !state_ptr->FetchCpuTemperatures() ||
      !state_ptr->FetchVirtualization() || !state_ptr->FetchVulnerabilities() ||
      !state_ptr->FetchPhysicalCpus()) {
    DCHECK(!state_ptr->error_.is_null());
    return;
  }

  state_ptr->FetchPhysicalCpusVirtualizationInfo(barrier);
  return;
}
}  // namespace

base::FilePath GetCStateDirectoryPath(const base::FilePath& root_dir,
                                      int logical_id) {
  std::string logical_cpu_dir = "cpu" + base::NumberToString(logical_id);
  std::string cpuidle_dirname = "cpuidle";
  return root_dir.Append(kRelativeCpuDir)
      .Append(logical_cpu_dir)
      .Append(cpuidle_dirname);
}

// If the CPU has a governing policy, return that path, otherwise return the
// cpufreq directory for the given logical CPU.
base::FilePath GetCpuFreqDirectoryPath(const base::FilePath& root_dir,
                                       int logical_id) {
  std::string cpufreq_policy_dir =
      "cpufreq/policy" + base::NumberToString(logical_id);

  auto policy_path =
      root_dir.Append(kRelativeCpuDir).Append(cpufreq_policy_dir);
  if (base::PathExists(policy_path)) {
    return policy_path;
  }

  std::string logical_cpu_dir = "cpu" + base::NumberToString(logical_id);
  std::string cpufreq_dirname = "cpufreq";
  return root_dir.Append(kRelativeCpuDir)
      .Append(logical_cpu_dir)
      .Append(cpufreq_dirname);
}

base::FilePath GetPhysicalPackageIdPath(const base::FilePath& root_dir,
                                        int logical_id) {
  std::string logical_cpu_dir = "cpu" + base::NumberToString(logical_id);
  std::string physical_package_id_filename = "topology/physical_package_id";
  return root_dir.Append(kRelativeCpuDir)
      .Append(logical_cpu_dir)
      .Append(physical_package_id_filename);
}

base::FilePath GetCoreIdPath(const base::FilePath& root_dir, int logical_id) {
  std::string logical_cpu_dir = "cpu" + base::NumberToString(logical_id);
  std::string core_id_filename = "topology/core_id";
  return root_dir.Append(kRelativeCpuDir)
      .Append(logical_cpu_dir)
      .Append(core_id_filename);
}

mojom::VulnerabilityInfo::Status GetVulnerabilityStatusFromMessage(
    const std::string& message) {
  // Messages in the |iTLB multihit| vulnerability takes a different form with
  // |KVM: Vulberable|, |KVM: Mitigation: $msg| and |Processor vulnerable|. We
  // remove prefix to convert the data to common form in order to parse the
  // status correctly.
  //
  // https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/multihit.html
  if (message == vulnerability::kNotAffectedContent) {
    return mojom::VulnerabilityInfo::Status::kNotAffected;
  }
  if (base::StartsWith(message, vulnerability::kVulnerablePrefix) ||
      base::StartsWith(message, vulnerability::kKvmVulnerablePrefix) ||
      message == vulnerability::kProcessorVulnerableContent) {
    return mojom::VulnerabilityInfo::Status::kVulnerable;
  }
  if (base::StartsWith(message, vulnerability::kMitigationPrefix) ||
      base::StartsWith(message, vulnerability::kKvmMitigationPrefix)) {
    return mojom::VulnerabilityInfo::Status::kMitigation;
  }
  if (base::StartsWith(message, vulnerability::kUnknownPrefix)) {
    return mojom::VulnerabilityInfo::Status::kUnknown;
  }
  return mojom::VulnerabilityInfo::Status::kUnrecognized;
}

void FetchCpuInfo(Context* context, FetchCpuInfoCallback callback) {
  State::Fetch(context, std::move(callback));
}

}  // namespace diagnostics
