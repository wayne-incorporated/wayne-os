// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/debugd_dbus_adaptor.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/files/file_util.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/object_path.h>

#include "debugd/src/constants.h"
#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

const char kDevCoredumpDBusErrorString[] =
    "org.chromium.debugd.error.DevCoreDump";
const char kPrintscanDebugSetCategoriesErrorString[] =
    "org.chromium.debugd.error.PrintscanDebugSetCategories";
const char kSetCrashSenderTestModeErrorString[] =
    "org.chromium.debugd.error.SetCrashSenderTestMode";

const char kShouldSendRlzPingKey[] = "should_send_rlz_ping";

const char kRlzEmbargoEndDateKey[] = "rlz_embargo_end_date";

const char kLanguageAllowedChars[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@";

}  // namespace

DebugdDBusAdaptor::DebugdDBusAdaptor(scoped_refptr<dbus::Bus> bus,
                                     const bool perf_logging)
    : org::chromium::debugdAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kDebugdServicePath)) {
  battery_tool_ = std::make_unique<BatteryTool>();
  container_tool_ = std::make_unique<ContainerTool>();
  crash_sender_tool_ = std::make_unique<CrashSenderTool>();
  cups_tool_ = std::make_unique<CupsTool>();
  cros_healthd_tool_ = std::make_unique<CrosHealthdTool>();
  debug_logs_tool_ = std::make_unique<DebugLogsTool>(bus);
  debug_mode_tool_ = std::make_unique<DebugModeTool>(bus);
  dev_features_tool_wrapper_ =
      std::make_unique<RestrictedToolWrapper<DevFeaturesTool>>(bus);
  dmesg_tool_ = std::make_unique<DmesgTool>();
  ec_typec_tool_ = std::make_unique<EcTypeCTool>();
  example_tool_ = std::make_unique<ExampleTool>();
  icmp_tool_ = std::make_unique<ICMPTool>();
  ipaddrs_tool_ = std::make_unique<IpAddrsTool>();
  kernel_feature_tool_ = std::make_unique<KernelFeatureTool>();
  log_tool_ = std::make_unique<LogTool>(bus, perf_logging);
  memory_tool_ = std::make_unique<MemtesterTool>();
  netif_tool_ = std::make_unique<NetifTool>();
  network_status_tool_ = std::make_unique<NetworkStatusTool>();
  oom_adj_tool_ = std::make_unique<OomAdjTool>();
  packet_capture_tool_ = std::make_unique<PacketCaptureTool>();
  perf_tool_ = std::make_unique<PerfTool>();
  ping_tool_ = std::make_unique<PingTool>();
  printscan_tool_ = std::make_unique<PrintscanTool>(bus);
  probe_tool_ = std::make_unique<ProbeTool>();
  route_tool_ = std::make_unique<RouteTool>();
  shill_scripts_tool_ = std::make_unique<ShillScriptsTool>();
  storage_tool_ = std::make_unique<StorageTool>();
  swap_tool_ = std::make_unique<SwapTool>();
  sysrq_tool_ = std::make_unique<SysrqTool>();
  systrace_tool_ = std::make_unique<SystraceTool>();
  tracepath_tool_ = std::make_unique<TracePathTool>();
  u2f_tool_ = std::make_unique<U2fTool>();
  verify_ro_tool_ = std::make_unique<VerifyRoTool>();
  vm_plugin_dispatcher_tool_ = std::make_unique<SimpleServiceTool>(
      "vmplugin_dispatcher", bus,
      vm_tools::plugin_dispatcher::kVmPluginDispatcherServiceName,
      vm_tools::plugin_dispatcher::kVmPluginDispatcherServicePath);
  wifi_fw_dump_tool_ = std::make_unique<WifiFWDumpTool>();
  wifi_power_tool_ = std::make_unique<WifiPowerTool>();
  session_manager_proxy_ = std::make_unique<SessionManagerProxy>(bus);
  scheduler_configuration_tool_ =
      std::make_unique<SchedulerConfigurationTool>();
  if (dev_features_tool_wrapper_->restriction().InDevMode() &&
      base::PathExists(
          base::FilePath(debugd::kDevFeaturesChromeRemoteDebuggingFlagPath))) {
    session_manager_proxy_->EnableChromeRemoteDebugging();
  }
  drm_trace_tool_ = std::make_unique<DRMTraceTool>(log_tool_.get());
  session_manager_proxy_->AddObserver(drm_trace_tool_.get());
}

DebugdDBusAdaptor::~DebugdDBusAdaptor() {
  session_manager_proxy_->RemoveObserver(drm_trace_tool_.get());
  // Destroy drm_trace_tool_ here since it holds a pointer to log_tool_, so
  // its lifetime should not exceed that of log_tool_.
  drm_trace_tool_.reset();
}

void DebugdDBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  auto* my_interface = dbus_object_.AddOrGetInterface(kDebugdInterface);
  DCHECK(my_interface);
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

std::string DebugdDBusAdaptor::SetOomScoreAdj(
    const std::map<pid_t, int32_t>& scores) {
  return oom_adj_tool_->Set(scores);
}

bool DebugdDBusAdaptor::PingStart(brillo::ErrorPtr* error,
                                  const base::ScopedFD& outfd,
                                  const std::string& destination,
                                  const brillo::VariantDictionary& options,
                                  std::string* handle) {
  return ping_tool_->Start(outfd, destination, options, handle, error);
}

bool DebugdDBusAdaptor::PingStop(brillo::ErrorPtr* error,
                                 const std::string& handle) {
  return ping_tool_->Stop(handle, error);
}

std::string DebugdDBusAdaptor::TracePathStart(
    const base::ScopedFD& outfd,
    const std::string& destination,
    const brillo::VariantDictionary& options) {
  return tracepath_tool_->Start(outfd, destination, options);
}

bool DebugdDBusAdaptor::TracePathStop(brillo::ErrorPtr* error,
                                      const std::string& handle) {
  return tracepath_tool_->Stop(handle, error);
}

void DebugdDBusAdaptor::SystraceStart(const std::string& categories) {
  (void)systrace_tool_->Start(categories);
}

void DebugdDBusAdaptor::SystraceStop(const base::ScopedFD& outfd) {
  systrace_tool_->Stop(outfd);
}

std::string DebugdDBusAdaptor::SystraceStatus() {
  return systrace_tool_->Status();
}

std::vector<std::string> DebugdDBusAdaptor::GetIpAddresses(
    const brillo::VariantDictionary& options) {
  return ipaddrs_tool_->GetIpAddresses(options);
}

std::vector<std::string> DebugdDBusAdaptor::GetRoutes(
    const brillo::VariantDictionary& options) {
  return route_tool_->GetRoutes(options);
}

std::string DebugdDBusAdaptor::GetNetworkStatus() {
  return network_status_tool_->GetNetworkStatus();
}

bool DebugdDBusAdaptor::GetPerfOutput(brillo::ErrorPtr* error,
                                      uint32_t duration_sec,
                                      const std::vector<std::string>& perf_args,
                                      int32_t* status,
                                      std::vector<uint8_t>* perf_data,
                                      std::vector<uint8_t>* perf_stat) {
  return perf_tool_->GetPerfOutput(duration_sec, perf_args, perf_data,
                                   perf_stat, status, error);
}

bool DebugdDBusAdaptor::GetPerfOutputFd(
    brillo::ErrorPtr* error,
    uint32_t duration_sec,
    const std::vector<std::string>& perf_args,
    const base::ScopedFD& stdout_fd,
    uint64_t* session_id) {
  return perf_tool_->GetPerfOutputFd(duration_sec, perf_args, stdout_fd,
                                     session_id, error);
}

bool DebugdDBusAdaptor::StopPerf(brillo::ErrorPtr* error, uint64_t session_id) {
  return perf_tool_->StopPerf(session_id, error);
}

bool DebugdDBusAdaptor::GetPerfOutputV2(
    brillo::ErrorPtr* error,
    const std::vector<std::string>& quipper_args,
    bool disable_cpu_idle,
    const base::ScopedFD& stdout_fd,
    uint64_t* session_id) {
  return perf_tool_->GetPerfOutputV2(quipper_args, disable_cpu_idle, stdout_fd,
                                     session_id, error);
}

void DebugdDBusAdaptor::DumpDebugLogs(bool is_compressed,
                                      const base::ScopedFD& fd) {
  debug_logs_tool_->GetDebugLogs(is_compressed, fd);
}

void DebugdDBusAdaptor::SetDebugMode(const std::string& subsystem) {
  debug_mode_tool_->SetDebugMode(subsystem);
}

std::string DebugdDBusAdaptor::GetLog(const std::string& name) {
  return log_tool_->GetLog(name).value_or("");
}

std::map<std::string, std::string> DebugdDBusAdaptor::GetAllLogs() {
  return log_tool_->GetAllLogs();
}

void DebugdDBusAdaptor::GetFeedbackLogsV2(
    const base::ScopedFD& fd,
    const std::string& username,
    const std::vector<int32_t>& requested_logs) {
  log_tool_->GetFeedbackLogsV2(fd, username, perf_tool_.get(), requested_logs);
}

void DebugdDBusAdaptor::GetFeedbackLogsV3(
    const base::ScopedFD& fd,
    const std::string& username,
    const std::vector<int32_t>& requested_logs) {
  log_tool_->GetFeedbackLogsV3(fd, username, perf_tool_.get(), requested_logs);
}

void DebugdDBusAdaptor::BackupArcBugReport(const std::string& username) {
  log_tool_->BackupArcBugReport(username);
}

void DebugdDBusAdaptor::DeleteArcBugReportBackup(const std::string& username) {
  log_tool_->DeleteArcBugReportBackup(username);
}

std::string DebugdDBusAdaptor::GetExample() {
  return example_tool_->GetExample();
}

int32_t DebugdDBusAdaptor::CupsAddAutoConfiguredPrinter(
    const std::string& name, const std::string& uri) {
  return cups_tool_->AddAutoConfiguredPrinter(name, uri, "en");
}

int32_t DebugdDBusAdaptor::CupsAddAutoConfiguredPrinterV2(
    const std::string& name,
    const std::string& uri,
    const std::string& language) {
  return cups_tool_->AddAutoConfiguredPrinter(
      name, uri,
      base::ContainsOnlyChars(language, kLanguageAllowedChars) ? language
                                                               : "en");
}

int32_t DebugdDBusAdaptor::CupsAddManuallyConfiguredPrinter(
    const std::string& name,
    const std::string& uri,
    const std::vector<uint8_t>& ppd_contents) {
  return cups_tool_->AddManuallyConfiguredPrinter(name, uri, "en",
                                                  ppd_contents);
}

int32_t DebugdDBusAdaptor::CupsAddManuallyConfiguredPrinterV2(
    const std::string& name,
    const std::string& uri,
    const std::string& language,
    const std::vector<uint8_t>& ppd_contents) {
  return cups_tool_->AddManuallyConfiguredPrinter(
      name, uri,
      base::ContainsOnlyChars(language, kLanguageAllowedChars) ? language
                                                               : "en",
      ppd_contents);
}

bool DebugdDBusAdaptor::CupsRemovePrinter(const std::string& name) {
  return cups_tool_->RemovePrinter(name);
}

std::vector<uint8_t> DebugdDBusAdaptor::CupsRetrievePpd(
    const std::string& name) {
  return cups_tool_->RetrievePpd(name);
}

std::string DebugdDBusAdaptor::GetInterfaces() {
  return netif_tool_->GetInterfaces();
}

std::string DebugdDBusAdaptor::TestICMP(const std::string& host) {
  return icmp_tool_->TestICMP(host);
}

std::string DebugdDBusAdaptor::TestICMPWithOptions(
    const std::string& host,
    const std::map<std::string, std::string>& options) {
  return icmp_tool_->TestICMPWithOptions(host, options);
}

std::string DebugdDBusAdaptor::BatteryFirmware(const std::string& option) {
  return battery_tool_->BatteryFirmware(option);
}

std::string DebugdDBusAdaptor::Smartctl(const std::string& option) {
  return storage_tool_->Smartctl(option);
}

std::string DebugdDBusAdaptor::Mmc(const std::string& option) {
  return storage_tool_->Mmc(option);
}

std::string DebugdDBusAdaptor::Ufs(const std::string& option) {
  return storage_tool_->Ufs(option);
}

std::string DebugdDBusAdaptor::Nvme(const std::string& option) {
  return storage_tool_->Nvme(option);
}

std::string DebugdDBusAdaptor::NvmeLog(const uint32_t page_id,
                                       const uint32_t length,
                                       bool raw_binary) {
  return storage_tool_->NvmeLog(page_id, length, raw_binary);
}

std::string DebugdDBusAdaptor::MemtesterStart(const base::ScopedFD& outfd,
                                              uint32_t memory) {
  return memory_tool_->Start(outfd, memory);
}

bool DebugdDBusAdaptor::MemtesterStop(brillo::ErrorPtr* error,
                                      const std::string& handle) {
  return memory_tool_->Stop(handle, error);
}

std::string DebugdDBusAdaptor::BadblocksStart(const base::ScopedFD& outfd) {
  return storage_tool_->Start(outfd);
}

bool DebugdDBusAdaptor::BadblocksStop(brillo::ErrorPtr* error,
                                      const std::string& handle) {
  return storage_tool_->Stop(handle, error);
}

bool DebugdDBusAdaptor::PacketCaptureStart(
    brillo::ErrorPtr* error,
    const base::ScopedFD& statfd,
    const base::ScopedFD& outfd,
    const brillo::VariantDictionary& options,
    std::string* handle) {
  bool is_dev_mode = dev_features_tool_wrapper_->restriction().InDevMode();
  // Use base::Unretained(this) as the packet_capture_tool_ is a member of
  // `this` and if packet_capture_tool_ is alive to execute the bound function,
  // it means DebugdDBusAdaptor should also be alive.
  bool packet_capture_started = packet_capture_tool_->Start(
      is_dev_mode, statfd, outfd, options, handle,
      base::BindOnce(&DebugdDBusAdaptor::OnPacketCaptureStopped,
                     base::Unretained(this)),
      error);
  if (packet_capture_started) {
    SendPacketCaptureStartSignal();
  }
  return packet_capture_started;
}

void DebugdDBusAdaptor::OnPacketCaptureStopped() {
  // Send PacketCaptureStopSignal if there are no active packet capture
  // processes running.
  if (!packet_capture_tool_->HasActivePacketCaptureProcess()) {
    SendPacketCaptureStopSignal();
  }
}

bool DebugdDBusAdaptor::PacketCaptureStop(brillo::ErrorPtr* error,
                                          const std::string& handle) {
  bool packet_capture_stopped = packet_capture_tool_->Stop(handle, error);
  return packet_capture_stopped;
}

bool DebugdDBusAdaptor::LogKernelTaskStates(brillo::ErrorPtr* error) {
  return sysrq_tool_->LogKernelTaskStates(error);
}

void DebugdDBusAdaptor::UploadCrashes() {
  crash_sender_tool_->UploadCrashes();
}

bool DebugdDBusAdaptor::UploadSingleCrash(
    brillo::ErrorPtr* error,
    const std::vector<std::tuple<std::string, base::ScopedFD>>& in_files,
    bool consent_already_checked_by_crash_reporter) {
  return crash_sender_tool_->UploadSingleCrash(
      in_files, error, consent_already_checked_by_crash_reporter);
}

bool DebugdDBusAdaptor::RemoveRootfsVerification(brillo::ErrorPtr* error) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->RemoveRootfsVerification(error);
}

bool DebugdDBusAdaptor::EnableBootFromUsb(brillo::ErrorPtr* error) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->EnableBootFromUsb(error);
}

bool DebugdDBusAdaptor::EnableChromeRemoteDebugging(brillo::ErrorPtr* error) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->EnableChromeRemoteDebugging(error);
}

bool DebugdDBusAdaptor::ConfigureSshServer(brillo::ErrorPtr* error) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->ConfigureSshServer(error);
}

bool DebugdDBusAdaptor::SetUserPassword(brillo::ErrorPtr* error,
                                        const std::string& username,
                                        const std::string& password) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->SetUserPassword(username, password, error);
}

bool DebugdDBusAdaptor::EnableChromeDevFeatures(
    brillo::ErrorPtr* error, const std::string& root_password) {
  auto tool = dev_features_tool_wrapper_->GetTool(error);
  return tool && tool->EnableChromeDevFeatures(root_password, error);
}

bool DebugdDBusAdaptor::QueryDevFeatures(brillo::ErrorPtr* error,
                                         int32_t* features) {
  // Special case: if access fails here, we return DEV_FEATURES_DISABLED rather
  // than a D-Bus error. However, we still want to return an error if we can
  // access the tool but the tool execution fails.
  auto tool = dev_features_tool_wrapper_->GetTool(nullptr);
  if (!tool) {
    *features = DEV_FEATURES_DISABLED;
    return true;
  }

  return tool && tool->QueryDevFeatures(features, error);
}

bool DebugdDBusAdaptor::EnableDevCoredumpUpload(brillo::ErrorPtr* error) {
  if (base::PathExists(base::FilePath(debugd::kDeviceCoredumpUploadFlagPath))) {
    VLOG(1) << "Device coredump upload already enabled";
    return true;
  }
  if (base::WriteFile(base::FilePath(debugd::kDeviceCoredumpUploadFlagPath), "",
                      0) < 0) {
    DEBUGD_ADD_ERROR(error, kDevCoredumpDBusErrorString,
                     "Failed to write flag file.");
    PLOG(ERROR) << "Failed to write flag file.";
    return false;
  }
  return true;
}

bool DebugdDBusAdaptor::DisableDevCoredumpUpload(brillo::ErrorPtr* error) {
  if (!base::PathExists(
          base::FilePath(debugd::kDeviceCoredumpUploadFlagPath))) {
    VLOG(1) << "Device coredump upload already disabled";
    return true;
  }
  if (!brillo::DeleteFile(
          base::FilePath(debugd::kDeviceCoredumpUploadFlagPath))) {
    DEBUGD_ADD_ERROR(error, kDevCoredumpDBusErrorString,
                     "Failed to delete flag file.");
    PLOG(ERROR) << "Failed to delete flag file.";
    return false;
  }
  return true;
}

bool DebugdDBusAdaptor::KstaledSetRatio(brillo::ErrorPtr* error,
                                        uint8_t kstaled_ratio,
                                        bool* out_result) {
  *out_result = swap_tool_->KstaledSetRatio(error, kstaled_ratio);
  return *out_result;
}

std::string DebugdDBusAdaptor::SwapEnable(int32_t size, bool change_now) {
  return swap_tool_->SwapEnable(size, change_now);
}

std::string DebugdDBusAdaptor::SwapDisable(bool change_now) {
  return swap_tool_->SwapDisable(change_now);
}

std::string DebugdDBusAdaptor::SwapStartStop(bool on) {
  return swap_tool_->SwapStartStop(on);
}

std::string DebugdDBusAdaptor::SwapStatus() {
  return swap_tool_->SwapStatus();
}

std::string DebugdDBusAdaptor::SwapSetParameter(
    const std::string& parameter_name, int32_t parameter_value) {
  return swap_tool_->SwapSetParameter(parameter_name, parameter_value);
}

std::string DebugdDBusAdaptor::SwapZramEnableWriteback(uint32_t size_mb) {
  return swap_tool_->SwapZramEnableWriteback(size_mb);
}

std::string DebugdDBusAdaptor::SwapZramMarkIdle(uint32_t age) {
  return swap_tool_->SwapZramMarkIdle(age);
}

std::string DebugdDBusAdaptor::SwapZramSetWritebackLimit(uint32_t limit) {
  return swap_tool_->SwapZramSetWritebackLimit(limit);
}

std::string DebugdDBusAdaptor::InitiateSwapZramWriteback(uint32_t mode) {
  return swap_tool_->InitiateSwapZramWriteback(mode);
}

std::string DebugdDBusAdaptor::SwapSetSwappiness(uint32_t swappiness_value) {
  return swap_tool_->SwapSetSwappiness(swappiness_value);
}

std::string DebugdDBusAdaptor::SetU2fFlags(const std::string& flags) {
  return u2f_tool_->SetFlags(flags);
}

std::string DebugdDBusAdaptor::GetU2fFlags() {
  return u2f_tool_->GetFlags();
}

void DebugdDBusAdaptor::ContainerStarted() {
  container_tool_->ContainerStarted();
}

void DebugdDBusAdaptor::ContainerStopped() {
  container_tool_->ContainerStopped();
}

std::string DebugdDBusAdaptor::WifiFWDump() {
  return wifi_fw_dump_tool_->WifiFWDump();
}

std::string DebugdDBusAdaptor::SetWifiPowerSave(bool enable) {
  return wifi_power_tool_->SetWifiPowerSave(enable);
}

std::string DebugdDBusAdaptor::GetWifiPowerSave() {
  return wifi_power_tool_->GetWifiPowerSave();
}

bool DebugdDBusAdaptor::RunShillScriptStart(
    brillo::ErrorPtr* error,
    const base::ScopedFD& outfd,
    const std::string& script,
    const std::vector<std::string>& script_args,
    std::string* handle) {
  return shill_scripts_tool_->Run(outfd, script, script_args, handle, error);
}

bool DebugdDBusAdaptor::RunShillScriptStop(brillo::ErrorPtr* error,
                                           const std::string& handle) {
  return shill_scripts_tool_->Stop(handle, error);
}

void DebugdDBusAdaptor::StartVmPluginDispatcher(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
    const std::string& in_user_id_hash,
    const std::string& in_lang) {
  // Perform basic validation of user ID hash.
  if (in_user_id_hash.length() != 40) {
    LOG(ERROR) << "Incorrect length of the user_id_hash (" << in_user_id_hash
               << ")";
    response->Return(false);
    return;
  }

  if (!base::ContainsOnlyChars(in_user_id_hash, "abcdef0123456789")) {
    LOG(ERROR) << "user_id_hash should only contain lower case hex digits ("
               << in_user_id_hash << ")";
    response->Return(false);
    return;
  }

  // Perform basic validation of the language string. We expect it to be
  // <language>[-<territory>].
  std::vector<base::StringPiece> chunks = base::SplitStringPiece(
      in_lang, "-", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (chunks.size() < 1 || chunks.size() > 2 || chunks[0].empty()) {
    LOG(ERROR) << "malformed language argument (" << in_lang << ")";
    response->Return(false);
    return;
  }

  vm_plugin_dispatcher_tool_->StartService(
      {{"CROS_USER_ID_HASH", in_user_id_hash}, {"CROS_USER_UI_LANG", in_lang}},
      std::move(response));
}

void DebugdDBusAdaptor::StopVmPluginDispatcher() {
  vm_plugin_dispatcher_tool_->StopService();
}

bool DebugdDBusAdaptor::SetRlzPingSent(brillo::ErrorPtr* error) {
  std::string stderr;
  int result = ProcessWithOutput::RunProcess(
      "/usr/sbin/vpd",
      {"-i", "RW_VPD", "-s", std::string(kShouldSendRlzPingKey) + "=0"},
      true,     // requires root
      false,    // disable_sandbox
      nullptr,  // stdin
      nullptr,  // stdout
      &stderr, error);
  if (result != EXIT_SUCCESS) {
    std::string error_string =
        "Failed to set vpd key: " + std::string(kShouldSendRlzPingKey) +
        " with exit code: " + std::to_string(result) + " with error: " + stderr;
    DEBUGD_ADD_ERROR(error, kDevCoredumpDBusErrorString, error_string);
    PLOG(ERROR) << error_string;
    return false;
  }
  // Remove |kRlzEmbargoEndDateKey|, which is no longer useful after
  // |kShouldSendRlzPingKey| is updated.
  result = ProcessWithOutput::RunProcess(
      "/usr/sbin/vpd",
      {"-i", "RW_VPD", "-d", std::string(kRlzEmbargoEndDateKey)},
      true,     // requires root
      false,    // disable_sandbox
      nullptr,  // stdin
      nullptr,  // stdout
      &stderr, error);
  if (result != EXIT_SUCCESS) {
    std::string error_string =
        "Failed to delete vpd key: " + std::string(kRlzEmbargoEndDateKey) +
        " with exit code: " + std::to_string(result) + " with error: " + stderr;
    DEBUGD_ADD_ERROR(error, kDevCoredumpDBusErrorString, error_string);
    PLOG(ERROR) << error_string;
  }
  // Regenerate the vpd cache log.
  result = ProcessWithOutput::RunProcess("/usr/sbin/dump_vpd_log", {"--force"},
                                         true,     // requires root
                                         false,    // disable_sandbox
                                         nullptr,  // stdin
                                         nullptr,  // stdout
                                         &stderr, error);
  if (result != EXIT_SUCCESS) {
    std::string error_string =
        "Failed to dump vpd log with exit code: " + std::to_string(result) +
        " with error: " + stderr;
    DEBUGD_ADD_ERROR(error, kDevCoredumpDBusErrorString, error_string);
    PLOG(ERROR) << error_string;
  }
  // The client only cares if updating |kShouldSendRlzPingKey| is successful, so
  // returns true regardless of the result of removing |kRlzEmbargoEndDateKey|
  // or the cache log update.
  return true;
}

bool DebugdDBusAdaptor::UpdateAndVerifyFWOnUsbStart(
    brillo::ErrorPtr* error,
    const base::ScopedFD& outfd,
    const std::string& image_file,
    const std::string& ro_db_dir,
    std::string* handle) {
  return verify_ro_tool_->UpdateAndVerifyFWOnUsb(error, outfd, image_file,
                                                 ro_db_dir, handle);
}

bool DebugdDBusAdaptor::UpdateAndVerifyFWOnUsbStop(brillo::ErrorPtr* error,
                                                   const std::string& handle) {
  return verify_ro_tool_->Stop(handle, error);
}

bool DebugdDBusAdaptor::SetSchedulerConfiguration(brillo::ErrorPtr* error,
                                                  const std::string& policy,
                                                  bool* result) {
  uint32_t num_cores_disabled;
  return SetSchedulerConfigurationV2(error, policy, false /* lock_policy */,
                                     result, &num_cores_disabled);
}

bool DebugdDBusAdaptor::SetSchedulerConfigurationV2(
    brillo::ErrorPtr* error,
    const std::string& policy,
    bool lock_policy,
    bool* result,
    uint32_t* num_cores_disabled) {
  *result = scheduler_configuration_tool_->SetPolicy(policy, lock_policy, error,
                                                     num_cores_disabled);
  return *result;
}

bool DebugdDBusAdaptor::EvaluateProbeFunction(
    brillo::ErrorPtr* error,
    const std::string& probe_statement,
    int log_level,
    base::ScopedFD* outfd,
    base::ScopedFD* errfd) {
  return probe_tool_->EvaluateProbeFunction(error, probe_statement, log_level,
                                            outfd, errfd);
}

bool DebugdDBusAdaptor::CollectSmartBatteryMetric(
    brillo::ErrorPtr* error,
    const std::string& metric_name,
    std::string* output) {
  return cros_healthd_tool_->CollectSmartBatteryMetric(error, metric_name,
                                                       output);
}

std::string DebugdDBusAdaptor::EcGetInventory() {
  return ec_typec_tool_->GetInventory();
}

bool DebugdDBusAdaptor::CallDmesg(brillo::ErrorPtr* error,
                                  const brillo::VariantDictionary& options,
                                  std::string* output) {
  return dmesg_tool_->CallDmesg(options, error, output);
}

bool DebugdDBusAdaptor::EcTypeCEnterMode(brillo::ErrorPtr* error,
                                         uint32_t port_num,
                                         uint32_t mode,
                                         std::string* output) {
  return ec_typec_tool_->EnterMode(error, port_num, mode, output);
}

bool DebugdDBusAdaptor::EcTypeCExitMode(brillo::ErrorPtr* error,
                                        uint32_t port_num,
                                        std::string* output) {
  return ec_typec_tool_->ExitMode(error, port_num, output);
}

bool DebugdDBusAdaptor::EcTypeCDpState(brillo::ErrorPtr* error,
                                       uint32_t port_num,
                                       bool* output) {
  return ec_typec_tool_->DpState(error, port_num, output);
}

bool DebugdDBusAdaptor::EcTypeCHpdState(brillo::ErrorPtr* error,
                                        uint32_t port_num,
                                        bool* output) {
  return ec_typec_tool_->HpdState(error, port_num, output);
}

bool DebugdDBusAdaptor::KernelFeatureEnable(brillo::ErrorPtr* error,
                                            const std::string& name,
                                            bool* result,
                                            std::string* err_str) {
  return kernel_feature_tool_->KernelFeatureEnable(error, name, result,
                                                   err_str);
}

bool DebugdDBusAdaptor::KernelFeatureList(brillo::ErrorPtr* error,
                                          bool* result,
                                          std::string* csv) {
  return kernel_feature_tool_->KernelFeatureList(error, result, csv);
}

bool DebugdDBusAdaptor::DRMTraceSetCategories(brillo::ErrorPtr* error,
                                              uint32_t categories) {
  return drm_trace_tool_->SetCategories(error, categories);
}

bool DebugdDBusAdaptor::DRMTraceSetSize(brillo::ErrorPtr* error,
                                        uint32_t size_enum) {
  return drm_trace_tool_->SetSize(error, size_enum);
}

bool DebugdDBusAdaptor::DRMTraceAnnotateLog(brillo::ErrorPtr* error,
                                            const std::string& log) {
  return drm_trace_tool_->AnnotateLog(error, log);
}

bool DebugdDBusAdaptor::DRMTraceSnapshot(brillo::ErrorPtr* error,
                                         uint32_t type_enum) {
  return drm_trace_tool_->Snapshot(error, type_enum);
}

bool DebugdDBusAdaptor::SetCrashSenderTestMode(brillo::ErrorPtr* error,
                                               bool mode) {
  if (!dev_features_tool_wrapper_->restriction().InDevMode()) {
    DEBUGD_ADD_ERROR(error, kSetCrashSenderTestModeErrorString,
                     "Dev mode is required to use this API.");
    return false;
  }

  crash_sender_tool_->SetTestMode(mode);
  return true;
}

bool DebugdDBusAdaptor::PrintscanDebugSetCategories(brillo::ErrorPtr* error,
                                                    uint32_t categories) {
  PrintscanCategories categories_enum;
  switch (categories) {
    case 0x0: {
      categories_enum = PrintscanCategories::PRINTSCAN_NO_CATEGORIES;
      break;
    }
    case 0x1: {
      categories_enum = PrintscanCategories::PRINTSCAN_PRINTING_CATEGORY;
      break;
    }
    case 0x2: {
      categories_enum = PrintscanCategories::PRINTSCAN_SCANNING_CATEGORY;
      break;
    }
    case 0x3: {
      categories_enum = PrintscanCategories::PRINTSCAN_ALL_CATEGORIES;
      break;
    }
    default: {
      DEBUGD_ADD_ERROR(error, kPrintscanDebugSetCategoriesErrorString,
                       "Invalid categories for PrintscanDebugSetCategories.");
      return false;
    }
  }
  return printscan_tool_->DebugSetCategories(error, categories_enum);
}

}  // namespace debugd
