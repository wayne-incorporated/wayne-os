// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_DEBUGD_DBUS_ADAPTOR_H_
#define DEBUGD_SRC_DEBUGD_DBUS_ADAPTOR_H_

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/scoped_file.h>
#include <brillo/dbus/exported_object_manager.h>
#include <brillo/dbus/exported_property_set.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>

#include "debugd/dbus_adaptors/org.chromium.debugd.h"
#include "debugd/src/battery_tool.h"
#include "debugd/src/container_tool.h"
#include "debugd/src/crash_sender_tool.h"
#include "debugd/src/cros_healthd_tool.h"
#include "debugd/src/cups_tool.h"
#include "debugd/src/debug_logs_tool.h"
#include "debugd/src/debug_mode_tool.h"
#include "debugd/src/dev_features_tool.h"
#include "debugd/src/dmesg_tool.h"
#include "debugd/src/drm_trace_tool.h"
#include "debugd/src/ec_typec_tool.h"
#include "debugd/src/example_tool.h"
#include "debugd/src/icmp_tool.h"
#include "debugd/src/ipaddrs_tool.h"
#include "debugd/src/kernel_feature_tool.h"
#include "debugd/src/log_tool.h"
#include "debugd/src/memory_tool.h"
#include "debugd/src/netif_tool.h"
#include "debugd/src/network_status_tool.h"
#include "debugd/src/oom_adj_tool.h"
#include "debugd/src/packet_capture_tool.h"
#include "debugd/src/perf_tool.h"
#include "debugd/src/ping_tool.h"
#include "debugd/src/printscan_tool.h"
#include "debugd/src/probe_tool.h"
#include "debugd/src/restricted_tool_wrapper.h"
#include "debugd/src/route_tool.h"
#include "debugd/src/scheduler_configuration_tool.h"
#include "debugd/src/session_manager_proxy.h"
#include "debugd/src/shill_scripts_tool.h"
#include "debugd/src/simple_service_tool.h"
#include "debugd/src/storage_tool.h"
#include "debugd/src/swap_tool.h"
#include "debugd/src/sysrq_tool.h"
#include "debugd/src/systrace_tool.h"
#include "debugd/src/tracepath_tool.h"
#include "debugd/src/u2f_tool.h"
#include "debugd/src/verify_ro_tool.h"
#include "debugd/src/wifi_fw_dump_tool.h"
#include "debugd/src/wifi_power_tool.h"

namespace debugd {

class DebugdDBusAdaptor : public org::chromium::debugdAdaptor,
                          public org::chromium::debugdInterface {
 public:
  explicit DebugdDBusAdaptor(scoped_refptr<dbus::Bus> bus,
                             const bool perf_logging);
  ~DebugdDBusAdaptor() override;

  // Register the D-Bus object and interfaces.
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // org::chromium::debugdInterface overrides; D-Bus methods.
  std::string BatteryFirmware(const std::string& option) override;
  bool PingStart(brillo::ErrorPtr* error,
                 const base::ScopedFD& outfd,
                 const std::string& dest,
                 const brillo::VariantDictionary& options,
                 std::string* handle) override;
  bool PingStop(brillo::ErrorPtr* error, const std::string& handle) override;
  std::string TracePathStart(const base::ScopedFD& outfd,
                             const std::string& destination,
                             const brillo::VariantDictionary& options) override;
  bool TracePathStop(brillo::ErrorPtr* error,
                     const std::string& handle) override;
  void SystraceStart(const std::string& categories) override;
  void SystraceStop(const base::ScopedFD& outfd) override;
  std::string SystraceStatus() override;
  std::vector<std::string> GetIpAddresses(
      const brillo::VariantDictionary& options) override;
  std::vector<std::string> GetRoutes(
      const brillo::VariantDictionary& options) override;
  std::string GetNetworkStatus() override;
  bool GetPerfOutput(brillo::ErrorPtr* error,
                     uint32_t duration_sec,
                     const std::vector<std::string>& perf_args,
                     int32_t* status,
                     std::vector<uint8_t>* perf_data,
                     std::vector<uint8_t>* perf_stat) override;
  bool GetPerfOutputFd(brillo::ErrorPtr* error,
                       uint32_t duration_sec,
                       const std::vector<std::string>& perf_args,
                       const base::ScopedFD& stdout_fd,
                       uint64_t* session_id) override;
  bool StopPerf(brillo::ErrorPtr* error, uint64_t session_id) override;
  bool GetPerfOutputV2(brillo::ErrorPtr* error,
                       const std::vector<std::string>& quipper_args,
                       bool disable_cpu_idle,
                       const base::ScopedFD& stdout_fd,
                       uint64_t* session_id) override;
  void DumpDebugLogs(bool is_compressed, const base::ScopedFD& fd) override;
  void SetDebugMode(const std::string& subsystem) override;
  std::string GetLog(const std::string& name) override;
  std::map<std::string, std::string> GetAllLogs() override;
  void GetFeedbackLogsV2(const base::ScopedFD& fd,
                         const std::string& username,
                         const std::vector<int32_t>& requested_logs) override;
  void GetFeedbackLogsV3(const base::ScopedFD& fd,
                         const std::string& username,
                         const std::vector<int32_t>& requested_logs) override;
  void BackupArcBugReport(const std::string& username) override;
  void DeleteArcBugReportBackup(const std::string& username) override;
  std::string GetExample() override;
  int32_t CupsAddAutoConfiguredPrinter(const std::string& name,
                                       const std::string& uri) override;
  int32_t CupsAddAutoConfiguredPrinterV2(const std::string& name,
                                         const std::string& uri,
                                         const std::string& language) override;
  int32_t CupsAddManuallyConfiguredPrinter(
      const std::string& name,
      const std::string& uri,
      const std::vector<uint8_t>& ppd_contents) override;
  int32_t CupsAddManuallyConfiguredPrinterV2(
      const std::string& name,
      const std::string& uri,
      const std::string& language,
      const std::vector<uint8_t>& ppd_contents) override;
  bool CupsRemovePrinter(const std::string& name) override;
  std::vector<uint8_t> CupsRetrievePpd(const std::string& name) override;
  std::string GetInterfaces() override;
  std::string TestICMP(const std::string& host) override;
  std::string TestICMPWithOptions(
      const std::string& host,
      const std::map<std::string, std::string>& options) override;
  std::string Smartctl(const std::string& option) override;
  std::string Mmc(const std::string& option) override;
  std::string Ufs(const std::string& option) override;
  std::string Nvme(const std::string& option) override;
  std::string NvmeLog(const uint32_t page_id,
                      const uint32_t length,
                      bool raw_binary) override;
  std::string MemtesterStart(const base::ScopedFD& outfd,
                             uint32_t memory) override;
  bool MemtesterStop(brillo::ErrorPtr* error,
                     const std::string& handle) override;
  std::string BadblocksStart(const base::ScopedFD& outfd) override;
  bool BadblocksStop(brillo::ErrorPtr* error,
                     const std::string& handle) override;
  bool PacketCaptureStart(brillo::ErrorPtr* error,
                          const base::ScopedFD& statfd,
                          const base::ScopedFD& outfd,
                          const brillo::VariantDictionary& options,
                          std::string* handle) override;
  bool PacketCaptureStop(brillo::ErrorPtr* error,
                         const std::string& handle) override;
  bool LogKernelTaskStates(brillo::ErrorPtr* error) override;
  void UploadCrashes() override;
  bool UploadSingleCrash(
      brillo::ErrorPtr* error,
      const std::vector<std::tuple<std::string, base::ScopedFD>>& in_files,
      bool consent_already_checked_by_crash_reporter) override;
  bool RemoveRootfsVerification(brillo::ErrorPtr* error) override;
  bool EnableBootFromUsb(brillo::ErrorPtr* error) override;
  bool EnableChromeRemoteDebugging(brillo::ErrorPtr* error) override;
  bool ConfigureSshServer(brillo::ErrorPtr* error) override;
  bool SetUserPassword(brillo::ErrorPtr* error,
                       const std::string& username,
                       const std::string& password) override;
  bool EnableChromeDevFeatures(brillo::ErrorPtr* error,
                               const std::string& root_password) override;
  bool QueryDevFeatures(brillo::ErrorPtr* error, int32_t* features) override;
  bool EnableDevCoredumpUpload(brillo::ErrorPtr* error) override;
  bool DisableDevCoredumpUpload(brillo::ErrorPtr* error) override;
  std::string SetOomScoreAdj(const std::map<pid_t, int32_t>& scores) override;
  bool KstaledSetRatio(brillo::ErrorPtr* error,
                       uint8_t kstaled_ratio,
                       bool* out_result) override;
  std::string SwapEnable(int32_t size, bool change_now) override;
  std::string SwapDisable(bool change_now) override;
  std::string SwapStartStop(bool on) override;
  std::string SwapStatus() override;
  std::string SwapSetParameter(const std::string& parameter_name,
                               int32_t parameter_value) override;
  std::string SwapZramEnableWriteback(uint32_t size_mb) override;
  std::string SwapZramMarkIdle(uint32_t age) override;
  std::string SwapZramSetWritebackLimit(uint32_t limit) override;
  std::string InitiateSwapZramWriteback(uint32_t mode) override;
  std::string SwapSetSwappiness(uint32_t swappiness_value) override;
  std::string SetU2fFlags(const std::string& flags) override;
  std::string GetU2fFlags() override;
  void ContainerStarted() override;
  void ContainerStopped() override;
  std::string WifiFWDump() override;
  std::string SetWifiPowerSave(bool enable) override;
  std::string GetWifiPowerSave() override;
  bool RunShillScriptStart(brillo::ErrorPtr* error,
                           const base::ScopedFD& outfd,
                           const std::string& script,
                           const std::vector<std::string>& script_args,
                           std::string* handle) override;
  bool RunShillScriptStop(brillo::ErrorPtr* error,
                          const std::string& handle) override;
  void StartVmPluginDispatcher(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
      const std::string& in_user_id_hash,
      const std::string& in_lang) override;
  void StopVmPluginDispatcher() override;
  bool SetRlzPingSent(brillo::ErrorPtr* error) override;
  bool UpdateAndVerifyFWOnUsbStart(brillo::ErrorPtr* error,
                                   const base::ScopedFD& outfd,
                                   const std::string& image_file,
                                   const std::string& ro_db_dir,
                                   std::string* handle) override;
  bool UpdateAndVerifyFWOnUsbStop(brillo::ErrorPtr* error,
                                  const std::string& handle) override;
  bool SetSchedulerConfiguration(brillo::ErrorPtr* error,
                                 const std::string& policy,
                                 bool* out) override;
  bool SetSchedulerConfigurationV2(brillo::ErrorPtr* error,
                                   const std::string& policy,
                                   bool lock_policy,
                                   bool* result,
                                   uint32_t* num_cores_disabled) override;
  bool EvaluateProbeFunction(brillo::ErrorPtr* error,
                             const std::string& probe_statement,
                             int log_level,
                             base::ScopedFD* outfd,
                             base::ScopedFD* errfd) override;
  bool CollectSmartBatteryMetric(brillo::ErrorPtr* error,
                                 const std::string& metric_name,
                                 std::string* output) override;
  std::string EcGetInventory() override;
  bool CallDmesg(brillo::ErrorPtr* error,
                 const brillo::VariantDictionary& options,
                 std::string* output) override;
  bool EcTypeCEnterMode(brillo::ErrorPtr* error,
                        uint32_t port_num,
                        uint32_t mode,
                        std::string* output) override;
  bool EcTypeCExitMode(brillo::ErrorPtr* error,
                       uint32_t port_num,
                       std::string* output) override;
  bool EcTypeCDpState(brillo::ErrorPtr* error,
                      uint32_t port_num,
                      bool* output) override;
  bool EcTypeCHpdState(brillo::ErrorPtr* error,
                       uint32_t port_num,
                       bool* output) override;

  bool KernelFeatureEnable(brillo::ErrorPtr* error,
                           const std::string& name,
                           bool* result,
                           std::string* err_str) override;
  bool KernelFeatureList(brillo::ErrorPtr* error,
                         bool* result,
                         std::string* csv) override;

  bool DRMTraceSetCategories(brillo::ErrorPtr* error,
                             uint32_t categories) override;
  bool DRMTraceSetSize(brillo::ErrorPtr* error, uint32_t size_enum) override;
  bool DRMTraceAnnotateLog(brillo::ErrorPtr* error,
                           const std::string& log) override;
  bool DRMTraceSnapshot(brillo::ErrorPtr* error, uint32_t type_enum) override;
  bool SetCrashSenderTestMode(brillo::ErrorPtr* error, bool mode) override;
  bool PrintscanDebugSetCategories(brillo::ErrorPtr* error,
                                   uint32_t categories) override;

 private:
  void OnPacketCaptureStopped();

  brillo::dbus_utils::DBusObject dbus_object_;

  std::unique_ptr<SessionManagerProxy> session_manager_proxy_;

  std::unique_ptr<BatteryTool> battery_tool_;
  std::unique_ptr<ContainerTool> container_tool_;
  std::unique_ptr<CrashSenderTool> crash_sender_tool_;
  std::unique_ptr<CupsTool> cups_tool_;
  std::unique_ptr<DebugLogsTool> debug_logs_tool_;
  std::unique_ptr<DebugModeTool> debug_mode_tool_;
  std::unique_ptr<DmesgTool> dmesg_tool_;
  std::unique_ptr<DRMTraceTool> drm_trace_tool_;
  std::unique_ptr<RestrictedToolWrapper<DevFeaturesTool>>
      dev_features_tool_wrapper_;
  std::unique_ptr<EcTypeCTool> ec_typec_tool_;
  std::unique_ptr<ExampleTool> example_tool_;
  std::unique_ptr<ICMPTool> icmp_tool_;
  std::unique_ptr<IpAddrsTool> ipaddrs_tool_;
  std::unique_ptr<LogTool> log_tool_;
  std::unique_ptr<MemtesterTool> memory_tool_;
  std::unique_ptr<NetifTool> netif_tool_;
  std::unique_ptr<NetworkStatusTool> network_status_tool_;
  std::unique_ptr<OomAdjTool> oom_adj_tool_;
  std::unique_ptr<PacketCaptureTool> packet_capture_tool_;
  std::unique_ptr<PerfTool> perf_tool_;
  std::unique_ptr<PingTool> ping_tool_;
  std::unique_ptr<PrintscanTool> printscan_tool_;
  std::unique_ptr<RouteTool> route_tool_;
  std::unique_ptr<SchedulerConfigurationTool> scheduler_configuration_tool_;
  std::unique_ptr<ShillScriptsTool> shill_scripts_tool_;
  std::unique_ptr<StorageTool> storage_tool_;
  std::unique_ptr<SwapTool> swap_tool_;
  std::unique_ptr<SysrqTool> sysrq_tool_;
  std::unique_ptr<SystraceTool> systrace_tool_;
  std::unique_ptr<TracePathTool> tracepath_tool_;
  std::unique_ptr<U2fTool> u2f_tool_;
  std::unique_ptr<VerifyRoTool> verify_ro_tool_;
  std::unique_ptr<SimpleServiceTool> vm_plugin_dispatcher_tool_;
  std::unique_ptr<WifiFWDumpTool> wifi_fw_dump_tool_;
  std::unique_ptr<WifiPowerTool> wifi_power_tool_;
  std::unique_ptr<ProbeTool> probe_tool_;
  std::unique_ptr<CrosHealthdTool> cros_healthd_tool_;
  std::unique_ptr<KernelFeatureTool> kernel_feature_tool_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_DEBUGD_DBUS_ADAPTOR_H_
