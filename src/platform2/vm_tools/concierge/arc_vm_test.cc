// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/arc_vm.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/memory/page_size.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/test/scoped_chromeos_version_info.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <base/timer/mock_timer.h>
#include <base/timer/timer.h>
#include <chromeos/patchpanel/dbus/fake_client.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libcrossystem/crossystem_fake.h>
#include <spaced/dbus-proxies.h>
#include <spaced/dbus-proxy-mocks.h>
#include <spaced/disk_usage_proxy.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/concierge/balloon_policy.h"
#include "vm_tools/concierge/fake_crosvm_control.h"
#include "vm_tools/concierge/vmm_swap_low_disk_policy.h"
#include "vm_tools/concierge/vmm_swap_tbw_policy.h"

using ::testing::_;

namespace vm_tools {
namespace concierge {
namespace {
constexpr int kSeneschalServerPort = 3000;
constexpr int kLcdDensity = 160;
}  // namespace

TEST(ArcVmParamsTest, NonDevModeKernelParams) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  cros_system.VbSetSystemPropertyInt("cros_debug", 0);
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.dev_mode=0"));
  EXPECT_TRUE(base::Contains(params, "androidboot.disable_runas=1"));
}

TEST(ArcVmParamsTest, DevModeKernelParams) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  cros_system.VbSetSystemPropertyInt("cros_debug", 1);
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.dev_mode=1"));
  EXPECT_TRUE(base::Contains(params, "androidboot.disable_runas=0"));
}

TEST(ArcVmParamsTest, SeneschalServerPortParam) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, base::StringPrintf("androidboot.seneschal_server_port=%d",
                                 kSeneschalServerPort)));
}

TEST(ArcVmParamsTest, EnableConsumerAutoUpdateToggleParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_consumer_auto_update_toggle(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.enable_consumer_auto_update_toggle=1"));
}

TEST(ArcVmParamsTest, EnableConsumerAutoUpdateToggleParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_consumer_auto_update_toggle(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.enable_consumer_auto_update_toggle=0"));
}

TEST(ArcVmParamsTest, ArcFilePickerParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_file_picker_experiment(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_file_picker=1"));
}

TEST(ArcVmParamsTest, ArcFilePickerParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_file_picker_experiment(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_file_picker=0"));
}

TEST(ArcVmParamsTest, CustomTabsParamTrue) {
  base::test::ScopedChromeOSVersionInfo info(
      "CHROMEOS_RELEASE_TRACK=canary-channel", base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_custom_tabs_experiment(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_custom_tabs=1"));
}

TEST(ArcVmParamsTest, CustomTabsParamFalse) {
  base::test::ScopedChromeOSVersionInfo info(
      "CHROMEOS_RELEASE_TRACK=canary-channel", base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_custom_tabs_experiment(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_custom_tabs=0"));
}

TEST(ArcVmParamsTest, CustomTabsParamStableChannel) {
  base::test::ScopedChromeOSVersionInfo info(
      "CHROMEOS_RELEASE_TRACK=stable-channel", base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_custom_tabs_experiment(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_custom_tabs=1"));
}

TEST(ArcVmParamsTest, KeyboardShortcutHelperParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_keyboard_shortcut_helper_integration(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.keyboard_shortcut_helper_integration=1"));
}

TEST(ArcVmParamsTest, KeyboardShortcutHelperParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_keyboard_shortcut_helper_integration(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.keyboard_shortcut_helper_integration=0"));
}

TEST(ArcVmParamsTest, EnableNotificationsRefreshParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_notifications_refresh(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.enable_notifications_refresh=1"));
}

TEST(ArcVmParamsTest, EnableNotificationsRefreshParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_notifications_refresh(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.enable_notifications_refresh=0"));
}

TEST(ArcVmParamsTest, EnableTtsCachingParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_tts_caching(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc.tts.caching=1"));
}

TEST(ArcVmParamsTest, EnableTtsCachingParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_tts_caching(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(base::Contains(params, "androidboot.arc.tts.caching=1"));
}

TEST(ArcVmParamsTest, EnableVirtioBlockDataParamTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_virtio_blk_data(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arcvm_virtio_blk_data=1"));
}

TEST(ArcVmParamsTest, EnableVirtioBlockDataParamFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_virtio_blk_data(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arcvm_virtio_blk_data=0"));
}

TEST(ArcVmParamsTest, EnableBroadcastAnrPrenotifyTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_broadcast_anr_prenotify(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc.broadcast_anr_prenotify=1"));
}

TEST(ArcVmParamsTest, EnableBroadcastAnrPrenotifyFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_broadcast_anr_prenotify(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(
      base::Contains(params, "androidboot.arc.broadcast_anr_prenotify=1"));
}

TEST(ArcVmParamsTest, VmMemoryPSIReports) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_vm_memory_psi_period(300);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arcvm_metrics_mem_psi_period=300"));
}

TEST(ArcVmParamsTest, VmMemoryPSIReportsDefault) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_vm_memory_psi_period(-1);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& param : params) {
    EXPECT_FALSE(
        base::StartsWith(param, "androidboot.arcvm_metrics_mem_psi_period="));
  }
}

TEST(ArcVmParamsTest, DisableMediaStoreMaintenanceTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_disable_media_store_maintenance(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.disable_media_store_maintenance=1"));
}

TEST(ArcVmParamsTest, DisableMediaStoreMaintenanceFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_disable_media_store_maintenance(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(
      base::Contains(params, "androidboot.disable_media_store_maintenance=1"));
}

TEST(ArcVmParamsTest, ArcGeneratePlayAutoInstallTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_generate_pai(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.arc_generate_pai=1"));
}

TEST(ArcVmParamsTest, ArcGeneratePlayAutoInstallFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_arc_generate_pai(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(base::Contains(params, "androidboot.arc_generate_pai=1"));
}

TEST(ArcVmParamsTest, DisableDownloadProviderTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_disable_download_provider(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.disable_download_provider=1"));
}

TEST(ArcVmParamsTest, DisableDownloadProviderFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_disable_download_provider(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(
      base::Contains(params, "androidboot.disable_download_provider=1"));
}

TEST(ArcVmParamsTest, GuestZramSize0) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_guest_zram_size(0);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.zram_size=0"));
}

TEST(ArcVmParamsTest, GuestZramSize100) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_guest_zram_size(100);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.zram_size=100"));
}

TEST(ArcVmParamsTest, ChromeOsChannelStable) {
  base::test::ScopedChromeOSVersionInfo info(
      "CHROMEOS_RELEASE_TRACK=stable-channel", base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.chromeos_channel=stable"));
}

TEST(ArcVmParamsTest, ChromeOsChannelTestImage) {
  base::test::ScopedChromeOSVersionInfo info(
      "CHROMEOS_RELEASE_TRACK=testimage-channel", base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.vshd_service_override=vshd_for_test"));
}

TEST(ArcVmParamsTest, ChromeOsChannelUnknown) {
  base::test::ScopedChromeOSVersionInfo info("CHROMEOS_RELEASE_TRACK=invalid",
                                             base::Time::Now());
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.chromeos_channel=unknown"));
}

TEST(ArcVmParamsTest, PanelOrientation) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_panel_orientation(StartArcVmRequest::ORIENTATION_180);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.arc.primary_display_rotation=ORIENTATION_180"));
}

TEST(ArcVmParamsTest, IioservicePresentParam) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params,
      base::StringPrintf("androidboot.iioservice_present=%d", USE_IIOSERVICE)));
}

TEST(ArcVmParamsTest, SwappinessNotPresentByDefault) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& oneParam : params) {
    EXPECT_FALSE(base::StartsWith(oneParam, "sysctl.vm.swappiness="));
  }
}

TEST(ArcVmParamsTest, SwappinessPresentParam) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_guest_swappiness(55);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, base::StringPrintf("sysctl.vm.swappiness=%d", 55)));
}

TEST(ArcVmParamsTest, MglruReclaimIntervalDisabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_mglru_reclaim_interval(0);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& param : params) {
    EXPECT_FALSE(
        base::StartsWith(param, "androidboot.arcvm_mglru_reclaim_interval="));
  }
}

TEST(ArcVmParamsTest, MglruReclaimWithoutSwappiness) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_mglru_reclaim_interval(30000);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params,
      base::StringPrintf("androidboot.arcvm_mglru_reclaim_interval=30000")));
  EXPECT_TRUE(base::Contains(
      params,
      base::StringPrintf("androidboot.arcvm_mglru_reclaim_swappiness=0")));
}

TEST(ArcVmParamsTest, MglruReclaimWithSwappiness) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_mglru_reclaim_interval(30000);
  request.set_mglru_reclaim_swappiness(100);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params,
      base::StringPrintf("androidboot.arcvm_mglru_reclaim_interval=30000")));
  EXPECT_TRUE(base::Contains(
      params,
      base::StringPrintf("androidboot.arcvm_mglru_reclaim_swappiness=100")));
}

TEST(ArcVmParamsTest, NativeBridgeExperimentNone) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_native_bridge_experiment(
      vm_tools::concierge::StartArcVmRequest::BINARY_TRANSLATION_TYPE_NONE);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.native_bridge=0"));
}

TEST(ArcVmParamsTest, NativeBridgeExperimentHoudini) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_native_bridge_experiment(
      vm_tools::concierge::StartArcVmRequest::BINARY_TRANSLATION_TYPE_HOUDINI);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.native_bridge=libhoudini.so"));
}

TEST(ArcVmParamsTest, NativeBridgeExperimentNdkTranslation) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_native_bridge_experiment(
      vm_tools::concierge::StartArcVmRequest::
          BINARY_TRANSLATION_TYPE_NDK_TRANSLATION);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, "androidboot.native_bridge=libndk_translation.so"));
}

TEST(ArcVmParamsTest, UsapProfileDefault) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_usap_profile(
      vm_tools::concierge::StartArcVmRequest::USAP_PROFILE_DEFAULT);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& oneParam : params) {
    EXPECT_FALSE(base::StartsWith(oneParam, "androidboot.usap_profile="));
  }
}

TEST(ArcVmParamsTest, UsapProfile4G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_usap_profile(
      vm_tools::concierge::StartArcVmRequest::USAP_PROFILE_4G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.usap_profile=4G"));
}

TEST(ArcVmParamsTest, UsapProfile8G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_usap_profile(
      vm_tools::concierge::StartArcVmRequest::USAP_PROFILE_8G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.usap_profile=8G"));
}

TEST(ArcVmParamsTest, UsapProfile16G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_usap_profile(
      vm_tools::concierge::StartArcVmRequest::USAP_PROFILE_16G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.usap_profile=16G"));
}

TEST(ArcVmParamsTest, PlayStoreAutoUpdateDefault) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_play_store_auto_update(
      arc::StartArcMiniInstanceRequest::AUTO_UPDATE_DEFAULT);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& oneParam : params) {
    EXPECT_FALSE(
        base::StartsWith(oneParam, "androidboot.play_store_auto_update="));
  }
}

TEST(ArcVmParamsTest, PlayStoreAutoUpdateON) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_play_store_auto_update(
      arc::StartArcMiniInstanceRequest::AUTO_UPDATE_ON);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.play_store_auto_update=1"));
}

TEST(ArcVmParamsTest, PlayStoreAutoUpdateOFF) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_play_store_auto_update(
      arc::StartArcMiniInstanceRequest::AUTO_UPDATE_OFF);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.play_store_auto_update=0"));
}

TEST(ArcVmParamsTest, DalvikMemoryProfileDefault) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_dalvik_memory_profile(
      arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_DEFAULT);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc_dalvik_memory_profile=4G"));
}

TEST(ArcVmParamsTest, DalvikMemoryProfile4G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_dalvik_memory_profile(
      arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_4G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc_dalvik_memory_profile=4G"));
}

TEST(ArcVmParamsTest, DalvikMemoryProfile8G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_dalvik_memory_profile(
      arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_8G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc_dalvik_memory_profile=8G"));
}

TEST(ArcVmParamsTest, DalvikMemoryProfile16G) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_dalvik_memory_profile(
      arc::StartArcMiniInstanceRequest::MEMORY_PROFILE_16G);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc_dalvik_memory_profile=16G"));
}

TEST(ArcVmParamsTest, LcdDensity) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_lcd_density(kLcdDensity);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(
      params, base::StringPrintf("androidboot.lcd_density=%d", kLcdDensity)));
}

TEST(ArcVmParamsTest, HostOnVmTrue) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  cros_system.VbSetSystemPropertyInt("inside_vm", 1);
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.host_is_in_vm=1"));
}

TEST(ArcVmParamsTest, HostOnVmFalse) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  cros_system.VbSetSystemPropertyInt("inside_vm", 0);
  StartArcVmRequest request;
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "androidboot.host_is_in_vm=0"));
}

TEST(ArcVmParamsTest, UreadaheadModeReadahead) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_ureadahead_mode(
      vm_tools::concierge::StartArcVmRequest::UREADAHEAD_MODE_READAHEAD);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arcvm_ureadahead_mode=readahead"));
}

TEST(ArcVmParamsTest, UreadaheadModeGenerate) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_ureadahead_mode(
      vm_tools::concierge::StartArcVmRequest::UREADAHEAD_MODE_GENERATE);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arcvm_ureadahead_mode=generate"));
}

TEST(ArcVmParamsTest, UreadaheadModeDisabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_ureadahead_mode(
      vm_tools::concierge::StartArcVmRequest::UREADAHEAD_MODE_DISABLED);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  for (const auto& oneParam : params) {
    EXPECT_FALSE(
        base::StartsWith(oneParam, "androidboot.arcvm_ureadahead_mode="));
  }
}

TEST(ArcVmParamsTest, ReadWriteEnabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_rw(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(base::Contains(params, "rw"));
}

TEST(ArcVmParamsTest, ReadWriteDisabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_rw(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(base::Contains(params, "rw"));
}

TEST(ArcVmParamsTest, WebViewZygoteLazyInitEnabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_web_view_zygote_lazy_init(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.arc.web_view_zygote.lazy_init=1"));
}

TEST(ArcVmParamsTest, WebViewZygoteLazyInitDisabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  request.set_enable_web_view_zygote_lazy_init(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_FALSE(
      base::Contains(params, "androidboot.arc.web_view_zygote.lazy_init=1"));
}

TEST(ArcVmParamsTest, PrivacyHubForChromeEnabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_privacy_hub_for_chrome(true);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.enable_privacy_hub_for_chrome=1"));
}

TEST(ArcVmParamsTest, PrivacyHubForChromeDisabled) {
  crossystem::Crossystem cros_system(
      std::make_unique<crossystem::fake::CrossystemFake>());
  StartArcVmRequest request;
  auto* mini_instance_request = request.mutable_mini_instance_request();
  mini_instance_request->set_enable_privacy_hub_for_chrome(false);
  std::vector<std::string> params =
      ArcVm::GetKernelParams(cros_system, request, kSeneschalServerPort);
  EXPECT_TRUE(
      base::Contains(params, "androidboot.enable_privacy_hub_for_chrome=0"));
}

TEST(ArcVmParamsTest, GetOemEtcSharedDataParam) {
  EXPECT_EQ(
      GetOemEtcSharedDataParam(299 /* uid */,
                               // gid is usually 299 but use a different value
                               // from UID for ease of testing.
                               300 /* gid */)
          .to_string(),
      "/run/arcvm/host_generated/oem/etc:oem_etc:type=fs:cache=always:uidmap=0 "
      "299 1, 5000 600 50:gidmap=0 300 1, 5000 600 "
      "50:timeout=3600:rewrite-security-xattrs=true:writeback=true:posix_acl="
      "false");
}

class FakeSwapVmCallback {
 public:
  ArcVm::SwapVmCallback Create() {
    return base::BindOnce(&FakeSwapVmCallback::Response,
                          weak_ptr_factory_.GetWeakPtr());
  }

  std::optional<SwapVmResponse> latest_response_;

 private:
  void Response(SwapVmResponse response) { latest_response_ = response; }

  base::WeakPtrFactory<FakeSwapVmCallback> weak_ptr_factory_{this};
};

// Test fixture for actually testing the ArcVm functionality.
class ArcVmTest : public ::testing::Test {
 protected:
  static constexpr int64_t kGuestMemorySize = 1 << 30;  // 1GiB

  void SetUp() override {
    FakeCrosvmControl::Init();

    // Create the temporary directory.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());

    // Allocate resources for the VM.
    uint32_t vsock_cid = vsock_cid_pool_.Allocate();

    vmm_swap_tbw_policy_->SetTargetTbwPerDay(512 * MIB);

    // The following owned and destroyed by ArcVm class unique_ptr destructor.
    auto swap_policy_timer = std::make_unique<base::MockOneShotTimer>();
    swap_policy_timer_ = swap_policy_timer.get();
    auto swap_state_monitor_timer =
        std::make_unique<base::MockRepeatingTimer>();
    swap_state_monitor_timer_ = swap_state_monitor_timer.get();
    auto aggressive_balloon_timer =
        std::make_unique<base::MockRepeatingTimer>();
    aggressive_balloon_timer_ = aggressive_balloon_timer.get();

    spaced_proxy_ = new org::chromium::SpacedProxyMock();
    SpacedProxyReturnSuccessCallback(10LL << 30);  // 10GiB

    disk_usage_proxy_ = std::make_unique<spaced::DiskUsageProxy>(
        std::unique_ptr<org::chromium::SpacedProxyMock>(spaced_proxy_));

    vm_ = std::unique_ptr<ArcVm>(new ArcVm(ArcVm::Config{
        .vsock_cid = vsock_cid,
        .network_client = std::make_unique<patchpanel::FakeClient>(),
        .seneschal_server_proxy = nullptr,
        .vmm_swap_low_disk_policy = std::make_unique<VmmSwapLowDiskPolicy>(
            base::FilePath("dummy"),
            raw_ref<spaced::DiskUsageProxy>::from_ptr(disk_usage_proxy_.get())),
        .vmm_swap_tbw_policy =
            raw_ref<VmmSwapTbwPolicy>::from_ptr(vmm_swap_tbw_policy_.get()),
        .guest_memory_size = kGuestMemorySize,
        .runtime_dir = temp_dir_.GetPath(),
        .data_disk_path = base::FilePath("dummy"),
        .features = {},
        .swap_policy_timer = std::move(swap_policy_timer),
        .swap_state_monitor_timer = std::move(swap_state_monitor_timer),
        .aggressive_balloon_timer = std::move(aggressive_balloon_timer)}));

    // The more than 28days enabled log unblocks the VmmSwapUsagePolicy.
    // We don't add OnDisabled log here because adding OnDisabled log at 50days
    // ago again will invalidate this enabled log on some test cases.
    vm_->vmm_swap_usage_policy_.OnEnabled(base::Time::Now() - base::Days(50));

    SetBalloonStats(0, 1024 * MIB);
  }
  void TearDown() override {
    vm_.reset();
    CrosvmControl::Reset();
  }

  void SetBalloonStats(uint64_t actual, uint64_t total) {
    FakeCrosvmControl::Get()->actual_balloon_size_ = actual;
    FakeCrosvmControl::Get()->balloon_stats_.total_memory = total;
  }

  void InitializeBalloonPolicy() {
    MemoryMargins margins;
    vm_->balloon_init_attempts_ = 0;
    vm_->InitializeBalloonPolicy(margins, "arcvm");
  }

  bool EnableVmmSwap() { return HandleSwapVmRequest(SwapOperation::ENABLE); }

  bool ForceEnableVmmSwap() {
    return HandleSwapVmRequest(SwapOperation::FORCE_ENABLE);
  }

  bool DisableVmmSwap() { return HandleSwapVmRequest(SwapOperation::DISABLE); }

  void ProceedTimeAfterSwapOut(base::TimeDelta delta) {
    vm_->last_vmm_swap_out_at_ -= delta;
  }

  void AddUsageLog(base::Time time, base::TimeDelta duration) {
    vm_->vmm_swap_usage_policy_.OnEnabled(time);
    vm_->vmm_swap_usage_policy_.OnDisabled(time + duration);
  }

  base::TimeDelta CalculateVmmSwapDurationTarget() {
    return vm_->CalculateVmmSwapDurationTarget();
  }

  void SpacedProxyReturnSuccessCallback(int64_t free_size) {
    ON_CALL(*spaced_proxy_, GetFreeDiskSpaceAsync(_, _, _, _))
        .WillByDefault(
            [free_size](const std::string& in_path,
                        base::OnceCallback<void(int64_t)> success_callback,
                        base::OnceCallback<void(brillo::Error*)> error_callback,
                        int timeout_ms) {
              std::move(success_callback).Run(free_size);
            });
  }

  void SpacedProxyMoveSuccessCallback() {
    ON_CALL(*spaced_proxy_, GetFreeDiskSpaceAsync(_, _, _, _))
        .WillByDefault(
            [&](const std::string& in_path,
                base::OnceCallback<void(int64_t)> success_callback,
                base::OnceCallback<void(brillo::Error*)> error_callback,
                int timeout_ms) {
              spaced_proxy_success_callback_ = std::move(success_callback);
            });
  }

 protected:
  // Actual virtual machine being tested.
  std::unique_ptr<ArcVm> vm_;

  raw_ptr<base::MockOneShotTimer> swap_policy_timer_;
  raw_ptr<base::MockRepeatingTimer> swap_state_monitor_timer_;
  raw_ptr<base::MockRepeatingTimer> aggressive_balloon_timer_;

  std::unique_ptr<VmmSwapTbwPolicy> vmm_swap_tbw_policy_ =
      std::make_unique<VmmSwapTbwPolicy>();
  org::chromium::SpacedProxyMock* spaced_proxy_;
  std::unique_ptr<spaced::DiskUsageProxy> disk_usage_proxy_;

  base::OnceCallback<void(int64_t)> spaced_proxy_success_callback_;

 private:
  bool HandleSwapVmRequest(SwapOperation operation) {
    SwapVmRequest request;
    request.set_operation(operation);
    vm_->HandleSwapVmRequest(request, swap_vm_callback_.Create());
    EXPECT_TRUE(swap_vm_callback_.latest_response_.has_value());
    return swap_vm_callback_.latest_response_.has_value() &&
           swap_vm_callback_.latest_response_.value().success();
  }

  FakeSwapVmCallback swap_vm_callback_;

  // Temporary directory where we will store our socket.
  base::ScopedTempDir temp_dir_;

  // Resource allocators for the VM.
  VsockCidPool vsock_cid_pool_;

  base::test::TaskEnvironment task_environment_;
};

class FakeAggressiveBalloonCallback {
 public:
  ArcVm::AggressiveBalloonCallback Create() {
    return base::BindOnce(&FakeAggressiveBalloonCallback::Response,
                          weak_ptr_factory_.GetWeakPtr());
  }

  int counter_ = 0;
  AggressiveBalloonResponse latest_response_;

 private:
  void Response(AggressiveBalloonResponse response) {
    counter_ += 1;
    latest_response_ = response;
  }

  base::WeakPtrFactory<FakeAggressiveBalloonCallback> weak_ptr_factory_{this};
};

TEST_F(ArcVmTest, InflateAggressiveBalloon) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  ASSERT_EQ(callback.counter_, 0);
  ASSERT_TRUE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, InflateAggressiveBalloonDisableBalloonPolicy) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  InitializeBalloonPolicy();
  vm_->InflateAggressiveBalloon(callback.Create());
  MemoryMargins margins;
  ASSERT_FALSE(vm_->GetBalloonPolicy(margins, "arcvm"));
}

TEST_F(ArcVmTest, InflateAggressiveBalloonTwice) {
  FakeAggressiveBalloonCallback callback1;
  FakeAggressiveBalloonCallback callback2;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback1.Create());
  vm_->InflateAggressiveBalloon(callback2.Create());
  ASSERT_EQ(callback1.counter_, 0);
  ASSERT_EQ(callback2.counter_, 1);
  ASSERT_FALSE(callback2.latest_response_.success());
}

TEST_F(ArcVmTest, InflateAggressiveBalloonOnTimer) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  aggressive_balloon_timer_->Fire();
  ASSERT_EQ(callback.counter_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->target_balloon_size_, 110 * MIB);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_set_balloon_size_, 1);
  ASSERT_TRUE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, InflateAggressiveBalloonOnTimerMultipleTimes) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  aggressive_balloon_timer_->Fire();
  aggressive_balloon_timer_->Fire();
  aggressive_balloon_timer_->Fire();
  ASSERT_EQ(callback.counter_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->target_balloon_size_, 130 * MIB);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_set_balloon_size_, 3);
  ASSERT_TRUE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, InflateAggressiveBalloonOnTimerFailedToSetBalloonSize) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  FakeCrosvmControl::Get()->result_set_balloon_size_ = false;
  aggressive_balloon_timer_->Fire();
  ASSERT_EQ(callback.counter_, 1);
  ASSERT_FALSE(callback.latest_response_.success());
  ASSERT_FALSE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, DeflateBalloonOnLmkd) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  ASSERT_EQ(vm_->DeflateBalloonOnLmkd(kPlatformPerceptibleMaxOmmScoreAdjValue,
                                      30 * MIB),
            30 * MIB);
  ASSERT_EQ(callback.counter_, 1);
  ASSERT_TRUE(callback.latest_response_.success());
  ASSERT_EQ(FakeCrosvmControl::Get()->target_balloon_size_, 70 * MIB);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_set_balloon_size_, 1);
  ASSERT_FALSE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, DeflateBalloonOnLmkdReenableBalloonPolicy) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  InitializeBalloonPolicy();
  vm_->InflateAggressiveBalloon(callback.Create());
  ASSERT_EQ(vm_->DeflateBalloonOnLmkd(kPlatformPerceptibleMaxOmmScoreAdjValue,
                                      30 * MIB),
            30 * MIB);
  MemoryMargins margins;
  EXPECT_TRUE(vm_->GetBalloonPolicy(margins, "arcvm"));
}

TEST_F(ArcVmTest, DeflateBalloonOnLmkdNotPerceptibleProcess) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  ASSERT_EQ(vm_->DeflateBalloonOnLmkd(
                kPlatformPerceptibleMaxOmmScoreAdjValue + 1, 30 * MIB),
            0);
  ASSERT_EQ(callback.counter_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_set_balloon_size_, 0);
  ASSERT_TRUE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, DeflateBalloonOnLmkdBiggerThanActualBalloonSize) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  ASSERT_EQ(vm_->DeflateBalloonOnLmkd(kPlatformPerceptibleMaxOmmScoreAdjValue,
                                      130 * MIB),
            100 * MIB);
  ASSERT_EQ(callback.counter_, 1);
  ASSERT_TRUE(callback.latest_response_.success());
  ASSERT_EQ(FakeCrosvmControl::Get()->target_balloon_size_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_set_balloon_size_, 1);
  ASSERT_FALSE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, StopAggressiveBalloon) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  vm_->InflateAggressiveBalloon(callback.Create());
  AggressiveBalloonResponse response;
  vm_->StopAggressiveBalloon(response);
  ASSERT_TRUE(response.success());
  ASSERT_EQ(callback.counter_, 1);
  ASSERT_FALSE(callback.latest_response_.success());
  ASSERT_FALSE(aggressive_balloon_timer_->IsRunning());
}

TEST_F(ArcVmTest, StopAggressiveBalloonReenableBalloonPolicy) {
  FakeAggressiveBalloonCallback callback;
  SetBalloonStats(100 * MIB, 1024 * MIB);
  InitializeBalloonPolicy();
  vm_->InflateAggressiveBalloon(callback.Create());
  AggressiveBalloonResponse response;
  vm_->StopAggressiveBalloon(response);
  ASSERT_TRUE(response.success());
  MemoryMargins margins;
  ASSERT_TRUE(vm_->GetBalloonPolicy(margins, "arcvm"));
}

TEST_F(ArcVmTest, CalculateVmmSwapDurationTarget) {
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize);
  EXPECT_EQ(CalculateVmmSwapDurationTarget(), base::Hours(24));
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize / 2);
  EXPECT_EQ(CalculateVmmSwapDurationTarget(), base::Hours(24) * 2);
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(0);
  EXPECT_EQ(CalculateVmmSwapDurationTarget(), base::Days(28));
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(1);
  EXPECT_EQ(CalculateVmmSwapDurationTarget(), base::Days(28));
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(((uint64_t)1) << 63);
  EXPECT_EQ(CalculateVmmSwapDurationTarget(), base::Seconds(0));
}

TEST_F(ArcVmTest, EnableVmmSwap) {
  ASSERT_TRUE(EnableVmmSwap());
  ASSERT_TRUE(swap_policy_timer_->IsRunning());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_trim_, 0);
}

TEST_F(ArcVmTest, EnableVmmSwapFail) {
  FakeCrosvmControl::Get()->result_enable_vmm_swap_ = false;
  ASSERT_FALSE(EnableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
}

TEST_F(ArcVmTest, VmmSwapTrimAfterEnable) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_trim_, 1);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_TRUE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, VmmSwapTrimFailed) {
  ASSERT_TRUE(EnableVmmSwap());
  FakeCrosvmControl::Get()->result_vmm_swap_trim_ = false;
  swap_policy_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, VmmSwapOutAfterTrim) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::PENDING;
  swap_state_monitor_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 1);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, EnableVmmSwapAgainJustAfterVmmSwapOut) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::PENDING;
  swap_state_monitor_timer_->Fire();
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  FakeCrosvmControl::Get()->count_vmm_swap_out_ = 0;
  FakeCrosvmControl::Get()->count_vmm_swap_trim_ = 0;
  ASSERT_FALSE(EnableVmmSwap());
  // Vmm-swap enable & trim without vmm-swap out.
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);
  ASSERT_TRUE(swap_policy_timer_->IsRunning());
  swap_policy_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_trim_, 1);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, EnableVmmSwapAgain24HoursAfterVmmSwapOut) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::PENDING;
  swap_state_monitor_timer_->Fire();
  ProceedTimeAfterSwapOut(base::Hours(24));
  ASSERT_TRUE(EnableVmmSwap());
}

TEST_F(ArcVmTest, EnableVmmSwapAgainExceedsTbwTarget) {
  const uint64_t target_size = 512 * MIB;
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(target_size);
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.metrics.staging_pages =
      4 * target_size / base::GetPageSize();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::PENDING;
  swap_state_monitor_timer_->Fire();
  ProceedTimeAfterSwapOut(base::Hours(24));
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  FakeCrosvmControl::Get()->count_vmm_swap_out_ = 0;
  FakeCrosvmControl::Get()->count_vmm_swap_trim_ = 0;
  ASSERT_FALSE(EnableVmmSwap());
  // Vmm-swap enable & trim without vmm-swap out.
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);
  ASSERT_TRUE(swap_policy_timer_->IsRunning());
  swap_policy_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_trim_, 1);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, EnableVmmSwapRejectedByUsagePolicy) {
  // The usage prediction target is 2 days.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize / 2);
  // Invalidates the usage log.
  AddUsageLog(base::Time::Now() - base::Days(50), base::Seconds(1));
  AddUsageLog(base::Time::Now() - base::Days(28) - base::Hours(1),
              base::Days(2));
  AddUsageLog(base::Time::Now() - base::Days(21) - base::Hours(1),
              base::Days(2));
  AddUsageLog(base::Time::Now() - base::Days(14) - base::Hours(1),
              base::Days(2));
  AddUsageLog(base::Time::Now() - base::Days(7) - base::Hours(1),
              base::Days(2));
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  ASSERT_FALSE(EnableVmmSwap());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, EnableVmmSwapRejectedByUsagePolicy4DaysTarget) {
  // The usage prediction target is 4 days.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize / 4);
  // Invalidates the usage log.
  AddUsageLog(base::Time::Now() - base::Days(50), base::Seconds(1));
  AddUsageLog(base::Time::Now() - base::Days(28) - base::Hours(1),
              base::Days(4));
  AddUsageLog(base::Time::Now() - base::Days(21) - base::Hours(1),
              base::Days(4));
  AddUsageLog(base::Time::Now() - base::Days(14) - base::Hours(1),
              base::Days(4));
  AddUsageLog(base::Time::Now() - base::Days(7) - base::Hours(1),
              base::Days(4));
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  ASSERT_FALSE(EnableVmmSwap());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, EnableVmmSwapPassUsagePolicy) {
  // The usage prediction target is 2 days.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize / 2);
  // Invalidates the usage log.
  AddUsageLog(base::Time::Now() - base::Days(50), base::Seconds(1));
  AddUsageLog(base::Time::Now() - base::Days(28) - base::Hours(1),
              base::Days(2) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(21) - base::Hours(1),
              base::Days(2) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(14) - base::Hours(1),
              base::Days(2) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(7) - base::Hours(1),
              base::Days(2) + base::Hours(2));
  ASSERT_TRUE(EnableVmmSwap());
}

TEST_F(ArcVmTest, EnableVmmSwapPassUsagePolicy4DaysTarget) {
  // The usage prediction target is 4 days.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize / 4);
  // Invalidates the usage log.
  AddUsageLog(base::Time::Now() - base::Days(50), base::Seconds(1));
  AddUsageLog(base::Time::Now() - base::Days(28) - base::Hours(1),
              base::Days(4) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(21) - base::Hours(1),
              base::Days(4) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(14) - base::Hours(1),
              base::Days(4) + base::Hours(2));
  AddUsageLog(base::Time::Now() - base::Days(7) - base::Hours(1),
              base::Days(4) + base::Hours(2));
  ASSERT_TRUE(EnableVmmSwap());
}

TEST_F(ArcVmTest, EnableVmmSwapRejectedByLowDiskPolicy) {
  // The usage prediction target is 2 days.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kGuestMemorySize);
  SpacedProxyReturnSuccessCallback(
      VmmSwapLowDiskPolicy::kTargetMinimumFreeDiskSpace + kGuestMemorySize - 1);

  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  ASSERT_FALSE(EnableVmmSwap());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, EnableVmmSwapAgainBeforeLowDiskPolicyResponse) {
  SpacedProxyMoveSuccessCallback();
  FakeSwapVmCallback swap_vm_callback;
  SwapVmRequest request;
  request.set_operation(SwapOperation::ENABLE);
  vm_->HandleSwapVmRequest(request, swap_vm_callback.Create());
  ASSERT_FALSE(swap_vm_callback.latest_response_.has_value());

  // Another enable request is rejected while there is a pending request.
  EXPECT_FALSE(EnableVmmSwap());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);

  std::move(spaced_proxy_success_callback_).Run(10LL << 30);  // 10GiB
  ASSERT_TRUE(swap_vm_callback.latest_response_.has_value());
  EXPECT_TRUE(swap_vm_callback.latest_response_.value().success());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, EnableVmmSwapZeroTbwTarget) {
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(0);
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  // No exception
  EXPECT_FALSE(EnableVmmSwap());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, EnableVmmSwapSmallTbwTarget) {
  // When the target is smaller than 1MiB.
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(1);
  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  // No exception
  EXPECT_FALSE(EnableVmmSwap());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, MonitorSwapStateChangeStillTrimInProgress) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.state =
      SwapState::TRIM_IN_PROGRESS;
  swap_state_monitor_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_TRUE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, MonitorSwapStateChangeTrimFailed) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::FAILED;
  swap_state_monitor_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, MonitorSwapStateChangeFailedToGetSwapStatus) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->result_vmm_swap_status_ = false;
  swap_state_monitor_timer_->Fire();
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
}

TEST_F(ArcVmTest, ForceEnableVmmSwap) {
  ASSERT_TRUE(ForceEnableVmmSwap());
  ASSERT_TRUE(swap_policy_timer_->IsRunning());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_trim_, 0);
}

TEST_F(ArcVmTest, ForceEnableVmmSwapFail) {
  FakeCrosvmControl::Get()->result_enable_vmm_swap_ = false;
  ASSERT_FALSE(ForceEnableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
}

TEST_F(ArcVmTest, ForceEnableVmmSwapAgainExceedsTbwTarget) {
  const uint64_t target_size = 512 * MIB;
  vmm_swap_tbw_policy_->SetTargetTbwPerDay(target_size);
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  FakeCrosvmControl::Get()->vmm_swap_status_.metrics.staging_pages =
      4 * target_size / base::GetPageSize();
  FakeCrosvmControl::Get()->vmm_swap_status_.state = SwapState::PENDING;
  swap_state_monitor_timer_->Fire();
  ASSERT_TRUE(ForceEnableVmmSwap());
}

TEST_F(ArcVmTest, DisableVmmSwap) {
  ASSERT_TRUE(EnableVmmSwap());
  ASSERT_TRUE(DisableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, DisableVmmSwapWhileTrimming) {
  ASSERT_TRUE(EnableVmmSwap());
  swap_policy_timer_->Fire();
  ASSERT_TRUE(DisableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
  ASSERT_FALSE(swap_state_monitor_timer_->IsRunning());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, DisableVmmSwapAbortEnabling) {
  SpacedProxyMoveSuccessCallback();
  FakeSwapVmCallback swap_vm_callback;
  SwapVmRequest request;
  request.set_operation(SwapOperation::ENABLE);
  vm_->HandleSwapVmRequest(request, swap_vm_callback.Create());
  ASSERT_FALSE(swap_vm_callback.latest_response_.has_value());
  ASSERT_TRUE(DisableVmmSwap());

  ASSERT_TRUE(swap_vm_callback.latest_response_.has_value());
  EXPECT_FALSE(swap_vm_callback.latest_response_.value().success());

  std::move(spaced_proxy_success_callback_).Run(10LL << 30);  // 10GiB
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, DisableVmmSwapAbortEnablingAndReenable) {
  SpacedProxyMoveSuccessCallback();
  FakeSwapVmCallback swap_vm_callback;
  SwapVmRequest request;
  request.set_operation(SwapOperation::ENABLE);
  vm_->HandleSwapVmRequest(request, swap_vm_callback.Create());
  ASSERT_FALSE(swap_vm_callback.latest_response_.has_value());
  ASSERT_TRUE(DisableVmmSwap());

  ASSERT_TRUE(swap_vm_callback.latest_response_.has_value());
  EXPECT_FALSE(swap_vm_callback.latest_response_.value().success());
  swap_vm_callback.latest_response_.reset();
  base::OnceCallback<void(int64_t)> success_callback =
      std::move(spaced_proxy_success_callback_);

  // Reenable
  vm_->HandleSwapVmRequest(request, swap_vm_callback.Create());
  ASSERT_FALSE(swap_vm_callback.latest_response_.has_value());

  // Obsolete spaced response.
  std::move(success_callback).Run(10LL << 30);  // 10GiB
  ASSERT_TRUE(swap_vm_callback.latest_response_.has_value());
  EXPECT_TRUE(swap_vm_callback.latest_response_.value().success());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 1);

  FakeCrosvmControl::Get()->count_enable_vmm_swap_ = 0;
  // The spaced response is ignored.
  std::move(spaced_proxy_success_callback_).Run(10LL << 30);  // 10GiB
  EXPECT_EQ(FakeCrosvmControl::Get()->count_enable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, DisableVmmSwapWithoutEnable) {
  ASSERT_TRUE(DisableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
  ASSERT_EQ(FakeCrosvmControl::Get()->count_vmm_swap_out_, 0);
  ASSERT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, DisableVmmSwapFail) {
  FakeCrosvmControl::Get()->result_disable_vmm_swap_ = false;
  ASSERT_TRUE(EnableVmmSwap());
  ASSERT_FALSE(DisableVmmSwap());
  ASSERT_FALSE(swap_policy_timer_->IsRunning());
}

TEST_F(ArcVmTest, HandleStatefulUpdateWithLow) {
  ASSERT_TRUE(EnableVmmSwap());
  spaced::StatefulDiskSpaceUpdate update;
  update.set_state(spaced::StatefulDiskSpaceState::LOW);
  vm_->HandleStatefulUpdate(update);
  EXPECT_FALSE(swap_policy_timer_->IsRunning());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, HandleStatefulUpdateWithCritical) {
  ASSERT_TRUE(EnableVmmSwap());
  spaced::StatefulDiskSpaceUpdate update;
  update.set_state(spaced::StatefulDiskSpaceState::CRITICAL);
  vm_->HandleStatefulUpdate(update);
  EXPECT_FALSE(swap_policy_timer_->IsRunning());
  EXPECT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 1);
}

TEST_F(ArcVmTest, HandleStatefulUpdateWhenVmmSwapIsNotEnabled) {
  spaced::StatefulDiskSpaceUpdate update;
  update.set_state(spaced::StatefulDiskSpaceState::LOW);
  vm_->HandleStatefulUpdate(update);
  EXPECT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 0);
}

TEST_F(ArcVmTest, HandleStatefulUpdateWhenStateIsNormal) {
  ASSERT_TRUE(EnableVmmSwap());
  spaced::StatefulDiskSpaceUpdate update;
  update.set_state(spaced::StatefulDiskSpaceState::NORMAL);
  vm_->HandleStatefulUpdate(update);
  EXPECT_EQ(FakeCrosvmControl::Get()->count_disable_vmm_swap_, 0);
}

}  // namespace concierge
}  // namespace vm_tools
