// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/chrome_setup.h"

#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <memory>
#include <set>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/hash/sha1.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/values.h>
#include <brillo/files/file_util.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>
#include <brillo/userdb_utils.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>
#include <chromeos/ui/chromium_command_builder.h>
#include <chromeos/ui/util.h>
#include <libsegmentation/feature_management.h>
#include <policy/device_policy.h>
#include <policy/libpolicy.h>

// IMPORTANT: If you want to check for the presence of a new USE flag within
// this file via UseFlagIsSet(), you need to add it to the IUSE list in the
// libchromeos-use-flags package's ebuild file. See docs/flags.md for more
// information about this file.

using chromeos::ui::ChromiumCommandBuilder;
using chromeos::ui::util::EnsureDirectoryExists;

namespace login_manager {

constexpr char kUiPath[] = "/ui";
constexpr char kSerializedAshSwitchesProperty[] = "serialized-ash-switches";
constexpr char kHelpContentIdProperty[] = "help-content-id";

const char kWallpaperProperty[] = "wallpaper";

const char kRegulatoryLabelProperty[] = "regulatory-label";

const char kPowerButtonPositionPath[] = "/ui/power-button";
const char kPowerButtonEdgeField[] = "edge";
const char kPowerButtonPositionField[] = "position";

const char kSideVolumeButtonPath[] = "/ui/side-volume-button";
const char kSideVolumeButtonRegion[] = "region";
const char kSideVolumeButtonSide[] = "side";

const char kHardwarePropertiesPath[] = "/hardware-properties";
const char kStylusCategoryField[] = "stylus-category";
const char kDisplayCategoryField[] = "display-type";
const char kFormFactorField[] = "form-factor";

constexpr char kFingerprintPath[] = "/fingerprint";
constexpr char kFingerprintSensorLocationField[] = "sensor-location";

constexpr char kArcScalePath[] = "/arc";
constexpr char kArcScaleProperty[] = "scale";

constexpr char kInstantTetheringPath[] = "/cross-device/instant-tethering";
constexpr char kDisableInstantTetheringProperty[] = "disable-instant-tethering";

constexpr char kOzoneNNPalmPropertiesPath[] = "/nnpalm";
constexpr char kOzoneNNPalmCompatibleProperty[] = "touch-compatible";
constexpr char kOzoneNNPalmModelVersionProperty[] = "model";
constexpr char kOzoneNNPalmRadiusProperty[] = "radius-polynomial";
constexpr std::array<const char*, 3> kOzoneNNPalmOptionalProperties = {
    kOzoneNNPalmCompatibleProperty, kOzoneNNPalmModelVersionProperty,
    kOzoneNNPalmRadiusProperty};

const char kPowerPath[] = "/power";
const char kAllowAmbientEQField[] = "allow-ambient-eq";
const char kAllowAmbientEQFeature[] = "AllowAmbientEQ";

constexpr char kHibernateField[] = "disable-hibernate";
constexpr char kHibernateFeature[] = "Hibernate";

constexpr char kPowerdHibernateExperimentFlag[] =
    "/var/lib/power_manager/enable_hibernate_experiment";

constexpr char kPowerdRoPrefPath[] = "/usr/share/power_manager";
constexpr char kPowerdBoardSpecificPrefPath[] =
    "/usr/share/power_manager/board_specific";

constexpr std::array<const char*, 2> kPowerdPrefPaths = {
    kPowerdBoardSpecificPrefPath,
    kPowerdRoPrefPath,
};

constexpr char kEnableCrashpadFlag[] = "--enable-crashpad";
constexpr char kEnableBreakpadFlag[] = "--no-enable-crashpad";

const char kSchedulerTunePath[] = "/scheduler-tune";
const char kBoostUrgentProperty[] = "boost-urgent";

constexpr char kModemPath[] = "/modem";
constexpr char kModemAttachApnProperty[] = "attach-apn-required";

constexpr char kHpsPath[] = "/hps";
constexpr char kHasHpsProperty[] = "has-hps";

// These hashes are only being used temporarily till we can determine if a
// device is a Chromebox for Meetings or not from the Install Time attributes.
// TODO(rkc, pbos): Remove these and related code once crbug.com/706523 is
// fixed.
const char* kChromeboxForMeetingAppIdHashes[] = {
    "E703483CEF33DEC18B4B6DD84B5C776FB9182BDB",
    "A3BC37E2148AC4E99BE4B16AF9D42DD1E592BBBE",
    "1C93BD3CF875F4A73C0B2A163BB8FBDA8B8B3D80",
    "307E96539209F95A1A8740C713E6998A73657D96",
    "4F25792AF1AA7483936DE29C07806F203C7170A0",
    "BD8781D757D830FC2E85470A1B6E8A718B7EE0D9",
    "4AC2B6C63C6480D150DFDA13E4A5956EB1D0DDBB",
    "81986D4F846CEDDDB962643FA501D1780DD441BB",
};

constexpr char kDmiProductNameFile[] = "/sys/class/dmi/id/product_name";

namespace {

// Path to file containing developer-supplied modifications to Chrome's
// environment and command line. Passed to
// ChromiumCommandBuilder::ApplyUserConfig().
const char kChromeDevConfigPath[] = "/etc/chrome_dev.conf";

// Returns a base::FilePath corresponding to the DATA_DIR environment variable.
base::FilePath GetDataDir(ChromiumCommandBuilder* builder) {
  return base::FilePath(builder->ReadEnvVar("DATA_DIR"));
}

// Returns a base::FilePath corresponding to the subdirectory of DATA_DIR where
// user data is stored.
base::FilePath GetUserDir(ChromiumCommandBuilder* builder) {
  return base::FilePath(GetDataDir(builder).Append("user"));
}

// Enables the "AutoNightLight" feature if "auto-night-light" is set to "True"
// in cros_config.
void SetUpAutoNightLightFlag(ChromiumCommandBuilder* builder,
                             brillo::CrosConfigInterface* cros_config) {
  std::string auto_night_light_str;
  if (!cros_config ||
      !cros_config->GetString("/", "auto-night-light", &auto_night_light_str)) {
    return;
  }

  if (auto_night_light_str != "true")
    return;

  builder->AddFeatureEnableOverride("AutoNightLight");
}

void SetUpHasHpsFlag(ChromiumCommandBuilder* builder,
                     brillo::CrosConfigInterface* cros_config) {
  std::string has_hps;
  if (!cros_config ||
      !cros_config->GetString(kHpsPath, kHasHpsProperty, &has_hps) ||
      has_hps != "true") {
    return;
  }

  builder->AddArg("--has-hps");
}

// Enables the "HandwritingRecognitionWebPlatformApi" Blink feature flag if
// "handwriting-web-platform-api" is set to "true" in cros_config.
void SetUpHandwritingRecognitionWebPlatformApiFlag(
    ChromiumCommandBuilder* builder, brillo::CrosConfigInterface* cros_config) {
  std::string handwriting_recognition_web_platform_api_str;
  if (!cros_config ||
      !cros_config->GetString("/ui", "handwriting-recognition-web-platform-api",
                              &handwriting_recognition_web_platform_api_str) ||
      handwriting_recognition_web_platform_api_str != "true") {
    return;
  }

  builder->AddFeatureEnableOverride("HandwritingRecognitionWebPlatformApi");
}

// Enables the "CellularUseAttachApn" Chrome feature flag if the
// "modem/attach-apn-required" property is set to "true" in cros_config.
void SetUpModemFlag(ChromiumCommandBuilder* builder,
                    brillo::CrosConfigInterface* cros_config) {
  std::string required;
  if (cros_config &&
      cros_config->GetString(kModemPath, kModemAttachApnProperty, &required) &&
      required == "true") {
    builder->AddFeatureEnableOverride("CellularUseAttachApn");
  }
}

void SetUpOsInstallFlags(ChromiumCommandBuilder* builder) {
  if (!builder->UseFlagIsSet("os_install_service")) {
    return;
  }

  std::string output;
  if (!base::GetAppOutput({"is_running_from_installer"}, &output)) {
    LOG(ERROR) << "Failed to run is_running_from_installer";
    return;
  }

  if (output == "yes\n") {
    builder->AddArg("--allow-os-install");
  }
}

// Called by AddUiFlags() to take a wallpaper flag type ("default" or "guest"
// or "child") and file type (e.g. "child", "default", "oem", "guest") and
// add the corresponding flags to |builder| if the files exist. Returns false
// if the files don't exist.
bool AddWallpaperFlags(
    ChromiumCommandBuilder* builder,
    const std::string& flag_type,
    const std::string& file_type,
    const base::RepeatingCallback<bool(const base::FilePath&)>& path_exists) {
  const base::FilePath large_path(base::StringPrintf(
      "/usr/share/chromeos-assets/wallpaper/%s_large.jpg", file_type.c_str()));
  const base::FilePath small_path(base::StringPrintf(
      "/usr/share/chromeos-assets/wallpaper/%s_small.jpg", file_type.c_str()));
  if (!path_exists.Run(large_path) || !path_exists.Run(small_path)) {
    LOG(WARNING) << "Could not find both paths: " << large_path.MaybeAsASCII()
                 << " and " << small_path.MaybeAsASCII();
    return false;
  }

  builder->AddArg(base::StringPrintf("--%s-wallpaper-large=%s",
                                     flag_type.c_str(),
                                     large_path.value().c_str()));
  builder->AddArg(base::StringPrintf("--%s-wallpaper-small=%s",
                                     flag_type.c_str(),
                                     small_path.value().c_str()));
  return true;
}

// Adds ARC related flags.
void AddArcFlags(ChromiumCommandBuilder* builder,
                 std::set<std::string>* disallowed_params_out,
                 brillo::CrosConfigInterface* cros_config) {
  if (builder->UseFlagIsSet("arc") ||
      (builder->UseFlagIsSet("cheets") && builder->is_test_build())) {
    builder->AddArg("--arc-availability=officially-supported");
  } else if (builder->UseFlagIsSet("cheets")) {
    builder->AddArg("--arc-availability=installed");
  } else {
    // Don't pass ARC availability related flags in chrome_dev.conf to Chrome if
    // ARC is not installed at all.
    disallowed_params_out->insert("--arc-availability");
    disallowed_params_out->insert("--enable-arc");
    disallowed_params_out->insert("--arc-available");
    disallowed_params_out->insert("-arc-availability");
    disallowed_params_out->insert("-enable-arc");
    disallowed_params_out->insert("-arc-available");
  }

  if (builder->UseFlagIsSet("arc_adb_sideloading"))
    builder->AddFeatureEnableOverride("ArcAdbSideloading");
  if (builder->UseFlagIsSet("arc_transition_m_to_n"))
    builder->AddArg("--arc-transition-migration-required");
  if (builder->UseFlagIsSet("arc_force_2x_scaling"))
    builder->AddArg("--force-remote-shell-scale=2");
  if (builder->UseFlagIsSet("arcvm") && !builder->UseFlagIsSet("arcpp"))
    builder->AddArg("--enable-arcvm");
  if (builder->UseFlagIsSet("arcvm_data_migration"))
    builder->AddFeatureEnableOverride("ArcVmDataMigration");
  if (builder->UseFlagIsSet("arcvm_virtio_blk_data"))
    builder->AddFeatureEnableOverride("ArcEnableVirtioBlkForData");
  if (builder->UseFlagIsSet("lvm_application_containers"))
    builder->AddFeatureEnableOverride("ArcLvmApplicationContainers");
  // Devices of tablet form factor will have special app behaviour.
  if (builder->UseFlagIsSet("tablet_form_factor"))
    builder->AddArg("--enable-tablet-form-factor");

  std::string arc_scale;
  if (cros_config &&
      cros_config->GetString(kArcScalePath, kArcScaleProperty, &arc_scale)) {
    builder->AddArg("--arc-scale=" + arc_scale);
  }

  // Pass USE flags of ARM binary translation libraries to Chrome.
  if (builder->UseFlagIsSet("houdini"))
    builder->AddArg("--enable-houdini");
  if (builder->UseFlagIsSet("houdini64"))
    builder->AddArg("--enable-houdini64");
  if (builder->UseFlagIsSet("houdini_dlc"))
    builder->AddArg("--enable-houdini-dlc");
  if (builder->UseFlagIsSet("ndk_translation"))
    builder->AddArg("--enable-ndk-translation");
  if (builder->UseFlagIsSet("ndk_translation64"))
    builder->AddArg("--enable-ndk-translation64");
}

void AddCrostiniFlags(ChromiumCommandBuilder* builder) {
  if (builder->UseFlagIsSet("kvm_host")) {
    builder->AddFeatureEnableOverride("Crostini");
  }
  if (builder->UseFlagIsSet("virtio_gpu")) {
    builder->AddFeatureEnableOverride("CrostiniGpuSupport");
  }
}

void AddPluginVmFlags(ChromiumCommandBuilder* builder) {
  if (builder->UseFlagIsSet("pita")) {
    builder->AddFeatureEnableOverride("PluginVm");
  }
  if (builder->UseFlagIsSet("pita-camera")) {
    builder->AddFeatureEnableOverride("PluginVmShowCameraPermissions");
  }
  if (builder->UseFlagIsSet("pita-microphone")) {
    builder->AddFeatureEnableOverride("PluginVmShowMicrophonePermissions");
  }
}

void AddBorealisFlags(ChromiumCommandBuilder* builder) {
  if (builder->UseFlagIsSet("borealis_host")) {
    builder->AddFeatureEnableOverride("Borealis");
    // TODO(b/161952658): Remove the feature override for the exo-pointer lock
    // when it is completed. This is only meant to be a temporary work-around.
    std::string channel_string;
    if (base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK",
                                          &channel_string) &&
        channel_string != "beta-channel" &&
        channel_string != "stable-channel" && channel_string != "ltc-channel" &&
        channel_string != "lts-channel") {
      builder->AddFeatureEnableOverride("ExoPointerLock");
    }
  }
}

void AddLacrosFlags(ChromiumCommandBuilder* builder) {
  if (builder->UseFlagIsSet("lacros"))
    builder->AddFeatureEnableOverride("LacrosSupport");
}

// Ensures that necessary directory exist with the correct permissions and sets
// related arguments and environment variables.
void CreateDirectories(ChromiumCommandBuilder* builder) {
  const uid_t uid = builder->uid();
  const gid_t gid = builder->gid();
  const uid_t kRootUid = 0;
  const gid_t kRootGid = 0;

  const base::FilePath data_dir = GetDataDir(builder);
  builder->AddArg("--user-data-dir=" + data_dir.value());

  const base::FilePath user_dir = GetUserDir(builder);
  CHECK(EnsureDirectoryExists(user_dir, uid, gid, 0755));
  // TODO(keescook): Remove Chrome's use of $HOME.
  builder->AddEnvVar("HOME", user_dir.value());

  // Old builds will have a profile dir that's owned by root; newer ones won't
  // have this directory at all.
  CHECK(EnsureDirectoryExists(data_dir.Append("Default"), uid, gid, 0755));

  const base::FilePath state_dir("/run/state");
  CHECK(brillo::DeletePathRecursively(state_dir));
  CHECK(EnsureDirectoryExists(state_dir, kRootUid, kRootGid, 0710));

  // Create a directory where the session manager can store a copy of the user
  // policy key, that will be readable by the chrome process as chronos.
  const base::FilePath policy_dir("/run/user_policy");
  CHECK(brillo::DeletePathRecursively(policy_dir));
  CHECK(EnsureDirectoryExists(policy_dir, kRootUid, gid, 0710));

  // Create a directory where the chrome process can store a reboot request so
  // that it persists across browser crashes but is always removed on reboot.
  // This directory also houses the default wayland and arc-bridge sockets that
  // are exported to VMs and Android.
  CHECK(EnsureDirectoryExists(base::FilePath("/run/chrome"), uid, gid, 0755));

  // Create a directory where the libassistant V2 can create socket files for
  // gRPC.
  const base::FilePath libassistant_dir("/run/libassistant");
  CHECK(brillo::DeletePathRecursively(libassistant_dir));
  CHECK(EnsureDirectoryExists(libassistant_dir, uid, gid, 0700));

  // Create the directory where policies for extensions installed in
  // device-local accounts are cached. This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/device_local_account_component_policy"), uid,
      gid, 0700));

  // Create the directory where external data referenced by policies is cached
  // for device-local accounts. This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/device_local_account_external_policy_data"),
      uid, gid, 0700));

  // Create the directory where external data referenced by device policy is
  // cached. This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/device_policy_external_data"), uid, gid,
      0700));

  // Create the directory where screensaver images data referenced by device
  // policy is cached. This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(base::FilePath("/var/cache/managed_screensaver"),
                              uid, gid, 0700));

  // Create the directory where the AppPack extensions are cached.
  // These extensions are read and written by chronos.
  CHECK(EnsureDirectoryExists(base::FilePath("/var/cache/app_pack"), uid, gid,
                              0700));

  // Create the directory where extensions for device-local accounts are cached.
  // These extensions are read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/device_local_account_extensions"), uid, gid,
      0700));

  // Create the directory where the Quirks Client can store downloaded
  // icc and other display profiles.
  CHECK(EnsureDirectoryExists(base::FilePath("/var/cache/display_profiles"),
                              uid, gid, 0700));

  // Create the directory for shared installed extensions.
  // Shared extensions are validated at runtime by the browser.
  // These extensions are read and written by chronos.
  CHECK(EnsureDirectoryExists(base::FilePath("/var/cache/shared_extensions"),
                              uid, gid, 0700));

  // Create the directory where policies for extensions installed in the
  // sign-in profile are cached. This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/signin_profile_component_policy"), uid, gid,
      0700));

  // Create the directory where extensions for the sign-in profile are cached.
  // This data is read and written by chronos.
  CHECK(EnsureDirectoryExists(
      base::FilePath("/var/cache/signin_profile_extensions"), uid, gid, 0700));

  // Tell Chrome where to write logging messages before the user logs in.
  base::FilePath system_log_dir("/var/log/chrome");
  CHECK(EnsureDirectoryExists(system_log_dir, uid, gid, 0755));
  builder->AddEnvVar("CHROME_LOG_FILE",
                     system_log_dir.Append("chrome").value());

  // Log directory for Lacros to write logging messages before the user logs in.
  base::FilePath lacros_system_log_dir("/var/log/lacros");
  CHECK(EnsureDirectoryExists(lacros_system_log_dir, uid, gid, 0755));

  // Log directory for the user session. Note that the user dir won't be mounted
  // until later (when the cryptohome is mounted), so we don't create
  // CHROMEOS_SESSION_LOG_DIR here.
  builder->AddEnvVar("CHROMEOS_SESSION_LOG_DIR",
                     user_dir.Append("log").value());

  // Disable Mesa's internal shader disk caching feature, since Chrome has its
  // own shader cache implementation and the GPU process sandbox does not
  // allow threads (Mesa uses threads for this feature).
  builder->AddEnvVar("MESA_GLSL_CACHE_DISABLE", "true");    // Mesa classic
  builder->AddEnvVar("MESA_SHADER_CACHE_DISABLE", "true");  // Mesa iris
}

// Adds system-related flags to the command line.
void AddSystemFlags(ChromiumCommandBuilder* builder,
                    brillo::CrosConfigInterface* cros_config) {
  const base::FilePath data_dir = GetDataDir(builder);

  // We need to delete these files as Chrome may have left them around from its
  // prior run (if it crashed).
  brillo::DeleteFile(data_dir.Append("SingletonLock"));
  brillo::DeleteFile(data_dir.Append("SingletonSocket"));

  // Some targets (embedded, VMs) do not need component updates.
  if (!builder->UseFlagIsSet("compupdates"))
    builder->AddArg("--disable-component-update");

  // On developer systems, set a flag to let the browser know.
  if (builder->is_developer_end_user())
    builder->AddArg("--system-developer-mode");

  if (builder->UseFlagIsSet("diagnostics"))
    builder->AddFeatureEnableOverride("UmaStorageDimensions");

  // TODO(b/187516317): remove when the issue is resolved in FW.
  if (builder->UseFlagIsSet("broken_24hours_wake"))
    builder->AddFeatureDisableOverride("SupportsRtcWakeOver24Hours");

  // Enable Wilco only features.
  if (builder->UseFlagIsSet("wilco")) {
    builder->AddFeatureEnableOverride("WilcoDtc");
    // Needed for scheduled update checks on Wilco.
    builder->AddArg("--register-max-dark-suspend-delay");
  }

  // Some platforms have SMT enabled by default.
  if (builder->UseFlagIsSet("scheduler_configuration_performance"))
    builder->AddArg("--scheduler-configuration-default=performance");

  // Enable runtime TPM selection. This UseFlag is set only on reven board.
  if (builder->UseFlagIsSet("tpm_dynamic"))
    builder->AddArg("--tpm-is-dynamic");

  // Enable special branded strings. This UseFlag is set only on reven board.
  if (builder->UseFlagIsSet("reven_branding"))
    builder->AddArg("--reven-branding");

  // In ash, we use mojo service manager as the mojo broker so disable it here.
  builder->AddArg("--disable-mojo-broker");
  builder->AddArg("--ash-use-cros-mojo-service-manager");
  builder->AddArg("--cros-healthd-uses-service-manager");

  SetUpOsInstallFlags(builder);
  SetUpSchedulerFlags(builder, cros_config);
}

std::string ConvertNullToEmptyString(const char* str) {
  return str ? str : std::string();
}

void SetUpHPEngageOneProAIOSystem(ChromiumCommandBuilder* builder) {
  std::string dmi_product_name;
  if (!base::ReadFileToString(base::FilePath(kDmiProductNameFile),
                              &dmi_product_name)) {
    LOG(ERROR) << "failed to load product_name dmi id file";
    return;
  }
  base::TrimWhitespaceASCII(dmi_product_name, base::TRIM_TRAILING,
                            &dmi_product_name);
  if (dmi_product_name != std::string("HP Engage One Pro AIO System")) {
    return;
  }

  auto udev = brillo::Udev::Create();
  auto enumerate = udev->CreateEnumerate();

  if (!enumerate->AddMatchSubsystem("input") || !enumerate->ScanDevices())
    return;

  for (std::unique_ptr<brillo::UdevListEntry> list_entry =
           enumerate->GetListEntry();
       list_entry; list_entry = list_entry->GetNext()) {
    std::string sys_path = ConvertNullToEmptyString(list_entry->GetName());

    std::unique_ptr<brillo::UdevDevice> device =
        udev->CreateDeviceFromSysPath(sys_path.c_str());
    if (!device)
      continue;

    double touch_slop_distance = 0;

    std::string touch_slop_distance_string = ConvertNullToEmptyString(
        device->GetPropertyValue("CROS_TOUCH_SLOP_DISTANCE"));

    if (!base::StringToDouble(touch_slop_distance_string,
                              &touch_slop_distance)) {
      if (touch_slop_distance_string != "")
        LOG(WARNING) << "Invalid touch-slop-distance: '"
                     << touch_slop_distance_string << "'.";
      continue;
    }
    builder->AddArg(
        base::StringPrintf("--touch-slop-distance=%f", touch_slop_distance));
    break;
  }
}

// Adds UI-related flags to the command line.
void AddUiFlags(ChromiumCommandBuilder* builder,
                brillo::CrosConfigInterface* cros_config) {
  const base::FilePath data_dir = GetDataDir(builder);

  // Force OOBE on test images that have requested it.
  if (base::PathExists(base::FilePath("/root/.test_repeat_oobe"))) {
    brillo::DeleteFile(data_dir.Append(".oobe_completed"));
    brillo::DeleteFile(data_dir.Append("Local State"));
  }

  // Disable logging redirection on test images to make debugging easier.
  if (builder->is_test_build())
    builder->AddArg("--disable-logging-redirect");

  if (builder->UseFlagIsSet("cfm_enabled_device") &&
      builder->UseFlagIsSet("screenshare_sw_codec")) {
    builder->AddFeatureEnableOverride("WebRtcScreenshareSwEncoding");
  }

  if (builder->UseFlagIsSet("touch_centric_device")) {
    // Tapping the power button should turn the screen off in laptop mode.
    builder->AddArg("--force-tablet-power-button");
    // Show touch centric OOBE screens during the first user run in laptop mode.
    builder->AddArg("--oobe-force-tablet-first-run");
  }

  if (builder->UseFlagIsSet("rialto")) {
    builder->AddArg("--enterprise-enable-zero-touch-enrollment=hands-off");
    builder->AddArg("--disable-machine-cert-request");
    builder->AddArg("--cellular-first");
    builder->AddArg(
        "--app-mode-oem-manifest=/etc/rialto_overlay_oem_manifest.json");
    builder->AddArg("--log-level=0");
    builder->AddArg("--disable-logging-redirect");
  }

  builder->AddArg("--login-manager");
  builder->AddArg("--login-profile=user");

  if (builder->UseFlagIsSet("natural_scroll_default"))
    builder->AddArg("--enable-natural-scroll-default");
  if (!builder->UseFlagIsSet("legacy_keyboard"))
    builder->AddArg("--has-chromeos-keyboard");
  if (builder->UseFlagIsSet("legacy_power_button"))
    builder->AddArg("--aura-legacy-power-button");
  if (builder->UseFlagIsSet("touchview"))
    builder->AddArg("--enable-touchview");
  if (builder->UseFlagIsSet("touchscreen_wakeup"))
    builder->AddArg("--touchscreen-usable-while-screen-off");
  if (builder->UseFlagIsSet("oobe_skip_to_login"))
    builder->AddArg("--oobe-skip-to-login");
  if (builder->UseFlagIsSet("oobe_skip_postlogin"))
    builder->AddArg("--oobe-skip-postlogin");

  if (builder->UseFlagIsSet("disable_background_blur"))
    builder->AddFeatureDisableOverride("EnableBackgroundBlur");

  if (builder->UseFlagIsSet("disable_explicit_dma_fences"))
    builder->AddArg("--disable-explicit-dma-fences");

  if (builder->UseFlagIsSet("shelf-hotseat"))
    builder->AddFeatureEnableOverride("ShelfHotseat");

  if (builder->UseFlagIsSet("webui-tab-strip")) {
    builder->AddFeatureEnableOverride("WebUITabStrip");
    builder->AddFeatureEnableOverride("WebUITabStripTabDragIntegration");
  }

  // TODO(b/180138001): Remove the following flag when a proper fix for
  // the freeze issue is found.
  if (builder->UseFlagIsSet("set_hw_overlay_strategy_none"))
    builder->AddArg("--enable-hardware-overlays=\"\"");

  SetUpAutoDimFlag(builder, cros_config);
  SetUpFormFactorFlag(builder, cros_config);

  SetUpWallpaperFlags(builder, cros_config,
                      base::BindRepeating(base::PathExists));

  // TODO(yongjaek): Remove the following flag when the kiosk mode app is ready
  // at crbug.com/309806.
  if (builder->UseFlagIsSet("moblab"))
    builder->AddArg("--disable-demo-mode");

  if (builder->UseFlagIsSet("allow_consumer_kiosk"))
    builder->AddArg("--enable-consumer-kiosk");

  if (builder->UseFlagIsSet("biod"))
    builder->AddFeatureEnableOverride("QuickUnlockFingerprint");

  if (builder->UseFlagIsSet("clear_fast_ink_buffer"))
    builder->AddArg("--ash-clear-fast-ink-buffer");

  if (builder->UseFlagIsSet("enable_dsp_hotword"))
    builder->AddFeatureEnableOverride("EnableDspHotword");

  SetUpPowerButtonPositionFlag(builder, cros_config);
  SetUpSideVolumeButtonPositionFlag(builder, cros_config);
  SetUpHelpContentSwitch(builder, cros_config);
  SetUpRegulatoryLabelFlag(builder, cros_config);
  SetUpInternalStylusFlag(builder, cros_config);
  SetUpFingerprintSensorLocationFlag(builder, cros_config);
  SetUpOzoneNNPalmPropertiesFlag(builder, cros_config);
  SetUpAutoNightLightFlag(builder, cros_config);
  SetUpAllowAmbientEQFlag(builder, cros_config);
  SetUpHibernateFlag(builder, cros_config);
  SetUpInstantTetheringFlag(builder, cros_config);
  SetUpModemFlag(builder, cros_config);
  SetUpHPEngageOneProAIOSystem(builder);
}

// Adds enterprise-related flags to the command line.
void AddEnterpriseFlags(ChromiumCommandBuilder* builder) {
  builder->AddArg("--enterprise-enrollment-initial-modulus=15");
  builder->AddArg("--enterprise-enrollment-modulus-limit=19");
}

}  // namespace

void SetUpSchedulerFlags(ChromiumCommandBuilder* builder,
                         brillo::CrosConfigInterface* cros_config) {
  // A platform can override default scheduler boosting value.
  std::string boost_urgent_str;
  int boost_urgent;

  if (cros_config &&
      cros_config->GetString(kSchedulerTunePath, kBoostUrgentProperty,
                             &boost_urgent_str) &&
      base::StringToInt(boost_urgent_str, &boost_urgent)) {
    builder->AddArg(
        base::StringPrintf("--scheduler-boost-urgent=%d", boost_urgent));
  }
}

void AddSerializedAshSwitches(ChromiumCommandBuilder* builder,
                              brillo::CrosConfigInterface* cros_config) {
  using std::string_literals::operator""s;
  std::string serialized_ash_switches;

  if (!cros_config->GetString(kUiPath, kSerializedAshSwitchesProperty,
                              &serialized_ash_switches)) {
    return;
  }

  for (const auto& flag :
       base::SplitString(serialized_ash_switches, "\0"s, base::KEEP_WHITESPACE,
                         base::SPLIT_WANT_NONEMPTY)) {
    if (base::StartsWith(flag,
                         "--enable-features=", base::CompareCase::SENSITIVE) ||
        base::StartsWith(flag,
                         "--disable-features=", base::CompareCase::SENSITIVE)) {
      std::vector<std::string> pieces = base::SplitString(
          flag, "=,", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
      CHECK_GE(pieces.size(), 2u);
      const bool is_enable_features = pieces[0] == "--enable-features";
      for (size_t i = 1; i < pieces.size(); i++) {
        if (is_enable_features)
          builder->AddFeatureEnableOverride(pieces[i]);
        else
          builder->AddFeatureDisableOverride(pieces[i]);
      }
    } else {
      builder->AddArg(flag);
    }
  }
}

void SetUpHelpContentSwitch(ChromiumCommandBuilder* builder,
                            brillo::CrosConfigInterface* cros_config) {
  std::string help_content_id;
  if (cros_config && cros_config->GetString(kUiPath, kHelpContentIdProperty,
                                            &help_content_id)) {
    builder->AddArg("--device-help-content-id=" + help_content_id);
  }
}

void SetUpRegulatoryLabelFlag(ChromiumCommandBuilder* builder,
                              brillo::CrosConfigInterface* cros_config) {
  std::string subdir;
  if (cros_config &&
      cros_config->GetString("/", kRegulatoryLabelProperty, &subdir)) {
    builder->AddArg("--regulatory-label-dir=" + subdir);
  }
}

void SetUpWallpaperFlags(
    ChromiumCommandBuilder* builder,
    brillo::CrosConfigInterface* cros_config,
    const base::RepeatingCallback<bool(const base::FilePath&)>& path_exists) {
  AddWallpaperFlags(builder, "guest", "guest", path_exists);
  AddWallpaperFlags(builder, "child", "child", path_exists);

  // Use the configuration if available.
  std::string filename;
  if (cros_config &&
      cros_config->GetString("/", kWallpaperProperty, &filename) &&
      AddWallpaperFlags(builder, "default", filename, path_exists)) {
    // If there's a wallpaper defined in cros config, mark this as an OEM
    // wallpaper.
    builder->AddArg("--default-wallpaper-is-oem");
    return;
  }

  // Fall back to oem.
  if (AddWallpaperFlags(builder, "default", "oem", path_exists)) {
    builder->AddArg("--default-wallpaper-is-oem");
    return;
  }

  // Fall back to default.
  AddWallpaperFlags(builder, "default", "default", path_exists);
}

void SetUpInternalStylusFlag(ChromiumCommandBuilder* builder,
                             brillo::CrosConfigInterface* cros_config) {
  std::string stylus_category;
  if (cros_config &&
      cros_config->GetString(kHardwarePropertiesPath, kStylusCategoryField,
                             &stylus_category) &&
      stylus_category == "internal") {
    builder->AddArg("--has-internal-stylus");
  }
}

void SetUpFingerprintSensorLocationFlag(
    ChromiumCommandBuilder* builder, brillo::CrosConfigInterface* cros_config) {
  std::string fingerprint_sensor_location;
  if (!cros_config ||
      !cros_config->GetString(kFingerprintPath, kFingerprintSensorLocationField,
                              &fingerprint_sensor_location)) {
    return;
  }

  if (fingerprint_sensor_location != "none") {
    builder->AddArg(base::StringPrintf("--fingerprint-sensor-location=%s",
                                       fingerprint_sensor_location.c_str()));
  }
}

void SetUpAutoDimFlag(ChromiumCommandBuilder* builder,
                      brillo::CrosConfigInterface* cros_config) {
  std::string display_type;
  if (cros_config &&
      cros_config->GetString(kHardwarePropertiesPath, kDisplayCategoryField,
                             &display_type) &&
      display_type == "old") {
    builder->AddArg("--enable-dim-shelf");
  }
}

void SetUpFormFactorFlag(ChromiumCommandBuilder* builder,
                         brillo::CrosConfigInterface* cros_config) {
  std::string form_factor;
  if (cros_config && cros_config->GetString(kHardwarePropertiesPath,
                                            kFormFactorField, &form_factor)) {
    builder->AddArg(
        base::StringPrintf("--form-factor=%s", form_factor.c_str()));
  }
}

void SetUpPowerButtonPositionFlag(ChromiumCommandBuilder* builder,
                                  brillo::CrosConfigInterface* cros_config) {
  std::string edge_as_string, position_as_string;
  if (!cros_config ||
      !cros_config->GetString(kPowerButtonPositionPath, kPowerButtonEdgeField,
                              &edge_as_string) ||
      !cros_config->GetString(kPowerButtonPositionPath,
                              kPowerButtonPositionField, &position_as_string)) {
    return;
  }

  double position_as_double = 0;
  if (!base::StringToDouble(position_as_string, &position_as_double)) {
    LOG(ERROR) << "Invalid value for power button position: "
               << position_as_string;
    return;
  }

  base::Value::Dict position_info;
  position_info.Set(kPowerButtonEdgeField, std::move(edge_as_string));
  position_info.Set(kPowerButtonPositionField, position_as_double);

  std::string json_position_info;
  base::JSONWriter::Write(position_info, &json_position_info);
  builder->AddArg(base::StringPrintf("--ash-power-button-position=%s",
                                     json_position_info.c_str()));
}

void SetUpSideVolumeButtonPositionFlag(
    ChromiumCommandBuilder* builder, brillo::CrosConfigInterface* cros_config) {
  std::string region_as_string, side_as_string;
  if (!cros_config ||
      !cros_config->GetString(kSideVolumeButtonPath, kSideVolumeButtonRegion,
                              &region_as_string) ||
      !cros_config->GetString(kSideVolumeButtonPath, kSideVolumeButtonSide,
                              &side_as_string)) {
    return;
  }

  base::Value::Dict position_info;
  position_info.Set(kSideVolumeButtonRegion, std::move(region_as_string));
  position_info.Set(kSideVolumeButtonSide, std::move(side_as_string));

  std::string json_position_info;
  if (!base::JSONWriter::Write(position_info, &json_position_info)) {
    LOG(ERROR) << "JSONWriter::Write failed in writing side volume button "
               << "position info.";
    return;
  }
  builder->AddArg("--ash-side-volume-button-position=" + json_position_info);
}

void SetUpOzoneNNPalmPropertiesFlag(ChromiumCommandBuilder* builder,
                                    brillo::CrosConfigInterface* cros_config) {
  base::Value::Dict info;
  if (cros_config) {
    std::string value;
    for (const char* property : kOzoneNNPalmOptionalProperties) {
      if (cros_config->GetString(kOzoneNNPalmPropertiesPath, property,
                                 &value)) {
        info.Set(property, std::move(value));
        continue;
      }
    }
  }

  std::string json_info;
  if (!base::JSONWriter::Write(info, &json_info)) {
    LOG(ERROR)
        << "JSONWriter::Write failed in writing Ozone NNPalm properties.";
    return;
  }
  builder->AddArg("--ozone-nnpalm-properties=" + json_info);
}

// Enables the "AllowAmbientEQ" feature if "allow-ambient-eq" is set to "1"
// in cros_config.
void SetUpAllowAmbientEQFlag(ChromiumCommandBuilder* builder,
                             brillo::CrosConfigInterface* cros_config) {
  std::string allow_ambient_eq_str;
  if (!cros_config || !cros_config->GetString(kPowerPath, kAllowAmbientEQField,
                                              &allow_ambient_eq_str)) {
    return;
  }

  if (allow_ambient_eq_str != "1")
    return;

  builder->AddFeatureEnableOverride("AllowAmbientEQ");
}

// Gets a powerd pref from |cros_config|, falling back on searching the
// file-based powerd preferences if not found. Powerd has a hierarchy of
// preferences it searches for a given key, so search both the core defaults
// set by boxster as well as file-based preferences customized by different
// overlays.
bool GetPowerdPref(const char* pref_name,
                   brillo::CrosConfigInterface* cros_config,
                   std::string* val_out) {
  if (cros_config && cros_config->GetString(kPowerPath, pref_name, val_out)) {
    return true;
  }

  std::string pref_name_underscores;
  base::ReplaceChars(pref_name, "-", "_", &pref_name_underscores);
  for (const char* pref_dir : kPowerdPrefPaths) {
    base::FilePath dir_path = base::FilePath(pref_dir);
    base::FilePath pref_path =
        base::FilePath(dir_path.Append(pref_name_underscores));

    if (base::PathExists(pref_path)) {
      if (base::ReadFileToString(pref_path, val_out)) {
        return true;
      }
    }
  }

  return false;
}

// Enables the "Hibernate" feature if "disable-hibernate" is set to 0 in
// the powerd preferences or the experimental flag is enabled.
void SetUpHibernateFlag(ChromiumCommandBuilder* builder,
                        brillo::CrosConfigInterface* cros_config) {
  std::string hibernate_str;

  // If the experimental flag is set, enable resume from hibernation.
  if (base::PathExists(base::FilePath(kPowerdHibernateExperimentFlag))) {
    builder->AddFeatureEnableOverride(kHibernateFeature);
    return;
  }

  if (!GetPowerdPref(kHibernateField, cros_config, &hibernate_str)) {
    return;
  }

  base::TrimWhitespaceASCII(hibernate_str, base::TRIM_ALL, &hibernate_str);
  if (hibernate_str == "0") {
    builder->AddFeatureEnableOverride(kHibernateFeature);
  }
}

void SetUpInstantTetheringFlag(ChromiumCommandBuilder* builder,
                               brillo::CrosConfigInterface* cros_config) {
  if (builder->UseFlagIsSet("disable_instant_tethering")) {
    builder->AddFeatureDisableOverride("InstantTethering");
    return;
  }

  std::string disable_instant_tethering_str;
  if (!cros_config || !cros_config->GetString(kInstantTetheringPath,
                                              kDisableInstantTetheringProperty,
                                              &disable_instant_tethering_str)) {
    return;
  }

  if (disable_instant_tethering_str == "true")
    builder->AddFeatureDisableOverride("InstantTethering");
}

void AddCrashHandlerFlag(ChromiumCommandBuilder* builder) {
  builder->AddArg(builder->UseFlagIsSet("force_breakpad")
                      ? kEnableBreakpadFlag
                      : kEnableCrashpadFlag);
}

// Adds flags related to machine learning features that are enabled only on a
// supported subset of devices.
void AddMlFlags(ChromiumCommandBuilder* builder,
                brillo::CrosConfigInterface* cros_config) {
  if (builder->UseFlagIsSet("ml_service"))
    builder->AddArg("--ml_service=enabled");

  if (builder->UseFlagIsSet("smartdim"))
    builder->AddFeatureEnableOverride("SmartDim");

  if (builder->UseFlagIsSet("enable_neural_palm_detection_filter"))
    builder->AddFeatureEnableOverride("EnableNeuralPalmDetectionFilter");

  if (builder->UseFlagIsSet("enable_heuristic_palm_detection_filter"))
    builder->AddFeatureEnableOverride("EnableHeuristicPalmDetectionFilter");

  if (!builder->UseFlagIsSet("ondevice_grammar"))
    builder->AddFeatureDisableOverride("OnDeviceGrammarCheck");

  if (builder->UseFlagIsSet("ondevice_handwriting"))
    builder->AddArg("--ondevice_handwriting=use_rootfs");
  else if (builder->UseFlagIsSet("ondevice_handwriting_dlc"))
    builder->AddArg("--ondevice_handwriting=use_dlc");

  if (builder->UseFlagIsSet("ondevice_speech")) {
    // libsoda is supported on devices with 4GB+ of physical RAM. base::SysInfo
    // reports total RAM minus some reserved stuff e.g. the kernel, so in
    // practice, we compare against 3GiB not 4GiB.
    // Theoretically: this will match devices with RAM > (3GiB + something).
    // In practice:   all such devices have 4GB+.
    constexpr int kSodaLibraryMinRamMB = 3072;
    if (base::SysInfo::AmountOfPhysicalMemoryMB() >= kSodaLibraryMinRamMB)
      builder->AddFeatureEnableOverride("OnDeviceSpeechRecognition");
  }

  if (builder->UseFlagIsSet("ondevice_document_scanner"))
    builder->AddArg("--ondevice_document_scanner=use_rootfs");
  else if (builder->UseFlagIsSet("ondevice_document_scanner_dlc"))
    builder->AddArg("--ondevice_document_scanner=use_dlc");

  if (!builder->UseFlagIsSet("federated_service")) {
    builder->AddFeatureDisableOverride("FederatedService");
  }

  if (builder->UseFlagIsSet("camera_feature_effects"))
    builder->AddArg("--camera-effects-supported-by-hardware");

  SetUpHandwritingRecognitionWebPlatformApiFlag(builder, cros_config);
  SetUpHasHpsFlag(builder, cros_config);
}

// Adds flags related to feature management that must be enabled for this
// device.
void AddFeatureManagementFlags(
    ChromiumCommandBuilder* builder,
    segmentation::FeatureManagement* feature_management) {
  std::set<std::string> features =
      feature_management->ListFeatures(segmentation::USAGE_CHROME);
  for (auto feature : features) {
    builder->AddFeatureEnableOverride(feature);
  }
}

void PerformChromeSetup(brillo::CrosConfigInterface* cros_config,
                        segmentation::FeatureManagement* feature_management,
                        bool* is_developer_end_user_out,
                        std::map<std::string, std::string>* env_vars_out,
                        std::vector<std::string>* args_out,
                        uid_t* uid_out) {
  DCHECK(env_vars_out);
  DCHECK(args_out);
  DCHECK(uid_out);

  ChromiumCommandBuilder builder;
  std::set<std::string> disallowed_prefixes;
  CHECK(builder.Init());
  CHECK(builder.SetUpChromium());

  // Please add new code to the most-appropriate helper function instead of
  // putting it here. Things that apply to all Chromium-derived binaries (e.g.
  // app_shell, content_shell, etc.) rather than just to Chrome belong in the
  // ChromiumCommandBuilder class instead.
  CreateDirectories(&builder);
  AddSerializedAshSwitches(&builder, cros_config);
  AddSystemFlags(&builder, cros_config);
  AddUiFlags(&builder, cros_config);
  AddArcFlags(&builder, &disallowed_prefixes, cros_config);
  AddCrostiniFlags(&builder);
  AddPluginVmFlags(&builder);
  AddBorealisFlags(&builder);
  AddLacrosFlags(&builder);
  AddEnterpriseFlags(&builder);
  AddCrashHandlerFlag(&builder);
  AddMlFlags(&builder, cros_config);
  AddFeatureManagementFlags(&builder, feature_management);

  // Apply any modifications requested by the developer.
  if (builder.is_developer_end_user()) {
    builder.ApplyUserConfig(base::FilePath(kChromeDevConfigPath),
                            disallowed_prefixes);
  }

  *is_developer_end_user_out = builder.is_developer_end_user();
  *env_vars_out = builder.environment_variables();
  *args_out = builder.arguments();
  *uid_out = builder.uid();

  // Do not add code here. Potentially-expensive work should be done between
  // StartServer() and WaitForServer().
}

}  // namespace login_manager
