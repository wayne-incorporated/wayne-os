// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/arc_setup.h"

#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <sched.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/environment.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/cryptohome.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/file_utils.h>
#include <brillo/files/file_util.h>
#include <brillo/files/safe_fd.h>
#include <brillo/scoped_mount_namespace.h>
#include <chromeos-config/libcros_config/cros_config.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <crypto/random.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <metrics/bootstat.h>
#include <metrics/metrics_library.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "arc/setup/arc_property_util.h"
#include "arc/setup/art_container.h"
#include "arc/setup/xml/android_xml_util.h"

#define EXIT_IF(f)                            \
  do {                                        \
    LOG(INFO) << "Running " << (#f) << "..."; \
    CHECK(!(f));                              \
  } while (false)

#define IGNORE_ERRORS(f)                                 \
  do {                                                   \
    LOG(INFO) << "Running " << (#f) << "...";            \
    LOG_IF(INFO, !(f)) << "Ignoring failures: " << (#f); \
  } while (false)

// TODO(yusukes): use android_filesystem_config.h.
#define AID_ROOT 0         /* traditional unix root user */
#define AID_SYSTEM 1000    /* system server */
#define AID_LOG 1007       /* log devices */
#define AID_SDCARD_RW 1015 /* external storage write access */
#define AID_MEDIA_RW 1023  /* internal media storage write access */
#define AID_EXTERNAL_STORAGE \
  1077 /* Full external storage access including USB OTG volumes */
#define AID_SHELL 2000     /* adb and debug shell user */
#define AID_CACHE 2001     /* cache access */
#define AID_EVERYBODY 9997 /* shared between all apps in the same profile */

namespace arc {

namespace {

// Lexicographically sorted. Usually you don't have to use these constants
// directly. Prefer base::FilePath variables in ArcPaths instead.
constexpr char kAdbdMountDirectory[] = "/run/arc/adbd";
constexpr char kAdbdUnixSocketMountDirectory[] = "/run/arc/adb";
constexpr char kAndroidCmdline[] = "/run/arc/cmdline.android";
constexpr char kAndroidGeneratedPropertiesDirectory[] =
    "/run/arc/host_generated";
constexpr char kAndroidKmsgFifo[] = "/run/arc/android.kmsg.fifo";
constexpr char kAndroidMutableSource[] =
    "/opt/google/containers/android/rootfs/android-data";
constexpr char kAndroidRootfsDirectory[] =
    "/opt/google/containers/android/rootfs/root";
constexpr char kArcVmPerBoardConfigPath[] = "/run/arcvm/host_generated/oem";
constexpr char kArcVmVendorImagePath[] =
    "/opt/google/vms/android/vendor.raw.img";
constexpr char kApkCacheDir[] = "/mnt/stateful_partition/unencrypted/apkcache";
constexpr char kArcBridgeSocketContext[] = "u:object_r:arc_bridge_socket:s0";
constexpr char kArcBridgeSocketPath[] = "/run/chrome/arc_bridge.sock";
constexpr char kBinFmtMiscDirectory[] = "/proc/sys/fs/binfmt_misc";
constexpr char kBootIdFile[] = "/proc/sys/kernel/random/boot_id";
constexpr char kBuildPropFile[] = "/usr/share/arc/properties/build.prop";
constexpr char kBuildPropFileVm[] = "/usr/share/arcvm/properties/build.prop";
constexpr char kCameraProfileDir[] =
    "/mnt/stateful_partition/encrypted/var/cache/camera";
constexpr char kCameraTestConfig[] = "/var/cache/camera/test_config.json";
constexpr char kCrasSocketDirectory[] = "/run/cras";
constexpr char kCombinedPropFileVm[] =
    "/run/arcvm/host_generated/combined.prop";
constexpr char kDalvikCacheSELinuxContext[] =
    "u:object_r:dalvikcache_data_file:s0";
constexpr char kDebugfsDirectory[] = "/run/arc/debugfs";
constexpr char kFakeKptrRestrict[] = "/run/arc/fake_kptr_restrict";
constexpr char kFakeMmapRndBits[] = "/run/arc/fake_mmap_rnd_bits";
constexpr char kFakeMmapRndCompatBits[] = "/run/arc/fake_mmap_rnd_compat_bits";
constexpr char kHostSideDalvikCacheDirectoryInContainer[] =
    "/var/run/arc/dalvik-cache";
constexpr char kMediaCodecsRelative[] = "etc/media_codecs_c2.xml";
constexpr char kMediaCodecsPerformanceRelative[] =
    "etc/media_codecs_performance_c2.xml";
constexpr char kMediaMountDirectory[] = "/run/arc/media";
constexpr char kMediaMyFilesDirectory[] = "/run/arc/media/MyFiles";
constexpr char kMediaMyFilesDefaultDirectory[] =
    "/run/arc/media/MyFiles-default";
constexpr char kMediaMyFilesReadDirectory[] = "/run/arc/media/MyFiles-read";
constexpr char kMediaMyFilesWriteDirectory[] = "/run/arc/media/MyFiles-write";
constexpr char kMediaProfileFile[] = "media_profiles.xml";
constexpr char kMediaRemovableDirectory[] = "/run/arc/media/removable";
constexpr char kMediaRemovableDefaultDirectory[] =
    "/run/arc/media/removable-default";
constexpr char kMediaRemovableReadDirectory[] = "/run/arc/media/removable-read";
constexpr char kMediaRemovableWriteDirectory[] =
    "/run/arc/media/removable-write";
constexpr char kObbMountDirectory[] = "/run/arc/obb";
constexpr char kObbRootfsDirectory[] =
    "/opt/google/containers/arc-obb-mounter/mountpoints/container-root";
constexpr char kObbRootfsImage[] =
    "/opt/google/containers/arc-obb-mounter/rootfs.squashfs";
constexpr char kOemMountDirectory[] = "/run/arc/oem";
constexpr char kPlatformXmlFileRelative[] = "etc/permissions/platform.xml";
constexpr char kRestoreconAllowlistSync[] = "/sys/kernel/debug/sync";
constexpr char kSdcardConfigfsDirectory[] = "/sys/kernel/config/sdcardfs";
constexpr char kSdcardMountDirectory[] = "/run/arc/sdcard";
constexpr char kSdcardRootfsDirectory[] =
    "/opt/google/containers/arc-sdcard/mountpoints/container-root";
constexpr char kSdcardRootfsImage[] =
    "/opt/google/containers/arc-sdcard/rootfs.squashfs";
constexpr char kSharedMountDirectory[] = "/run/arc/shared_mounts";
constexpr char kSysfsCpu[] = "/sys/devices/system/cpu";
constexpr char kSysfsTracing[] = "/sys/kernel/tracing";
constexpr char kSystemLibArmDirectoryRelative[] = "system/lib/arm";
constexpr char kSystemLibArm64DirectoryRelative[] = "system/lib64/arm64";
constexpr char kSystemImage[] = "/opt/google/containers/android/system.raw.img";
constexpr char kTestharnessDirectory[] = "/run/arc/testharness";
constexpr char kUsbDevicesDirectory[] = "/dev/bus/usb";
constexpr char kZygotePreloadDoneFile[] = ".preload_done";

constexpr const char kPropertyFilesPathVm[] = "/usr/share/arcvm/properties";
constexpr const char kPropertyFilesPath[] = "/usr/share/arc/properties";
constexpr const char kGeneratedPropertyFilesPathVm[] =
    "/run/arcvm/host_generated";
constexpr const char kGeneratedPropertyFilesPath[] = "/run/arc/host_generated";

// Names for possible binfmt_misc entries.
constexpr const char* kBinFmtMiscEntryNames[] = {"arm_dyn", "arm_exe",
                                                 "arm64_dyn", "arm64_exe"};

// These are board-specific configuration settings, which are managed through
// the chromeos-config architecture.
// For details, see:
// https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/chromeos-config/#arc
//
// Board-specific config files are automatically managed/generated via project
// config repos. For details, see:
// https://chromium.googlesource.com/chromiumos/config/
// For an example, see:
// https://chromium.googlesource.com/chromiumos/config/+/HEAD/test/project/fake/fake/sw_build_config/platform/chromeos-config/generated/arc/
constexpr char kHardwareFeaturesSetting[] = "/arc/hardware-features";
constexpr char kMediaProfilesSetting[] = "/arc/media-profiles";
constexpr char kMediaCodecsSetting[] = "/arc/media-codecs";
constexpr char kMediaCodecsPerformanceSetting[] =
    "/arc/media-codecs-performance";
constexpr char kSystemPath[] = "system-path";

constexpr uid_t kHostRootUid = 0;
constexpr gid_t kHostRootGid = 0;

constexpr uid_t kHostChronosUid = 1000;
constexpr gid_t kHostChronosGid = 1000;

constexpr uid_t kHostArcCameraUid = 603;
constexpr gid_t kHostArcCameraGid = 603;

constexpr uid_t kShiftUid = 655360;
constexpr gid_t kShiftGid = 655360;
constexpr uid_t kRootUid = AID_ROOT + kShiftUid;
constexpr gid_t kRootGid = AID_ROOT + kShiftGid;
constexpr uid_t kSystemUid = AID_SYSTEM + kShiftUid;
constexpr gid_t kSystemGid = AID_SYSTEM + kShiftGid;
constexpr uid_t kMediaUid = AID_MEDIA_RW + kShiftUid;
constexpr gid_t kMediaGid = AID_MEDIA_RW + kShiftGid;
constexpr uid_t kShellUid = AID_SHELL + kShiftUid;
constexpr uid_t kShellGid = AID_SHELL + kShiftGid;
constexpr gid_t kSdcardRwGid = AID_SDCARD_RW + kShiftGid;
constexpr gid_t kEverybodyGid = AID_EVERYBODY + kShiftGid;

// Time to wait for a ResetApplicationContainerReply from DBus.
// The value is taken from kDefaultTimeoutMs in cryptohome/cryptohome.cc.
constexpr int kResetLvmDbusTimeoutMs = 300000;

// The maximum time to wait for /data/media setup.
constexpr base::TimeDelta kInstalldTimeout = base::Seconds(60);

// Property name for fingerprint.
constexpr char kFingerprintProp[] = "ro.build.fingerprint";

// System salt and arc salt file size.
constexpr size_t kSaltFileSize = 16;

bool RegisterAllBinFmtMiscEntries(ArcMounter* mounter,
                                  const base::FilePath& entry_directory,
                                  const base::FilePath& binfmt_misc_directory) {
  std::unique_ptr<ScopedMount> binfmt_misc_mount =
      ScopedMount::CreateScopedMount(mounter, "binfmt_misc",
                                     binfmt_misc_directory, "binfmt_misc",
                                     MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
  if (!binfmt_misc_mount)
    return false;

  const base::FilePath binfmt_misc_register_path =
      binfmt_misc_directory.Append("register");
  for (auto entry_name : kBinFmtMiscEntryNames) {
    const base::FilePath entry_path = entry_directory.Append(entry_name);
    // arm64_{dyn,exe} are only available on some boards/configurations. Only
    // install them if they are present.
    if (!base::PathExists(entry_path))
      continue;
    const base::FilePath format_path = binfmt_misc_directory.Append(entry_name);
    if (base::PathExists(format_path)) {
      // If we had already registered this format earlier and failed
      // unregistering it for some reason, the next operation will fail.
      LOG(WARNING) << "Skipping re-registration of " << entry_path.value();
      continue;
    }
    if (!base::CopyFile(entry_path, binfmt_misc_register_path)) {
      PLOG(ERROR) << "Failed to register " << entry_path.value();
      return false;
    }
  }

  return true;
}

void UnregisterBinFmtMiscEntry(const base::FilePath& entry_path) {
  // This function is for Mode::STOP. Ignore errors to make sure to run all
  // clean up code.
  base::File entry(entry_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  if (!entry.IsValid()) {
    PLOG(INFO) << "Ignoring failure: Failed to open " << entry_path.value();
    return;
  }
  constexpr char kBinfmtMiscUnregister[] = "-1";
  IGNORE_ERRORS(
      entry.Write(0, kBinfmtMiscUnregister, sizeof(kBinfmtMiscUnregister) - 1));
}

// Prepends |path_to_prepend| to each element in [first, last), and returns the
// result as a vector.
template <typename It>
std::vector<base::FilePath> PrependPath(It first,
                                        It last,
                                        const base::FilePath& path_to_prepend) {
  std::vector<base::FilePath> result;
  std::transform(first, last, std::back_inserter(result),
                 [&path_to_prepend](const char* path) {
                   return path_to_prepend.Append(path);
                 });
  return result;
}

// Returns SDK version upgrade type to be sent to UMA.
ArcSdkVersionUpgradeType GetUpgradeType(AndroidSdkVersion system_sdk_version,
                                        AndroidSdkVersion data_sdk_version) {
  if (data_sdk_version == AndroidSdkVersion::UNKNOWN ||  // First boot
      data_sdk_version == system_sdk_version) {
    return ArcSdkVersionUpgradeType::NO_UPGRADE;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_M) {
    if (system_sdk_version == AndroidSdkVersion::ANDROID_P)
      return ArcSdkVersionUpgradeType::M_TO_P;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_N_MR1 &&
      system_sdk_version == AndroidSdkVersion::ANDROID_P) {
    return ArcSdkVersionUpgradeType::N_TO_P;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_N_MR1 &&
      system_sdk_version == AndroidSdkVersion::ANDROID_R) {
    return ArcSdkVersionUpgradeType::N_TO_R;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_P &&
      system_sdk_version == AndroidSdkVersion::ANDROID_R) {
    return ArcSdkVersionUpgradeType::P_TO_R;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_P &&
      system_sdk_version == AndroidSdkVersion::ANDROID_TIRAMISU) {
    return ArcSdkVersionUpgradeType::P_TO_T;
  }
  if (data_sdk_version == AndroidSdkVersion::ANDROID_R &&
      system_sdk_version == AndroidSdkVersion::ANDROID_TIRAMISU) {
    return ArcSdkVersionUpgradeType::R_TO_T;
  }
  if (data_sdk_version < system_sdk_version) {
    LOG(ERROR) << "Unexpected Upgrade: data_sdk_version="
               << static_cast<int>(data_sdk_version) << " system_sdk_version="
               << static_cast<int>(system_sdk_version);
    return ArcSdkVersionUpgradeType::UNKNOWN_UPGRADE;
  }
  LOG(ERROR) << "Unexpected Downgrade: data_sdk_version="
             << static_cast<int>(data_sdk_version)
             << " system_sdk_version=" << static_cast<int>(system_sdk_version);
  return ArcSdkVersionUpgradeType::UNKNOWN_DOWNGRADE;
}

void CheckProcessIsAliveOrExit(const std::string& pid_str) {
  pid_t pid;
  EXIT_IF(!base::StringToInt(pid_str, &pid));
  if (!IsProcessAlive(pid)) {
    LOG(ERROR) << "Process " << pid << " is NOT alive";
    exit(EXIT_FAILURE);
  }
  LOG(INFO) << "Process " << pid << " is still alive, at least as a zombie";
  // TODO(yusukes): Check if the PID is a zombie or not, and log accordingly.
}

void CheckNamespacesAvailableOrExit(const std::string& pid_str) {
  const base::FilePath proc("/proc");
  const base::FilePath ns = proc.Append(pid_str).Append("ns");
  EXIT_IF(!base::PathExists(ns));
  for (const char* entry :
       {"cgroup", "ipc", "mnt", "net", "pid", "user", "uts"}) {
    // Use the same syscall, open, as nsenter. Other syscalls like lstat may
    // succeed when open doesn't.
    const base::FilePath path_to_check = ns.Append(entry);
    base::ScopedFD fd(open(path_to_check.value().c_str(), O_RDONLY));
    if (!fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << path_to_check.value();
      exit(EXIT_FAILURE);
    }
  }
  LOG(INFO) << "Process " << pid_str << " still has all namespace entries";
}

void CheckOtherProcEntriesOrExit(const std::string& pid_str) {
  const base::FilePath proc("/proc");
  const base::FilePath proc_pid = proc.Append(pid_str);
  for (const char* entry : {"cwd", "root"}) {
    // Use open for the same reason as CheckNamespacesAvailableOrExit().
    const base::FilePath path_to_check = proc_pid.Append(entry);
    base::ScopedFD fd(open(path_to_check.value().c_str(), O_RDONLY));
    if (!fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << path_to_check.value();
      exit(EXIT_FAILURE);
    }
  }
  LOG(INFO) << "Process " << pid_str << " still has other proc entries";
}

// Creates subdirectories under dalvik-cache directory if not exists.
bool CreateArtContainerDataDirectory(
    const base::FilePath& art_dalvik_cache_directory) {
  for (const std::string& isa : ArtContainer::GetIsas()) {
    base::FilePath isa_directory = art_dalvik_cache_directory.Append(isa);
    // Use the same permissions as the ones used in maybeCreateDalvikCache() in
    // framework/base/cmds/app_process/app_main.cpp
    if (!InstallDirectory(0711, kRootUid, kRootGid, isa_directory)) {
      PLOG(ERROR) << "Failed to create art container data dir: "
                  << isa_directory.value();
      return false;
    }
  }
  return true;
}

// Stores relative path, mode_t for sdcard mounts.
// mode is an octal mask for file persmissions here.
struct EsdfsMount {
  const char* relative_path;
  mode_t mode;
  gid_t gid;
};

const std::vector<EsdfsMount> GetEsdfsMounts(AndroidSdkVersion version) {
  constexpr std::array<EsdfsMount, 3> kEsdfsMounts{{
      {"default/emulated", 0006, kSdcardRwGid},
      {"read/emulated", 0027, kEverybodyGid},
      {"write/emulated", 0007, kEverybodyGid},
  }};
  std::vector<EsdfsMount> mounts;
  for (const auto& mount : kEsdfsMounts)
    mounts.push_back(mount);
  if (version > AndroidSdkVersion::ANDROID_P) {
    // For container R.
    mounts.push_back({"full/emulated", 0007, kEverybodyGid});
  }
  return mounts;
}

// Esdfs mount options:
// --------------------
// fsuid, fsgid  : Lower filesystem's uid/gid.
//
// derive_gid    : Changes uid/gid values on the lower filesystem for tracking
//                 storage user by apps and various categories.
//
// default_normal: Does not treat the default mount (using gid AID_SDCARD_RW)
//                 differently. Without this, the gid presented by the upper
//                 filesystem does not include the user, and would allow shell
//                 users to access all user’s data.
//
// mask          : Masks away permissions.
//
// gid           : Upper filesystem's group id.
//
// ns_fd         : Namespace file descriptor used to set the base namespace for
//                 the esdfs mount, similar to the  argument to setns(2).
//
// dl_uid, dl_gid: Downloads integration uid/gid.
//
// dl_loc        : The Android download directory acts as an overlay on dl_loc.

std::string CreateEsdfsMountOpts(uid_t fsuid,
                                 gid_t fsgid,
                                 mode_t mask,
                                 uid_t userid,
                                 gid_t gid,
                                 const base::FilePath& host_downloads_directory,
                                 int container_userns_fd) {
  std::string opts = base::StringPrintf(
      "fsuid=%d,fsgid=%d,derive_gid,default_normal,mask=%d,multiuser,"
      "gid=%d,dl_loc=%s,dl_uid=%d,dl_gid=%d,ns_fd=%d",
      fsuid, fsgid, mask, gid, host_downloads_directory.value().c_str(),
      kHostChronosUid, kHostChronosGid, container_userns_fd);
  LOG(INFO) << "Esdfs mount options: " << opts;
  return opts;
}

// Wait upto kInstalldTimeout for the sdcard source directory to be setup.
// On failure, exit.
bool WaitForSdcardSource(const base::FilePath& android_root,
                         AndroidSdkVersion sdk_version) {
  bool ret;
  base::TimeDelta elapsed;
  // <android_root>/data path to synchronize with installd
  const base::FilePath fs_version =
      sdk_version > AndroidSdkVersion::ANDROID_P
          ?
          // For container R.
          android_root.Append("data/misc/installd/layout_version")
          : android_root.Append("data/.layout_version");

  LOG(INFO) << "Waiting upto " << kInstalldTimeout
            << " for installd to complete setting up /data.";
  ret = WaitForPaths({fs_version}, kInstalldTimeout, &elapsed);

  LOG(INFO) << "Waiting for installd took " << elapsed.InSeconds() << "s";
  if (!ret)
    LOG(ERROR) << "Timed out waiting for /data setup.";

  return ret;
}

// Reads a random number for the container from /var/lib/misc/arc_salt. If
// the file does not exist, generates a new one. This file will be cleared
// and regenerated after powerwash.
std::string GetOrCreateArcSalt() {
  constexpr char kArcSaltFile[] = "/var/lib/misc/arc_salt";
  constexpr mode_t kArcSaltFilePermissions = 0400;

  std::string arc_salt;
  const base::FilePath arc_salt_file(kArcSaltFile);
  if (!base::ReadFileToString(arc_salt_file, &arc_salt) ||
      arc_salt.size() != kSaltFileSize) {
    char rand_value[kSaltFileSize];
    crypto::RandBytes(rand_value, kSaltFileSize);
    arc_salt = std::string(rand_value, kSaltFileSize);
    if (!brillo::WriteToFileAtomic(arc_salt_file, arc_salt.data(),
                                   arc_salt.size(), kArcSaltFilePermissions)) {
      LOG(ERROR) << "Failed to write arc salt file.";
      return std::string();
    }
  }
  return arc_salt;
}

bool IsChromeOSUserAvailable(Mode mode) {
  switch (mode) {
    case Mode::BOOT_CONTINUE:
    case Mode::CREATE_DATA:
    case Mode::REMOVE_DATA:
    case Mode::REMOVE_STALE_DATA:
    case Mode::MOUNT_SDCARD:
    case Mode::HANDLE_UPGRADE:
      return true;
    case Mode::PREPARE_HOST_GENERATED_DIR:
    case Mode::APPLY_PER_BOARD_CONFIG:
    case Mode::SETUP:
    case Mode::STOP:
    case Mode::ONETIME_SETUP:
    case Mode::ONETIME_STOP:
    case Mode::PRE_CHROOT:
    case Mode::UNMOUNT_SDCARD:
    case Mode::UPDATE_RESTORECON_LAST:
    case Mode::UNKNOWN:
      return false;
  }
}

// Converts Dalvik memory profile to androidboot property if applicable.
std::string GetDalvikMemoryProfileParam(
    const std::string& dalvik_memory_profile) {
  if (dalvik_memory_profile.empty())
    return std::string();
  return base::StringPrintf("androidboot.arc_dalvik_memory_profile=%s ",
                            dalvik_memory_profile.c_str());
}

// Converts MediaStore maintenance bool to androidboot property if applicable.
std::string GetDisableMediaStoreMaintenance(
    bool disable_media_store_maintenance) {
  if (!disable_media_store_maintenance)
    return std::string();
  return "androidboot.disable_media_store_maintenance=1 ";
}

// Converts disable download provider bool to androidboot property if
// applicable.
std::string GetDisableDownloadProvider(bool disable_download_provider) {
  if (!disable_download_provider)
    return std::string();
  return "androidboot.disable_download_provider=1 ";
}

// Converts Generate PAI bool to androidboot property if applicable.
std::string GetGeneratePaiParam(bool arc_generate_pai) {
  return arc_generate_pai ? "androidboot.arc_generate_pai=1 " : std::string();
}

std::string GetSELinuxContext(const base::FilePath& path) {
  char* con = nullptr;
  if (lgetfilecon(path.value().c_str(), &con) < 0) {
    if (errno != ENOENT)
      PLOG(ERROR) << "lgetfilecon failed for " << path.value();
    return std::string();
  }
  std::string result = con;
  freecon(con);
  return result;
}

std::optional<base::FilePath> GetConfigPath(brillo::CrosConfigInterface& config,
                                            const std::string& path) {
  std::string value;
  if (!config.GetString(path, kSystemPath, &value)) {
    return std::nullopt;
  }
  return base::FilePath(value);
}

}  // namespace

// A struct that holds all the FilePaths ArcSetup uses.
struct ArcPaths {
  static std::unique_ptr<ArcPaths> Create(Mode mode, const Config& config) {
    base::FilePath root_path;
    base::FilePath user_path;
    base::FilePath android_data;
    base::FilePath android_data_old;

    if (IsChromeOSUserAvailable(mode)) {
      brillo::cryptohome::home::Username chromeos_user(
          config.GetStringOrDie("CHROMEOS_USER"));
      root_path = brillo::cryptohome::home::GetRootPath(chromeos_user);
      user_path = brillo::cryptohome::home::GetUserPath(chromeos_user);

      // Ensure the root directory and the user directory exist.
      EXIT_IF(root_path.empty() || !base::DirectoryExists(root_path));
      EXIT_IF(user_path.empty() || !base::DirectoryExists(user_path));

      android_data = root_path.Append("android-data");
      android_data_old = root_path.Append("android-data-old");
    }
    return base::WrapUnique(
        new ArcPaths(root_path, user_path, android_data, android_data_old));
  }

  // Lexicographically sorted.
  const base::FilePath adbd_mount_directory{kAdbdMountDirectory};
  const base::FilePath adbd_unix_socket_mount_directory{
      kAdbdUnixSocketMountDirectory};
  const base::FilePath android_cmdline{kAndroidCmdline};
  const base::FilePath android_generated_properties_directory{
      kAndroidGeneratedPropertiesDirectory};
  const base::FilePath android_kmsg_fifo{kAndroidKmsgFifo};
  const base::FilePath android_mutable_source{kAndroidMutableSource};
  const base::FilePath android_rootfs_directory{kAndroidRootfsDirectory};
  const base::FilePath arc_bridge_socket_path{kArcBridgeSocketPath};
  const base::FilePath apk_cache_dir{kApkCacheDir};
  const base::FilePath art_dalvik_cache_directory{kArtDalvikCacheDirectory};
  const base::FilePath binfmt_misc_directory{kBinFmtMiscDirectory};
  const base::FilePath camera_profile_dir{kCameraProfileDir};
  const base::FilePath camera_test_config{kCameraTestConfig};
  const base::FilePath cras_socket_directory{kCrasSocketDirectory};
  const base::FilePath debugfs_directory{kDebugfsDirectory};
  const base::FilePath fake_kptr_restrict{kFakeKptrRestrict};
  const base::FilePath fake_mmap_rnd_bits{kFakeMmapRndBits};
  const base::FilePath fake_mmap_rnd_compat_bits{kFakeMmapRndCompatBits};
  const base::FilePath host_side_dalvik_cache_directory_in_container{
      kHostSideDalvikCacheDirectoryInContainer};
  const base::FilePath media_codecs_relative{kMediaCodecsRelative};
  const base::FilePath media_codecs_performance_relative{
      kMediaCodecsPerformanceRelative};
  const base::FilePath media_mount_directory{kMediaMountDirectory};
  const base::FilePath media_myfiles_directory{kMediaMyFilesDirectory};
  const base::FilePath media_myfiles_default_directory{
      kMediaMyFilesDefaultDirectory};
  const base::FilePath media_myfiles_read_directory{kMediaMyFilesReadDirectory};
  const base::FilePath media_myfiles_write_directory{
      kMediaMyFilesWriteDirectory};
  const base::FilePath media_profile_file{kMediaProfileFile};
  const base::FilePath media_removable_directory{kMediaRemovableDirectory};
  const base::FilePath media_removable_default_directory{
      kMediaRemovableDefaultDirectory};
  const base::FilePath media_removable_read_directory{
      kMediaRemovableReadDirectory};
  const base::FilePath media_removable_write_directory{
      kMediaRemovableWriteDirectory};
  const base::FilePath obb_mount_directory{kObbMountDirectory};
  const base::FilePath obb_rootfs_directory{kObbRootfsDirectory};
  const base::FilePath oem_mount_directory{kOemMountDirectory};
  const base::FilePath platform_xml_file_relative{kPlatformXmlFileRelative};
  const base::FilePath sdcard_configfs_directory{kSdcardConfigfsDirectory};
  const base::FilePath sdcard_mount_directory{kSdcardMountDirectory};
  const base::FilePath sdcard_rootfs_directory{kSdcardRootfsDirectory};
  const base::FilePath shared_mount_directory{kSharedMountDirectory};
  const base::FilePath sysfs_cpu{kSysfsCpu};
  const base::FilePath sysfs_tracing{kSysfsTracing};
  const base::FilePath system_lib_arm_directory_relative{
      kSystemLibArmDirectoryRelative};
  const base::FilePath system_lib64_arm64_directory_relative{
      kSystemLibArm64DirectoryRelative};
  const base::FilePath testharness_directory{kTestharnessDirectory};
  const base::FilePath usb_devices_directory{kUsbDevicesDirectory};

  const base::FilePath restorecon_allowlist_sync{kRestoreconAllowlistSync};

  const base::FilePath root_directory;
  const base::FilePath user_directory;
  const base::FilePath android_data_directory;
  const base::FilePath android_data_old_directory;

 private:
  ArcPaths(const base::FilePath& root_directory,
           const base::FilePath& user_directory,
           const base::FilePath& android_data_directory,
           const base::FilePath& android_data_old_directory)
      : root_directory(root_directory),
        user_directory(user_directory),
        android_data_directory(android_data_directory),
        android_data_old_directory(android_data_old_directory) {}
  ArcPaths(const ArcPaths&) = delete;
  ArcPaths& operator=(const ArcPaths&) = delete;
};

ArcSetup::ArcSetup(Mode mode, const base::FilePath& config_json)
    : mode_(mode),
      config_(config_json, base::Environment::Create()),
      arc_mounter_(GetDefaultMounter()),
      arc_paths_(ArcPaths::Create(mode_, config_)),
      arc_setup_metrics_(std::make_unique<ArcSetupMetrics>()) {
  CHECK(mode == Mode::APPLY_PER_BOARD_CONFIG || mode == Mode::CREATE_DATA ||
        mode == Mode::REMOVE_DATA || mode == Mode::REMOVE_STALE_DATA ||
        mode == Mode::HANDLE_UPGRADE || !config_json.empty());
}

ArcSetup::~ArcSetup() = default;

// static
std::string ArcSetup::GetPlayStoreAutoUpdateParam(
    PlayStoreAutoUpdate play_store_auto_update) {
  switch (play_store_auto_update) {
    case PlayStoreAutoUpdate::kDefault:
      return std::string();
    case PlayStoreAutoUpdate::kOn:
    case PlayStoreAutoUpdate::kOff:
      return base::StringPrintf(
          "androidboot.play_store_auto_update=%d ",
          play_store_auto_update == PlayStoreAutoUpdate::kOn);
  }
}

// Note: This function has to be in sync with Android's arc-boot-type-detector.
// arc-boot-type-detector's DeleteExecutableFilesInData() function is very
// similar to this.
void ArcSetup::DeleteExecutableFilesInData(
    bool should_delete_data_dalvik_cache_directory,
    bool should_delete_data_app_executables) {
  if (!should_delete_data_dalvik_cache_directory &&
      !should_delete_data_app_executables) {
    return;
  }

  // Move data/dalvik-cache.
  if (should_delete_data_dalvik_cache_directory) {
    MoveDirIntoDataOldDir(arc_paths_->android_data_directory.Append(
                              base::FilePath("data/dalvik-cache")),
                          arc_paths_->android_data_old_directory);
  }

  // Move data/app/*/oat cache.
  const base::FilePath app_directory =
      arc_paths_->android_data_directory.Append(base::FilePath("data/app"));
  if (should_delete_data_app_executables && base::PathExists(app_directory)) {
    base::ElapsedTimer timer;

    base::FileEnumerator dir_enum(app_directory, false /* recursive */,
                                  base::FileEnumerator::DIRECTORIES);
    for (base::FilePath pkg_directory_name = dir_enum.Next();
         !pkg_directory_name.empty(); pkg_directory_name = dir_enum.Next()) {
      MoveDirIntoDataOldDir(pkg_directory_name.Append("oat"),
                            arc_paths_->android_data_old_directory);
    }
    LOG(INFO) << "Moving data/app/<package_name>/oat took "
              << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  }
}

ArcBinaryTranslationType ArcSetup::IdentifyBinaryTranslationType() {
  bool is_houdini_available = kUseHoudini || kUseHoudini64;
  bool is_ndk_translation_available = kUseNdkTranslation;

  if (!base::PathExists(arc_paths_->android_rootfs_directory.Append(
          "system/lib/libndk_translation.so"))) {
    // Allow developers to use custom android build
    // without ndk-translation in it.
    is_ndk_translation_available = false;
  }

  if (!is_houdini_available && !is_ndk_translation_available)
    return ArcBinaryTranslationType::NONE;

  const bool prefer_ndk_translation =
      (!is_houdini_available ||
       config_.GetBoolOrDie("NATIVE_BRIDGE_EXPERIMENT"));

  if (is_ndk_translation_available && prefer_ndk_translation)
    return ArcBinaryTranslationType::NDK_TRANSLATION;

  return ArcBinaryTranslationType::HOUDINI;
}

void ArcSetup::SetUpBinFmtMisc(ArcBinaryTranslationType bin_type) {
  const std::string system_arch = base::SysInfo::OperatingSystemArchitecture();
  if (system_arch != "x86_64")
    return;

  base::FilePath root_directory;

  switch (bin_type) {
    case ArcBinaryTranslationType::NONE: {
      // No binary translation at all, neither Houdini nor NDK translation.
      return;
    }
    case ArcBinaryTranslationType::HOUDINI: {
      root_directory = arc_paths_->android_rootfs_directory.Append("vendor");
      break;
    }
    case ArcBinaryTranslationType::NDK_TRANSLATION: {
      root_directory = arc_paths_->android_rootfs_directory.Append("system");
      break;
    }
  }

  EXIT_IF(!RegisterAllBinFmtMiscEntries(
      arc_mounter_.get(), root_directory.Append("etc/binfmt_misc"),
      arc_paths_->binfmt_misc_directory));
}

void ArcSetup::SetUpAndroidData(const base::FilePath& bind_target) {
  mode_t android_data_mode = 0700;
  gid_t android_data_gid = kRootGid;
  if (USE_ARCVM) {
    // When ARCVM is enabled on the board, allow vm_concierge to access the
    // directory. Note that vm_concierge runs as ugid crosvm in minijail.
    uid_t dummy_uid;
    EXIT_IF(!GetUserId("crosvm", &dummy_uid, &android_data_gid));
    android_data_mode = 0750;
  }
  EXIT_IF(!InstallDirectory(android_data_mode, kRootUid, android_data_gid,
                            arc_paths_->android_data_directory));

  // match android/system/core/rootdir/init.rc
  EXIT_IF(!InstallDirectory(0771, kSystemUid, kSystemGid,
                            arc_paths_->android_data_directory.Append("data")));

  if (USE_ARCVM) {
    // For ARCVM, create /data/media too since crosvm exports the directory via
    // virtio-fs.
    const base::FilePath android_data_media_directory =
        arc_paths_->android_data_directory.Append("data").Append("media");
    EXIT_IF(!InstallDirectory(0770, kMediaUid, kMediaGid,
                              android_data_media_directory));

    // Set up /data/media/0/Download with a strict permission so that users
    // cannot modify the directory before it is covered by Chrome OS Downloads.
    const base::FilePath android_data_media_root_for_user =
        android_data_media_directory.Append("0");
    const base::FilePath android_download_directory =
        android_data_media_root_for_user.Append("Download");
    EXIT_IF(!InstallDirectory(0770, kMediaUid, kMediaGid,
                              android_data_media_root_for_user));
    EXIT_IF(!InstallDirectory(0700, kRootUid, kRootGid,
                              android_download_directory));

    // Restore the contexts of /data/media directories. This is needed to ensure
    // Android's vold can mount Chrome OS Downloads on /data/media/0/Download.
    constexpr char kDataMediaSELinuxContext[] =
        "u:object_r:media_rw_data_file:s0";
    EXIT_IF(!Chcon(kDataMediaSELinuxContext, android_data_media_directory));
    EXIT_IF(!Chcon(kDataMediaSELinuxContext, android_data_media_root_for_user));
    EXIT_IF(!Chcon(kDataMediaSELinuxContext, android_download_directory));
  }

  // To make our bind-mount business easier, we first bind-mount the real
  // android-data directory to bind_target (usually $ANDROID_MUTABLE_SOURCE).
  // Then we do not need to pass the android-data path to other processes.
  EXIT_IF(!arc_mounter_->BindMount(arc_paths_->android_data_directory,
                                   bind_target));
}

void ArcSetup::UnmountSdcard() {
  // We unmount here in both the ESDFS and the FUSE cases in order to
  // clean up after Android's /system/bin/sdcard. However, the paths
  // must be the same in both cases.
  for (const auto& mount : GetEsdfsMounts(GetSdkVersion())) {
    base::FilePath kDestDirectory =
        arc_paths_->sdcard_mount_directory.Append(mount.relative_path);
    IGNORE_ERRORS(arc_mounter_->Umount(kDestDirectory));
  }

  LOG(INFO) << "Unmount sdcard complete.";
}

void ArcSetup::CreateContainerFilesAndDirectories() {
  // Create the FIFO file and start its reader job.
  RemoveAndroidKmsgFifo();
  EXIT_IF(mkfifo(arc_paths_->android_kmsg_fifo.value().c_str(), 0644) < 0);
  {
    base::ScopedFD fd =
        brillo::OpenFifoSafely(arc_paths_->android_kmsg_fifo, O_RDONLY, 0);
    EXIT_IF(!fd.is_valid());
    EXIT_IF(fchown(fd.get(), kRootUid, kRootGid) < 0);
  }
  EXIT_IF(!LaunchAndWait(
      {"/sbin/initctl", "start", "--no-wait", "arc-kmsg-logger"}));
}

void ArcSetup::ApplyPerBoardConfigurations() {
  EXIT_IF(!brillo::MkdirRecursively(
               arc_paths_->oem_mount_directory.Append("etc"), 0755)
               .is_valid());

  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->oem_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               "mode=0755"));
  EXIT_IF(!brillo::MkdirRecursively(
               arc_paths_->oem_mount_directory.Append("etc/permissions"), 0755)
               .is_valid());

  ApplyPerBoardConfigurationsInternal(arc_paths_->oem_mount_directory);
}

void ArcSetup::ApplyPerBoardConfigurationsInternal(
    const base::FilePath& oem_mount_directory) {
  auto config = std::make_unique<brillo::CrosConfig>();

  base::FilePath media_profile_xml =
      base::FilePath(arc_paths_->camera_profile_dir)
          .Append(arc_paths_->media_profile_file);

  std::string media_profile_setting;
  if (auto media_profile_setting =
          GetConfigPath(*config, kMediaProfilesSetting)) {
    media_profile_xml = *media_profile_setting;
  } else {
    // TODO(chromium:1083652) Remove dynamic shell scripts once all overlays
    // are migrated to static XML config.
    const base::FilePath generate_camera_profile(
        "/usr/bin/generate_camera_profile");
    if (base::PathExists(generate_camera_profile))
      EXIT_IF(!LaunchAndWait({generate_camera_profile.value()}));
  }

  if (base::PathExists(media_profile_xml)) {
    std::optional<std::string> content =
        FilterMediaProfile(media_profile_xml, arc_paths_->camera_test_config);
    EXIT_IF(!content);

    if (content->size() > 0) {
      const base::FilePath new_media_profile_xml =
          base::FilePath(oem_mount_directory)
              .Append("etc")
              .Append(arc_paths_->media_profile_file);
      brillo::SafeFD dest_parent(
          brillo::SafeFD::Root()
              .first.OpenExistingDir(new_media_profile_xml.DirName())
              .first);
      (void)dest_parent.Unlink(new_media_profile_xml.BaseName().value());
      brillo::SafeFD dest_fd(dest_parent
                                 .MakeFile(new_media_profile_xml.BaseName(),
                                           0644 /*permissions*/,
                                           kHostArcCameraUid, kHostArcCameraGid)
                                 .first);
      EXIT_IF(!base::WriteFileDescriptor(dest_fd.get(), *content));
    }
  }
  base::FilePath hardware_features_xml =
      GetConfigPath(*config, kHardwareFeaturesSetting)
          .value_or(base::FilePath("/etc/hardware_features.xml"));
  if (!base::PathExists(hardware_features_xml))
    return;

  const base::FilePath platform_xml_file =
      base::FilePath(oem_mount_directory)
          .Append(arc_paths_->platform_xml_file_relative);

  segmentation::FeatureManagement feature_management;
  std::optional<std::string> content =
      AppendFeatureManagement(hardware_features_xml, feature_management);
  EXIT_IF(!content);

  brillo::SafeFD dest_parent(
      brillo::SafeFD::Root()
          .first.OpenExistingDir(platform_xml_file.DirName())
          .first);
  (void)dest_parent.Unlink(platform_xml_file.BaseName().value());
  brillo::SafeFD dest_fd(dest_parent
                             .MakeFile(platform_xml_file.BaseName(),
                                       0644 /*permissions*/, kRootUid, kRootGid)
                             .first);
  EXIT_IF(!base::WriteFileDescriptor(dest_fd.get(), *content));

  // TODO(chromium:1083652) Remove dynamic shell scripts once all overlays
  // are migrated to static XML config.
  const base::FilePath board_hardware_features(
      "/usr/sbin/board_hardware_features");
  if (!base::PathExists(board_hardware_features))
    return;

  // The board_hardware_features is usually made by shell script and should
  // receive platform XML file argument in absolute path to avoid unexpected
  // environment issues.
  EXIT_IF(!LaunchAndWait(
      {board_hardware_features.value(), platform_xml_file.value()}));
}

void ArcSetup::SetUpSdcard() {
  constexpr unsigned int mount_flags =
      MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME;
  const base::FilePath source_directory =
      arc_paths_->android_mutable_source.Append("data/media");
  const base::FilePath host_downloads_directory =
      arc_paths_->user_directory.Append("MyFiles").Append("Downloads");

  // Get the container's user namespace file descriptor.
  const int container_pid = config_.GetIntOrDie("CONTAINER_PID");
  base::ScopedFD container_userns_fd(HANDLE_EINTR(
      open(base::StringPrintf("/proc/%d/ns/user", container_pid).c_str(),
           O_RDONLY)));

  const AndroidSdkVersion sdk_version = GetSdkVersion();
  // Installd setups up the user data directory skeleton on first-time boot.
  // Wait for setup
  EXIT_IF(
      !WaitForSdcardSource(arc_paths_->android_mutable_source, sdk_version));

  // Ensure the Downloads directory exists.
  EXIT_IF(!base::DirectoryExists(host_downloads_directory));

  for (const auto& mount : GetEsdfsMounts(sdk_version)) {
    base::FilePath dest_directory =
        arc_paths_->sdcard_mount_directory.Append(mount.relative_path);

    // Don't mount if the final destination path doesn't fall under
    // "/run/arc/sdcard" directory
    EXIT_IF(
        !base::FilePath("/run/arc/sdcard").IsParent(Realpath(dest_directory)));

    EXIT_IF(!arc_mounter_->Mount(
        source_directory.value(), dest_directory, "esdfs", mount_flags,
        CreateEsdfsMountOpts(kMediaUid, kMediaGid, mount.mode, kRootUid,
                             mount.gid, host_downloads_directory,
                             container_userns_fd.get())
            .c_str()));
  }

  LOG(INFO) << "Esdfs setup complete.";
}

void ArcSetup::SetUpSharedTmpfsForExternalStorage() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->sdcard_mount_directory));
  EXIT_IF(!base::DirectoryExists(arc_paths_->sdcard_mount_directory));
  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->sdcard_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               "mode=0755"));
  EXIT_IF(!arc_mounter_->SharedMount(arc_paths_->sdcard_mount_directory));
  EXIT_IF(
      !InstallDirectory(0755, kRootUid, kRootGid,
                        arc_paths_->sdcard_mount_directory.Append("default")));
  EXIT_IF(!InstallDirectory(0755, kRootUid, kRootGid,
                            arc_paths_->sdcard_mount_directory.Append("read")));
  EXIT_IF(
      !InstallDirectory(0755, kRootUid, kRootGid,
                        arc_paths_->sdcard_mount_directory.Append("write")));

  if (GetSdkVersion() > AndroidSdkVersion::ANDROID_P) {
    // For container R.
    EXIT_IF(
        !InstallDirectory(0755, kRootUid, kRootGid,
                          arc_paths_->sdcard_mount_directory.Append("full")));
  }

  // Create the mount directories. In original Android, these are created in
  // EmulatedVolume.cpp just before /system/bin/sdcard is fork()/exec()'ed.
  // Following code just emulates it. The directories are owned by Android's
  // root.
  // Note that, these creation should be conceptually done in arc-sdcard
  // container, but to keep it simpler, here create the directories instead.
  EXIT_IF(!InstallDirectory(
      0755, kRootUid, kRootGid,
      arc_paths_->sdcard_mount_directory.Append("default/emulated")));
  EXIT_IF(!InstallDirectory(
      0755, kRootUid, kRootGid,
      arc_paths_->sdcard_mount_directory.Append("read/emulated")));
  EXIT_IF(!InstallDirectory(
      0755, kRootUid, kRootGid,
      arc_paths_->sdcard_mount_directory.Append("write/emulated")));

  if (GetSdkVersion() > AndroidSdkVersion::ANDROID_P) {
    // For container R.
    EXIT_IF(!InstallDirectory(
        0755, kRootUid, kRootGid,
        arc_paths_->sdcard_mount_directory.Append("full/emulated")));
  }
}

void ArcSetup::SetUpFilesystemForObbMounter() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->obb_mount_directory));
  EXIT_IF(!brillo::MkdirRecursively(arc_paths_->obb_mount_directory, 0755)
               .is_valid());
  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->obb_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               "mode=0755"));
  EXIT_IF(!arc_mounter_->SharedMount(arc_paths_->obb_mount_directory));
}

bool ArcSetup::GenerateHostSideCodeInternal(
    const base::FilePath& host_dalvik_cache_directory,
    ArcCodeRelocationResult* result) {
  *result = ArcCodeRelocationResult::ERROR_UNABLE_TO_RELOCATE;
  std::unique_ptr<ArtContainer> art_container =
      ArtContainer::CreateContainer(arc_mounter_.get(), GetSdkVersion());
  if (!art_container) {
    LOG(ERROR) << "Failed to create art container";
    return false;
  }
  const std::string salt = GetOrCreateArcSalt();
  if (salt.empty()) {
    *result = ArcCodeRelocationResult::SALT_EMPTY;
    return false;
  }

  const uint64_t offset_seed = GetArtCompilationOffsetSeed(
      GetSystemBuildPropertyOrDie(kFingerprintProp), salt);
  if (!art_container->PatchImage(offset_seed)) {
    LOG(ERROR) << "Failed to relocate boot images";
    return false;
  }
  *result = ArcCodeRelocationResult::SUCCESS;
  return true;
}

bool ArcSetup::GenerateHostSideCode(
    const base::FilePath& host_dalvik_cache_directory) {
  ArcCodeRelocationResult result;
  base::ElapsedTimer timer;
  if (!GenerateHostSideCodeInternal(host_dalvik_cache_directory, &result)) {
    // If anything fails, delete code in cache.
    LOG(INFO) << "Failed to generate host-side code. Deleting existing code in "
              << host_dalvik_cache_directory.value();
    DeleteFilesInDir(host_dalvik_cache_directory);
  }
  base::TimeDelta time_delta = timer.Elapsed();
  LOG(INFO) << "GenerateHostSideCode took "
            << time_delta.InMillisecondsRoundedUp() << "ms";

  return result == ArcCodeRelocationResult::SUCCESS;
}

bool ArcSetup::InstallLinksToHostSideCodeInternal(
    const base::FilePath& src_isa_directory,
    const base::FilePath& dest_isa_directory,
    const std::string& isa) {
  bool src_file_exists = false;
  LOG(INFO) << "Adding symlinks to " << dest_isa_directory.value();

  // Do the same as maybeCreateDalvikCache() in
  // framework/base/cmds/app_process/app_main.cpp.
  EXIT_IF(!InstallDirectory(0711, kRootUid, kRootGid, dest_isa_directory));
  EXIT_IF(!Chcon(kDalvikCacheSELinuxContext, dest_isa_directory));

  base::FileEnumerator src_file_iter(
      src_isa_directory, false /* recursive */,
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS);
  for (auto src_file = src_file_iter.Next(); !src_file.empty();
       src_file = src_file_iter.Next()) {
    const base::FilePath base_name = src_file.BaseName();
    LOG(INFO) << "Processing " << base_name.value();

    base::FilePath link_target;
    if (S_ISLNK(src_file_iter.GetInfo().stat().st_mode)) {
      // *boot*.oat files in |src_isa_directory| are links to /system. Create a
      // link to /system.
      EXIT_IF(!base::ReadSymbolicLink(src_file, &link_target));
    } else {
      // Create a link to a host-side *boot*.art file.
      link_target =
          arc_paths_->host_side_dalvik_cache_directory_in_container.Append(isa)
              .Append(base_name);
    }

    const base::FilePath dest_file = dest_isa_directory.Append(base_name);
    // Remove |dest_file| first when it exists. When |dest_file| is a symlink,
    // this deletes the link itself.
    IGNORE_ERRORS(brillo::DeleteFile(dest_file));
    EXIT_IF(!base::CreateSymbolicLink(link_target, dest_file));
    EXIT_IF(lchown(dest_file.value().c_str(), kRootUid, kRootGid) != 0);
    EXIT_IF(!Chcon(kDalvikCacheSELinuxContext, dest_file));

    LOG(INFO) << "Created a link to " << link_target.value();
    src_file_exists = true;
  }

  return src_file_exists;
}

void ArcSetup::InstallLinksToHostSideCode() {
  base::ElapsedTimer timer;
  const base::FilePath& src_directory = arc_paths_->art_dalvik_cache_directory;
  const base::FilePath dest_directory =
      arc_paths_->android_data_directory.Append("data/dalvik-cache");

  EXIT_IF(!InstallDirectory(0771, kRootUid, kRootGid, dest_directory));
  EXIT_IF(!Chcon(kDalvikCacheSELinuxContext, dest_directory));

  // Iterate through each isa sub directory. For example, dalvik-cache/x86 and
  // dalvik-cache/x86_64
  base::FileEnumerator src_directory_iter(src_directory, false,
                                          base::FileEnumerator::DIRECTORIES);
  for (auto src_isa_directory = src_directory_iter.Next();
       !src_isa_directory.empty();
       src_isa_directory = src_directory_iter.Next()) {
    if (IsDirectoryEmpty(src_isa_directory))
      continue;
    const std::string isa = src_isa_directory.BaseName().value();
    if (!InstallLinksToHostSideCodeInternal(src_isa_directory,
                                            dest_directory.Append(isa), isa)) {
      LOG(ERROR) << "InstallLinksToHostSideCodeInternal() for " << isa
                 << " failed. "
                 << "Deleting container's /data/dalvik-cache...";
      DeleteExecutableFilesInData(true, /* delete dalvik cache */
                                  false /* delete data app executables */);
      break;
    }
  }

  LOG(INFO) << "InstallLinksToHostSideCode() took "
            << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
}

void ArcSetup::CreateAndroidCmdlineFile(bool is_dev_mode) {
  const bool is_inside_vm = config_.GetBoolOrDie("CHROMEOS_INSIDE_VM");

  const bool disable_media_store_maintenance =
      config_.GetBoolOrDie("DISABLE_MEDIA_STORE_MAINTENANCE");
  const bool disable_download_provider =
      config_.GetBoolOrDie("DISABLE_DOWNLOAD_PROVIDER");

  // The host-side dalvik-cache directory is mounted into the container
  // via the json file. Create it regardless of whether the code integrity
  // feature is enabled.
  EXIT_IF(
      !CreateArtContainerDataDirectory(arc_paths_->art_dalvik_cache_directory));

  // Mount host-compiled and host-verified .art and .oat files. The container
  // will see these files, but other than that, the /data and /cache
  // directories are empty and read-only which is the best for security.

  if (GetSdkVersion() == AndroidSdkVersion::ANDROID_P) {
    // Unconditionally generate host-side code here for P.
    EXIT_IF(!GenerateHostSideCode(arc_paths_->art_dalvik_cache_directory));
  } else {
    LOG(INFO) << "Skip generation of host-side code for versions higher than P";
  }
  EXIT_IF(!Chown(kRootUid, kRootGid, arc_paths_->art_dalvik_cache_directory));
  // Remove the file zygote may have created.
  IGNORE_ERRORS(brillo::DeleteFile(
      arc_paths_->art_dalvik_cache_directory.Append(kZygotePreloadDoneFile)));

  // Make sure directories for all ISA are there just to make config.json happy.
  for (const auto* isa : {"arm", "arm64", "x86", "x86_64"}) {
    EXIT_IF(!brillo::MkdirRecursively(
                 arc_paths_->art_dalvik_cache_directory.Append(isa), 0755)
                 .is_valid());
  }

  PlayStoreAutoUpdate play_store_auto_update;
  std::string dalvik_memory_profile;

  bool play_store_auto_update_on;
  // PLAY_AUTO_UPDATE forces Play Store auto-update feature to on or off. If not
  // set, its state is left unchanged.
  if (config_.GetBool("PLAY_STORE_AUTO_UPDATE", &play_store_auto_update_on)) {
    play_store_auto_update = play_store_auto_update_on
                                 ? PlayStoreAutoUpdate::kOn
                                 : PlayStoreAutoUpdate::kOff;
  } else {
    play_store_auto_update = PlayStoreAutoUpdate::kDefault;
  }

  config_.GetString("DALVIK_MEMORY_PROFILE", &dalvik_memory_profile);

  const base::FilePath lsb_release_file_path("/etc/lsb-release");
  LOG(INFO) << "Developer mode is " << is_dev_mode;
  LOG(INFO) << "Inside VM is " << is_inside_vm;
  const std::string chromeos_channel =
      GetChromeOsChannelFromFile(lsb_release_file_path);
  LOG(INFO) << "ChromeOS channel is \"" << chromeos_channel << "\"";
  const int arc_lcd_density = config_.GetIntOrDie("ARC_LCD_DENSITY");
  LOG(INFO) << "lcd_density is " << arc_lcd_density;
  const int arc_file_picker = config_.GetIntOrDie("ARC_FILE_PICKER_EXPERIMENT");
  LOG(INFO) << "arc_file_picker is " << arc_file_picker;
  const int arc_custom_tabs = config_.GetIntOrDie("ARC_CUSTOM_TABS_EXPERIMENT");
  LOG(INFO) << "arc_custom_tabs is " << arc_custom_tabs;
  LOG(INFO) << "MediaStore maintenance is " << !disable_media_store_maintenance;

  bool arc_generate_pai;
  if (!config_.GetBool("ARC_GENERATE_PAI", &arc_generate_pai))
    arc_generate_pai = false;
  LOG(INFO) << "arc_generate_pai is " << arc_generate_pai;

  const int enable_notifications_refresh =
      config_.GetIntOrDie("ENABLE_NOTIFICATIONS_REFRESH");
  LOG(INFO) << "enable_notifications_refresh is "
            << enable_notifications_refresh;

  const int enable_tts_caching = config_.GetIntOrDie("ENABLE_TTS_CACHING");
  LOG(INFO) << "enable_tts_caching is " << enable_tts_caching;

  const int host_ureadahead_generation =
      config_.GetBoolOrDie("HOST_UREADAHEAD_GENERATION");
  LOG(INFO) << "host_ureadahead_generation is " << host_ureadahead_generation;

  const int enable_consumer_auto_update_toggle =
      config_.GetIntOrDie("ENABLE_CONSUMER_AUTO_UPDATE_TOGGLE");
  LOG(INFO) << "consumer_auto_update_toggle is "
            << enable_consumer_auto_update_toggle;

  const int enable_privacy_hub_for_chrome =
      config_.GetIntOrDie("ENABLE_PRIVACY_HUB_FOR_CHROME");
  LOG(INFO) << "enable_privacy_hub_for_chrome is "
            << enable_privacy_hub_for_chrome;

  std::string native_bridge;
  switch (IdentifyBinaryTranslationType()) {
    case ArcBinaryTranslationType::NONE:
      native_bridge = "0";
      break;
    case ArcBinaryTranslationType::HOUDINI:
      native_bridge = "libhoudini.so";
      break;
    case ArcBinaryTranslationType::NDK_TRANSLATION:
      native_bridge = "libndk_translation.so";
      break;
  }
  LOG(INFO) << "native_bridge is \"" << native_bridge << "\"";
  LOG(INFO) << "dalvik memory profile is \""
            << (dalvik_memory_profile.empty() ? "default"
                                              : dalvik_memory_profile)
            << "\"";

  // Get the CLOCK_BOOTTIME offset and send it to the container as the at which
  // the container "booted". Given that there is no way to namespace time in
  // Linux, we need to communicate this in a userspace-only way.
  //
  // For the time being, the only component that uses this is bootstat. It uses
  // it to timeshift all readings from CLOCK_BOOTTIME and be able to more
  // accurately report the time against "Android boot".
  struct timespec ts;
  EXIT_IF(clock_gettime(CLOCK_BOOTTIME, &ts) != 0);

  // Note that we are intentionally not setting the ro.kernel.qemu property
  // since that is tied to running the Android emulator, which has a few key
  // differences:
  // * It assumes that ADB is connected through the qemu pipe, which is not
  //   true in Chrome OS' case.
  // * It controls whether the emulated GLES implementation should be used
  //   (but can be overriden by setting ro.kernel.qemu.gles to -1).
  // * It disables a bunch of pixel formats and uses only RGB565.
  // * It disables Bluetooth (which we might do regardless).
  const std::string content = base::StringPrintf(
      "androidboot.hardware=cheets "
      "androidboot.container=1 "
      "androidboot.dev_mode=%d "
      "androidboot.disable_runas=%d "
      "androidboot.host_is_in_vm=%d "
      "androidboot.lcd_density=%d "
      "androidboot.native_bridge=%s "
      "androidboot.arc_file_picker=%d "
      "androidboot.arc_custom_tabs=%d "
      "androidboot.chromeos_channel=%s "
      "%s" /* Play Store auto-update mode */
      "%s" /* Dalvik memory profile */
      "%s" /* Disable MediaStore maintenance */
      "%s" /* Disable download provider */
      "%s" /* PAI Generation */
      "androidboot.boottime_offset=%" PRId64
      " " /* in nanoseconds */
      "androidboot.enable_notifications_refresh=%d "
      "androidboot.arc.tts.caching=%d "
      "androidboot.enable_consumer_auto_update_toggle=%d "
      "androidboot.arc.ureadahead_generation=%d "
      "androidboot.enable_privacy_hub_for_chrome=%d\n",
      is_dev_mode, !is_dev_mode, is_inside_vm, arc_lcd_density,
      native_bridge.c_str(), arc_file_picker, arc_custom_tabs,
      chromeos_channel.c_str(),
      GetPlayStoreAutoUpdateParam(play_store_auto_update).c_str(),
      GetDalvikMemoryProfileParam(dalvik_memory_profile).c_str(),
      GetDisableMediaStoreMaintenance(disable_media_store_maintenance).c_str(),
      GetDisableDownloadProvider(disable_download_provider).c_str(),
      GetGeneratePaiParam(arc_generate_pai).c_str(),
      ts.tv_sec * base::Time::kNanosecondsPerSecond + ts.tv_nsec,
      enable_notifications_refresh, enable_tts_caching,
      enable_consumer_auto_update_toggle, host_ureadahead_generation,
      enable_privacy_hub_for_chrome);

  EXIT_IF(!WriteToFile(arc_paths_->android_cmdline, 0644, content));
}

void ArcSetup::CreateFakeProcfsFiles() {
  // Android attempts to modify these files in procfs during init
  // Since these files on the host side require root permissions to modify (real
  // root, not android-root), we need to present fake versions to Android.
  constexpr char kProcSecurityContext[] = "u:object_r:proc_security:s0";

  EXIT_IF(!WriteToFile(arc_paths_->fake_kptr_restrict, 0644, "2\n"));
  EXIT_IF(!Chown(kRootUid, kRootGid, arc_paths_->fake_kptr_restrict));
  EXIT_IF(!Chcon(kProcSecurityContext, arc_paths_->fake_kptr_restrict));

  EXIT_IF(!WriteToFile(arc_paths_->fake_mmap_rnd_bits, 0644, "32\n"));
  EXIT_IF(!Chown(kRootUid, kRootGid, arc_paths_->fake_mmap_rnd_bits));
  EXIT_IF(!Chcon(kProcSecurityContext, arc_paths_->fake_mmap_rnd_bits));

  EXIT_IF(!WriteToFile(arc_paths_->fake_mmap_rnd_compat_bits, 0644, "16\n"));
  EXIT_IF(!Chown(kRootUid, kRootGid, arc_paths_->fake_mmap_rnd_compat_bits));
  EXIT_IF(!Chcon(kProcSecurityContext, arc_paths_->fake_mmap_rnd_compat_bits));
}

void ArcSetup::SetUpMountPointForDebugFilesystem(bool is_dev_mode) {
  const base::FilePath sync_mount_directory =
      arc_paths_->debugfs_directory.Append("sync");

  EXIT_IF(!InstallDirectory(0755, kHostRootUid, kHostRootGid,
                            arc_paths_->debugfs_directory));

  // debug/sync does not exist on all kernels
  EXIT_IF(!arc_mounter_->UmountIfExists(sync_mount_directory));

  EXIT_IF(
      !InstallDirectory(0755, kSystemUid, kSystemGid, sync_mount_directory));

  const base::FilePath sync_directory("/sys/kernel/debug/sync");

  if (base::DirectoryExists(sync_directory)) {
    EXIT_IF(!Chown(kSystemUid, kSystemGid, sync_directory));
    EXIT_IF(!Chown(kSystemUid, kSystemGid, sync_directory.Append("info")));
    // Kernel change that introduces sw_sync is follows sync/info
    if (base::PathExists(sync_directory.Append("sw_sync")))
      EXIT_IF(!Chown(kSystemUid, kSystemGid, sync_directory.Append("sw_sync")));

    EXIT_IF(!arc_mounter_->BindMount(sync_directory, sync_mount_directory));
  }

  const base::FilePath tracing_mount_directory =
      arc_paths_->debugfs_directory.Append("tracing");

  EXIT_IF(!arc_mounter_->UmountIfExists(tracing_mount_directory));
  EXIT_IF(!InstallDirectory(0755, kHostRootUid, kHostRootGid,
                            tracing_mount_directory));

  if (!is_dev_mode)
    return;

  const base::FilePath tracing_directory("/sys/kernel/tracing");
  EXIT_IF(!arc_mounter_->BindMount(tracing_directory, tracing_mount_directory));
}

void ArcSetup::MountDemoApps(const base::FilePath& demo_apps_image,
                             const base::FilePath& demo_apps_mount_directory) {
  // Verify that the demo apps image is under an imageloader mount point.
  EXIT_IF(demo_apps_image.ReferencesParent());
  EXIT_IF(!base::FilePath("/run/imageloader").IsParent(demo_apps_image));

  // Create the target mount point directory.
  EXIT_IF(!InstallDirectory(0700, kHostRootUid, kHostRootGid,
                            demo_apps_mount_directory));

  // imageloader securely verifies images before mounting them, so we can trust
  // the provided image and can mount it without MS_NOEXEC.
  EXIT_IF(!arc_mounter_->LoopMount(demo_apps_image.value(),
                                   demo_apps_mount_directory,
                                   MS_RDONLY | MS_NODEV));
}

void ArcSetup::SetUpMountPointsForMedia() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->media_mount_directory));
  EXIT_IF(!InstallDirectory(0755, kRootUid, kSystemGid,
                            arc_paths_->media_mount_directory));

  const std::string media_mount_options =
      base::StringPrintf("mode=0755,uid=%u,gid=%u", kRootUid, kSystemGid);
  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->media_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               media_mount_options.c_str()));
  EXIT_IF(!arc_mounter_->SharedMount(arc_paths_->media_mount_directory));
  for (auto* directory :
       {"removable", "removable-default", "removable-read", "removable-write",
        "MyFiles", "MyFiles-default", "MyFiles-read", "MyFiles-write"}) {
    EXIT_IF(
        !InstallDirectory(0755, kMediaUid, kMediaGid,
                          arc_paths_->media_mount_directory.Append(directory)));
  }
}

void ArcSetup::SetUpMountPointForAdbd() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->adbd_mount_directory));
  EXIT_IF(!InstallDirectory(0770, kShellUid, kShellGid,
                            arc_paths_->adbd_mount_directory));

  const std::string adbd_mount_options =
      base::StringPrintf("mode=0770,uid=%u,gid=%u", kShellUid, kShellGid);
  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->adbd_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               adbd_mount_options.c_str()));
  EXIT_IF(!arc_mounter_->SharedMount(arc_paths_->adbd_mount_directory));
}

// Setup mount point for ADB over Unix sockets. This is used to enforce
// permission of the Unix sockets through SELinux. The mount is needed for
// ARC++ container whenever ADB debugging is enabled.
void ArcSetup::SetUpMountPointForAdbdUnixSocket() {
  EXIT_IF(!arc_mounter_->UmountIfExists(
      arc_paths_->adbd_unix_socket_mount_directory));
  EXIT_IF(!InstallDirectory(0775, kShellUid, kShellGid,
                            arc_paths_->adbd_unix_socket_mount_directory));
  const std::string adbd_unix_socket_mount_options =
      base::StringPrintf("mode=0775,uid=%u,gid=%u", kShellUid, kShellGid);
  EXIT_IF(!arc_mounter_->Mount("tmpfs",
                               arc_paths_->adbd_unix_socket_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               adbd_unix_socket_mount_options.c_str()));
  EXIT_IF(
      !arc_mounter_->SharedMount(arc_paths_->adbd_unix_socket_mount_directory));
}

void ArcSetup::CleanUpStaleMountPoints() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_directory));
  EXIT_IF(!arc_mounter_->UmountIfExists(
      arc_paths_->media_myfiles_default_directory));
  EXIT_IF(
      !arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_read_directory));
  EXIT_IF(
      !arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_write_directory));
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->media_removable_directory));
  EXIT_IF(!arc_mounter_->UmountIfExists(
      arc_paths_->media_removable_default_directory));
  EXIT_IF(!arc_mounter_->UmountIfExists(
      arc_paths_->media_removable_read_directory));
  EXIT_IF(!arc_mounter_->UmountIfExists(
      arc_paths_->media_removable_write_directory));
  // If the android_mutable_source path cannot be unmounted below continue
  // anyway. This allows the mini-container to start and allows tests to
  // exercise the mini-container (b/148185982).
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->android_mutable_source));
}

void ArcSetup::SetUpSharedMountPoints() {
  EXIT_IF(!arc_mounter_->UmountIfExists(arc_paths_->shared_mount_directory));
  EXIT_IF(!InstallDirectory(0755, kRootUid, kRootGid,
                            arc_paths_->shared_mount_directory));
  // Use 0755 to make sure only the real root user can write to the shared
  // mount point.
  EXIT_IF(!arc_mounter_->Mount("tmpfs", arc_paths_->shared_mount_directory,
                               "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                               "mode=0755"));
  EXIT_IF(!arc_mounter_->SharedMount(arc_paths_->shared_mount_directory));
}

void ArcSetup::SetUpOwnershipForSdcardConfigfs() {
  // Make sure <configfs>/sdcardfs/ and <configfs>/sdcardfs/extensions} are
  // owned by android-root.
  const base::FilePath extensions_dir =
      arc_paths_->sdcard_configfs_directory.Append("extensions");
  if (base::PathExists(extensions_dir)) {
    EXIT_IF(!Chown(kRootUid, kRootGid, arc_paths_->sdcard_configfs_directory));
    EXIT_IF(!Chown(kRootUid, kRootGid, extensions_dir));
  }
}

void ArcSetup::RestoreContext() {
  std::vector<base::FilePath> directories = {
      // Restore the label for the file now since this is the only place to do
      // so.
      // The file is bind-mounted in the container as /proc/cmdline, but unlike
      // /run/arc and /run/camera, the file cannot have the "mount_outside"
      // option
      // because /proc for the container is always mounted inside the container,
      // and cmdline file has to be mounted on top of that.
      arc_paths_->android_cmdline,

      arc_paths_->debugfs_directory,      arc_paths_->obb_mount_directory,
      arc_paths_->sdcard_mount_directory, arc_paths_->sysfs_cpu,
      arc_paths_->sysfs_tracing,
  };
  if (base::DirectoryExists(arc_paths_->restorecon_allowlist_sync))
    directories.push_back(arc_paths_->restorecon_allowlist_sync);
  // usbfs does not exist on test VMs without any USB emulation, skip it there.
  if (base::DirectoryExists(arc_paths_->usb_devices_directory))
    directories.push_back(arc_paths_->usb_devices_directory);

  EXIT_IF(!RestoreconRecursively(directories));
}

void ArcSetup::SetUpGraphicsSysfsContext() {
  const base::FilePath sysfs_drm_path("/sys/class/drm");
  const std::string sysfs_drm_context("u:object_r:gpu_device:s0");
  const std::string render_node_pattern("renderD*");
  const std::vector<std::string> attrs{
      "uevent",           "config",           "vendor", "device",
      "subsystem_vendor", "subsystem_device", "drm"};

  base::FileEnumerator drm_directory(
      sysfs_drm_path, false,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS,
      render_node_pattern);

  for (auto dev = drm_directory.Next(); !dev.empty();
       dev = drm_directory.Next()) {
    auto device = Realpath(dev.Append("device"));
    // If it's virtio gpu, actually the PCI device
    // directory should be the parent directory.
    if (device.BaseName().value().find("virtio") == 0)
      device = device.DirName();
    for (const auto& attr : attrs) {
      auto attr_path = device.Append(attr);
      if (base::PathExists(attr_path))
        EXIT_IF(!Chcon(sysfs_drm_context, Realpath(attr_path)));
    }
  }
}

void ArcSetup::SetUpPowerSysfsContext() {
  const base::FilePath sysfs_power_supply_path("/sys/class/power_supply");
  const std::string sysfs_batteryinfo_context(
      "u:object_r:sysfs_batteryinfo:s0");

  base::FileEnumerator power_supply_dir(
      sysfs_power_supply_path, false /* recursive */,
      base::FileEnumerator::FileType::DIRECTORIES);

  for (auto power_supply = power_supply_dir.Next(); !power_supply.empty();
       power_supply = power_supply_dir.Next()) {
    base::FileEnumerator power_supply_attrs(
        power_supply, false /* recursive */,
        base::FileEnumerator::FileType::FILES);

    for (auto attr = power_supply_attrs.Next(); !attr.empty();
         attr = power_supply_attrs.Next()) {
      EXIT_IF(!Chcon(sysfs_batteryinfo_context, Realpath(attr)));
    }
  }
}

void ArcSetup::MakeMountPointsReadOnly() {
  // NOLINTNEXTLINE(runtime/int)
  constexpr unsigned long remount_flags =
      MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;
  constexpr char kMountOptions[] = "seclabel,mode=0755";

  const std::string media_mount_options =
      base::StringPrintf("mode=0755,uid=%u,gid=%u", kRootUid, kSystemGid);

  // Make these mount points readonly so that Android container cannot modify
  // files/directories inside these filesystem. Android container cannot remove
  // the readonly flag because it is run in user namespace.
  // These directories are also bind-mounted as read-write into either the
  // SDCARD or arc-obb-mounter container, which runs outside of the user
  // namespace so that such a daemon can modify files/directories inside the
  // filesystem (See also arc-sdcard.conf and arc-obb-mounter.conf).
  EXIT_IF(!arc_mounter_->Remount(arc_paths_->sdcard_mount_directory,
                                 remount_flags, kMountOptions));
  EXIT_IF(!arc_mounter_->Remount(arc_paths_->obb_mount_directory, remount_flags,
                                 kMountOptions));
  EXIT_IF(!arc_mounter_->Remount(arc_paths_->media_mount_directory,
                                 remount_flags, media_mount_options.c_str()));
}

void ArcSetup::SetUpCameraProperty(const base::FilePath& build_prop) {
  // Camera HAL V3 needs two properties from build.prop for picture taking.
  // Copy the information to /var/cache.
  const base::FilePath camera_prop_directory("/var/cache/camera");
  const base::FilePath camera_prop_file =
      base::FilePath(camera_prop_directory).Append("camera.prop");
  EXIT_IF(!brillo::MkdirRecursively(camera_prop_directory, 0755).is_valid());

  std::string content;
  EXIT_IF(!base::ReadFileToString(build_prop, &content));

  std::vector<std::string> properties = base::SplitString(
      content, "\n", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_ALL);
  const std::string kSystemManufacturer = "ro.product.system.manufacturer=";
  const std::string kManufacturer = "ro.product.manufacturer=";
  const std::string kSystemModel = "ro.product.system.model=";
  const std::string kModel = "ro.product.model=";
  std::string camera_properties;
  for (const auto& property : properties) {
    if (!property.compare(0, kManufacturer.length(), kManufacturer) ||
        !property.compare(0, kModel.length(), kModel)) {
      // For Android P.
      camera_properties += property + "\n";
    } else if (!property.compare(0, kSystemManufacturer.length(),
                                 kSystemManufacturer)) {
      // Android Q+ only has |kSystemManufacturer| in /system/build.prop, and
      // |kSystemManufacturer| is copied to |kManufacturer| at boot time. Do
      // the same here.
      camera_properties +=
          kManufacturer + property.substr(kSystemManufacturer.length()) + "\n";
    } else if (!property.compare(0, kSystemModel.length(), kSystemModel)) {
      // Do the same for |kSystemModel| for Android Q+.
      camera_properties +=
          kModel + property.substr(kSystemModel.length()) + "\n";
    }
  }
  EXIT_IF(!WriteToFile(camera_prop_file, 0644, camera_properties));
}

void ArcSetup::SetUpSharedApkDirectory() {
  EXIT_IF(!InstallDirectory(0700, kSystemUid, kSystemGid,
                            arc_paths_->apk_cache_dir));
}

void ArcSetup::CleanUpBinFmtMiscSetUp() {
  const std::string system_arch = base::SysInfo::OperatingSystemArchitecture();
  if (system_arch != "x86_64")
    return;
  std::unique_ptr<ScopedMount> binfmt_misc_mount =
      ScopedMount::CreateScopedMount(
          arc_mounter_.get(), "binfmt_misc", arc_paths_->binfmt_misc_directory,
          "binfmt_misc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
  // This function is for Mode::STOP. Ignore errors to make sure to run all
  // clean up code.
  if (!binfmt_misc_mount) {
    PLOG(INFO) << "Ignoring failure: Failed to mount binfmt_misc";
    return;
  }

  for (auto entry_name : kBinFmtMiscEntryNames) {
    UnregisterBinFmtMiscEntry(
        arc_paths_->binfmt_misc_directory.Append(entry_name));
  }
}

AndroidSdkVersion ArcSetup::SdkVersionFromString(
    const std::string& version_str) {
  const std::string version_codename_str =
      GetSystemBuildPropertyOrDie("ro.build.version.codename");
  if (version_codename_str != "REL") {
    LOG(INFO) << "Not a release version; classifying as Android Development.";
    return AndroidSdkVersion::ANDROID_DEVELOPMENT;
  }
  int version;
  if (base::StringToInt(version_str, &version)) {
    switch (version) {
      case 23:
        return AndroidSdkVersion::ANDROID_M;
      case 25:
        return AndroidSdkVersion::ANDROID_N_MR1;
      case 28:
        return AndroidSdkVersion::ANDROID_P;
      case 30:
        return AndroidSdkVersion::ANDROID_R;
      case 31:
        return AndroidSdkVersion::ANDROID_S;
      case 32:
        return AndroidSdkVersion::ANDROID_S_V2;
      case 33:
        return AndroidSdkVersion::ANDROID_TIRAMISU;
    }
  }

  LOG(ERROR) << "Unknown SDK version : " << version_str;
  return AndroidSdkVersion::UNKNOWN;
}

AndroidSdkVersion ArcSetup::GetSdkVersion() {
  const std::string version_str =
      GetSystemBuildPropertyOrDie("ro.build.version.sdk");
  LOG(INFO) << "SDK version string: " << version_str;

  const AndroidSdkVersion version = SdkVersionFromString(version_str);
  if (version == AndroidSdkVersion::UNKNOWN)
    LOG(FATAL) << "Unknown SDK version: " << version_str;
  return version;
}

void ArcSetup::UnmountOnStop() {
  // This function is for Mode::STOP. Use IGNORE_ERRORS to make sure to run all
  // clean up code.
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->shared_mount_directory.Append("cache")));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->shared_mount_directory.Append("data")));
  IGNORE_ERRORS(arc_mounter_->LoopUmountIfExists(
      arc_paths_->shared_mount_directory.Append("demo_apps")));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(arc_paths_->adbd_mount_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_directory));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->media_myfiles_default_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_read_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_myfiles_write_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_removable_directory));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->media_removable_default_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_removable_read_directory));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->media_removable_write_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->media_mount_directory));
  IGNORE_ERRORS(arc_mounter_->Umount(arc_paths_->sdcard_mount_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->shared_mount_directory));
  IGNORE_ERRORS(arc_mounter_->Umount(arc_paths_->obb_mount_directory));
  IGNORE_ERRORS(arc_mounter_->Umount(arc_paths_->oem_mount_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->android_mutable_source));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->debugfs_directory.Append("sync")));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(
      arc_paths_->debugfs_directory.Append("tracing")));
  // Clean up in case this was not unmounted.
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->binfmt_misc_directory));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->android_rootfs_directory.Append(
          arc_paths_->system_lib_arm_directory_relative)));
  IGNORE_ERRORS(
      arc_mounter_->UmountIfExists(arc_paths_->android_rootfs_directory.Append(
          arc_paths_->system_lib64_arm64_directory_relative)));
}

void ArcSetup::RemoveAndroidKmsgFifo() {
  // This function is for Mode::STOP. Use IGNORE_ERRORS to make sure to run all
  // clean up code.
  IGNORE_ERRORS(brillo::DeleteFile(arc_paths_->android_kmsg_fifo));
}

// Note: This function has to be in sync with Android's arc-boot-type-detector.
// arc-boot-type-detector's main() function is very similar to this.
void ArcSetup::GetBootTypeAndDataSdkVersion(
    ArcBootType* out_boot_type, AndroidSdkVersion* out_data_sdk_version) {
  const std::string system_fingerprint =
      GetSystemBuildPropertyOrDie(kFingerprintProp);

  // Note: The XML file name has to match com.android.server.pm.Settings's
  // mSettingsFilename. This will be very unlikely to change, but we still need
  // to be careful.
  const base::FilePath packages_xml =
      arc_paths_->android_data_directory.Append("data/system/packages.xml");

  if (!base::PathExists(packages_xml)) {
    // This path is taken when /data is empty, which is not an error.
    LOG(INFO) << packages_xml.value()
              << " does not exist. This is the very first boot aka opt-in.";
    *out_boot_type = ArcBootType::FIRST_BOOT;
    *out_data_sdk_version = AndroidSdkVersion::UNKNOWN;
    return;
  }

  // Get a fingerprint from /data/system/packages.xml.
  std::string data_fingerprint;
  std::string data_sdk_version;
  if (!GetFingerprintAndSdkVersionFromPackagesXml(
          packages_xml, &data_fingerprint, &data_sdk_version)) {
    LOG(ERROR) << "Failed to get a fingerprint from " << packages_xml.value();
    // Return kFirstBootAfterUpdate so the caller invalidates art/oat files
    // which is safer than returning kRegularBoot.
    *out_boot_type = ArcBootType::FIRST_BOOT_AFTER_UPDATE;
    *out_data_sdk_version = AndroidSdkVersion::UNKNOWN;
    return;
  }

  // If two fingerprints don't match, this is the first boot after OTA.
  // Android's PackageManagerService.isUpgrade(), at least on M, N, and
  // O releases, does exactly the same to detect OTA.
  const bool ota_detected = system_fingerprint != data_fingerprint;
  if (!ota_detected) {
    LOG(INFO) << "This is regular boot.";
  } else {
    LOG(INFO) << "This is the first boot after OTA: system="
              << system_fingerprint << ", data=" << data_fingerprint;
  }
  LOG(INFO) << "Data SDK version: " << data_sdk_version;
  LOG(INFO) << "System SDK version: " << static_cast<int>(GetSdkVersion());
  *out_boot_type = ota_detected ? ArcBootType::FIRST_BOOT_AFTER_UPDATE
                                : ArcBootType::REGULAR_BOOT;
  *out_data_sdk_version = SdkVersionFromString(data_sdk_version);
}

void ArcSetup::ShouldDeleteDataExecutables(
    ArcBootType boot_type,
    bool* out_should_delete_data_dalvik_cache_directory,
    bool* out_should_delete_data_app_executables) {
  if (boot_type == ArcBootType::FIRST_BOOT_AFTER_UPDATE) {
    // Delete /data/dalvik-cache and /data/app/<package_name>/oat before the
    // container starts since this is the first boot after OTA.
    *out_should_delete_data_dalvik_cache_directory = true;
    *out_should_delete_data_app_executables = true;
    return;
  }
  // Otherwise, clear neither /data/dalvik-cache nor /data/app/*/oat.
  *out_should_delete_data_dalvik_cache_directory = false;
  *out_should_delete_data_app_executables = false;
}

std::string ArcSetup::GetSerialNumber() {
  const std::string chromeos_user = config_.GetStringOrDie("CHROMEOS_USER");
  const std::string salt = GetOrCreateArcSalt();
  EXIT_IF(salt.empty());  // at this point, the salt file should always exist.
  return arc::GenerateFakeSerialNumber(chromeos_user, salt);
}

void ArcSetup::MountSharedAndroidDirectories() {
  const base::FilePath cache_directory =
      arc_paths_->android_data_directory.Append("cache");
  const base::FilePath data_directory =
      arc_paths_->android_data_directory.Append("data");

  const base::FilePath shared_cache_directory =
      arc_paths_->shared_mount_directory.Append("cache");
  const base::FilePath shared_data_directory =
      arc_paths_->shared_mount_directory.Append("data");

  if (!base::PathExists(shared_data_directory)) {
    EXIT_IF(!InstallDirectory(0700, kHostRootUid, kHostRootGid,
                              shared_data_directory));
  }

  // First, make the original data directory a mount point and also make it
  // executable. This has to be done *before* passing the directory into
  // the shared mount point because the new flags won't be propagated if the
  // mount point has already been shared with the MS_SLAVE one.
  EXIT_IF(!arc_mounter_->BindMount(data_directory, data_directory));

  // TODO(b/213625515): Investigate if this mount can be made
  // NO_EXEC, and if we can mount /data directory from inside the
  // container as EXEC.
  EXIT_IF(
      !arc_mounter_->Remount(data_directory, MS_NOSUID | MS_NODEV, "seclabel"));

  // Finally, bind-mount /data to the shared mount point.
  EXIT_IF(!arc_mounter_->Mount(data_directory.value(), shared_data_directory,
                               nullptr, MS_BIND, nullptr));
  // Remount the mount point of original data directory as non-executable.
  EXIT_IF(!arc_mounter_->Remount(data_directory,
                                 MS_NOSUID | MS_NODEV | MS_NOEXEC, "seclabel"));
  // Remount the mount point of shared data directory as non-executable.
  EXIT_IF(!arc_mounter_->Remount(shared_data_directory,
                                 MS_NOSUID | MS_NODEV | MS_NOEXEC, "seclabel"));

  const std::string demo_session_apps =
      config_.GetStringOrDie("DEMO_SESSION_APPS_PATH");
  if (!demo_session_apps.empty()) {
    MountDemoApps(base::FilePath(demo_session_apps),
                  arc_paths_->shared_mount_directory.Append("demo_apps"));
  }
}

void ArcSetup::UnmountSharedAndroidDirectories() {
  const base::FilePath data_directory =
      arc_paths_->android_data_directory.Append("data");
  const base::FilePath shared_cache_directory =
      arc_paths_->shared_mount_directory.Append("cache");
  const base::FilePath shared_data_directory =
      arc_paths_->shared_mount_directory.Append("data");
  const base::FilePath shared_demo_apps_directory =
      arc_paths_->shared_mount_directory.Append("demo_apps");

  IGNORE_ERRORS(arc_mounter_->Umount(data_directory));
  IGNORE_ERRORS(arc_mounter_->UmountIfExists(shared_cache_directory));
  IGNORE_ERRORS(arc_mounter_->Umount(shared_data_directory));
  IGNORE_ERRORS(arc_mounter_->LoopUmountIfExists(shared_demo_apps_directory));
  IGNORE_ERRORS(arc_mounter_->Umount(arc_paths_->shared_mount_directory));
}

void ArcSetup::MaybeStartAdbdProxy(bool is_dev_mode,
                                   bool is_inside_vm,
                                   const std::string& serialnumber) {
  if (!is_dev_mode || is_inside_vm)
    return;
  const base::FilePath adbd_config_path("/etc/arc/adbd.json");
  if (!base::PathExists(adbd_config_path))
    return;
  // Poll the firmware to determine whether UDC is enabled or not. We're only
  // stopping the process if it's explicitly disabled because some systems (like
  // ARM) do not have this signal wired in and just rely on the presence of
  // adbd.json.
  if (LaunchAndWait({"/usr/bin/crossystem", "dev_enable_udc?0"}))
    return;

  // Now that we have identified that the system is capable of continuing, touch
  // the path where the FIFO will be located.
  const base::FilePath control_endpoint_path("/run/arc/adbd/ep0");
  EXIT_IF(!CreateOrTruncate(control_endpoint_path, 0600));
  EXIT_IF(!Chown(kShellUid, kShellGid, control_endpoint_path));

  EXIT_IF(!LaunchAndWait(
      {"/sbin/initctl", "start", "--no-wait", "arc-adbd",
       base::StringPrintf("SERIALNUMBER=%s", serialnumber.c_str())}));
}

void ArcSetup::ContinueContainerBoot(ArcBootType boot_type,
                                     const std::string& serialnumber) {
  constexpr char kCommand[] = "/system/bin/arcbootcontinue";

  const bool mount_demo_apps =
      !config_.GetStringOrDie("DEMO_SESSION_APPS_PATH").empty();

  std::string copy_packages_cache;
  if (config_.GetBoolOrDie("SKIP_PACKAGES_CACHE_SETUP")) {
    copy_packages_cache = "2";
  } else if (config_.GetBoolOrDie("COPY_PACKAGES_CACHE")) {
    copy_packages_cache = "1";
  } else {
    copy_packages_cache = "0";
  }

  // Run |kCommand| on the container side. The binary does the following:
  // * Bind-mount the actual cache and data in /var/arc/shared_mounts to /cache
  //   and /data.
  // * Set ro.boot.serialno and others.
  // * Then, set ro.data_mounted=1 to ask /init to start the processes in the
  //   "main" class.
  // We don't use -S (set UID), -G (set GID), and /system/bin/runcon here and
  // instead run the command with UID 0 (host's root) because our goal is to
  // remove or reduce [u]mount operations from the container, especially from
  // its /init, and then to enforce it with SELinux.
  const std::string pid_str = config_.GetStringOrDie("CONTAINER_PID");
  const std::vector<std::string> command_line = {
      "/usr/bin/nsenter", "-t", pid_str,
      "-m",  // enter mount namespace
      "-U",  // enter user namespace
      "-i",  // enter System V IPC namespace
      "-n",  // enter network namespace
      "-p",  // enter pid namespace
      "-r",  // set the root directory
      "-w",  // set the working directory
      "--", kCommand, "--serialno", serialnumber, "--disable-boot-completed",
      config_.GetStringOrDie("DISABLE_BOOT_COMPLETED_BROADCAST"),
      "--container-boot-type", std::to_string(static_cast<int>(boot_type)),
      // When copy_packages_cache is set to "0" or "1", arccachesetup copies
      // /system/etc/packages_cache.xml to /data/system/packages.xml. If it is
      // set to "2", arccachesetup skips copying. When copy_packages_cache is
      // "1" or "2", SystemServer copies /data/system/packages.xml
      // to /data/system/packages_copy.xml after the initialization stage of
      // PackageManagerService.
      "--copy-packages-cache", copy_packages_cache,
      "--skip-gms-core-cache-setup",
      config_.GetStringOrDie("SKIP_GMS_CORE_CACHE_SETUP"), "--mount-demo-apps",
      mount_demo_apps ? "1" : "0", "--is-demo-session",
      config_.GetStringOrDie("IS_DEMO_SESSION"), "--locale",
      config_.GetStringOrDie("LOCALE"), "--preferred-languages",
      config_.GetStringOrDie("PREFERRED_LANGUAGES"),
      // Whether ARC should transition the management setup
      //   "0": No transition necessary.
      //   "1": Child -> regular transition, should disable supervision.
      //   "2": Regular -> child transition, should enable supervision.
      //   "3": Unmanaged -> managed transition, should enable management.
      // TODO(tantoshchuk): rename command line option to
      // "--management-transition" here and on ARC side.
      "--supervision-transition",
      config_.GetStringOrDie("MANAGEMENT_TRANSITION"),
      "--enable-adb-sideloading", config_.GetStringOrDie("ENABLE_ADB_SIDELOAD"),
      "--enable-arc-nearby-share",
      config_.GetStringOrDie("ENABLE_ARC_NEARBY_SHARE"),
      "--skip-tts-cache-setup", config_.GetStringOrDie("SKIP_TTS_CACHE_SETUP")};

  base::ElapsedTimer timer;
  if (!LaunchAndWait(command_line)) {
    auto elapsed = timer.Elapsed().InMillisecondsRoundedUp();
    // ContinueContainerBoot() failed. Try to find out why it failed and log
    // messages accordingly. If one of these functions calls exit(), it means
    // that '/usr/bin/nsenter' is very likely the command that failed (rather
    // than '/system/bin/arcbootcontinue'.)
    CheckProcessIsAliveOrExit(pid_str);
    CheckNamespacesAvailableOrExit(pid_str);
    CheckOtherProcEntriesOrExit(pid_str);

    // Either nsenter or arcbootcontinue failed, but we don't know which. For
    // example, arcbootcontinue may fail if it tries to set a property while
    // init is being shut down or crashing.
    LOG(ERROR) << kCommand << " failed for unknown reason after " << elapsed
               << "ms";
    exit(EXIT_FAILURE);
  }
  LOG(INFO) << "Running " << kCommand << " took "
            << timer.Elapsed().InMillisecondsRoundedUp() << "ms";

  StartNetworking();
}

void ArcSetup::EnsureContainerDirectories() {
  // uid/gid will be modified by cras.conf later.
  // FIXME(b/64553266): Work around push_to_device/deploy_vendor_image running
  // arc_setup after cras.conf by skipping the setup if the directory exists.
  if (!base::DirectoryExists(arc_paths_->cras_socket_directory))
    EXIT_IF(!InstallDirectory(01770, kHostRootUid, kHostRootGid,
                              arc_paths_->cras_socket_directory));

  // arc-setup writes to /run/arc/host_generated even before starting the mini
  // container.
  EXIT_IF(!InstallDirectory(0755, kHostRootUid, kHostRootGid,
                            base::FilePath("/run/arc")));
  EXIT_IF(!InstallDirectory(0775, kHostRootUid, kHostRootGid,
                            base::FilePath("/run/arc/host_generated")));
}

void ArcSetup::SetUpTestharness(bool is_dev_mode) {
  if (base::DirectoryExists(arc_paths_->testharness_directory))
    return;

  if (is_dev_mode) {
    EXIT_IF(!InstallDirectory(07770, kSystemUid, kSystemGid,
                              arc_paths_->testharness_directory));
    const base::FilePath key_file =
        arc_paths_->testharness_directory.Append("keys");
    EXIT_IF(!WriteToFile(key_file, 0777, ""));
    EXIT_IF(!Chown(kSystemUid, kSystemGid, key_file));
  } else {
    // Even in non-Developer mode, we still need the directory so
    // config.json bind-mounting can happen correctly.
    // We will just restrict access to it and make sure no key file
    // is generated.
    EXIT_IF(!InstallDirectory(0000, kHostRootUid, kHostRootGid,
                              arc_paths_->testharness_directory));
  }
}

void ArcSetup::StartNetworking() {
  if (!patchpanel::Client::New()->NotifyArcStartup(
          config_.GetIntOrDie("CONTAINER_PID"))) {
    LOG(ERROR) << "Failed to notify network service";
  }
}

void ArcSetup::StopNetworking() {
  // The container pid isn't available at this point.
  if (!patchpanel::Client::New()->NotifyArcShutdown())
    LOG(ERROR) << "Failed to notify network service";
}

void ArcSetup::MountOnOnetimeSetup() {
  const bool is_writable = config_.GetBoolOrDie("WRITABLE_MOUNT");
  const unsigned long writable_flag =  // NOLINT(runtime/int)
      is_writable ? 0 : MS_RDONLY;

  if (is_writable)
    EXIT_IF(!arc_mounter_->Remount(base::FilePath("/"), 0 /* rw */, nullptr));

  // Try to drop as many privileges as possible. If we end up starting ARC,
  // we'll bind-mount the rootfs directory in the container-side with the
  // appropriate flags.
  EXIT_IF(!arc_mounter_->LoopMount(
      kSystemImage, arc_paths_->android_rootfs_directory,
      MS_NOEXEC | MS_NOSUID | MS_NODEV | writable_flag));

  unsigned long kBaseFlags =  // NOLINT(runtime/int)
      writable_flag | MS_NOEXEC | MS_NOSUID;

  // Though we can technically mount these in mount namespace with minijail,
  // we do not bother to handle loopback mounts by ourselves but just mount it
  // in host namespace. Unlike system.raw.img, these images are always squashfs.
  // Unlike system.raw.img, we don't remount them as exec either. The images do
  // not contain any executables.
  EXIT_IF(!arc_mounter_->LoopMount(
      kSdcardRootfsImage, arc_paths_->sdcard_rootfs_directory, kBaseFlags));
  EXIT_IF(!arc_mounter_->LoopMount(
      kObbRootfsImage, arc_paths_->obb_rootfs_directory, kBaseFlags));
}

void ArcSetup::UnmountOnOnetimeStop() {
  IGNORE_ERRORS(arc_mounter_->LoopUmount(arc_paths_->obb_rootfs_directory));
  IGNORE_ERRORS(arc_mounter_->LoopUmount(arc_paths_->sdcard_rootfs_directory));
  IGNORE_ERRORS(arc_mounter_->LoopUmount(arc_paths_->android_rootfs_directory));
}

void ArcSetup::BindMountInContainerNamespaceOnPreChroot(
    const base::FilePath& rootfs,
    const ArcBinaryTranslationType binary_translation_type) {
  if (binary_translation_type == ArcBinaryTranslationType::HOUDINI) {
    // system_lib_arm either is empty or contains ndk-translation's libraries.
    // Since houdini is selected bind-mount its libraries instead.
    EXIT_IF(!arc_mounter_->BindMount(
        rootfs.Append("vendor/lib/arm"),
        rootfs.Append(arc_paths_->system_lib_arm_directory_relative)));

    if (kUseHoudini64) {
      // Bind mount arm64 directory for houdini64.
      EXIT_IF(!arc_mounter_->BindMount(
          rootfs.Append("vendor/lib64/arm64"),
          rootfs.Append(arc_paths_->system_lib64_arm64_directory_relative)));
    }
  }

  const base::FilePath proc_rnd_compat =
      rootfs.Append("proc/sys/vm/mmap_rnd_compat_bits");

  if (base::PathExists(proc_rnd_compat)) {
    EXIT_IF(!arc_mounter_->BindMount(arc_paths_->fake_mmap_rnd_compat_bits,
                                     proc_rnd_compat));
  }
}

void ArcSetup::RestoreContextOnPreChroot(const base::FilePath& rootfs) {
  {
    // The list of container directories that need to be recursively re-labeled.
    // Note that "var/run" (the parent directory) is not in the list  because
    // some of entries in the directory are on a read-only filesystem.
    // Note: The array is for directories. Do no add files to the array. Add
    // them to |kPaths| below instead.
    std::vector<const char*> directories{"dev",
                                         "oem/etc",
                                         "var/run/arc/adb",
                                         "var/run/arc/apkcache",
                                         "var/run/arc/dalvik-cache",
                                         "var/run/chrome",
                                         "var/run/cras"};

    // Transform |kDirectories| because the mount points are visible only in
    // |rootfs|. Note that Chrome OS' file_contexts does recognize paths with
    // the |rootfs| prefix.
    EXIT_IF(!RestoreconRecursively(
        PrependPath(directories.cbegin(), directories.cend(), rootfs)));
  }

  {
    // Do the same as above for files and directories but in a non-recursive
    // way.
    constexpr std::array<const char*, 5> kPaths{
        "default.prop", "sys/kernel/debug", "system/build.prop", "var/run/arc",
        "vendor/build.prop"};
    EXIT_IF(!Restorecon(PrependPath(kPaths.cbegin(), kPaths.cend(), rootfs)));
  }
}

void ArcSetup::CreateDevColdbootDoneOnPreChroot(const base::FilePath& rootfs) {
  const base::FilePath coldboot_done = rootfs.Append("dev/.coldboot_done");
  EXIT_IF(!CreateOrTruncate(coldboot_done, 0755));
  EXIT_IF(!Chown(kRootUid, kRootGid, coldboot_done));
}

void ArcSetup::SendUpgradeMetrics(AndroidSdkVersion data_sdk_version) {
  LOG(INFO) << "Sending upgrade metrics";
  arc_setup_metrics_->SendSdkVersionUpgradeType(
      GetUpgradeType(GetSdkVersion(), data_sdk_version));
}

void ArcSetup::DeleteAndroidDataOnUpgrade(AndroidSdkVersion data_sdk_version) {
  if (!ShouldDeleteAndroidData(GetSdkVersion(), data_sdk_version))
    return;

  LOG(INFO) << "Deleting old Android data";
  EXIT_IF(!MoveDirIntoDataOldDir(arc_paths_->android_data_directory,
                                 arc_paths_->android_data_old_directory));
}

void ArcSetup::DeleteAndroidMediaProviderDataOnUpgrade(
    AndroidSdkVersion data_sdk_version) {
  if (GetSdkVersion() < AndroidSdkVersion::ANDROID_R)
    return;
  if (data_sdk_version != AndroidSdkVersion::ANDROID_P)
    return;
  LOG(INFO) << "Deleting old Android Media Provider data";
  const auto media_provider_data_directory =
      arc_paths_->android_data_directory.Append(
          "data/data/com.android.providers.media");
  EXIT_IF(!MoveDirIntoDataOldDir(media_provider_data_directory,
                                 arc_paths_->android_data_old_directory));
}

// TODO(b/230408800): Remove this and GetSELinuxContext after M110.
void ArcSetup::DeleteAndroidDataIfDataHasIncorrectSELinuxContexts() {
  if (GetSdkVersion() != AndroidSdkVersion::ANDROID_R)
    return;

  const auto downloads_provider_dir_path =
      arc_paths_->android_data_directory.Append(
          "data/data/com.android.providers.downloads");
  const auto downloads_provider_db_path =
      downloads_provider_dir_path.Append("databases/downloads.db");

  // This inconsistency is highly likely a result of b/228881316.
  // (Files are incorrectly labeled as system_data_file while dirs are fine.)
  if (GetSELinuxContext(downloads_provider_dir_path) ==
          "u:object_r:privapp_data_file:s0:c512,c768" &&
      GetSELinuxContext(downloads_provider_db_path) ==
          "u:object_r:system_data_file:s0:c512,c768") {
    LOG(WARNING) << "Data has invalid SELinux contexts "
                 << "(likely caused by b/228881316). Deleting /data";
    EXIT_IF(!MoveDirIntoDataOldDir(arc_paths_->android_data_directory,
                                   arc_paths_->android_data_old_directory));
  }
}

void ArcSetup::OnSetup() {
  const bool is_dev_mode = config_.GetBoolOrDie("CHROMEOS_DEV_MODE");

  SetUpSharedMountPoints();
  CreateContainerFilesAndDirectories();
  ApplyPerBoardConfigurations();
  SetUpSharedTmpfsForExternalStorage();
  SetUpFilesystemForObbMounter();
  CreateAndroidCmdlineFile(is_dev_mode);
  CreateFakeProcfsFiles();
  SetUpMountPointForDebugFilesystem(is_dev_mode);
  SetUpMountPointsForMedia();
  SetUpMountPointForAdbd();
  SetUpMountPointForAdbdUnixSocket();
  CleanUpStaleMountPoints();
  RestoreContext();
  SetUpGraphicsSysfsContext();
  if (GetSdkVersion() > AndroidSdkVersion::ANDROID_P) {
    // For container R.
    SetUpTestharness(is_dev_mode);

    if (!USE_ARCVM) {
      // In case the udev rules for creating and populating this directory fail,
      // create the directory so that the bind mount succeeds and allows ARC to
      // boot, as this is a non-essential feature.
      // This is intended for CTS compliance on R container: b/277541769
      EXIT_IF(!brillo::MkdirRecursively(base::FilePath("/dev/arc_input"), 0755)
                   .is_valid());
    }
  }
  SetUpPowerSysfsContext();
  MakeMountPointsReadOnly();
  SetUpCameraProperty(base::FilePath(kBuildPropFile));
  SetUpSharedApkDirectory();
}

void ArcSetup::OnBootContinue() {
  const bool is_dev_mode = config_.GetBoolOrDie("CHROMEOS_DEV_MODE");
  const bool is_inside_vm = config_.GetBoolOrDie("CHROMEOS_INSIDE_VM");
  const std::string serialnumber = GetSerialNumber();

  ArcBootType boot_type;
  AndroidSdkVersion data_sdk_version;
  GetBootTypeAndDataSdkVersion(&boot_type, &data_sdk_version);

  SendUpgradeMetrics(data_sdk_version);
  DeleteAndroidDataOnUpgrade(data_sdk_version);

  bool should_delete_data_dalvik_cache_directory;
  bool should_delete_data_app_executables;
  ShouldDeleteDataExecutables(boot_type,
                              &should_delete_data_dalvik_cache_directory,
                              &should_delete_data_app_executables);
  DeleteExecutableFilesInData(should_delete_data_dalvik_cache_directory,
                              should_delete_data_app_executables);

  // The socket isn't created when the mini-container is started, so the
  // arc-setup --mode=pre-chroot call won't label it. Label it here instead.
  EXIT_IF(!Chcon(kArcBridgeSocketContext, arc_paths_->arc_bridge_socket_path));

  // Set up |android_mutable_source|. Although the container does not use
  // the directory directly, we should still set up the directory so that
  // session_manager can delete (to be more precise, move) the directory
  // on opt-out. Since this creates cache and data directories when they
  // don't exist, this has to be done before calling ShareAndroidData().
  SetUpAndroidData(arc_paths_->android_mutable_source);

  InstallLinksToHostSideCode();

  // Set up /run/arc/shared_mounts/{cache,data,demo_apps} to expose the user's
  // data to the container. Demo apps are setup only for demo sessions.
  MountSharedAndroidDirectories();

  MaybeStartAdbdProxy(is_dev_mode, is_inside_vm, serialnumber);

  // Asks the container to continue boot.
  ContinueContainerBoot(boot_type, serialnumber);

  // Unmount /run/arc/shared_mounts and its children. They are unnecessary at
  // this point.
  UnmountSharedAndroidDirectories();

  const std::string env_chromeos_user = base::StringPrintf(
      "CHROMEOS_USER=%s", config_.GetStringOrDie("CHROMEOS_USER").c_str());
  const std::string env_container_pid = base::StringPrintf(
      "CONTAINER_PID=%d", config_.GetIntOrDie("CONTAINER_PID"));
  EXIT_IF(!LaunchAndWait({"/sbin/initctl", "start", "--no-wait", "arc-sdcard",
                          env_chromeos_user, env_container_pid}));

  const base::FilePath packages_xml =
      arc_paths_->android_data_directory.Append("data/system/packages.xml");

  int media_uid;
  int media_gid;
  const AndroidSdkVersion sdk_version = GetSdkVersion();
  if (sdk_version >= AndroidSdkVersion::ANDROID_R &&
      FindMediaProviderUid(packages_xml, &media_uid)) {
    media_gid = AID_EXTERNAL_STORAGE;
    LOG(INFO) << "Using " << media_uid << ":" << media_gid << " for myfiles";
  } else {
    LOG(INFO) << "Using default media uid:gid for myfiles";
    media_uid = AID_MEDIA_RW;
    media_gid = AID_MEDIA_RW;
  }

  const std::string env_media_uid =
      base::StringPrintf("ANDROID_MEDIA_UID=%d", media_uid);
  const std::string env_media_gid =
      base::StringPrintf("ANDROID_MEDIA_GID=%d", media_gid);
  LOG(INFO) << "Mounting myfiles with " << env_media_uid << ":"
            << env_media_gid;

  EXIT_IF(!LaunchAndWait({"/sbin/initctl", "start", "--no-wait", "arc-myfiles",
                          env_media_uid, env_media_gid}));
}

void ArcSetup::OnStop() {
  StopNetworking();
  CleanUpBinFmtMiscSetUp();
  UnmountOnStop();
  RemoveAndroidKmsgFifo();
}

void ArcSetup::OnOnetimeSetup() {
  EnsureContainerDirectories();
  MountOnOnetimeSetup();

  // Setup ownership for <configfs>/sdcard, if the directory exists.
  SetUpOwnershipForSdcardConfigfs();
}

void ArcSetup::OnOnetimeStop() {
  UnmountOnOnetimeStop();
}

void ArcSetup::OnPreChroot() {
  // Note: Do not try to create a directory in tmpfs here. Recent (4.8+)
  // kernel doesn't allow us to do so and returns EOVERFLOW. b/78262683

  // binfmt_misc setup has to be done before entering container
  // namespace below (namely before CreateScopedMountNamespaceForPid).
  ArcBinaryTranslationType binary_translation_type =
      IdentifyBinaryTranslationType();
  SetUpBinFmtMisc(binary_translation_type);

  int container_pid;
  base::FilePath rootfs;

  EXIT_IF(!GetOciContainerState(base::FilePath("/dev/stdin"), &container_pid,
                                &rootfs));

  // Enter the container namespace since the paths we want to re-label here
  // are easier to access from inside of it.
  std::unique_ptr<brillo::ScopedMountNamespace> container_mount_ns =
      brillo::ScopedMountNamespace::CreateForPid(container_pid);
  PLOG_IF(FATAL, !container_mount_ns)
      << "Failed to enter the container mount namespace";

  BindMountInContainerNamespaceOnPreChroot(rootfs, binary_translation_type);
  if (create_tagged_ashmem_)
    CreateTaggedAshmem(rootfs);
  RestoreContextOnPreChroot(rootfs);
  CreateDevColdbootDoneOnPreChroot(rootfs);
}

void ArcSetup::CreateTaggedAshmem(const base::FilePath& rootfs) {
  std::string boot_id;
  EXIT_IF(!base::ReadFileToString(base::FilePath(kBootIdFile), &boot_id));

  CHECK(!boot_id.empty());
  if (boot_id.back() == '\n')
    boot_id.pop_back();

  // Inherit device type from host's ashmem file.
  struct stat st_buf;
  if (stat("/dev/ashmem", &st_buf) != 0)
    PLOG(FATAL) << "Failed to stat ashmem on host";

  const base::FilePath guest_ashmem = rootfs.Append("dev/ashmem" + boot_id);
  // Don't bother specifying G and O bits since umask will just clobber them.
  if (mknod(guest_ashmem.value().c_str(), S_IFCHR | 0600, st_buf.st_rdev) != 0)
    PLOG(FATAL) << "Failed to mknod " << guest_ashmem;

  // Since the file is world-rw-able, this is an optional adjustment.
  if (chown(guest_ashmem.value().c_str(), kRootUid, kRootGid) != 0)
    PLOG(WARNING) << "Failed to chown to android root: " << guest_ashmem;

  if (chmod(guest_ashmem.value().c_str(), 0666) != 0)
    PLOG(FATAL) << "Failed to chmod " << guest_ashmem;
}

void ArcSetup::OnRemoveData() {
  // Since deleting files in android-data may take long, just move the directory
  // for now and let arc-stale-directory-remover delete files in the background.
  EXIT_IF(!MoveDirIntoDataOldDir(arc_paths_->android_data_directory,
                                 arc_paths_->android_data_old_directory));

  // Delete virtio-blk disk image if exists.
  if (USE_ARCVM) {
    // Disk path /home/root/<hash>/crosvm/YXJjdm0=.img is constructed in
    // concierge's CreateDiskImage method. Image name "YXJjdm0=" is static
    // because it is generated by vm_tools::GetEncodedName("arcvm").
    constexpr const char kImageFileName[] = "YXJjdm0=.img";
    const base::FilePath image_dir =
        arc_paths_->root_directory.Append("crosvm");

    brillo::SafeFD fd;
    brillo::SafeFD::Error err;
    std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingDir(image_dir);

    if (!brillo::SafeFD::IsError(err)) {
      base::ElapsedTimer timer;
      // No need to delete the image in the background because deleting a single
      // image file won't take more than 1 second.
      err = fd.Unlink(kImageFileName);
      CHECK(!brillo::SafeFD::IsError(err) ||
            // Abort if the |err| is not ENOENT.
            (err == brillo::SafeFD::Error::kIOError && errno == ENOENT))
          << "err=" << static_cast<int>(err) << ", errno=" << errno;
      LOG_IF(INFO, !brillo::SafeFD::IsError(err))
          << "Deleting disk image (crosvm/YXJjdm0=.img) took "
          << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
    } else {
      LOG(ERROR) << "Failed to open the image directory: " << image_dir
                 << ", err=" << static_cast<int>(err) << ", errno=" << errno;
    }
  }

  // Ensure to remove ARC /data in LVM stateful partition.
  if (USE_ARCVM && USE_LVM_STATEFUL_PARTITION)
    RemoveDataInLvm();
}

void ArcSetup::RemoveDataInLvm() {
  brillo::DBusConnection connection;
  scoped_refptr<dbus::Bus> bus = connection.Connect();
  if (!bus) {
    LOG(ERROR) << "Failed to connect to system D-Bus service";
    return;
  }

  auto userdataauth_proxy = org::chromium::UserDataAuthInterfaceProxy(bus);
  user_data_auth::ResetApplicationContainerRequest request;
  user_data_auth::ResetApplicationContainerReply reply;
  brillo::ErrorPtr err;

  request.set_application_name("arcvm");
  const std::string chromeos_user = config_.GetStringOrDie("CHROMEOS_USER");
  request.mutable_account_id()->set_account_id(chromeos_user);

  LOG(INFO) << "Attempting to remove ARC /data in LVM";
  if (!userdataauth_proxy.ResetApplicationContainer(request, &reply, &err,
                                                    kResetLvmDbusTimeoutMs) ||
      err) {
    std::string msg;
    if (err.get())
      msg = err->GetDomain() + "," + err->GetCode() + "," + err->GetMessage();
    LOG(ERROR) << "ResetApplicationContainer call failed: " << msg;
    return;
  }
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "Failed to reset application container: " << reply.error();
    return;
  }
  LOG(INFO) << "Successfully removed ARC /data in LVM";
}

void ArcSetup::OnRemoveStaleData() {
  // To protect itself, base::SafeFD::RmDir() uses a default maximum
  // recursion depth of 256. In this case, we are deleting the user's
  // arbitrary filesystem and want to be more generous. However, RmDir()
  // uses one fd per path level when recursing so we will have the max
  // number of fds per process as an upper bound (default 1024). Leave a
  // 25% buffer below this default 1024 limit to give lots of room for
  // incidental usage elsewhere in the process. Use this everywhere here
  // for consistency.
  constexpr int kRmdirMaxDepth = 768;

  brillo::SafeFD root = brillo::SafeFD::Root().first;

  if (USE_ARCVM) {
    // On ARCVM, stale *.odex files are kept in /data/vendor/arc.
    base::FilePath arcvm_stale_odex = arc_paths_->android_data_directory.Append(
        "data/vendor/arc/old_arc_executables_pre_ota");
    brillo::SafeFD parent_dir =
        root.OpenExistingDir(arcvm_stale_odex.DirName()).first;
    brillo::SafeFD::Error err = parent_dir.Rmdir(
        arcvm_stale_odex.BaseName().value(), true /*recursive*/, kRmdirMaxDepth,
        true /*keep_going*/);
    if (brillo::SafeFD::IsError(err) &&
        err != brillo::SafeFD::Error::kDoesNotExist) {
      LOG(ERROR) << "Errors while cleaning old data from "
                 << arcvm_stale_odex.value();
    }
  }

  // Moving data to android_data_old no longer has race conditions so it is safe
  // to delete the entire directory.
  brillo::SafeFD parent_dir =
      root.OpenExistingDir(arc_paths_->android_data_old_directory.DirName())
          .first;
  brillo::SafeFD::Error err = parent_dir.Rmdir(
      arc_paths_->android_data_old_directory.BaseName().value(),
      true /*recursive*/, kRmdirMaxDepth, true /*keep_going*/);
  if (brillo::SafeFD::IsError(err) &&
      err != brillo::SafeFD::Error::kDoesNotExist) {
    LOG(ERROR) << "Errors while cleaning old data from "
               << arc_paths_->android_data_old_directory.value();
  }
}

void ArcSetup::OnPrepareHostGeneratedDir() {
  const bool is_arcvm = config_.GetBoolOrDie("IS_ARCVM");
#if USE_ARC_HW_OEMCRYPTO
  const bool hw_oemcrypto_support = true;
#else
  const bool hw_oemcrypto_support = false;
#endif  // USE_ARC_HW_OEMCRYPTO
  const bool debuggable = config_.GetBoolOrDie("ANDROID_DEBUGGABLE");
  LOG(INFO) << "Debuggable is " << debuggable;

  const base::FilePath property_files_source_dir(
      base::FilePath(is_arcvm ? kPropertyFilesPathVm : kPropertyFilesPath));
  const base::FilePath property_files_dest_path(
      is_arcvm ? base::FilePath(kGeneratedPropertyFilesPathVm)
                     .Append("combined.prop")
               : base::FilePath(kGeneratedPropertyFilesPath));

  brillo::DBusConnection dbus_connection;
  scoped_refptr<::dbus::Bus> bus = nullptr;
  if (hw_oemcrypto_support) {
    bus = dbus_connection.Connect();
    CHECK(bus);
  }

  EXIT_IF(!ExpandPropertyFiles(property_files_source_dir,
                               property_files_dest_path,
                               /*single_file=*/is_arcvm, hw_oemcrypto_support,
                               /*include_soc_props=*/true, debuggable, bus));

  if (!is_arcvm)
    return;

  // CACHE_PARTITION is set when a dedicated cache partition is used
  // (b/182953041). The set value is the device number to be used.
  // This option is for test build only, and is not used in production.
  const std::string cache_partition = config_.GetStringOrDie("CACHE_PARTITION");

  // For ARCVM, the first stage fstab file needs to be generated.
  EXIT_IF(!GenerateFirstStageFstab(
      property_files_dest_path,
      base::FilePath(kGeneratedPropertyFilesPathVm).Append("fstab"),
      base::FilePath(kArcVmVendorImagePath), cache_partition));
}

void ArcSetup::OnApplyPerBoardConfig() {
  base::FilePath per_board_config_path(kArcVmPerBoardConfigPath);
  ApplyPerBoardConfigurationsInternal(per_board_config_path);
  SetUpCameraProperty(base::FilePath(kBuildPropFileVm));

  // ARCVM's platform.xml has to be owned by crosvm for proper ugid mapping by
  // crosvm.
  brillo::SafeFD fd;
  brillo::SafeFD::Error err;
  std::tie(fd, err) = brillo::SafeFD::Root().first.OpenExistingFile(
      per_board_config_path.Append(kPlatformXmlFileRelative));
  if (err == brillo::SafeFD::Error::kDoesNotExist)
    return;  // the board does not have the file.
  EXIT_IF(!fd.is_valid());

  uid_t crosvm_uid;
  gid_t crosvm_gid;
  EXIT_IF(!GetUserId("crosvm", &crosvm_uid, &crosvm_gid));
  EXIT_IF(fchown(fd.get(), crosvm_uid, crosvm_gid));

  auto config = std::make_unique<brillo::CrosConfig>();
  if (auto media_codecs_c2_xml = GetConfigPath(*config, kMediaCodecsSetting);
      media_codecs_c2_xml && base::PathExists(*media_codecs_c2_xml)) {
    EXIT_IF(!SafeCopyFile(*media_codecs_c2_xml, brillo::SafeFD::Root().first,
                          arc_paths_->media_codecs_relative,
                          brillo::SafeFD::Root()
                              .first.OpenExistingDir(per_board_config_path)
                              .first,
                          0644, crosvm_uid, crosvm_gid));
  }

  if (auto media_codecs_performance_c2_xml =
          GetConfigPath(*config, kMediaCodecsPerformanceSetting);
      media_codecs_performance_c2_xml &&
      base::PathExists(*media_codecs_performance_c2_xml)) {
    EXIT_IF(!SafeCopyFile(*media_codecs_performance_c2_xml,
                          brillo::SafeFD::Root().first,
                          arc_paths_->media_codecs_performance_relative,
                          brillo::SafeFD::Root()
                              .first.OpenExistingDir(per_board_config_path)
                              .first,
                          0644, crosvm_uid, crosvm_gid));
  }
}

void ArcSetup::OnCreateData() {
  const base::FilePath bind_target(
      config_.GetStringOrDie("ANDROID_MUTABLE_SOURCE"));
  // bind_target may be already bound if arc-create-data has previously run
  // during this session.
  EXIT_IF(!arc_mounter_->UmountIfExists(bind_target));
  // Create data folder and bind to bind_target. The bind mount will be cleaned
  // up in vm_concierge.conf's post-stop script, when the mnt_concierge
  // namespace is unmounted.
  SetUpAndroidData(bind_target);
}

void ArcSetup::OnMountSdcard() {
  // Set up sdcard asynchronously from arc-sdcard so that waiting on installd
  // does not add latency to boot-continue (and result in session-manager
  // related timeouts).
  SetUpSdcard();
}

void ArcSetup::OnUnmountSdcard() {
  UnmountSdcard();
}

void ArcSetup::OnUpdateRestoreconLast() {
  // On Android, /init writes the security.restorecon_last attribute to /data
  // (and /cache on N) after it finishes updating labels of the files in the
  // directories, but on ARC, writing the attribute fails silently because
  // processes in user namespace are not allowed to write arbitrary entries
  // under security.* even with CAP_SYS_ADMIN. (b/33084415, b/33402785)
  // As a workaround, let this command outside the container set the
  // attribute for ARC.
  constexpr char kRestoreconLastXattr[] = "security.restorecon_last";
  std::vector<base::FilePath> context_files;
  std::vector<base::FilePath> target_directories = {
      arc_paths_->android_mutable_source.Append("data")};

  // The order of files to read is important. Do not reorder.
  context_files.push_back(
      arc_paths_->android_rootfs_directory.Append("plat_file_contexts"));
  context_files.push_back(
      arc_paths_->android_rootfs_directory.Append("vendor_file_contexts"));

  std::string hash;
  EXIT_IF(!GetSha1HashOfFiles(context_files, &hash));
  for (const auto& target : target_directories) {
    EXIT_IF(!SetXattr(target, kRestoreconLastXattr, hash));
  }
}

void ArcSetup::OnHandleUpgrade() {
  ArcBootType boot_type;
  AndroidSdkVersion data_sdk_version;
  GetBootTypeAndDataSdkVersion(&boot_type, &data_sdk_version);

  SendUpgradeMetrics(data_sdk_version);
  DeleteAndroidMediaProviderDataOnUpgrade(data_sdk_version);
  DeleteAndroidDataOnUpgrade(data_sdk_version);
  DeleteAndroidDataIfDataHasIncorrectSELinuxContexts();
}

std::string ArcSetup::GetSystemBuildPropertyOrDie(const std::string& name) {
  if (system_properties_.empty()) {
    // First time read of system properties file.
    // We don't know if we are in a container or on VM yet, so try the
    // build.prop location on container first and fall back to the
    // conbined.prop location on VM if empty.
    const base::FilePath build_prop =
        arc_paths_->android_generated_properties_directory.Append("build.prop");
    GetPropertiesFromFile(build_prop, &system_properties_);
    if (system_properties_.empty()) {
      const base::FilePath combined_prop_vm(kCombinedPropFileVm);
      GetPropertiesFromFile(combined_prop_vm, &system_properties_);
    }
  }
  DCHECK(!system_properties_.empty());
  const auto it = system_properties_.find(name);
  CHECK(system_properties_.end() != it) << "Failed to read property: " << name;
  CHECK(!it->second.empty());
  return it->second;
}

void ArcSetup::Run() {
  switch (mode_) {
    case Mode::SETUP: {
      bootstat::BootStat bootstat;
      bootstat.LogEvent("mini-android-start");
      OnSetup();
      bootstat.LogEvent("arc-setup-for-mini-android-end");
      break;
    }
    case Mode::STOP:
      OnStop();
      break;
    case Mode::BOOT_CONTINUE: {
      bootstat::BootStat bootstat;
      bootstat.LogEvent("android-start");
      OnBootContinue();
      bootstat.LogEvent("arc-setup-end");
      break;
    }
    case Mode::ONETIME_SETUP:
      OnOnetimeSetup();
      break;
    case Mode::ONETIME_STOP:
      OnOnetimeStop();
      break;
    case Mode::PRE_CHROOT:
      OnPreChroot();
      break;
    case Mode::PREPARE_HOST_GENERATED_DIR:
      OnPrepareHostGeneratedDir();
      break;
    case Mode::APPLY_PER_BOARD_CONFIG:
      OnApplyPerBoardConfig();
      break;
    case Mode::CREATE_DATA:
      OnCreateData();
      break;
    case Mode::REMOVE_DATA:
      OnRemoveData();
      break;
    case Mode::REMOVE_STALE_DATA:
      OnRemoveStaleData();
      break;
    case Mode::MOUNT_SDCARD:
      OnMountSdcard();
      break;
    case Mode::UNMOUNT_SDCARD:
      OnUnmountSdcard();
      break;
    case Mode::UPDATE_RESTORECON_LAST:
      OnUpdateRestoreconLast();
      break;
    case Mode::HANDLE_UPGRADE:
      OnHandleUpgrade();
      break;
    case Mode::UNKNOWN:
      NOTREACHED();
      break;
  }
}

void ArcSetup::MountOnOnetimeSetupForTesting() {
  MountOnOnetimeSetup();
}

void ArcSetup::UnmountOnOnetimeStopForTesting() {
  UnmountOnOnetimeStop();
}
}  // namespace arc
