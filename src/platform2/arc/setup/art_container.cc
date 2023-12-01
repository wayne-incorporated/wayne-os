// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/art_container.h"

#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include <memory>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/process/process.h>
#include <chromeos/libminijail.h>
#include <scoped_minijail.h>

namespace arc {

namespace {

constexpr char kAndroidRootfs[] =
    "/opt/google/containers/arc-art/mountpoints/container-root";
constexpr char kAndroidVendor[] =
    "/opt/google/containers/arc-art/mountpoints/vendor";
constexpr char kLibLogStderrName[] = "liblog_stderr.so";

// Variables defined in Android <pi-arc>/art/build/art.go
constexpr uint32_t kArtBaseAddressMaxDelta = 0x1000000;
constexpr uint32_t kArtBaseAddressMinDelta = -0x1000000;

constexpr char kArtDevRootfsDirectory[] =
    "/opt/google/containers/arc-art/mountpoints/dev-rootfs";
constexpr char kArtDevRootfsImage[] =
    "/opt/google/containers/arc-art/dev-rootfs.squashfs";
constexpr char kArtRootfsDirectory[] =
    "/opt/google/containers/arc-art/mountpoints/container-root";
// TODO(xzhou): Use sysconf(_SC_PAGESIZE).
constexpr uint32_t kPageSize = 4096;
constexpr char kPatchOat[] = "/system/bin/patchoat";
constexpr char kPidFile[] = "/run/patchoat.pid";
constexpr char kSystemImage[] = "/opt/google/containers/android/system.raw.img";
constexpr char kVendorImage[] = "/opt/google/containers/android/vendor.raw.img";

// Ported from Andriod nyc
template <typename T>
struct Identity {
  using type = T;
};

#define CHECK_CONSTEXPR(x, out, dummy) \
  (UNLIKELY(!(x))) ? (LOG(ERROR) << "Check failed: " << #x out, dummy):

#define DCHECK_CONSTEXPR(x, out, dummy) CHECK_CONSTEXPR(x, out, dummy)

template <typename T>
static constexpr int CLZ(T x) {
  static_assert(std::is_integral<T>::value, "T must be integral");
  static_assert(std::is_unsigned<T>::value, "T must be unsigned");
  static_assert(sizeof(T) <= sizeof(long long),  // NOLINT [runtime/int] [4]
                "T too large, must be smaller than long long");
  return DCHECK_CONSTEXPR(x != 0, "x must not be zero",
                          T(0))(sizeof(T) == sizeof(uint32_t))
             ? __builtin_clz(x)
             : __builtin_clzll(x);
}

template <typename T>
static constexpr bool IsPowerOfTwo(T x) {
  static_assert(std::is_integral<T>::value, "T must be integral");
  return (x & (x - 1)) == 0;
}

// For rounding integers.
template <typename T>
static constexpr T RoundDown(T x, typename Identity<T>::type n) {
  return DCHECK_CONSTEXPR(IsPowerOfTwo(n), , T(0))(x & -n);
}

template <typename T>
static constexpr T RoundUp(T x, typename std::remove_reference<T>::type n) {
  return RoundDown(x + n - 1, n);
}

template <int n, typename T>
static constexpr bool IsAligned(T x) {
  static_assert((n & (n - 1)) == 0, "n is not a power of two");
  return (x & (n - 1)) == 0;
}

#define CHECK_ALIGNED(value, alignment) \
  CHECK(IsAligned<alignment>(value)) << reinterpret_cast<const void*>(value)

template <typename T>
T GetRandomNumber(T min, T max) {
  CHECK_LT(min, max);
  std::uniform_int_distribution<T> dist(min, max);
  std::random_device rng;
  return dist(rng);
}

int32_t GetOffset(int32_t min, int32_t max, uint64_t offset_seed) {
  CHECK_LT(min, max);
  const uint32_t range = max - min;
  const uint32_t offset = offset_seed % range;
  CHECK_LT(offset, range);
  return min + offset;
}

int32_t ChooseRelocationOffsetDelta(int32_t min_delta,
                                    int32_t max_delta,
                                    uint64_t offset_seed) {
  CHECK_ALIGNED(min_delta, kPageSize);
  CHECK_ALIGNED(max_delta, kPageSize);
  CHECK_LT(min_delta, max_delta);

  int32_t r = offset_seed ? GetOffset(min_delta, max_delta, offset_seed)
                          : GetRandomNumber(min_delta, max_delta);
  if (r % 2 == 0) {
    r = RoundUp(r, kPageSize);
  } else {
    r = RoundDown(r, kPageSize);
  }
  CHECK_LE(min_delta, r);
  CHECK_GE(max_delta, r);
  CHECK_ALIGNED(r, kPageSize);
  return r;
}

}  // namespace

struct ArtContainerPaths {
  const base::FilePath art_dalvik_cache_directory{kArtDalvikCacheDirectory};
  const base::FilePath art_dev_rootfs_directory{kArtDevRootfsDirectory};
  const base::FilePath art_rootfs_directory{kArtRootfsDirectory};
  const base::FilePath vendor_directory{kAndroidVendor};
};

// static
std::unique_ptr<ArtContainer> ArtContainer::CreateContainer(
    ArcMounter* mounter, AndroidSdkVersion sdk_version) {
  auto art_paths = std::make_unique<ArtContainerPaths>();

  // Make sure the data directory exits.
  CHECK(base::PathExists(art_paths->art_dalvik_cache_directory));

  return std::unique_ptr<ArtContainer>(
      new ArtContainer(mounter, std::move(art_paths), sdk_version));
}

// static
std::vector<std::string> ArtContainer::GetIsas() {
  std::vector<std::string> isas;
  for (const std::string& arch : {"arm", "arm64", "x86", "x86_64"}) {
    if (base::DirectoryExists(base::FilePath(kFrameworkPath).Append(arch)))
      isas.push_back(arch);
  }
  return isas;
}

ArtContainer::ArtContainer(ArcMounter* mounter,
                           std::unique_ptr<ArtContainerPaths> art_paths,
                           AndroidSdkVersion sdk_version)
    : mounter_(mounter),
      art_paths_(std::move(art_paths)),
      sdk_version_(sdk_version) {}

ArtContainer::~ArtContainer() = default;

bool ArtContainer::PatchImage(uint64_t offset_seed) {
  int pid = fork();
  if (pid == -1) {
    PLOG(ERROR) << "Failed to fork()";
    return false;
  }

  if (pid == 0) {
    // Avoid doing any cleanup in the child process. This avoids problems where
    // an atexit(3) handler (if any) that can modify global state (e.g. mounts)
    // is called before it is expected (i.e. when main() returns in the parent).
    _exit(PatchImageChild(offset_seed) ? EXIT_SUCCESS : EXIT_FAILURE);
  }

  base::Process process(pid);
  int exit_code = -1;
  if (!process.WaitForExit(&exit_code)) {
    PLOG(ERROR) << "Failed to wait for the ART container";
    return false;
  }
  if (exit_code != EXIT_SUCCESS) {
    LOG(ERROR) << "The ART container exited with non-zero code: " << exit_code;
    return false;
  }
  return true;
}

bool ArtContainer::PatchImageChild(uint64_t offset_seed) {
  {
    // Enter an intermediate mount namespace to avoid leaking mounts.
    ScopedMinijail art_jail(minijail_new());
    if (!art_jail)
      return false;
    minijail_namespace_vfs(art_jail.get());
    minijail_enter(art_jail.get());
  }

  // Mount rootfs, /vendor, /dev, /data for ART container.
  // TODO(xzhou): Simplify using minijail mounts.
  std::unique_ptr<ScopedMount> art_rootfs = ScopedMount::CreateScopedLoopMount(
      mounter_, kSystemImage, art_paths_->art_rootfs_directory,
      MS_RDONLY | MS_NOSUID | MS_NODEV);
  if (!art_rootfs)
    return false;
  std::unique_ptr<ScopedMount> loop_vendor = ScopedMount::CreateScopedLoopMount(
      mounter_, kVendorImage, art_paths_->vendor_directory,
      MS_RDONLY | MS_NOEXEC | MS_NOSUID);
  if (!loop_vendor)
    return false;
  std::unique_ptr<ScopedMount> art_vendor = ScopedMount::CreateScopedBindMount(
      mounter_, art_paths_->vendor_directory,
      art_paths_->art_rootfs_directory.Append("vendor"));
  if (!art_vendor)
    return false;
  // Patchoat did not map /dev/ashmem with PROT_EXEC and using MS_NOEXEC here.
  std::unique_ptr<ScopedMount> loop_dev = ScopedMount::CreateScopedLoopMount(
      mounter_, kArtDevRootfsImage, art_paths_->art_dev_rootfs_directory,
      MS_RDONLY | MS_NOEXEC | MS_NOSUID);
  if (!loop_dev)
    return false;
  std::unique_ptr<ScopedMount> art_dev = ScopedMount::CreateScopedBindMount(
      mounter_, art_paths_->art_dev_rootfs_directory.Append("dev"),
      art_paths_->art_rootfs_directory.Append("dev"));
  if (!art_dev)
    return false;
  // Bind mount /dev/ashmem from host to art container. The minor number of
  // ashmem is dynamic, we overwrite the one in art_dev.
  std::unique_ptr<ScopedMount> ashmem = ScopedMount::CreateScopedBindMount(
      mounter_, base::FilePath("/dev/ashmem"),
      art_paths_->art_rootfs_directory.Append("dev/ashmem"));
  if (!ashmem)
    return false;
  std::unique_ptr<ScopedMount> art_data = ScopedMount::CreateScopedBindMount(
      mounter_, art_paths_->art_dalvik_cache_directory.DirName(),
      art_paths_->art_rootfs_directory.Append("data"));
  if (!art_data)
    return false;

  for (const std::string& isa : ArtContainer::GetIsas()) {
    if (!PatchImage(isa, offset_seed))
      return false;
  }
  return true;
}

bool ArtContainer::PatchImage(const std::string& isa, uint64_t offset_seed) {
  // Remove outdated files in dalvik-cache directory.
  if (!DeleteFilesInDir(art_paths_->art_dalvik_cache_directory.Append(isa))) {
    LOG(ERROR) << "Failed to delete existing images in "
               << kArtDalvikCacheDirectory;
    return false;
  }

  LOG(INFO) << "Running patchoat container...";
  // Start the patchoat container and relocate boot images.
  ScopedMinijail art_jail(minijail_new());
  minijail_no_new_privs(art_jail.get());
  int ret = minijail_enter_pivot_root(art_jail.get(), kAndroidRootfs);
  if (ret != 0) {
    LOG(ERROR) << "Can not set pivot root: " << strerror(-ret);
    return false;
  }
  minijail_namespace_vfs(art_jail.get());
  minijail_namespace_net(art_jail.get());
  minijail_namespace_pids(art_jail.get());
  minijail_skip_remount_private(art_jail.get());
  minijail_use_alt_syscall(art_jail.get(), "android");
  minijail_write_pid_file(art_jail.get(), kPidFile);

  // Preserve stdout and stderr.
  minijail_preserve_fd(art_jail.get(), STDOUT_FILENO, STDOUT_FILENO);
  minijail_preserve_fd(art_jail.get(), STDERR_FILENO, STDERR_FILENO);
  // Log to host stderr with priority 4, which is LOG_INFO and cannot
  // #include <syslog.h> due to name collisions with base/logging.h.
  minijail_log_to_fd(STDOUT_FILENO, 4);
  minijail_log_to_fd(STDERR_FILENO, 4);

  ret = minijail_mount_with_data(art_jail.get(), "proc", "/proc", "proc",
                                 MS_RDONLY | MS_NODEV | MS_NOEXEC, nullptr);
  // Set up private mount points.
  if (ret != 0) {
    LOG(ERROR) << "Failed to mount /proc: " << strerror(-ret);
    return false;
  }

  const base::FilePath art_container_data_directory =
      base::FilePath(kArtDalvikCacheDirectory).DirName();
  ret = minijail_bind(art_jail.get(),
                      art_container_data_directory.value().c_str(), "/data", 1);
  if (ret != 0) {
    LOG(ERROR) << "Failed to mount container data dir: " << strerror(-ret);
    return false;
  }

  ret = minijail_mount_with_data(art_jail.get(), "none", "/", "none",
                                 MS_REC | MS_PRIVATE, nullptr);
  if (ret != 0) {
    LOG(ERROR) << "Failed to mark PRIVATE recursively under pivot root "
               << strerror(-ret);
    return false;
  }

  std::string output_arg;
  switch (sdk_version_) {
    case AndroidSdkVersion::UNKNOWN:
      LOG(ERROR) << "Unknown Android sdk version.";
      return false;
    // For Android P, use --output-image-directory.
    default:
      output_arg = "--output-image-directory=/data/dalvik-cache/" + isa;
      break;
  }

  std::string isa_arg = "--instruction-set=" + isa;

  int32_t offset = ChooseRelocationOffsetDelta(
      kArtBaseAddressMinDelta, kArtBaseAddressMaxDelta, offset_seed);
  std::string base_offset_arg = "--base-offset-delta=" + std::to_string(offset);

  const char* argv[] = {kPatchOat,
                        "--input-image-location=/system/framework/boot.art",
                        output_arg.c_str(),
                        isa_arg.c_str(),
                        base_offset_arg.c_str(),
                        "--dump-timings",
                        nullptr};

  // Set LD_PRELOAD to redirect all logd messages to stderr.
  base::FilePath liblog_stderr_path =
      art_paths_->art_rootfs_directory.Append("system/lib")
          .Append(kLibLogStderrName);
  // TODO(xzhou): Remove the check once the DSO is added to master-arc-dev.
  if (base::PathExists(liblog_stderr_path)) {
    LOG(INFO) << "Preloading " << kLibLogStderrName << " ...";
    // This is executed in a child process and does not change parent's env.
    setenv("LD_PRELOAD", kLibLogStderrName, 1 /* overwrite */);
  } else {
    LOG(ERROR) << "liblog_stderr does not exist, logd message not available";
  }
  LOG(INFO) << "Running " << kPatchOat << " for isa " << isa;
  // Need a android environment, no preload.
  // TODO(xzhou): Fix b/65159408 and run container as non root user.
  ret = minijail_run_no_preload(art_jail.get(), argv[0],
                                const_cast<char**>(argv));
  if (ret != 0) {
    LOG(ERROR) << "Failed to run minijail: " << strerror(-ret);
    return false;
  }

  do {
    ret = minijail_wait(art_jail.get());
  } while (ret == -EINTR);

  LOG(INFO) << "minijail wait return status: " << ret;

  return ret == EXIT_SUCCESS;
}

// static
int32_t ArtContainer::ChooseRelocationOffsetDeltaForTesting(
    int32_t min_delta, int32_t max_delta, uint64_t offset_seed) {
  return ChooseRelocationOffsetDelta(min_delta, max_delta, offset_seed);
}

}  // namespace arc
