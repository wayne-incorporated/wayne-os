// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/service.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <google/protobuf/repeated_field.h>
#include <grp.h>
#include <linux/capability.h>
#include <net/route.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <base/base64url.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/format_macros.h>
#include <base/functional/bind.h>
#include <base/functional/bind_internal.h>
#include <base/functional/callback.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/hash/md5.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/waitable_event.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <base/uuid.h>
#include <base/version.h>
#include <blkid/blkid.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/files/safe_fd.h>
#include <brillo/osrelease_reader.h>
#include <brillo/process/process.h>
#include <chromeos/constants/vm_tools.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <crosvm/qcow_utils.h>
#include <dbus/object_proxy.h>
#include <dbus/shadercached/dbus-constants.h>
#include <dbus/vm_concierge/dbus-constants.h>
#include <spaced/dbus-proxies.h>
#include <spaced/disk_usage_proxy.h>
#include <vm_cicerone/cicerone_service.pb.h>
#include <vm_concierge/concierge_service.pb.h>
#include <vm_protos/proto_bindings/vm_guest.pb.h>

#include "vm_tools/common/naming.h"
#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/arc_vm.h"
#include "vm_tools/concierge/dlc_helper.h"
#include "vm_tools/concierge/future.h"
#include "vm_tools/concierge/if_method_exists.h"
#include "vm_tools/concierge/plugin_vm.h"
#include "vm_tools/concierge/plugin_vm_helper.h"
#include "vm_tools/concierge/seneschal_server_proxy.h"
#include "vm_tools/concierge/shadercached_helper.h"
#include "vm_tools/concierge/shared_data.h"
#include "vm_tools/concierge/ssh_keys.h"
#include "vm_tools/concierge/termina_vm.h"
#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vm_builder.h"
#include "vm_tools/concierge/vm_permission_interface.h"
#include "vm_tools/concierge/vm_util.h"
#include "vm_tools/concierge/vm_wl_interface.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

using std::string;

namespace vm_tools {
namespace concierge {

namespace {

// Default path to VM kernel image and rootfs.
constexpr char kVmDefaultPath[] = "/run/imageloader/cros-termina";

// Name of the VM kernel image.
constexpr char kVmKernelName[] = "vm_kernel";

// Name of the VM rootfs image.
constexpr char kVmRootfsName[] = "vm_rootfs.img";

// Name of the VM tools image to be mounted at kToolsMountPath.
constexpr char kVmToolsDiskName[] = "vm_tools.img";

// The VM instance name of Arcvm
constexpr char kArcVmName[] = "arcvm";

// How long we should wait for a VM to start up.
// While this timeout might be high, it's meant to be a final failure point, not
// the lower bound of how long it takes.  On a loaded system (like extracting
// large compressed files), it could take 10 seconds to boot.
constexpr base::TimeDelta kVmStartupDefaultTimeout = base::Seconds(60);

// crosvm log directory name.
constexpr char kCrosvmLogDir[] = "log";

// Extension for crosvm log files
constexpr char kCrosvmLogFileExt[] = "log";

// Extension for vmlog_forwarder listener sockets.
constexpr char kCrosvmLogSocketExt[] = "lsock";

// crosvm gpu cache directory name.
constexpr char kCrosvmGpuCacheDir[] = "gpucache";

// Path to system boot_id file.
constexpr char kBootIdFile[] = "/proc/sys/kernel/random/boot_id";

// Extended attribute indicating that user has picked a size for a non-sparse
// disk image and it should not be resized.
constexpr char kDiskImagePreallocatedWithUserChosenSizeXattr[] =
    "user.crostini.user_chosen_size";

// File extension for raw disk types
constexpr char kRawImageExtension[] = ".img";

// File extension for qcow2 disk types
constexpr char kQcowImageExtension[] = ".qcow2";

// File extension for Plugin VMs disk types
constexpr char kPluginVmImageExtension[] = ".pvm";

// Valid file extensions for disk images
constexpr const char* kDiskImageExtensions[] = {kRawImageExtension,
                                                kQcowImageExtension, nullptr};

// Valid file extensions for Plugin VM images
constexpr const char* kPluginVmImageExtensions[] = {kPluginVmImageExtension,
                                                    nullptr};

// The Id of the DLC that supplies the Bios for the Bruschetta VM.
constexpr char kBruschettaBiosDlcId[] = "edk2-ovmf-dlc";

// File path for the Bruschetta Bios file inside the DLC root.
constexpr char kBruschettaBiosDlcPath[] = "opt/CROSVM_CODE.fd";

constexpr uint64_t kMinimumDiskSize = 1ll * 1024 * 1024 * 1024;  // 1 GiB
constexpr uint64_t kDiskSizeMask = ~4095ll;  // Round to disk block size.

// vmlog_forwarder relies on creating a socket for crosvm to receive log
// messages. Socket paths may only be 108 character long. Further, while Linux
// actually allows for 108 non-null bytes to be used, the rust interface to bind
// only allows for 107, with the last byte always being null.
//
// We can abbreviate the directories in the path by opening the target directory
// and using /proc/self/fd/ to access it, but this still uses up
// 21 + (fd digits) characters on the prefix and file extension. This leaves us
// with 86 - (fd digits) characters for the base64 encoding of the VM
// name. Base64 always produces encoding that are a multiple of 4 digits long,
// so we can either allow for 63/84 characters before/after encoding, or
// 60/80. The first will break if our file descriptor numbers ever go above 99,
// which seems unlikely but not impossible. We can definitely be sure they won't
// go above 99,999, however.
constexpr int kMaxVmNameLength = 60;

constexpr uint64_t kDefaultIoLimit = 1024 * 1024;  // 1 Mib

// How often we should broadcast state of a disk operation (import or export).
constexpr base::TimeDelta kDiskOpReportInterval = base::Seconds(15);

// The minimum kernel version of the host which supports virtio-pmem.
constexpr KernelVersionAndMajorRevision kMinKernelVersionForVirtioPmem =
    std::make_pair(4, 4);

// File path that reports the L1TF vulnerability status.
constexpr const char kL1TFFilePath[] =
    "/sys/devices/system/cpu/vulnerabilities/l1tf";

// File path that reports the MDS vulnerability status.
constexpr const char kMDSFilePath[] =
    "/sys/devices/system/cpu/vulnerabilities/mds";

// Path of system timezone file.
constexpr char kLocaltimePath[] = "/etc/localtime";
// Path to zone info directory in host.
constexpr char kZoneInfoPath[] = "/usr/share/zoneinfo";

// Feature name of per-boot-vm-shader-cache
constexpr char kPerBootVmShaderCacheFeature[] = "VmPerBootShaderCache";

constexpr gid_t kCrosvmUGid = 299;

// A feature name for throttling ARCVM's crosvm with cpu.cfs_quota_us.
constexpr char kArcVmInitialThrottleFeatureName[] =
    "CrOSLateBootArcVmInitialThrottle";
// A parameter name for |kArcVmInitialThrottleFeatureName|. Can be 1 to 100,
// or -1 (disabled).
constexpr char kArcVmInitialThrottleFeatureQuotaParam[] = "quota";

// Needs to be const as libfeatures does pointers checking.
const VariationsFeature kArcVmInitialThrottleFeature{
    kArcVmInitialThrottleFeatureName, FEATURE_DISABLED_BY_DEFAULT};

// Rational for setting bytes-per-inode to 32KiB (rather than the default 16
// KiB) in go/borealis-inode.
const uint64_t kExt4BytesPerInode = 32768;

// Opts to be used when making an ext4 image. Note: these were specifically
// selected for Borealis, please take care when using outside of Borealis
// (especially the casefold feature).
const std::vector<std::string> kExtMkfsOpts = {
    "-Elazy_itable_init=0,lazy_journal_init=0,discard", "-Ocasefold",
    "-i" + std::to_string(kExt4BytesPerInode)};

// TODO(b/280391260): Use dynamic target based on device's disk size.
// A TBW limit that is unlikely to impact disk health over the lifetime of a
// given device
constexpr uint64_t kTbwTargetForVmmSwapPerDay = 550 * 1024 * 1024;  // 550 MiB
// The path to the history file for VmmSwapTbwPolicy.
constexpr char kVmmSwapTbwHistoryFilePath[] =
    "/var/lib/vm_concierge/vmm_swap_policy/tbw_history";

// Maximum size of logs to send through D-Bus. Must be less than the maximum
// D-Bus array length (64 MiB) and the configured maximum message size for the
// system bus (usually 32 MiB).
constexpr int64_t kMaxGetVmLogsSize = 30 * 1024 * 1024;  // 30 MiB

// Fds to all the images required while starting a VM.
struct VmStartImageFds {
  std::optional<base::ScopedFD> kernel_fd;
  std::optional<base::ScopedFD> rootfs_fd;
  std::optional<base::ScopedFD> initrd_fd;
  std::optional<base::ScopedFD> storage_fd;
  std::optional<base::ScopedFD> bios_fd;
  std::optional<base::ScopedFD> pflash_fd;
};

// Args related to CPU configuration for a VM.
struct VmCpuArgs {
  std::string cpu_affinity;
  std::vector<std::string> cpu_capacity;
  std::vector<std::vector<std::string>> cpu_clusters;
};

std::optional<VmStartImageFds> GetVmStartImageFds(
    const std::unique_ptr<dbus::MessageReader>& reader,
    const google::protobuf::RepeatedField<int>& fds) {
  struct VmStartImageFds result;
  for (const auto& fdType : fds) {
    base::ScopedFD fd;
    if (!reader->PopFileDescriptor(&fd)) {
      LOG(ERROR) << "Failed to pop VM start image file descriptor";
      return std::nullopt;
    }
    switch (fdType) {
      case StartVmRequest_FdType_KERNEL:
        result.kernel_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_ROOTFS:
        result.rootfs_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_INITRD:
        result.initrd_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_STORAGE:
        result.storage_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_BIOS:
        result.bios_fd = std::move(fd);
        break;
      case StartVmRequest_FdType_PFLASH:
        result.pflash_fd = std::move(fd);
        break;
      default:
        LOG(WARNING) << "received request with unknown FD type " << fdType
                     << ". Ignoring.";
    }
  }
  return result;
}

std::string ConvertToFdBasedPaths(brillo::SafeFD& root_fd,
                                  bool is_rootfs_writable,
                                  VMImageSpec& image_spec,
                                  std::vector<brillo::SafeFD>& owned_fds) {
  std::string failure_reason;
  if (image_spec.kernel.empty() && image_spec.bios.empty()) {
    LOG(ERROR) << "neither a kernel nor a BIOS were provided";
    failure_reason = "neither a kernel nor a BIOS were provided";
    return failure_reason;
  }

  if (!image_spec.kernel.empty()) {
    failure_reason =
        ConvertToFdBasedPath(root_fd, &image_spec.kernel, O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM kernel path: " << image_spec.kernel.value();
      failure_reason = "Kernel path does not exist";
      return failure_reason;
    }
  }

  if (!image_spec.bios.empty()) {
    failure_reason =
        ConvertToFdBasedPath(root_fd, &image_spec.bios, O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM BIOS path: " << image_spec.bios.value();
      failure_reason = "BIOS path does not exist";
      return failure_reason;
    }
  }

  if (!image_spec.pflash.empty()) {
    failure_reason =
        ConvertToFdBasedPath(root_fd, &image_spec.pflash, O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM pflash path: " << image_spec.pflash.value();
      failure_reason = "pflash path does not exist";
      return failure_reason;
    }
  }

  if (!image_spec.initrd.empty()) {
    failure_reason =
        ConvertToFdBasedPath(root_fd, &image_spec.initrd, O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM initrd path: " << image_spec.initrd.value();
      failure_reason = "Initrd path does not exist";
      return failure_reason;
    }
  }

  if (!image_spec.rootfs.empty()) {
    failure_reason =
        ConvertToFdBasedPath(root_fd, &image_spec.rootfs,
                             is_rootfs_writable ? O_RDWR : O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Missing VM rootfs path: " << image_spec.rootfs.value();
      failure_reason = "Rootfs path does not exist";
      return failure_reason;
    }
  }

  return failure_reason;
}

VmCpuArgs GetVmCpuArgs(int32_t cpus) {
  VmCpuArgs result;
  // Group the CPUs by their physical package ID to determine CPU cluster
  // layout.
  std::vector<std::vector<std::string>> cpu_clusters;
  std::map<int32_t, std::vector<std::string>> cpu_capacity_groups;
  std::vector<std::string> cpu_capacity;
  for (int32_t cpu = 0; cpu < cpus; cpu++) {
    auto physical_package_id = GetCpuPackageId(cpu);
    if (physical_package_id) {
      CHECK_GE(*physical_package_id, 0);
      if (*physical_package_id + 1 > cpu_clusters.size())
        cpu_clusters.resize(*physical_package_id + 1);
      cpu_clusters[*physical_package_id].push_back(std::to_string(cpu));
    }

    auto capacity = GetCpuCapacity(cpu);
    if (capacity) {
      CHECK_GE(*capacity, 0);
      cpu_capacity.push_back(base::StringPrintf("%d=%d", cpu, *capacity));
      auto group = cpu_capacity_groups.find(*capacity);
      if (group != cpu_capacity_groups.end()) {
        group->second.push_back(std::to_string(cpu));
      } else {
        auto g = {std::to_string(cpu)};
        cpu_capacity_groups.insert({*capacity, g});
      }
    }
  }

  std::optional<std::string> cpu_affinity =
      GetCpuAffinityFromClusters(cpu_clusters, cpu_capacity_groups);
  if (cpu_affinity) {
    result.cpu_affinity = *cpu_affinity;
  }
  result.cpu_capacity = std::move(cpu_capacity);
  result.cpu_clusters = std::move(cpu_clusters);
  return result;
}

void SetVmCpuArgs(int32_t cpus, VmBuilder& vm_builder) {
  VmCpuArgs vm_cpu_args = GetVmCpuArgs(cpus);
  if (!vm_cpu_args.cpu_affinity.empty()) {
    vm_builder.AppendCustomParam("--cpu-affinity", vm_cpu_args.cpu_affinity);
  }

  if (!vm_cpu_args.cpu_capacity.empty()) {
    vm_builder.AppendCustomParam(
        "--cpu-capacity", base::JoinString(vm_cpu_args.cpu_capacity, ","));
  }

  if (!vm_cpu_args.cpu_clusters.empty()) {
    for (const auto& cluster : vm_cpu_args.cpu_clusters) {
      auto cpu_list = base::JoinString(cluster, ",");
      vm_builder.AppendCustomParam("--cpu-cluster", cpu_list);
    }
  }

  /* Enable hugepages on devices with > 7 GB memory */
  if (base::SysInfo::AmountOfPhysicalMemoryMB() >= 7 * 1024) {
    vm_builder.AppendCustomParam("--hugepages", "");
  }
}

// Posted to a grpc thread to startup a listener service. Puts a copy of
// the pointer to the grpc server in |server_copy| and then signals |event|.
// It will listen on the address specified in |listener_address|.
void RunListenerService(grpc::Service* listener,
                        const std::string& listener_address,
                        base::WaitableEvent* event,
                        std::shared_ptr<grpc::Server>* server_copy) {
  // Build the grpc server.
  grpc::ServerBuilder builder;
  builder.AddListeningPort(listener_address, grpc::InsecureServerCredentials());
  builder.RegisterService(listener);

  std::shared_ptr<grpc::Server> server(builder.BuildAndStart().release());

  *server_copy = server;
  event->Signal();

  if (server) {
    server->Wait();
  }
}

// Sets up a gRPC listener service by starting the |grpc_thread| and posting
// the main task to run for the thread. |listener_address| should be the
// address the gRPC server is listening on. A copy of the pointer to the
// server is put in |server_copy|. Returns true if setup & started
// successfully, false otherwise.
bool SetupListenerService(base::Thread* grpc_thread,
                          grpc::Service* listener_impl,
                          const std::string& listener_address,
                          std::shared_ptr<grpc::Server>* server_copy) {
  // Start the grpc thread.
  if (!grpc_thread->Start()) {
    LOG(ERROR) << "Failed to start grpc thread";
    return false;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool ret = grpc_thread->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&RunListenerService, listener_impl,
                                listener_address, &event, server_copy));
  if (!ret) {
    LOG(ERROR) << "Failed to post server startup task to grpc thread";
    return false;
  }

  // Wait for the VM grpc server to start.
  event.Wait();

  if (!server_copy) {
    LOG(ERROR) << "grpc server failed to start";
    return false;
  }

  return true;
}

// Converts an IPv4 address to a string. The result will be stored in |str|
// on success.
bool IPv4AddressToString(const uint32_t address, std::string* str) {
  CHECK(str);

  char result[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, result, sizeof(result)) != result) {
    return false;
  }
  *str = std::string(result);
  return true;
}

// Get the path to the latest available cros-termina component.
base::FilePath GetLatestVMPath() {
  base::FilePath component_dir(kVmDefaultPath);
  base::FileEnumerator dir_enum(component_dir, false,
                                base::FileEnumerator::DIRECTORIES);

  base::Version latest_version("0");
  base::FilePath latest_path;

  for (base::FilePath path = dir_enum.Next(); !path.empty();
       path = dir_enum.Next()) {
    base::Version version(path.BaseName().value());
    if (!version.IsValid())
      continue;

    if (version > latest_version) {
      latest_version = version;
      latest_path = path;
    }
  }

  return latest_path;
}

// Gets the path to a VM disk given the name, user id, and location.
bool GetDiskPathFromName(
    const std::string& vm_name,
    const std::string& cryptohome_id,
    StorageLocation storage_location,
    bool create_parent_dir,
    base::FilePath* path_out,
    enum DiskImageType preferred_image_type = DiskImageType::DISK_IMAGE_AUTO) {
  switch (storage_location) {
    case STORAGE_CRYPTOHOME_ROOT: {
      const auto qcow2_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kQcowImageExtension, create_parent_dir);
      if (!qcow2_path) {
        if (create_parent_dir)
          LOG(ERROR) << "Failed to get qcow2 path";
        return false;
      }
      const auto raw_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kRawImageExtension, create_parent_dir);
      if (!raw_path) {
        if (create_parent_dir)
          LOG(ERROR) << "Failed to get raw path";
        return false;
      }

      const bool qcow2_exists = base::PathExists(*qcow2_path);
      const bool raw_exists = base::PathExists(*raw_path);

      // This scenario (both <name>.img and <name>.qcow2 exist) should never
      // happen. It is prevented by the later checks in this function.
      // However, in case it does happen somehow (e.g. user manually created
      // files in dev mode), bail out, since we can't tell which one the user
      // wants.
      if (qcow2_exists && raw_exists) {
        LOG(ERROR) << "Both qcow2 and raw variants of " << vm_name
                   << " already exist.";
        return false;
      }

      // Return the path to an existing image of any type, if one exists.
      // If not, generate a path based on the preferred image type.
      if (qcow2_exists) {
        *path_out = *qcow2_path;
      } else if (raw_exists) {
        *path_out = *raw_path;
      } else if (preferred_image_type == DISK_IMAGE_QCOW2) {
        *path_out = *qcow2_path;
      } else if (preferred_image_type == DISK_IMAGE_RAW ||
                 preferred_image_type == DISK_IMAGE_AUTO) {
        *path_out = *raw_path;
      } else {
        LOG(ERROR) << "Unknown image type " << preferred_image_type;
        return false;
      }
      return true;
    }
    case STORAGE_CRYPTOHOME_PLUGINVM: {
      const auto plugin_path =
          GetFilePathFromName(cryptohome_id, vm_name, storage_location,
                              kPluginVmImageExtension, create_parent_dir);
      if (!plugin_path) {
        if (create_parent_dir)
          LOG(ERROR) << "failed to get plugin path";
        return false;
      }
      *path_out = *plugin_path;
      return true;
    }
    default:
      LOG(ERROR) << "Unknown storage location type";
      return false;
  }
}

bool CheckVmExists(const std::string& vm_name,
                   const std::string& cryptohome_id,
                   base::FilePath* out_path = nullptr,
                   StorageLocation* storage_location = nullptr) {
  for (int l = StorageLocation_MIN; l <= StorageLocation_MAX; l++) {
    StorageLocation location = static_cast<StorageLocation>(l);
    base::FilePath disk_path;
    if (GetDiskPathFromName(vm_name, cryptohome_id, location,
                            false, /* create_parent_dir */
                            &disk_path) &&
        base::PathExists(disk_path)) {
      if (out_path) {
        *out_path = disk_path;
      }
      if (storage_location) {
        *storage_location = location;
      }
      return true;
    }
  }

  return false;
}

// Returns the desired size of VM disks, which is 90% of the available space
// (excluding the space already taken up by the disk). If storage ballooning
// is being used, we instead return 95% of the total disk space.
uint64_t CalculateDesiredDiskSize(base::FilePath disk_location,
                                  uint64_t current_usage,
                                  bool storage_ballooning = false) {
  if (storage_ballooning) {
    auto total_space =
        base::SysInfo::AmountOfTotalDiskSpace(disk_location.DirName());
    return ((total_space * 95) / 100) & kDiskSizeMask;
  }
  uint64_t free_space =
      base::SysInfo::AmountOfFreeDiskSpace(disk_location.DirName());
  free_space += current_usage;
  uint64_t disk_size = ((free_space * 9) / 10) & kDiskSizeMask;

  return std::max(disk_size, kMinimumDiskSize);
}

// Returns true if the disk should not be automatically resized because it is
// not sparse and its size was specified by the user.
bool IsDiskPreallocatedWithUserChosenSize(const std::string& disk_path) {
  return getxattr(disk_path.c_str(),
                  kDiskImagePreallocatedWithUserChosenSizeXattr, NULL, 0) >= 0;
}

// Mark a non-sparse disk with an xattr indicating its size has been chosen by
// the user.
bool SetPreallocatedWithUserChosenSizeAttr(const base::ScopedFD& fd) {
  // The xattr value doesn't matter, only its existence.
  // Store something human-readable for debugging.
  constexpr char val[] = "1";
  return fsetxattr(fd.get(), kDiskImagePreallocatedWithUserChosenSizeXattr, val,
                   sizeof(val), 0) == 0;
}

void FormatDiskImageStatus(const DiskImageOperation* op,
                           DiskImageStatusResponse* status) {
  status->set_status(op->status());
  status->set_command_uuid(op->uuid());
  status->set_failure_reason(op->failure_reason());
  status->set_progress(op->GetProgress());
}

uint64_t GetFileUsage(const base::FilePath& path) {
  struct stat st;
  if (stat(path.value().c_str(), &st) == 0) {
    // Use the st_blocks value to get the space usage (as in 'du') of the
    // file. st_blocks is always in units of 512 bytes, regardless of the
    // underlying filesystem and block device block size.
    return st.st_blocks * 512;
  }
  return 0;
}

// Returns the current kernel version. If there is a failure to retrieve the
// version it returns <INT_MIN, INT_MIN>.
KernelVersionAndMajorRevision GetKernelVersion() {
  struct utsname buf;
  if (uname(&buf))
    return std::make_pair(INT_MIN, INT_MIN);

  // Parse uname result in the form of x.yy.zzz. The parsed data should be in
  // the expected format.
  std::vector<base::StringPiece> versions = base::SplitStringPiece(
      buf.release, ".", base::WhitespaceHandling::TRIM_WHITESPACE,
      base::SplitResult::SPLIT_WANT_ALL);
  DCHECK_EQ(versions.size(), 3);
  DCHECK(!versions[0].empty());
  DCHECK(!versions[1].empty());
  int version;
  bool result = base::StringToInt(versions[0], &version);
  DCHECK(result);
  int major_revision;
  result = base::StringToInt(versions[1], &major_revision);
  DCHECK(result);
  return std::make_pair(version, major_revision);
}

// vm_name should always be less then kMaxVmNameLength characters long.
base::FilePath GetVmLogPath(const std::string& owner_id,
                            const std::string& vm_name,
                            const std::string& extension,
                            bool log_to_cryptohome = true) {
  if (!log_to_cryptohome) {
    return base::FilePath();
  }
  std::string encoded_vm_name = GetEncodedName(vm_name);

  base::FilePath path = base::FilePath(kCryptohomeRoot)
                            .Append(kCrosvmDir)
                            .Append(owner_id)
                            .Append(kCrosvmLogDir)
                            .Append(encoded_vm_name)
                            .AddExtension(extension);

  base::FilePath parent_dir = path.DirName();
  if (!base::DirectoryExists(parent_dir)) {
    base::File::Error dir_error;
    if (!base::CreateDirectoryAndGetError(parent_dir, &dir_error)) {
      LOG(ERROR) << "Failed to create crosvm log directory in " << parent_dir
                 << ": " << base::File::ErrorToString(dir_error);
      return base::FilePath();
    }
  }
  return path;
}

// Returns a hash string that is safe to use as a filename.
std::string GetMd5HashForFilename(const std::string& str) {
  std::string result;
  base::MD5Digest digest;
  base::MD5Sum(str.data(), str.size(), &digest);
  base::StringPiece hash_piece(reinterpret_cast<char*>(&digest.a[0]),
                               sizeof(digest.a));
  // Note, we can not have '=' symbols in this path or it will break crosvm's
  // commandline argument parsing, so we use OMIT_PADDING.
  base::Base64UrlEncode(hash_piece, base::Base64UrlEncodePolicy::OMIT_PADDING,
                        &result);
  return result;
}

// Returns whether the VM is trusted or untrusted based on the source image,
// whether we're passing custom kernel args, the host kernel version and a
// flag passed down by the user.
bool IsUntrustedVM(bool run_as_untrusted,
                   bool is_trusted_image,
                   bool has_custom_kernel_params,
                   KernelVersionAndMajorRevision host_kernel_version) {
  // Nested virtualization is enabled for all kernels >=
  // |kMinKernelVersionForUntrustedAndNestedVM|. This means that even with a
  // trusted image the VM started will essentially be untrusted.
  if (host_kernel_version >= kMinKernelVersionForUntrustedAndNestedVM)
    return true;

  // Any untrusted image definitely results in an unstrusted VM.
  if (!is_trusted_image)
    return true;

  // Arbitrary kernel params cannot be trusted.
  if (has_custom_kernel_params)
    return true;

  if (run_as_untrusted)
    return true;

  return false;
}

// Clears close-on-exec flag for a file descriptor to pass it to a subprocess
// such as crosvm. Returns a failure reason on failure.
string RemoveCloseOnExec(int raw_fd) {
  int flags = fcntl(raw_fd, F_GETFD);
  if (flags == -1) {
    return "Failed to get flags for passed fd";
  }

  flags &= ~FD_CLOEXEC;
  if (fcntl(raw_fd, F_SETFD, flags) == -1) {
    return "Failed to clear close-on-exec flag for fd";
  }

  return "";
}

// Reclaims memory of the crosvm process with |pid| by writing "shmem" to
// /proc/<pid>/reclaim. Since this function may block 10 seconds or more, do
// not call on the main thread.
ReclaimVmMemoryResponse ReclaimVmMemoryInternal(pid_t pid, int32_t page_limit) {
  ReclaimVmMemoryResponse response;

  if (page_limit < 0) {
    LOG(ERROR) << "Invalid negative page_limit " << page_limit;
    response.set_failure_reason("Negative page_limit");
    return response;
  }

  const std::string path = base::StringPrintf("/proc/%d/reclaim", pid);
  base::ScopedFD fd(
      HANDLE_EINTR(open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW)));
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open " << path;
    response.set_failure_reason("Failed to open /proc filesystem");
    return response;
  }

  const std::string reclaim = "shmem";
  std::list commands = {reclaim};
  if (page_limit != 0) {
    LOG(INFO) << "per-process reclaim active: [" << page_limit << "] pages";
    commands.push_front(reclaim + " " + base::NumberToString(page_limit));
  }
  ssize_t bytes_written = 0;
  int attempts = 0;
  bool write_ok = false;
  for (const auto& v : commands) {
    ++attempts;
    // We want to open the file only once, and write two times to it,
    // different values.  WriteFile() and its variants would
    // open/close/write,  which would cause an unnecessary open/close
    // cycle, so we use write() directly.
    bytes_written = HANDLE_EINTR(write(fd.get(), v.c_str(), v.size()));
    write_ok = (bytes_written == v.size());
    if (write_ok || (errno != EINVAL)) {
      break;
    }
  }

  if (!write_ok) {
    PLOG(ERROR) << "Failed to write to " << path
                << " bytes_written: " << bytes_written
                << " attempts: " << attempts;
    response.set_failure_reason("Failed to write to /proc filesystem");
    return response;
  }

  LOG(INFO) << "Successfully reclaimed VM memory. PID=" << pid;
  response.set_success(true);
  return response;
}

// Determines what classification type this VM has. Classifications are
// roughly related to products, and the classification broadly determines what
// features are available to a given VM.
//
// TODO(b/213090722): Determining a VM's type based on its properties like
// this is undesirable. Instead we should provide the type in the request, and
// determine its properties from that.
VmId::Type ClassifyVm(const StartVmRequest& request) {
  if (request.vm_type() == VmInfo::BOREALIS ||
      request.vm().dlc_id() == "borealis-dlc")
    return VmId::Type::BOREALIS;
  if (request.vm_type() == VmInfo::TERMINA || request.start_termina())
    return VmId::Type::TERMINA;
  // Bruschetta VMs are distinguished by having a separate bios, either as an FD
  // or a dlc.
  bool has_bios_fd =
      std::any_of(request.fds().begin(), request.fds().end(),
                  [](int type) { return type == StartVmRequest::BIOS; });
  if (request.vm_type() == VmInfo::BRUSCHETTA || has_bios_fd ||
      request.vm().dlc_id() == "edk2-ovmf-dlc")
    return VmId::Type::BRUSCHETTA;
  return VmId::Type::UNKNOWN;
}

}  // namespace

base::FilePath Service::GetVmGpuCachePathInternal(const std::string& owner_id,
                                                  const std::string& vm_name) {
  std::string vm_dir;
  // Note, we can not have '=' symbols in this path or it will break crosvm's
  // commandline argument parsing, so we use OMIT_PADDING.
  base::Base64UrlEncode(vm_name, base::Base64UrlEncodePolicy::OMIT_PADDING,
                        &vm_dir);

  std::string cache_id;
  std::string error;
  std::optional<bool> per_boot_cache =
      IsFeatureEnabled(kPerBootVmShaderCacheFeature, &error);
  if (!per_boot_cache.has_value()) {
    LOG(WARNING) << "Failed to check per-boot cache feature: " << error
                 << ", failing back to per-boot cache";
  }

  // if per-boot cache feature is enabled or we failed to read BUILD_ID from
  // /etc/os-release, set |cache_id| as boot-id.
  brillo::OsReleaseReader reader;
  reader.Load();
  if (per_boot_cache.value_or(true) ||
      !reader.GetString("BUILD_ID", &cache_id)) {
    CHECK(base::ReadFileToString(base::FilePath(kBootIdFile), &cache_id));
  }

  return base::FilePath(kCryptohomeRoot)
      .Append(kCrosvmDir)
      .Append(owner_id)
      .Append(kCrosvmGpuCacheDir)
      .Append(GetMd5HashForFilename(cache_id))
      .Append(vm_dir);
}

std::optional<int64_t> Service::GetAvailableMemory() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetAvailableMemoryKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get available memory size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint64_t available_kb;
  if (!reader.PopUint64(&available_kb)) {
    LOG(ERROR)
        << "Failed to read available memory size from the D-Bus response";
    return std::nullopt;
  }
  return available_kb * KIB;
}

std::optional<int64_t> Service::GetForegroundAvailableMemory() {
  dbus::MethodCall method_call(
      resource_manager::kResourceManagerInterface,
      resource_manager::kGetForegroundAvailableMemoryKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR)
        << "Failed to get foreground available memory size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint64_t available_kb;
  if (!reader.PopUint64(&available_kb)) {
    LOG(ERROR) << "Failed to read foreground available memory size from the "
                  "D-Bus response";
    return std::nullopt;
  }
  return available_kb * KIB;
}

std::optional<MemoryMargins> Service::GetMemoryMargins() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetMemoryMarginsKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get critical margin size from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  MemoryMargins margins;
  if (!reader.PopUint64(&margins.critical)) {
    LOG(ERROR)
        << "Failed to read available critical margin from the D-Bus response";
    return std::nullopt;
  }
  if (!reader.PopUint64(&margins.moderate)) {
    LOG(ERROR)
        << "Failed to read available moderate margin from the D-Bus response";
    return std::nullopt;
  }
  margins.critical *= KIB;
  margins.moderate *= KIB;
  return margins;
}

std::optional<ComponentMemoryMargins> Service::GetComponentMemoryMargins() {
  static constexpr char kChromeCriticalKey[] = "ChromeCritical";
  static constexpr char kChromeModerateKey[] = "ChromeModerate";
  static constexpr char kArcvmForegroundKey[] = "ArcvmForeground";
  static constexpr char kArcvmPerceptibleKey[] = "ArcvmPerceptible";
  static constexpr char kArcvmCachedKey[] = "ArcvmCached";

  dbus::MethodCall method_call(
      resource_manager::kResourceManagerInterface,
      resource_manager::kGetComponentMemoryMarginsKBMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get component margin sizes from resourced.";
    return std::nullopt;
  }

  dbus::MessageReader reader(dbus_response.get());
  dbus::MessageReader array_reader(nullptr);
  if (!reader.PopArray(&array_reader)) {
    LOG(ERROR) << "Failed parsing component memory margins";
    return std::nullopt;
  }

  ComponentMemoryMargins margins;

  while (array_reader.HasMoreData()) {
    dbus::MessageReader dict_entry_reader(nullptr);
    if (array_reader.PopDictEntry(&dict_entry_reader)) {
      std::string key;
      uint64_t value;
      if (!dict_entry_reader.PopString(&key) ||
          !dict_entry_reader.PopUint64(&value)) {
        LOG(ERROR) << "Error popping dictionary entry from D-Bus message";
        return std::nullopt;
      }
      value *= KIB;
      if (key == kChromeCriticalKey) {
        margins.chrome_critical = value;
      } else if (key == kChromeModerateKey) {
        margins.chrome_moderate = value;
      } else if (key == kArcvmForegroundKey) {
        margins.arcvm_foreground = value;
      } else if (key == kArcvmPerceptibleKey) {
        margins.arcvm_perceptible = value;
      } else if (key == kArcvmCachedKey) {
        margins.arcvm_cached = value;
      } else {
        LOG(ERROR) << "Unrecognized dict entry for component memory margins";
      }
    }
  }
  return margins;
}

std::optional<resource_manager::GameMode> Service::GetGameMode() {
  dbus::MethodCall method_call(resource_manager::kResourceManagerInterface,
                               resource_manager::kGetGameModeMethod);
  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, resource_manager_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to get geme mode from resourced";
    return std::nullopt;
  }
  dbus::MessageReader reader(dbus_response.get());
  uint8_t game_mode;
  if (!reader.PopByte(&game_mode)) {
    LOG(ERROR) << "Failed to read game mode from the D-Bus response";
    return std::nullopt;
  }
  return static_cast<resource_manager::GameMode>(game_mode);
}

static std::optional<std::string> GameModeToForegroundVmName(
    resource_manager::GameMode game_mode) {
  using resource_manager::GameMode;
  if (game_mode == GameMode::BOREALIS) {
    return "borealis";
  }
  if (game_mode == GameMode::OFF) {
    return std::nullopt;
  }
  LOG(ERROR) << "Unexpected game mode value " << static_cast<int>(game_mode);
  return std::nullopt;
}

// Runs balloon policy against each VM to balance memory.
// This will be called periodically by balloon_resizing_timer_.
void Service::RunBalloonPolicy() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // TODO(b/191946183): Design and migrate to a new D-Bus API
  // that is less chatty for implementing balloon logic.

  if (vms_.size() == 0) {
    // If there are no VMs there are no balloon policies to
    // run. The timer will be restarted when a new VM is launched.
    balloon_resizing_timer_.Stop();
    LOG(INFO) << "Stopping balloon resize timer.";
    return;
  }

  std::optional<MemoryMargins> memory_margins_opt = GetMemoryMargins();
  if (!memory_margins_opt) {
    LOG(ERROR) << "Failed to get ChromeOS memory margins";
    return;
  }
  MemoryMargins memory_margins = *memory_margins_opt;

  const auto available_memory = GetAvailableMemory();
  if (!available_memory.has_value()) {
    return;
  }
  const auto game_mode = GetGameMode();
  if (!game_mode.has_value()) {
    return;
  }
  std::optional<int64_t> foreground_available_memory;
  if (*game_mode != resource_manager::GameMode::OFF) {
    // foreground_available_memory is only used when the game mode is enabled.
    foreground_available_memory = GetForegroundAvailableMemory();
    if (!foreground_available_memory.has_value()) {
      return;
    }
  }

  std::optional<ComponentMemoryMargins> component_margins =
      GetComponentMemoryMargins();
  if (!component_margins) {
    LOG(ERROR) << "Failed to get component memory margins";
    return;
  }

  const auto foreground_vm_name = GameModeToForegroundVmName(*game_mode);
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      // Skip suspended VMs since there is no effect.
      continue;
    }

    const std::unique_ptr<BalloonPolicyInterface>& policy =
        vm->GetBalloonPolicy(memory_margins, vm_entry.first.name());
    if (!policy) {
      // Skip VMs that don't have a memory policy. It may just not be ready
      // yet.
      continue;
    }

    auto stats_opt = vm->GetBalloonStats();
    if (!stats_opt) {
      // Stats not available. Skip running policies.
      continue;
    }
    BalloonStats stats = *stats_opt;

    // Switch available memory for this VM based on the current game mode.
    bool is_in_game_mode = foreground_vm_name.has_value() &&
                           vm_entry.first.name() == foreground_vm_name;
    const int64_t available_memory_for_vm =
        is_in_game_mode ? *foreground_available_memory : *available_memory;

    int64_t delta = policy->ComputeBalloonDelta(
        stats, available_memory_for_vm, is_in_game_mode, vm_entry.first.name(),
        *available_memory, *component_margins);

    uint64_t target =
        std::max(static_cast<int64_t>(0),
                 static_cast<int64_t>(stats.balloon_actual) + delta);
    if (target != stats.balloon_actual) {
      vm->SetBalloonSize(target);
    }
  }
}

std::optional<bool> Service::IsFeatureEnabled(const std::string& feature_name,
                                              std::string* error_out) {
  dbus::MethodCall method_call(
      chromeos::kChromeFeaturesServiceInterface,
      chromeos::kChromeFeaturesServiceIsFeatureEnabledMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(feature_name);

  dbus::ScopedDBusError error;
  auto dbus_response = brillo::dbus_utils::CallDBusMethodWithErrorResponse(
      bus_, chrome_features_service_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &error);
  if (error.is_set()) {
    *error_out = error.message();
    return std::nullopt;
  }

  dbus::MessageReader reader(dbus_response.get());
  bool result;
  if (!reader.PopBool(&result)) {
    *error_out = "Failed to read bool from D-Bus response";
    return std::nullopt;
  }

  *error_out = "";
  return result;
}

bool Service::ListVmDisksInLocation(const string& cryptohome_id,
                                    StorageLocation location,
                                    const string& lookup_name,
                                    ListVmDisksResponse* response) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  base::FilePath image_dir;
  base::FileEnumerator::FileType file_type = base::FileEnumerator::FILES;
  const char* const* allowed_ext = kDiskImageExtensions;
  switch (location) {
    case STORAGE_CRYPTOHOME_ROOT:
      image_dir = base::FilePath(kCryptohomeRoot)
                      .Append(kCrosvmDir)
                      .Append(cryptohome_id);
      break;

    case STORAGE_CRYPTOHOME_PLUGINVM:
      image_dir = base::FilePath(kCryptohomeRoot)
                      .Append(kPluginVmDir)
                      .Append(cryptohome_id);
      file_type = base::FileEnumerator::DIRECTORIES;
      allowed_ext = kPluginVmImageExtensions;
      break;

    default:
      response->set_failure_reason("Unsupported storage location for images");
      return false;
  }

  if (!base::DirectoryExists(image_dir)) {
    // No directory means no VMs, return the empty response.
    return true;
  }

  uint64_t total_size = 0;
  base::FileEnumerator dir_enum(image_dir, false, file_type);
  for (base::FilePath path = dir_enum.Next(); !path.empty();
       path = dir_enum.Next()) {
    string extension = path.BaseName().Extension();
    bool allowed = false;
    for (auto p = allowed_ext; *p; p++) {
      if (extension == *p) {
        allowed = true;
        break;
      }
    }
    if (!allowed) {
      continue;
    }

    base::FilePath bare_name = path.BaseName().RemoveExtension();
    if (bare_name.empty()) {
      continue;
    }
    std::string image_name = GetDecodedName(bare_name.value());
    if (image_name.empty()) {
      continue;
    }
    if (!lookup_name.empty() && lookup_name != image_name) {
      continue;
    }

    uint64_t size = dir_enum.GetInfo().IsDirectory()
                        ? ComputeDirectorySize(path)
                        : GetFileUsage(path);
    total_size += size;

    uint64_t min_size;
    uint64_t available_space;
    auto iter = FindVm(cryptohome_id, image_name);
    if (iter == vms_.end()) {
      // VM may not be running - in this case, we can't determine min_size or
      // available_space, so report 0 for unknown.
      min_size = 0;
      available_space = 0;
    } else {
      min_size = iter->second->GetMinDiskSize();
      available_space = iter->second->GetAvailableDiskSpace();
    }

    enum DiskImageType image_type = DiskImageType::DISK_IMAGE_AUTO;
    if (extension == kRawImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_RAW;
    } else if (extension == kQcowImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_QCOW2;
    } else if (extension == kPluginVmImageExtension) {
      image_type = DiskImageType::DISK_IMAGE_PLUGINVM;
    }

    VmDiskInfo* image = response->add_images();
    image->set_name(std::move(image_name));
    image->set_storage_location(location);
    image->set_size(size);
    image->set_min_size(min_size);
    image->set_available_space(available_space);
    image->set_image_type(image_type);
    image->set_user_chosen_size(
        IsDiskPreallocatedWithUserChosenSize(path.value()));
    image->set_path(path.value());
  }

  response->set_total_size(response->total_size() + total_size);
  return true;
}

std::unique_ptr<Service> Service::Create(base::OnceClosure quit_closure) {
  auto service = base::WrapUnique(new Service(std::move(quit_closure)));

  if (!service->Init()) {
    service.reset();
  }

  return service;
}

Service::Service(base::OnceClosure quit_closure)
    : next_seneschal_server_port_(kFirstSeneschalServerPort),
      quit_closure_(std::move(quit_closure)),
      host_kernel_version_(GetKernelVersion()),
      weak_ptr_factory_(this) {}

Service::~Service() {
  if (grpc_server_vm_) {
    grpc_server_vm_->Shutdown();
  }
  AsyncNoReject(
      dbus_thread_.task_runner(),
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object) {
            dbus_object.reset();
          },
          std::move(dbus_object_)))
      .Get();
}

void Service::OnSignalReadable() {
  struct signalfd_siginfo siginfo;
  if (read(signal_fd_.get(), &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
    PLOG(ERROR) << "Failed to read from signalfd";
    return;
  }

  if (siginfo.ssi_signo == SIGCHLD) {
    HandleChildExit();
  } else if (siginfo.ssi_signo == SIGTERM) {
    HandleSigterm();
  } else {
    LOG(ERROR) << "Received unknown signal from signal fd: "
               << strsignal(siginfo.ssi_signo);
  }
}

bool Service::Init() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // It's not possible to ask minijail to set up a user namespace and switch to
  // a non-0 uid/gid, or to set up supplemental groups. Concierge needs both
  // supplemental groups and to run as a user whose id is unchanged from the
  // root namespace (dbus authentication requires this), so we configure this
  // here.
  if (setresuid(kCrosvmUGid, kCrosvmUGid, kCrosvmUGid) < 0) {
    PLOG(ERROR) << "Failed to set uid to crosvm";
    return false;
  }
  if (setresgid(kCrosvmUGid, kCrosvmUGid, kCrosvmUGid) < 0) {
    PLOG(ERROR) << "Failed to set gid to crosvm";
    return false;
  }
  // Ideally we would just call initgroups("crosvm") here, but internally glibc
  // interprets EINVAL as signaling that the list of supplemental groups is too
  // long and truncates the list, when it could also indicate that some of the
  // gids are unmapped in the current namespace. Instead we look up the groups
  // ourselves so we can log a useful error if the mapping is wrong.
  int ngroups = 0;
  getgrouplist("crosvm", kCrosvmUGid, nullptr, &ngroups);
  std::vector<gid_t> groups(ngroups);
  if (getgrouplist("crosvm", kCrosvmUGid, groups.data(), &ngroups) < 0) {
    PLOG(ERROR) << "Failed to get supplemental groups for user crosvm";
    return false;
  }
  if (setgroups(ngroups, groups.data()) < 0) {
    PLOG(ERROR)
        << "Failed to set supplemental groups. This probably means you have "
           "added user crosvm to groups that are not mapped in the concierge "
           "user namespace and need to update vm_concierge.conf.";
    return false;
  }

  // Change the umask so that the runtime directory for each VM will get the
  // right permissions.
  umask(002);

  // Set up the signalfd for receiving SIGCHLD and SIGTERM.
  // This applies to all threads created afterwards.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGTERM);

  // Restore process' "dumpable" flag so that /proc will be writable.
  // We need it to properly set up jail for Plugin VM helper process.
  if (prctl(PR_SET_DUMPABLE, 1) < 0) {
    PLOG(ERROR) << "Failed to set PR_SET_DUMPABLE";
    return false;
  }

  signal_fd_.reset(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create signalfd";
    return false;
  }

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(),
      base::BindRepeating(&Service::OnSignalReadable, base::Unretained(this)));
  if (!watcher_) {
    LOG(ERROR) << "Failed to watch signalfd";
    return false;
  }

  // Now block signals from the normal signal handling path so that we will get
  // them via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed to block signals via sigprocmask";
    return false;
  }

  // TODO(b/193806814): This log line helps us detect when there is a race
  // during signal setup. When we eventually fix that bug we won't need it.
  LOG(INFO) << "Finished setting up signal handlers";

  if (!dbus_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start dbus thread";
    return false;
  }

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  opts.dbus_task_runner = dbus_thread_.task_runner();
  bus_ = new dbus::Bus(std::move(opts));

  if (!AsyncNoReject(dbus_thread_.task_runner(),
                     base::BindOnce(
                         [](scoped_refptr<dbus::Bus> bus) {
                           if (!bus->Connect()) {
                             LOG(ERROR) << "Failed to connect to system bus";
                             return false;
                           }
                           return true;
                         },
                         bus_))
           .Get()
           .val) {
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kVmConciergeServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kVmConciergeServicePath << " object";
    return false;
  }
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr, bus_, dbus::ObjectPath(kVmConciergeServicePath));
  concierge_adaptor_.RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(base::DoNothing());

  untrusted_vm_utils_ = std::make_unique<UntrustedVMUtils>(
      base::FilePath(kL1TFFilePath), base::FilePath(kMDSFilePath));

  dlcservice_client_ = std::make_unique<DlcHelper>(bus_);

  // TODO(b/269214379): Wait for completion for RegisterAsync on
  // chromeos-dbus-bindings after we complete migration and remove
  // ExportMethodAndBlock.
  if (!AsyncNoReject(
           dbus_thread_.task_runner(),
           base::BindOnce(
               [](Service* service, dbus::ExportedObject* exported_object_,
                  scoped_refptr<dbus::Bus> bus) {
                 if (!bus->RequestOwnershipAndBlock(
                         kVmConciergeServiceName, dbus::Bus::REQUIRE_PRIMARY)) {
                   LOG(ERROR) << "Failed to take ownership of "
                              << kVmConciergeServiceName;
                   return false;
                 }

                 return true;
               },
               base::Unretained(this), base::Unretained(exported_object_),
               bus_))
           .Get()
           .val) {
    return false;
  }

  // Set up the D-Bus client for shill.
  shill_client_ = std::make_unique<ShillClient>(bus_);
  shill_client_->RegisterResolvConfigChangedHandler(base::BindRepeating(
      &Service::OnResolvConfigChanged, weak_ptr_factory_.GetWeakPtr()));
  shill_client_->RegisterDefaultServiceChangedHandler(
      base::BindRepeating(&Service::OnDefaultNetworkServiceChanged,
                          weak_ptr_factory_.GetWeakPtr()));

  // Set up the D-Bus client for powerd and register suspend/resume handlers.
  power_manager_client_ = std::make_unique<PowerManagerClient>(bus_);
  power_manager_client_->RegisterSuspendDelay(
      base::BindRepeating(&Service::HandleSuspendImminent,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&Service::HandleSuspendDone,
                          weak_ptr_factory_.GetWeakPtr()));

  // Setup D-Bus proxy for spaced.
  disk_usage_proxy_ = std::make_unique<spaced::DiskUsageProxy>(
      std::make_unique<org::chromium::SpacedProxy>(bus_));
  disk_usage_proxy_->AddObserver(this);
  disk_usage_proxy_->StartMonitoring();

  // Get the D-Bus proxy for communicating with cicerone.
  cicerone_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::cicerone::kVmCiceroneServiceName,
      dbus::ObjectPath(vm_tools::cicerone::kVmCiceroneServicePath));
  if (!cicerone_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::cicerone::kVmCiceroneServiceName;
    return false;
  }
  cicerone_service_proxy_->ConnectToSignal(
      vm_tools::cicerone::kVmCiceroneServiceName,
      vm_tools::cicerone::kTremplinStartedSignal,
      base::BindRepeating(&Service::OnTremplinStartedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&Service::OnSignalConnected,
                     weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with seneschal.
  seneschal_service_proxy_ = bus_->GetObjectProxy(
      vm_tools::seneschal::kSeneschalServiceName,
      dbus::ObjectPath(vm_tools::seneschal::kSeneschalServicePath));
  if (!seneschal_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::seneschal::kSeneschalServiceName;
    return false;
  }

  // Get the D-Bus proxy for communicating with Plugin VM dispatcher.
  vm_permission_service_proxy_ = vm_permission::GetServiceProxy(bus_);
  if (!vm_permission_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for VM permission service";
    return false;
  }

  // Get the D-Bus proxy for communicating with Plugin VM dispatcher.
  vmplugin_service_proxy_ = pvm::dispatcher::GetServiceProxy(bus_);
  if (!vmplugin_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for Plugin VM dispatcher service";
    return false;
  }
  pvm::dispatcher::RegisterVmToolsChangedCallbacks(
      vmplugin_service_proxy_,
      base::BindRepeating(&Service::OnVmToolsStateChangedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&Service::OnSignalConnected,
                     weak_ptr_factory_.GetWeakPtr()));

  // Get the D-Bus proxy for communicating with resource manager.
  resource_manager_service_proxy_ = bus_->GetObjectProxy(
      resource_manager::kResourceManagerServiceName,
      dbus::ObjectPath(resource_manager::kResourceManagerServicePath));
  if (!resource_manager_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << resource_manager::kResourceManagerServiceName;
    return false;
  }

  // Get the D-Bus proxy for communicating with Chrome Features Service.
  chrome_features_service_proxy_ = bus_->GetObjectProxy(
      chromeos::kChromeFeaturesServiceName,
      dbus::ObjectPath(chromeos::kChromeFeaturesServicePath));
  if (!chrome_features_service_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << chromeos::kChromeFeaturesServiceName;
    return false;
  }

  shadercached_proxy_ = bus_->GetObjectProxy(
      shadercached::kShaderCacheServiceName,
      dbus::ObjectPath(shadercached::kShaderCacheServicePath));
  if (!shadercached_proxy_) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << shadercached::kShaderCacheServiceName;
    return false;
  }

  CHECK(feature::PlatformFeatures::Initialize(bus_));

  // Setup & start the gRPC listener services.
  if (!SetupListenerService(
          &grpc_thread_vm_, &startup_listener_,
          base::StringPrintf("vsock:%u:%u", VMADDR_CID_ANY,
                             vm_tools::kDefaultStartupListenerPort),
          &grpc_server_vm_)) {
    LOG(ERROR) << "Failed to setup/startup the VM grpc server";
    return false;
  }

  if (!reclaim_thread_.Start()) {
    LOG(ERROR) << "Failed to start memory reclaim thread";
    return false;
  }

  if (!localtime_watcher_.Watch(
          base::FilePath(kLocaltimePath),
          base::FilePathWatcher::Type::kNonRecursive,
          base::BindRepeating(&Service::OnLocaltimeFileChanged,
                              weak_ptr_factory_.GetWeakPtr()))) {
    LOG(WARNING) << "Failed to initialize file watcher for timezone change";
  }

  vmm_swap_tbw_policy_->SetTargetTbwPerDay(kTbwTargetForVmmSwapPerDay);
  base::FilePath tbw_history_file_path(kVmmSwapTbwHistoryFilePath);
  // VmmSwapTbwPolicy repopulate pessimistic history if it fails to init. This
  // is safe to continue using regardless of the result.
  vmm_swap_tbw_policy_->Init(tbw_history_file_path);

  return true;
}

void Service::HandleChildExit() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // We can't just rely on the information in the siginfo structure because
  // more than one child may have exited but only one SIGCHLD will be
  // generated.
  while (true) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid <= 0) {
      if (pid == -1 && errno != ECHILD) {
        PLOG(ERROR) << "Unable to reap child processes";
      }
      break;
    }

    if (WIFEXITED(status)) {
      if (WEXITSTATUS(status) != 0) {
        LOG(INFO) << "Process " << pid << " exited with status "
                  << WEXITSTATUS(status);
      }
    } else if (WIFSIGNALED(status)) {
      LOG(INFO) << "Process " << pid << " killed by signal " << WTERMSIG(status)
                << (WCOREDUMP(status) ? " (core dumped)" : "");
    } else {
      LOG(WARNING) << "Unknown exit status " << status << " for process "
                   << pid;
    }

    // See if this is a process we launched.
    auto iter = std::find_if(vms_.begin(), vms_.end(), [=](auto& pair) {
      VmBaseImpl::Info info = pair.second->GetInfo();
      return pid == info.pid;
    });

    if (iter != vms_.end()) {
      // Remove it from VMs using storage ballooning. This is quick and needs
      // to be done to clean up balloon state before we notify others of the
      // VM being stopped.
      if (iter->second->GetInfo().storage_ballooning) {
        RemoveStorageBalloonVm(iter->first);
      }

      // Notify that the VM has exited.
      NotifyVmStopped(iter->first, iter->second->GetInfo().cid, VM_EXITED);

      // Now remove it from the vm list.
      vms_.erase(iter);
    }
  }
}

void Service::HandleSigterm() {
  LOG(INFO) << "Shutting down due to SIGTERM";

  StopAllVmsImpl(SERVICE_SHUTDOWN);
  if (!quit_closure_.is_null()) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(quit_closure_));
  }
}

// Helper function to return the filesystem type of a given file/path. If no
// file system exists, or if the function fails, it will return an empty string.
std::string GetFilesystem(const base::FilePath& disk_location) {
  std::string output;
  blkid_cache blkid_cache;
  // No cache file is used as it should always query information from
  // the device, i.e. setting cache file to /dev/null.
  if (blkid_get_cache(&blkid_cache, "/dev/null") != 0) {
    LOG(ERROR) << "Failed to initialize blkid cache handler";
    return output;
  }
  blkid_dev dev = blkid_get_dev(blkid_cache, disk_location.value().c_str(),
                                BLKID_DEV_NORMAL);
  if (!dev) {
    LOG(ERROR) << "Failed to get device for '" << disk_location.value().c_str()
               << "'";
    blkid_put_cache(blkid_cache);
    return output;
  }

  char* filesystem_type =
      blkid_get_tag_value(blkid_cache, "TYPE", disk_location.value().c_str());
  if (filesystem_type) {
    output = filesystem_type;
  }
  blkid_put_cache(blkid_cache);
  return output;
}

void Service::StartVm(dbus::MethodCall* method_call,
                      dbus::ExportedObject::ResponseSender response_sender) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto reader = std::make_unique<dbus::MessageReader>(method_call);

  StartVmRequest request;
  StartVmResponse response;
  // We change to a success status later if necessary.
  response.set_status(VM_STATUS_FAILURE);

  if (!reader->PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse StartVmRequest from message";
    response.set_failure_reason("Unable to parse protobuf");
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  if (!CheckStartVmPreconditions(request, &response)) {
    SendDbusResponse(std::move(response_sender), method_call, response);
    return;
  }

  response = StartVmInternal(std::move(request), std::move(reader));
  SendDbusResponse(std::move(response_sender), method_call, response);
  return;
}

StartVmResponse Service::StartVmInternal(
    StartVmRequest request, std::unique_ptr<dbus::MessageReader> reader) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  StartVmResponse response;
  response.set_status(VM_STATUS_FAILURE);

  VmId::Type classification = ClassifyVm(request);
  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_vm_type(ToLegacyVmType(classification));

  std::optional<VmStartImageFds> vm_start_image_fds =
      GetVmStartImageFds(reader, request.fds());
  if (!vm_start_image_fds) {
    response.set_failure_reason("failed to get a VmStartImage fd");
    return response;
  }

  // Make sure we have our signal connected if starting a Termina VM.
  if (classification == VmId::Type::TERMINA &&
      !is_tremplin_started_signal_connected_) {
    LOG(ERROR) << "Can't start Termina VM without TremplinStartedSignal";
    response.set_failure_reason("TremplinStartedSignal not connected");
    return response;
  }

  if (request.disks_size() > kMaxExtraDisks) {
    LOG(ERROR) << "Rejecting request with " << request.disks_size()
               << " extra disks";
    response.set_failure_reason("Too many extra disks");
    return response;
  }

  // Exists just to keep FDs around for crosvm to inherit
  std::vector<brillo::SafeFD> owned_fds;
  auto root_fd_result = brillo::SafeFD::Root();

  if (brillo::SafeFD::IsError(root_fd_result.second)) {
    LOG(ERROR) << "Could not open root directory: "
               << static_cast<int>(root_fd_result.second);
    response.set_failure_reason("Could not open root directory");
    return response;
  }
  auto root_fd = std::move(root_fd_result.first);

  string failure_reason;
  VMImageSpec image_spec =
      GetImageSpec(request.vm(), vm_start_image_fds->kernel_fd,
                   vm_start_image_fds->rootfs_fd, vm_start_image_fds->initrd_fd,
                   vm_start_image_fds->bios_fd, vm_start_image_fds->pflash_fd,
                   classification == VmId::Type::TERMINA, &failure_reason);
  if (!failure_reason.empty()) {
    LOG(ERROR) << "Failed to get image paths: " << failure_reason;
    response.set_failure_reason("Failed to get image paths: " + failure_reason);
    return response;
  }

  string convert_fd_based_path_result = ConvertToFdBasedPaths(
      root_fd, request.writable_rootfs(), image_spec, owned_fds);
  if (!convert_fd_based_path_result.empty()) {
    response.set_failure_reason(convert_fd_based_path_result);
    return response;
  }

  std::optional<base::FilePath> pflash_result = GetInstalledOrRequestPflashPath(
      VmId(request.owner_id(), request.name()), image_spec.pflash);
  if (!pflash_result) {
    LOG(ERROR) << "Failed to get pflash path";
    response.set_failure_reason("Failed to get pflash path");
    return response;
  }
  // The path can be empty if no pflash file is installed or nothing sent by the
  // user.
  base::FilePath pflash = pflash_result.value();

  const bool is_untrusted_vm =
      IsUntrustedVM(request.run_as_untrusted(), image_spec.is_trusted_image,
                    !request.kernel_params().empty(), host_kernel_version_);
  if (is_untrusted_vm) {
    std::string reason;
    if (!untrusted_vm_utils_->IsUntrustedVMAllowed(host_kernel_version_,
                                                   &reason)) {
      LOG(ERROR) << reason;
      response.set_failure_reason(reason);
      return response;
    }
  }

  // Track the next available virtio-blk device name.
  // Assume that the rootfs filesystem was assigned /dev/pmem0 if
  // pmem is used, /dev/vda otherwise.
  // Assume every subsequent image was assigned a letter in alphabetical order
  // starting from 'b'.
  bool use_pmem = host_kernel_version_ >= kMinKernelVersionForVirtioPmem &&
                  USE_PMEM_DEVICE_FOR_ROOTFS;
  string rootfs_device = use_pmem ? "/dev/pmem0" : "/dev/vda";
  unsigned char disk_letter = use_pmem ? 'a' : 'b';
  std::vector<Disk> disks;

  // In newer components, the /opt/google/cros-containers directory
  // is split into its own disk image(vm_tools.img).  Detect whether it exists
  // to keep compatibility with older components with only vm_rootfs.img.
  string tools_device;
  if (base::PathExists(image_spec.tools_disk)) {
    failure_reason = ConvertToFdBasedPath(root_fd, &image_spec.tools_disk,
                                          O_RDONLY, owned_fds);
    if (!failure_reason.empty()) {
      LOG(ERROR) << "Could not open tools_disk file";
      response.set_failure_reason(failure_reason);
      return response;
    }
    disks.push_back(
        Disk{.path = std::move(image_spec.tools_disk), .writable = false});
    tools_device = base::StringPrintf("/dev/vd%c", disk_letter++);
  }

  if (request.disks().size() == 0) {
    LOG(ERROR) << "Missing required stateful disk";
    response.set_failure_reason("Missing required stateful disk");
    return response;
  }

  // Assume the stateful device is the first disk in the request.
  string stateful_device = base::StringPrintf("/dev/vd%c", disk_letter);

  auto stateful_path = base::FilePath(request.disks()[0].path());
  int64_t stateful_size = -1;
  if (!base::GetFileSize(stateful_path, &stateful_size)) {
    LOG(ERROR) << "Could not determine stateful disk size";
    response.set_failure_reason(
        "Internal error: unable to determine stateful disk size");
    return response;
  }

  // Storage ballooning enabled for Borealis (for ext4 setups in order
  // to not interfere with the storage management solutions of legacy
  // setups) and Bruschetta VMs.
  if (classification == VmId::Type::BOREALIS &&
      GetFilesystem(stateful_path) == "ext4") {
    vm_info->set_storage_ballooning(request.storage_ballooning());
  } else if (classification == VmId::Type::BRUSCHETTA) {
    vm_info->set_storage_ballooning(true);
  }

  for (const auto& d : request.disks()) {
    Disk disk{.path = base::FilePath(d.path()),
              .writable = d.writable(),
              .sparse = !IsDiskPreallocatedWithUserChosenSize(d.path())};

    failure_reason = ConvertToFdBasedPath(
        root_fd, &disk.path, disk.writable ? O_RDWR : O_RDONLY, owned_fds);

    if (!failure_reason.empty()) {
      LOG(ERROR) << "Could not open disk file";
      response.set_failure_reason(failure_reason);
      return response;
    }

    disks.push_back(disk);
  }

  // Check if an opened storage image was passed over D-BUS.
  if (vm_start_image_fds->storage_fd.has_value()) {
    // We only allow untrusted VMs to mount extra storage.
    if (!is_untrusted_vm) {
      LOG(ERROR) << "storage fd passed for a trusted VM";

      response.set_failure_reason("storage fd is passed for a trusted VM");
      return response;
    }

    int raw_fd = vm_start_image_fds->storage_fd.value().get();
    string failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason.empty()) {
      LOG(ERROR) << "failed to remove close-on-exec flag: " << failure_reason;
      response.set_failure_reason(
          "failed to get a path for extra storage disk: " + failure_reason);
      return response;
    }

    bool writable = false;
    int mode = fcntl(raw_fd, F_GETFL);
    if (mode & O_RDWR || mode & O_WRONLY) {
      writable = true;
    }

    disks.push_back(Disk{.path = base::FilePath(kProcFileDescriptorsPath)
                                     .Append(base::NumberToString(raw_fd)),
                         .writable = writable,
                         .block_id = "cr-extra-disk"});
  }

  // Create the runtime directory.
  base::FilePath runtime_dir;
  if (!base::CreateTemporaryDirInDir(base::FilePath(kRuntimeDir), "vm.",
                                     &runtime_dir)) {
    PLOG(ERROR) << "Unable to create runtime directory for VM";

    response.set_failure_reason(
        "Internal error: unable to create runtime directory");
    return response;
  }

  if (request.name().size() > kMaxVmNameLength) {
    LOG(ERROR) << "VM name is too long";

    response.set_failure_reason("VM name is too long");
    return response;
  }
  base::FilePath log_path =
      GetVmLogPath(request.owner_id(), request.name(), kCrosvmLogSocketExt);

  if (request.enable_vulkan() && !request.enable_gpu()) {
    LOG(ERROR) << "Vulkan enabled without GPU";
    response.set_failure_reason("Vulkan enabled without GPU");
    return response;
  }

  if (request.enable_big_gl() && !request.enable_gpu()) {
    LOG(ERROR) << "Big GL enabled without GPU";
    response.set_failure_reason("Big GL enabled without GPU");
    return response;
  }

  if (request.enable_virtgpu_native_context() && !request.enable_gpu()) {
    LOG(ERROR) << "Virtgpu native context enabled without GPU";
    response.set_failure_reason("Virtgpu native context enabled without GPU");
    return response;
  }

  // Enable the render server for Vulkan.
  const bool enable_render_server = request.enable_vulkan();
  // Enable foz db list (dynamic un/loading for RO mesa shader cache) only for
  // Borealis, for now.
  const bool enable_foz_db_list = classification == VmId::Type::BOREALIS;

  VMGpuCacheSpec gpu_cache_spec;
  if (request.enable_gpu()) {
    gpu_cache_spec =
        PrepareVmGpuCachePaths(request.owner_id(), request.name(),
                               enable_render_server, enable_foz_db_list);
  }

  // Allocate resources for the VM.
  uint32_t vsock_cid = vsock_cid_pool_.Allocate();
  if (vsock_cid == 0) {
    LOG(ERROR) << "Unable to allocate vsock context id";

    response.set_failure_reason("Unable to allocate vsock cid");
    return response;
  }
  vm_info->set_cid(vsock_cid);

  std::unique_ptr<patchpanel::Client> network_client =
      patchpanel::Client::New(bus_);
  if (!network_client) {
    LOG(ERROR) << "Unable to open networking service client";

    response.set_failure_reason("Unable to open network service client");
    return response;
  }

  uint32_t seneschal_server_port = next_seneschal_server_port_++;
  std::unique_ptr<SeneschalServerProxy> server_proxy =
      SeneschalServerProxy::CreateVsockProxy(bus_, seneschal_service_proxy_,
                                             seneschal_server_port, vsock_cid,
                                             {}, {});
  if (!server_proxy) {
    LOG(ERROR) << "Unable to start shared directory server";

    response.set_failure_reason("Unable to start shared directory server");
    return response;
  }

  uint32_t seneschal_server_handle = server_proxy->handle();
  vm_info->set_seneschal_server_handle(seneschal_server_handle);

  // Set up a "checker" that will wait until the VM is ready or a signal is
  // received while waiting for the VM to start or we timeout.
  std::unique_ptr<VmStartChecker> vm_start_checker =
      VmStartChecker::Create(signal_fd_.get());
  if (!vm_start_checker) {
    LOG(ERROR) << "Failed to create VM start checker";
    response.set_failure_reason("Failed to create VM start checker");
    return response;
  }
  // This will signal the event fd passed in when the VM is ready.
  startup_listener_.AddPendingVm(vsock_cid, vm_start_checker->GetEventFd());

  // Start the VM and build the response.
  VmFeatures features{
      .gpu = request.enable_gpu(),
      .dgpu_passthrough = request.enable_dgpu_passthrough(),
      .vulkan = request.enable_vulkan(),
      .big_gl = request.enable_big_gl(),
      .virtgpu_native_context = request.enable_virtgpu_native_context(),
      .render_server = enable_render_server,
      .software_tpm = request.software_tpm(),
      .vtpm_proxy = request.vtpm_proxy(),
      .audio_capture = request.enable_audio_capture(),
  };

  std::vector<std::string> params(
      std::make_move_iterator(request.mutable_kernel_params()->begin()),
      std::make_move_iterator(request.mutable_kernel_params()->end()));
  features.kernel_params = std::move(params);

  std::vector<std::string> oem_strings(
      std::make_move_iterator(request.mutable_oem_strings()->begin()),
      std::make_move_iterator(request.mutable_oem_strings()->end()));
  features.oem_strings = std::move(oem_strings);

  // We use _SC_NPROCESSORS_ONLN here rather than
  // base::SysInfo::NumberOfProcessors() so that offline CPUs are not counted.
  // Also, |untrusted_vm_utils_| may disable SMT leading to cores being
  // disabled. Hence, only allocate the lower of (available cores, cpus
  // allocated by the user).
  const int32_t cpus =
      request.cpus() == 0
          ? sysconf(_SC_NPROCESSORS_ONLN)
          : std::min(static_cast<int32_t>(sysconf(_SC_NPROCESSORS_ONLN)),
                     static_cast<int32_t>(request.cpus()));

  // Notify VmLogForwarder that a vm is starting up.
  VmId vm_id(request.owner_id(), request.name());
  SendVmStartingUpSignal(vm_id, *vm_info);

  VmBuilder vm_builder;
  vm_builder.SetKernel(std::move(image_spec.kernel))
      .SetBios(std::move(image_spec.bios))
      .SetPflash(std::move(pflash))
      .SetInitrd(std::move(image_spec.initrd))
      .SetCpus(cpus)
      .AppendDisks(std::move(disks))
      .AppendSharedDir(CreateFontsSharedDataParam())
      .EnableSmt(false /* enable */)
      .SetGpuCachePath(std::move(gpu_cache_spec.device))
      .AppendCustomParam("--vcpu-cgroup-path",
                         base::FilePath(kTerminaVcpuCpuCgroup).value())
      .SetRenderServerCachePath(std::move(gpu_cache_spec.render_server));
  if (enable_foz_db_list) {
    auto prepare_result = PrepareShaderCache(request.owner_id(), request.name(),
                                             bus_, shadercached_proxy_);
    if (prepare_result.has_value()) {
      auto precompiled_cache_path =
          base::FilePath(prepare_result.value().precompiled_cache_path());
      vm_builder.SetFozDbListPath(std::move(gpu_cache_spec.foz_db_list))
          .SetPrecompiledCachePath(precompiled_cache_path)
          .AppendSharedDir(CreateShaderSharedDataParam(precompiled_cache_path));
    } else {
      LOG(ERROR) << "Unable to initialize shader cache: "
                 << prepare_result.error();
    }
  }
  if (!image_spec.rootfs.empty()) {
    vm_builder.SetRootfs({.device = std::move(rootfs_device),
                          .path = std::move(image_spec.rootfs),
                          .writable = request.writable_rootfs()});
  }

  VmWlInterface::Result wl_result =
      VmWlInterface::CreateWaylandServer(bus_, vm_id, classification);
  if (!wl_result.has_value()) {
    response.set_failure_reason("Unable to start a wayland server: " +
                                wl_result.error());
    LOG(ERROR) << response.failure_reason();
    return response;
  }
  std::unique_ptr<ScopedWlSocket> socket = std::move(wl_result).value();
  vm_builder.SetWaylandSocket(socket->GetPath().value());

  // Group the CPUs by their physical package ID to determine CPU cluster
  // layout.
  SetVmCpuArgs(cpus, vm_builder);

  auto vm = TerminaVm::Create(TerminaVm::Config{
      .vsock_cid = vsock_cid,
      .network_client = std::move(network_client),
      .seneschal_server_proxy = std::move(server_proxy),
      .runtime_dir = std::move(runtime_dir),
      .log_path = std::move(log_path),
      .stateful_device = std::move(stateful_device),
      .stateful_size = static_cast<uint64_t>(std::move(stateful_size)),
      .features = features,
      .vm_permission_service_proxy = vm_permission_service_proxy_,
      .bus = bus_,
      .id = vm_id,
      .classification = classification,
      .vm_builder = std::move(vm_builder),
      .socket = std::move(socket)});
  if (!vm) {
    LOG(ERROR) << "Unable to start VM";

    startup_listener_.RemovePendingVm(vsock_cid);
    response.set_failure_reason("Unable to start VM");
    return response;
  }

  // Wait for the VM to finish starting up and for maitre'd to signal that it's
  // ready.
  base::TimeDelta timeout = kVmStartupDefaultTimeout;
  if (request.timeout() != 0) {
    timeout = base::Seconds(request.timeout());
  }

  VmStartChecker::Status vm_start_checker_status =
      vm_start_checker->Wait(timeout);
  if (vm_start_checker_status != VmStartChecker::Status::READY) {
    LOG(ERROR) << "Error starting VM. VmStartCheckerStatus="
               << vm_start_checker_status;
    response.set_failure_reason(std::to_string(vm_start_checker_status));
    return response;
  }

  // maitre'd is ready.  Finish setting up the VM.
  if (!vm->ConfigureNetwork(nameservers_, search_domains_)) {
    LOG(ERROR) << "Failed to configure VM network";

    response.set_failure_reason("Failed to configure VM network");
    return response;
  }

  // Attempt to set the timezone of the VM correctly. Incorrect timezone does
  // not introduce issues to turnup process. Timezone can also be set during
  // runtime upon host's update.
  std::string error;
  if (!vm->SetTimezone(GetHostTimeZone(), &error)) {
    LOG(WARNING) << "Failed to set VM timezone: " << error;
  }

  // Do all the mounts.
  for (const auto& disk : request.disks()) {
    string src = base::StringPrintf("/dev/vd%c", disk_letter++);

    if (!disk.do_mount())
      continue;

    uint64_t flags = disk.flags();
    if (!disk.writable()) {
      flags |= MS_RDONLY;
    }
    if (!vm->Mount(std::move(src), disk.mount_point(), disk.fstype(), flags,
                   disk.data())) {
      LOG(ERROR) << "Failed to mount " << disk.path() << " -> "
                 << disk.mount_point();

      response.set_failure_reason("Failed to mount extra disk");
      return response;
    }
  }

  // Mount the 9p server.
  if (!vm->Mount9P(seneschal_server_port, "/mnt/shared")) {
    LOG(ERROR) << "Failed to mount shared directory";

    response.set_failure_reason("Failed to mount shared directory");
    return response;
  }

  // Determine the VM token. Termina doesnt use a VM token because it has
  // per-container tokens.
  std::string vm_token = "";
  if (!request.start_termina())
    vm_token = base::Uuid::GenerateRandomV4().AsLowercaseString();

  // Notify cicerone that we have started a VM.
  // We must notify cicerone now before calling StartTermina, but we will only
  // send the VmStartedSignal on success.
  NotifyCiceroneOfVmStarted(vm_id, vm->cid(), vm->GetInfo().pid, vm_token);

  vm_tools::StartTerminaResponse::MountResult mount_result =
      vm_tools::StartTerminaResponse::UNKNOWN;
  int64_t free_bytes = -1;
  // Allow untrusted VMs to have privileged containers.
  if (request.start_termina() &&
      !StartTermina(vm.get(), is_untrusted_vm /* allow_privileged_containers */,
                    request.features(), &failure_reason, &mount_result,
                    &free_bytes)) {
    response.set_failure_reason(std::move(failure_reason));
    response.set_mount_result((StartVmResponse::MountResult)mount_result);
    return response;
  }
  response.set_mount_result((StartVmResponse::MountResult)mount_result);
  if (free_bytes >= 0) {
    response.set_free_bytes(free_bytes);
    response.set_free_bytes_has_value(true);
  }

  if (!vm_token.empty() &&
      !vm->ConfigureContainerGuest(vm_token, request.vm_username(),
                                   &failure_reason)) {
    failure_reason =
        "Failed to configure the container guest: " + failure_reason;
    // TODO(b/162562622): This request is temporarily non-fatal. Once we are
    // satisfied that the maitred changes have been completed, we will make this
    // failure fatal.
    LOG(WARNING) << failure_reason;
  }

  LOG(INFO) << "Started VM with pid " << vm->pid();

  // Mount an extra disk in the VM. We mount them after calling StartTermina
  // because /mnt/external is set up there.
  if (vm_start_image_fds->storage_fd.has_value()) {
    const string external_disk_path =
        base::StringPrintf("/dev/vd%c", disk_letter++);

    // To support multiple extra disks in the future easily, we use integers for
    // names of mount points. Since we support only one extra disk for now,
    // |target_dir| is always "0".
    if (!vm->MountExternalDisk(std::move(external_disk_path),
                               /* target_dir= */ "0")) {
      LOG(ERROR) << "Failed to mount " << external_disk_path;

      response.set_failure_reason("Failed to mount extra disk");
      return response;
    }
  }

  response.set_success(true);
  response.set_status(request.start_termina() ? VM_STATUS_STARTING
                                              : VM_STATUS_RUNNING);
  vm_info->set_ipv4_address(vm->IPv4Address());
  vm_info->set_pid(vm->pid());
  vm_info->set_permission_token(vm->PermissionToken());

  HandleVmStarted(vm_id, *vm_info, vm->GetVmSocketPath(), response.status());

  if (vm_info->storage_ballooning()) {
    AddStorageBalloonVm(vm_id);
  }
  vms_[vm_id] = std::move(vm);
  return response;
}

// Typical check based on the name of protocol buffer fields. Our business logic
// usually means that VM name is stored in field called name and owner_id stored
// in owner_id.
template <class _RequestProto, class _ResponseProto>
bool ValidateVmNameAndOwner(const _RequestProto& request,
                            _ResponseProto& response,
                            bool empty_vm_name_allowed = false) {
  auto set_failure_reason = [&](const char* reason) {
    if constexpr (kHasFailureReason<_ResponseProto>) {
      response.set_failure_reason(reason);
    } else if constexpr (kHasReason<_ResponseProto>) {
      response.set_reason(reason);
    } else {
    }
  };

  if constexpr (kHasOwnerId<_RequestProto>) {
    if (!IsValidOwnerId(request.owner_id())) {
      LOG(ERROR) << "Empty or malformed owner ID";
      set_failure_reason("Empty or malformed owner ID");
      return false;
    }
  }

  if constexpr (kHasCryptohomeId<_RequestProto>) {
    if (!IsValidOwnerId(request.cryptohome_id())) {
      LOG(ERROR) << "Empty or malformed owner ID";
      set_failure_reason("Empty or malformed owner ID");
      return false;
    }
  }

  if constexpr (kHasName<_RequestProto>) {
    if (!IsValidVmName(request.name())) {
      LOG(ERROR) << "Empty or malformed VM name";
      set_failure_reason("Empty or malformed VM name");
      return false;
    }
  }

  if constexpr (kHasVmName<_RequestProto>) {
    if (request.vm_name().empty() && empty_vm_name_allowed) {
      // Allow empty VM name, for ListVmDisks
    } else if (!IsValidVmName(request.vm_name())) {
      LOG(ERROR) << "Empty or malformed VM name";
      set_failure_reason("Empty or malformed VM name");
      return false;
    }
  }

  return true;
}

StopVmResponse Service::StopVm(const StopVmRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  StopVmResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  VmId vm_id(request.owner_id(), request.name());

  if (!StopVmInternal(vm_id, STOP_VM_REQUESTED)) {
    LOG(ERROR) << "Unable to shut down VM";
    response.set_failure_reason("Unable to shut down VM");
  } else {
    response.set_success(true);
  }
  return response;
}

bool Service::StopVmInternal(const VmId& vm_id, VmStopReason reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto iter = FindVm(vm_id);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    return true;
  }

  // Notify that we are about to stop a VM.
  NotifyVmStopping(iter->first, iter->second->GetInfo().cid);

  if (!iter->second->Shutdown()) {
    return false;
  }

  // Notify that we have stopped a VM.
  NotifyVmStopped(iter->first, iter->second->GetInfo().cid, reason);

  if (iter->second->GetInfo().storage_ballooning) {
    RemoveStorageBalloonVm(iter->first);
  }

  vms_.erase(iter);
  return true;
}

void Service::StopVmInternalAsTask(VmId vm_id, VmStopReason reason) {
  StopVmInternal(vm_id, reason);
}

// Wrapper to destroy VM in another thread
class VMDelegate : public base::PlatformThread::Delegate {
 public:
  VMDelegate() = default;
  ~VMDelegate() override = default;
  VMDelegate& operator=(VMDelegate&& other) = default;
  explicit VMDelegate(const Service&) = delete;
  VMDelegate& operator=(const Service&) = delete;
  explicit VMDelegate(VmBaseImpl* vm) : vm_(vm) {}
  void ThreadMain() override { vm_->Shutdown(); }

 private:
  VmBaseImpl* vm_;
};

void Service::StopAllVms() {
  StopAllVmsImpl(STOP_ALL_VMS_REQUESTED);
  return;
}

void Service::StopAllVmsImpl(VmStopReason reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "Received StopAllVms request";

  struct ThreadContext {
    base::PlatformThreadHandle handle;
    VMDelegate delegate;
  };
  std::vector<ThreadContext> ctxs(vms_.size());

  // Spawn a thread for each VM to shut it down.
  int i = 0;
  for (auto& vm : vms_) {
    ThreadContext& ctx = ctxs[i++];

    const VmId& id = vm.first;
    VmBaseImpl* vm_base_impl = vm.second.get();
    VmBaseImpl::Info info = vm_base_impl->GetInfo();

    // Notify that we are about to stop a VM.
    NotifyVmStopping(id, info.cid);

    // The VM will be destructred in the new thread, stopping it normally (and
    // then forcibly) it if it hasn't stopped yet.
    //
    // Would you just take a lambda function? Why do we need the Delegate?...
    ctx.delegate = VMDelegate(vm_base_impl);
    base::PlatformThread::Create(0, &ctx.delegate, &ctx.handle);
  }

  i = 0;
  for (auto& vm : vms_) {
    ThreadContext& ctx = ctxs[i++];
    base::PlatformThread::Join(ctx.handle);

    const VmId& id = vm.first;
    VmBaseImpl* vm_base_impl = vm.second.get();
    VmBaseImpl::Info info = vm_base_impl->GetInfo();

    // Notify that we have stopped a VM.
    NotifyVmStopped(id, info.cid, reason);
  }

  vms_.clear();

  if (!ctxs.empty()) {
    LOG(INFO) << "Stopped all Vms";
  }
}

SuspendVmResponse Service::SuspendVm(const SuspendVmRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  SuspendVmResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    response.set_success(true);
    return response;
  }

  auto& vm = iter->second;
  if (!vm->UsesExternalSuspendSignals()) {
    LOG(ERROR) << "Received D-Bus suspend request for " << iter->first
               << " but it does not use external suspend signals.";

    response.set_failure_reason(
        "VM does not support external suspend signals.");
    return response;
  }

  vm->Suspend();

  response.set_success(true);
  return response;
}

ResumeVmResponse Service::ResumeVm(const ResumeVmRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ResumeVmResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    // This is not an error to Chrome
    response.set_success(true);
    return response;
  }

  auto& vm = iter->second;
  if (!vm->UsesExternalSuspendSignals()) {
    LOG(ERROR) << "Received D-Bus resume request for " << iter->first
               << " but it does not use external suspend signals.";

    response.set_failure_reason(
        "VM does not support external suspend signals.");
    return response;
  }

  vm->Resume();

  string failure_reason;
  if (vm->SetTime(&failure_reason)) {
    LOG(INFO) << "Successfully set VM clock in " << iter->first << ".";
  } else {
    LOG(ERROR) << "Failed to set VM clock in " << iter->first << ": "
               << failure_reason;
  }

  vm->SetResolvConfig(nameservers_, search_domains_);

  response.set_success(true);
  return response;
}

GetVmInfoResponse Service::GetVmInfo(const GetVmInfoRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  GetVmInfoResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";

    return response;
  }

  VmBaseImpl::Info vm = iter->second->GetInfo();

  VmInfo* vm_info = response.mutable_vm_info();
  vm_info->set_ipv4_address(vm.ipv4_address);
  vm_info->set_pid(vm.pid);
  vm_info->set_cid(vm.cid);
  vm_info->set_seneschal_server_handle(vm.seneschal_server_handle);
  vm_info->set_permission_token(vm.permission_token);
  vm_info->set_vm_type(ToLegacyVmType(vm.type));
  vm_info->set_storage_ballooning(vm.storage_ballooning);

  response.set_success(true);
  return response;
}

GetVmEnterpriseReportingInfoResponse Service::GetVmEnterpriseReportingInfo(
    const GetVmEnterpriseReportingInfoRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  GetVmEnterpriseReportingInfoResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    const std::string error_message = "Requested VM does not exist";
    LOG(ERROR) << error_message;
    response.set_failure_reason(error_message);
    return response;
  }

  // failure_reason and success will be set by GetVmEnterpriseReportingInfo.
  if (!iter->second->GetVmEnterpriseReportingInfo(&response)) {
    LOG(ERROR) << "Failed to get VM enterprise reporting info";
  }
  return response;
}

ArcVmCompleteBootResponse Service::ArcVmCompleteBoot(
    const ArcVmCompleteBootRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ArcVmCompleteBootResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response.set_result(ArcVmCompleteBootResult::BAD_REQUEST);
    return response;
  }

  VmId vm_id(request.owner_id(), kArcVmName);

  auto iter = FindVm(vm_id.owner_id(), vm_id.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Unable to locate ArcVm instance";
    response.set_result(ArcVmCompleteBootResult::ARCVM_NOT_FOUND);
    return response;
  }

  // Create the RT v-Cpu for the VM now that boot is complete
  auto& vm = iter->second;
  vm->MakeRtVcpu();

  // Notify the VM guest userland ready
  SendVmGuestUserlandReadySignal(vm_id,
                                 GuestUserlandReady::ARC_BRIDGE_CONNECTED);

  response.set_result(ArcVmCompleteBootResult::SUCCESS);
  return response;
}

SetBalloonTimerResponse Service::SetBalloonTimer(
    const SetBalloonTimerRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  SetBalloonTimerResponse response;

  if (request.timer_interval_millis() == 0) {
    LOG(INFO) << "timer_interval_millis is 0. Stop the timer.";
    balloon_resizing_timer_.Stop();
  } else {
    LOG(INFO) << "Update balloon timer interval as "
              << request.timer_interval_millis() << "ms.";
    balloon_resizing_timer_.Start(
        FROM_HERE, base::Milliseconds(request.timer_interval_millis()), this,
        &Service::RunBalloonPolicy);
  }

  response.set_success(true);
  return response;
}

AdjustVmResponse Service::AdjustVm(const AdjustVmRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  AdjustVmResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  StorageLocation location;
  if (!CheckVmExists(request.name(), request.owner_id(), nullptr, &location)) {
    response.set_failure_reason("Requested VM does not exist");
    return response;
  }

  std::vector<string> params(request.params().begin(), request.params().end());

  string failure_reason;
  bool success = false;
  if (request.operation() == "pvm.shared-profile") {
    if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success = pvm::helper::ToggleSharedProfile(
          bus_, vmplugin_service_proxy_,
          VmId(request.owner_id(), request.name()), std::move(params),
          &failure_reason);
    }
  } else if (request.operation() == "memsize") {
    if (params.size() != 1) {
      failure_reason = "Incorrect number of arguments for 'memsize' operation";
    } else if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success =
          pvm::helper::SetMemorySize(bus_, vmplugin_service_proxy_,
                                     VmId(request.owner_id(), request.name()),
                                     std::move(params), &failure_reason);
    }
  } else if (request.operation() == "rename") {
    if (params.size() != 1) {
      failure_reason = "Incorrect number of arguments for 'rename' operation";
    } else if (params[0].empty()) {
      failure_reason = "New name can not be empty";
    } else if (CheckVmExists(params[0], request.owner_id())) {
      failure_reason = "VM with such name already exists";
    } else if (location != STORAGE_CRYPTOHOME_PLUGINVM) {
      failure_reason = "Operation is not supported for the VM";
    } else {
      success = RenamePluginVm(request.owner_id(), request.name(), params[0],
                               &failure_reason);
    }
  } else {
    failure_reason = "Unrecognized operation";
  }

  response.set_success(success);
  response.set_failure_reason(failure_reason);
  return response;
}

SyncVmTimesResponse Service::SyncVmTimes() {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  SyncVmTimesResponse response;
  int failures = 0;
  int requests = 0;
  for (auto& vm_entry : vms_) {
    requests++;
    string failure_reason;
    if (!vm_entry.second->SetTime(&failure_reason)) {
      failures++;
      response.add_failure_reason(std::move(failure_reason));
    }
  }
  response.set_requests(requests);
  response.set_failures(failures);

  return response;
}

bool Service::StartTermina(TerminaVm* vm,
                           bool allow_privileged_containers,
                           const google::protobuf::RepeatedField<int>& features,
                           string* failure_reason,
                           vm_tools::StartTerminaResponse::MountResult* result,
                           int64_t* out_free_bytes) {
  LOG(INFO) << "Starting Termina-specific services";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(result);

  std::string dst_addr;
  IPv4AddressToString(vm->ContainerSubnet(), &dst_addr);
  size_t prefix_length = vm->ContainerPrefixLength();

  std::string container_subnet_cidr =
      base::StringPrintf("%s/%zu", dst_addr.c_str(), prefix_length);

  string error;
  vm_tools::StartTerminaResponse response;
  if (!vm->StartTermina(std::move(container_subnet_cidr),
                        allow_privileged_containers, features, &error,
                        &response)) {
    failure_reason->assign(error);
    return false;
  }

  if (response.mount_result() ==
      vm_tools::StartTerminaResponse::PARTIAL_DATA_LOSS) {
    LOG(ERROR) << "Possible data loss from filesystem corruption detected";
  }

  *result = response.mount_result();
  if (response.free_bytes_has_value()) {
    *out_free_bytes = response.free_bytes();
  }

  return true;
}

// Executes a command on the specified disk path. Returns false when
// `GetAppOutputWithExitCode()` fails (i.e., the command could not be launched
// or does not exit cleanly). Otherwise returns true and sets |exit_code|.
bool ExecuteCommandOnDisk(const base::FilePath& disk_path,
                          const std::string& executable_path,
                          const std::vector<string>& opts,
                          int* exit_code) {
  std::vector<string> args = {executable_path, disk_path.value()};
  args.insert(args.end(), opts.begin(), opts.end());
  string output;
  return base::GetAppOutputWithExitCode(base::CommandLine(args), &output,
                                        exit_code);
}

// Generates a file path that is a distinct sibling of the specified path and
// does not contain the equal sign '='.
base::FilePath GenerateTempFilePathWithNoEqualSign(const base::FilePath& path) {
  string temp_name;
  base::RemoveChars(path.BaseName().value(), "=", &temp_name);
  return path.DirName().Append(temp_name + ".tmp");
}

// Creates a filesystem at the specified file/path.
bool CreateFilesystem(const base::FilePath& disk_location,
                      enum FilesystemType filesystem_type,
                      const std::vector<string>& mkfs_opts,
                      const std::vector<string>& tune2fs_opts) {
  std::string filesystem_string;
  switch (filesystem_type) {
    case FilesystemType::EXT4:
      filesystem_string = "ext4";
      break;
    case FilesystemType::UNSPECIFIED:
    default:
      LOG(ERROR) << "Filesystem was not specified";
      return false;
  }

  std::string existing_filesystem = GetFilesystem(disk_location);
  if (!existing_filesystem.empty() &&
      existing_filesystem != filesystem_string) {
    LOG(ERROR) << "Filesystem already exists but is the wrong type, expected:"
               << filesystem_string << ", got:" << existing_filesystem;
    return false;
  }

  if (existing_filesystem == filesystem_string) {
    return true;
  }

  LOG(INFO) << "Creating " << filesystem_string << " filesystem at "
            << disk_location;
  int exit_code = -1;
  ExecuteCommandOnDisk(disk_location, "/sbin/mkfs." + filesystem_string,
                       mkfs_opts, &exit_code);
  if (exit_code != 0) {
    LOG(ERROR) << "Can't format '" << disk_location << "' as "
               << filesystem_string << ", exit status: " << exit_code;
    return false;
  }

  if (tune2fs_opts.empty()) {
    return true;
  }

  LOG(INFO) << "Adjusting ext4 filesystem at " << disk_location
            << " with tune2fs";
  // Currently, tune2fs cannot handle paths containing '=' (b/267134417).
  // To avoid the issue, below we temporarily rename the disk image so that it
  // does not contain '=', apply tune2fs to the renamed path, and then rename
  // the disk image back to its original name.
  // TODO(b/267134417): Remove this workaround once tune2fs is fixed.
  const base::FilePath temp_disk_location =
      GenerateTempFilePathWithNoEqualSign(disk_location);

  if (!base::Move(disk_location, temp_disk_location)) {
    LOG(ERROR) << "Failed to move " << disk_location << " to "
               << temp_disk_location;
    unlink(temp_disk_location.value().c_str());
    return false;
  }

  exit_code = -1;
  ExecuteCommandOnDisk(temp_disk_location, "/sbin/tune2fs", tune2fs_opts,
                       &exit_code);

  // Move the disk image back to the original location before checking the exit
  // code. This is to make the behavior on tune2fs failures aligh with that on
  // mkfs failures (the disk image exists in the original location).
  // Note that the disk image is removed if the move (rename) operation fails,
  // but it should be much rarer than mkfs/tune2fs failures.
  if (!base::Move(temp_disk_location, disk_location)) {
    LOG(ERROR) << "Failed to move " << temp_disk_location << " back to "
               << disk_location;
    unlink(temp_disk_location.value().c_str());
    return false;
  }

  if (exit_code != 0) {
    LOG(ERROR) << "Can't adjust '" << disk_location
               << "' with tune2fs, exit status: " << exit_code;
    return false;
  }

  return true;
}

void Service::CreateDiskImage(dbus::MethodCall* method_call,
                              dbus::ExportedObject::ResponseSender sender) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  dbus::MessageReader reader(method_call);

  CreateDiskImageRequest request;
  CreateDiskImageResponse response;

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse CreateDiskImageRequest from message";
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Unable to parse CreateImageDiskRequest");

    SendDbusResponse(std::move(sender), method_call, response);
    return;
  }

  base::ScopedFD in_fd{};
  if (request.storage_location() == STORAGE_CRYPTOHOME_PLUGINVM) {
    if (!reader.PopFileDescriptor(&in_fd)) {
      LOG(ERROR) << "CreateDiskImage: no fd found";
      response.set_failure_reason("no source fd found");

      SendDbusResponse(std::move(sender), method_call, response);
      return;
    }
  }

  SendDbusResponse(
      std::move(sender), method_call,
      CreateDiskImageInternal(std::move(request), std::move(in_fd)));
  return;
}

CreateDiskImageResponse Service::CreateDiskImageInternal(
    CreateDiskImageRequest request, base::ScopedFD in_fd) {
  CreateDiskImageResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response.set_status(DISK_STATUS_FAILED);
    return response;
  }

  // Set up the disk image as a sparse file when
  //   1) |allocation_type| is DISK_ALLOCATION_TYPE_SPARSE, or
  //   2) |allocation_type| is DISK_ALLOCATION_TYPE_AUTO (the default value) and
  //      |disk_size| is 0.
  // The latter case exists to preserve the old behaviors for existing callers.
  if (request.allocation_type() ==
      DiskImageAllocationType::DISK_ALLOCATION_TYPE_AUTO) {
    LOG(WARNING) << "Disk allocation type is unspecified (or specified as "
                    "auto). Whether to create a sparse disk image will be "
                    "automatically determined using the requested disk size.";
  }
  bool is_sparse = request.allocation_type() ==
                       DiskImageAllocationType::DISK_ALLOCATION_TYPE_SPARSE ||
                   (request.allocation_type() ==
                        DiskImageAllocationType::DISK_ALLOCATION_TYPE_AUTO &&
                    request.disk_size() == 0);
  if (!is_sparse && request.disk_size() == 0) {
    response.set_failure_reason(
        "Request is invalid, disk size must be non-zero for non-sparse disks");
    return response;
  }
  if (!is_sparse && request.storage_ballooning()) {
    response.set_failure_reason(
        "Request is invalid, storage ballooning is only available for sparse "
        "disks");
    return response;
  }

  base::FilePath disk_path;
  StorageLocation disk_location;
  if (CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                    &disk_location)) {
    if (disk_location != request.storage_location()) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "VM/disk with same name already exists in another storage location");
      return response;
    }

    if (disk_location == STORAGE_CRYPTOHOME_PLUGINVM) {
      // We do not support extending Plugin VM images.
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Plugin VM with such name already exists");
      return response;
    }

    struct stat st;
    if (stat(disk_path.value().c_str(), &st) < 0) {
      PLOG(ERROR) << "stat() of existing VM image failed for "
                  << disk_path.value();
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "internal error: image exists but stat() failed");
      return response;
    }

    uint64_t current_size = st.st_size;
    uint64_t current_usage = st.st_blocks * 512ull;
    LOG(INFO) << "Found existing disk at " << disk_path.value()
              << " with current size " << current_size << " and usage "
              << current_usage;

    // Automatically extend existing sparse disk images if |disk_size| is
    // unspecified or 0 (unless storage ballooning is being used).
    if (is_sparse && !request.storage_ballooning()) {
      if (request.disk_size() != 0) {
        // TODO(b/232176243): Think about cases where a non-zero |disk_size| is
        // specified for an existing sparse disk image.
        LOG(INFO) << "Ignoring specified disk size for existing sparse image. "
                     "Automatic resizing is enabled only when the disk size is "
                     "unspecified or specified to be 0";
      } else if (IsDiskPreallocatedWithUserChosenSize(disk_path.value())) {
        // If the user.crostini.user_chosen_size xattr exists, don't resize the
        // disk. (The value stored in the xattr is ignored; only its existence
        // matters.)
        LOG(INFO) << "Disk image has "
                  << kDiskImagePreallocatedWithUserChosenSizeXattr
                  << " xattr - keeping existing size " << current_size;
      } else {
        uint64_t disk_size = CalculateDesiredDiskSize(disk_path, current_usage);
        if (disk_size > current_size) {
          LOG(INFO) << "Expanding disk image from " << current_size << " to "
                    << disk_size;
          if (expand_disk_image(disk_path.value().c_str(), disk_size) != 0) {
            // If expanding the disk failed, continue with a warning.
            // Currently, raw images can be resized, and qcow2 images cannot.
            LOG(WARNING) << "Failed to expand disk image " << disk_path.value();
          }
        } else {
          LOG(INFO) << "Current size " << current_size
                    << " is already at least requested size " << disk_size
                    << " - not expanding";
        }
      }
    }

    response.set_status(DISK_STATUS_EXISTS);
    response.set_disk_path(disk_path.value());
    return response;
  }

  if (!GetDiskPathFromName(request.vm_name(), request.cryptohome_id(),
                           request.storage_location(),
                           true, /* create_parent_dir */
                           &disk_path, request.image_type())) {
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Failed to create vm image");

    return response;
  }

  if (request.storage_location() == STORAGE_CRYPTOHOME_PLUGINVM) {
    // Make sure we have the FD to fill with disk image data.
    if (!in_fd.is_valid()) {
      LOG(ERROR) << "CreateDiskImage: fd is not valid";
      response.set_failure_reason("fd is not valid");
    }

    // Get the name of directory for ISO images. Do not create it - it will be
    // created by the PluginVmCreateOperation code.
    base::FilePath iso_dir;
    if (!GetPluginIsoDirectory(request.vm_name(), request.cryptohome_id(),
                               false /* create */, &iso_dir)) {
      LOG(ERROR) << "Unable to determine directory for ISOs";

      response.set_failure_reason("Unable to determine ISO directory");
      return response;
    }

    std::vector<string> params(
        std::make_move_iterator(request.mutable_params()->begin()),
        std::make_move_iterator(request.mutable_params()->end()));

    auto op = PluginVmCreateOperation::Create(
        std::move(in_fd), iso_dir, request.source_size(),
        VmId(request.cryptohome_id(), request.vm_name()), std::move(params));

    response.set_disk_path(disk_path.value());
    response.set_status(op->status());
    response.set_command_uuid(op->uuid());
    response.set_failure_reason(op->failure_reason());

    if (op->status() == DISK_STATUS_IN_PROGRESS) {
      std::string uuid = op->uuid();
      disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(&Service::RunDiskImageOperation,
                         weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
    }

    return response;
  }

  uint64_t disk_size = request.disk_size()
                           ? request.disk_size()
                           : CalculateDesiredDiskSize(
                                 disk_path, 0, request.storage_ballooning());

  if (request.image_type() == DISK_IMAGE_RAW ||
      request.image_type() == DISK_IMAGE_AUTO) {
    LOG(INFO) << "Creating raw disk at: " << disk_path.value() << " size "
              << disk_size;
    base::ScopedFD fd(
        open(disk_path.value().c_str(), O_CREAT | O_NONBLOCK | O_WRONLY, 0600));
    if (!fd.is_valid()) {
      PLOG(ERROR) << "Failed to create raw disk";
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Failed to create raw disk file");

      return response;
    }

    if (!is_sparse) {
      LOG(INFO) << "Creating user-chosen-size raw disk image";
      if (!SetPreallocatedWithUserChosenSizeAttr(fd)) {
        PLOG(ERROR) << "Failed to set user_chosen_size xattr";
        unlink(disk_path.value().c_str());
        response.set_status(DISK_STATUS_FAILED);
        response.set_failure_reason("Failed to set user_chosen_size xattr");

        return response;
      }

      LOG(INFO) << "Preallocating user-chosen-size raw disk image";
      if (fallocate(fd.get(), 0, 0, disk_size) != 0) {
        PLOG(ERROR) << "Failed to allocate raw disk";
        unlink(disk_path.value().c_str());
        response.set_status(DISK_STATUS_FAILED);
        response.set_failure_reason("Failed to allocate raw disk file");

        return response;
      }

      LOG(INFO) << "Disk image preallocated";
      response.set_status(DISK_STATUS_CREATED);
      response.set_disk_path(disk_path.value());

    } else {
      LOG(INFO) << "Creating sparse raw disk image";
      int ret = ftruncate(fd.get(), disk_size);
      if (ret != 0) {
        PLOG(ERROR) << "Failed to truncate raw disk";
        unlink(disk_path.value().c_str());
        response.set_status(DISK_STATUS_FAILED);
        response.set_failure_reason("Failed to truncate raw disk file");

        return response;
      }

      LOG(INFO) << "Sparse raw disk image created";
      response.set_status(DISK_STATUS_CREATED);
      response.set_disk_path(disk_path.value());
    }

    if (request.filesystem_type() == FilesystemType::UNSPECIFIED) {
      // Skip creating a filesystem when no filesystem type is specified.
      return response;
    }

    // Create a filesystem on the disk to make it usable for the VM.
    std::vector<string> mkfs_opts(
        std::make_move_iterator(request.mutable_mkfs_opts()->begin()),
        std::make_move_iterator(request.mutable_mkfs_opts()->end()));
    if (mkfs_opts.empty()) {
      // Set the default options.
      mkfs_opts = kExtMkfsOpts;
    }
    // -q is added to silence the output.
    mkfs_opts.push_back("-q");

    const std::vector<string> tune2fs_opts(
        std::make_move_iterator(request.mutable_tune2fs_opts()->begin()),
        std::make_move_iterator(request.mutable_tune2fs_opts()->end()));

    if (!CreateFilesystem(disk_path, request.filesystem_type(), mkfs_opts,
                          tune2fs_opts)) {
      PLOG(ERROR) << "Failed to create filesystem";
      unlink(disk_path.value().c_str());
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Failed to create filesystem");
    }

    return response;
  }

  LOG(INFO) << "Creating qcow2 disk at: " << disk_path.value() << " size "
            << disk_size;
  int ret = create_qcow_with_size(disk_path.value().c_str(), disk_size);
  if (ret != 0) {
    LOG(ERROR) << "Failed to create qcow2 disk image: " << strerror(ret);
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Failed to create qcow2 disk image");

    return response;
  }

  response.set_disk_path(disk_path.value());
  response.set_status(DISK_STATUS_CREATED);

  return response;
}

DestroyDiskImageResponse Service::DestroyDiskImage(
    const DestroyDiskImageRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  DestroyDiskImageResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response.set_status(DISK_STATUS_FAILED);
    return response;
  }

  // Stop the associated VM if it is still running.
  auto iter = FindVm(request.cryptohome_id(), request.vm_name());
  if (iter != vms_.end()) {
    LOG(INFO) << "Shutting down VM";

    if (!StopVmInternal(VmId(request.cryptohome_id(), request.vm_name()),
                        DESTROY_DISK_IMAGE_REQUESTED)) {
      LOG(ERROR) << "Unable to shut down VM";

      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Unable to shut down VM");
      return response;
    }
  }

  // Delete shader cache best-effort. Shadercached is only distributed to boards
  // if borealis enabled. There is no way to check VM type easily unless we turn
  // it up.
  // TODO(endlesspring): Deal with errors once we distriute to all boards.
  auto _ = PurgeShaderCache(request.cryptohome_id(), request.vm_name(), bus_,
                            shadercached_proxy_);

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("No such image");
    return response;
  }

  if (!EraseGuestSshKeys(request.cryptohome_id(), request.vm_name())) {
    // Don't return a failure here, just log an error because this is only a
    // side effect and not what the real request is about.
    LOG(ERROR) << "Failed removing guest SSH keys for VM " << request.vm_name();
  }

  if (location == STORAGE_CRYPTOHOME_PLUGINVM) {
    // Plugin VMs need to be unregistered before we can delete them.
    VmId vm_id(request.cryptohome_id(), request.vm_name());
    bool registered;
    if (!pvm::dispatcher::IsVmRegistered(bus_, vmplugin_service_proxy_, vm_id,
                                         &registered)) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason(
          "failed to check Plugin VM registration status");

      return response;
    }

    if (registered &&
        !pvm::dispatcher::UnregisterVm(bus_, vmplugin_service_proxy_, vm_id)) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("failed to unregister Plugin VM");

      return response;
    }

    base::FilePath iso_dir;
    if (GetPluginIsoDirectory(vm_id.name(), vm_id.owner_id(),
                              false /* create */, &iso_dir) &&
        base::PathExists(iso_dir) && !base::DeletePathRecursively(iso_dir)) {
      LOG(ERROR) << "Unable to remove ISO directory for " << vm_id.name();

      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Unable to remove ISO directory");

      return response;
    }

    // Delete GPU shader disk cache.
    base::FilePath gpu_cache_path =
        GetVmGpuCachePathInternal(request.cryptohome_id(), request.vm_name());
    if (!base::DeletePathRecursively(gpu_cache_path)) {
      LOG(ERROR) << "Failed to remove GPU cache for VM: " << gpu_cache_path;
    }
  }

  bool delete_result = (location == STORAGE_CRYPTOHOME_PLUGINVM)
                           ? base::DeletePathRecursively(disk_path)
                           : base::DeleteFile(disk_path);
  if (!delete_result) {
    response.set_status(DISK_STATUS_FAILED);
    response.set_failure_reason("Disk removal failed");

    return response;
  }

  // Pflash may not be present for all VMs. We should only report error if it
  // exists and we failed to delete it. The |DeleteFile| API handles the
  // non-existing case as a success.
  std::optional<PflashMetadata> pflash_metadata =
      GetPflashMetadata(request.cryptohome_id(), request.vm_name());
  if (pflash_metadata && pflash_metadata->is_installed) {
    if (!base::DeleteFile(pflash_metadata->path)) {
      response.set_status(DISK_STATUS_FAILED);
      response.set_failure_reason("Pflash removal failed");
      return response;
    }
  }

  response.set_status(DISK_STATUS_DESTROYED);
  return response;
}

ResizeDiskImageResponse Service::ResizeDiskImage(
    const ResizeDiskImageRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ResizeDiskImageResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response.set_status(DISK_STATUS_FAILED);
    return response;
  }

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("Resize image doesn't exist");
    return response;
  }

  auto size = request.disk_size() & kDiskSizeMask;
  if (size != request.disk_size()) {
    LOG(INFO) << "Rounded requested disk size from " << request.disk_size()
              << " to " << size;
  }

  auto op = VmResizeOperation::Create(
      VmId(request.cryptohome_id(), request.vm_name()), location, disk_path,
      size,
      base::BindOnce(&Service::ResizeDisk, weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&Service::ProcessResize,
                          weak_ptr_factory_.GetWeakPtr()));

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Service::RunDiskImageOperation,
                       weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  } else if (op->status() == DISK_STATUS_RESIZED) {
    DiskImageStatusEnum status = DISK_STATUS_RESIZED;
    std::string failure_reason;
    FinishResize(request.cryptohome_id(), request.vm_name(), location, &status,
                 &failure_reason);
    if (status != DISK_STATUS_RESIZED) {
      response.set_status(status);
      response.set_failure_reason(failure_reason);
    }
  }

  return response;
}

void Service::ResizeDisk(const std::string& owner_id,
                         const std::string& vm_name,
                         StorageLocation location,
                         uint64_t new_size,
                         DiskImageStatusEnum* status,
                         std::string* failure_reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Unable to find VM " << vm_name;
    *failure_reason = "No such image";
    *status = DISK_STATUS_DOES_NOT_EXIST;
    return;
  }

  *status = iter->second->ResizeDisk(new_size, failure_reason);
}

void Service::ProcessResize(const std::string& owner_id,
                            const std::string& vm_name,
                            StorageLocation location,
                            uint64_t target_size,
                            DiskImageStatusEnum* status,
                            std::string* failure_reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Unable to find VM " << vm_name;
    *failure_reason = "No such image";
    *status = DISK_STATUS_DOES_NOT_EXIST;
    return;
  }

  *status = iter->second->GetDiskResizeStatus(failure_reason);

  if (*status == DISK_STATUS_RESIZED) {
    FinishResize(owner_id, vm_name, location, status, failure_reason);
  }
}

void Service::FinishResize(const std::string& owner_id,
                           const std::string& vm_name,
                           StorageLocation location,
                           DiskImageStatusEnum* status,
                           std::string* failure_reason) {
  base::FilePath disk_path;
  if (!GetDiskPathFromName(vm_name, owner_id, location,
                           false, /* create_parent_dir */
                           &disk_path)) {
    LOG(ERROR) << "Failed to get disk path after resize";
    *failure_reason = "Failed to get disk path after resize";
    *status = DISK_STATUS_FAILED;
    return;
  }

  base::ScopedFD fd(
      open(disk_path.value().c_str(), O_CREAT | O_NONBLOCK | O_WRONLY, 0600));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open disk image";
    *failure_reason = "Failed to open disk image";
    *status = DISK_STATUS_FAILED;
    return;
  }

  // This disk now has a user-chosen size by virtue of being resized.
  if (!SetPreallocatedWithUserChosenSizeAttr(fd)) {
    LOG(ERROR) << "Failed to set user-chosen size xattr";
    *failure_reason = "Failed to set user-chosen size xattr";
    *status = DISK_STATUS_FAILED;
    return;
  }
}

void Service::ExportDiskImage(dbus::MethodCall* method_call,
                              dbus::ExportedObject::ResponseSender sender) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  dbus::MessageReader reader(method_call);

  ExportDiskImageRequest request;
  ExportDiskImageResponse response;
  response.set_status(DISK_STATUS_FAILED);

  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Unable to parse ExportDiskImageRequest from message";
    response.set_failure_reason("Unable to parse ExportDiskRequest");
    SendDbusResponse(std::move(sender), method_call, response);
    return;
  }

  // Get the FD to fill with disk image data.
  base::ScopedFD storage_fd;
  if (!reader.PopFileDescriptor(&storage_fd)) {
    LOG(ERROR) << "export: no fd found";
    response.set_failure_reason("export: no fd found");
    SendDbusResponse(std::move(sender), method_call, response);
    return;
  }

  base::ScopedFD digest_fd;
  if (request.generate_sha256_digest() &&
      !reader.PopFileDescriptor(&digest_fd)) {
    LOG(ERROR) << "export: no digest fd found";
    response.set_failure_reason("export: no digest fd found");
    SendDbusResponse(std::move(sender), method_call, response);
    return;
  }

  SendDbusResponse(
      std::move(sender), method_call,
      ExportDiskImageInternal(std::move(request), std::move(storage_fd),
                              std::move(digest_fd)));
  return;
}

ExportDiskImageResponse Service::ExportDiskImageInternal(
    ExportDiskImageRequest request,
    base::ScopedFD storage_fd,
    base::ScopedFD digest_fd) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExportDiskImageResponse response;
  response.set_status(DISK_STATUS_FAILED);

  if (!ValidateVmNameAndOwner(request, response)) {
    response.set_status(DISK_STATUS_FAILED);
    return response;
  }

  base::FilePath disk_path;
  StorageLocation location;
  if (!CheckVmExists(request.vm_name(), request.cryptohome_id(), &disk_path,
                     &location)) {
    response.set_status(DISK_STATUS_DOES_NOT_EXIST);
    response.set_failure_reason("Export image doesn't exist");
    return response;
  }

  ArchiveFormat fmt;
  switch (location) {
    case STORAGE_CRYPTOHOME_ROOT:
      fmt = ArchiveFormat::TAR_GZ;
      break;
    case STORAGE_CRYPTOHOME_PLUGINVM:
      fmt = ArchiveFormat::ZIP;
      break;
    default:
      LOG(ERROR) << "Unsupported location for source image";
      response.set_failure_reason("Unsupported location for image");
      return response;
  }

  VmId vm_id(request.cryptohome_id(), request.vm_name());

  if (!request.force()) {
    if (FindVm(vm_id) != vms_.end()) {
      LOG(ERROR) << "VM is currently running";
      response.set_failure_reason("VM is currently running");
      return response;
    }

    // For Parallels VMs we want to be sure that the VM is shut down, not
    // merely suspended, to have consistent export.
    if (location == STORAGE_CRYPTOHOME_PLUGINVM) {
      bool is_shut_down;
      if (!pvm::dispatcher::IsVmShutDown(bus_, vmplugin_service_proxy_, vm_id,
                                         &is_shut_down)) {
        LOG(ERROR) << "Unable to query VM state";
        response.set_failure_reason("Unable to query VM state");
        return response;
      }
      if (!is_shut_down) {
        LOG(ERROR) << "VM is not shut down";
        response.set_failure_reason("VM needs to be shut down for exporting");
        return response;
      }
    }
  }

  auto op = VmExportOperation::Create(vm_id, disk_path, std::move(storage_fd),
                                      std::move(digest_fd), fmt);

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Service::RunDiskImageOperation,
                       weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }

  return response;
}

ImportDiskImageResponse Service::ImportDiskImage(
    const ImportDiskImageRequest& request, const base::ScopedFD& in_fd) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ImportDiskImageResponse response;
  response.set_status(DISK_STATUS_FAILED);

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  if (CheckVmExists(request.vm_name(), request.cryptohome_id())) {
    response.set_status(DISK_STATUS_EXISTS);
    response.set_failure_reason("VM/disk with such name already exists");
    return response;
  }

  if (request.storage_location() != STORAGE_CRYPTOHOME_PLUGINVM) {
    LOG(ERROR)
        << "Locations other than STORAGE_CRYPTOHOME_PLUGINVM are not supported";
    response.set_failure_reason("Unsupported location for image");
    return response;
  }

  base::FilePath disk_path;
  if (!GetDiskPathFromName(request.vm_name(), request.cryptohome_id(),
                           request.storage_location(),
                           true, /* create_parent_dir */
                           &disk_path)) {
    response.set_failure_reason("Failed to set up vm image name");
    return response;
  }

  auto op = PluginVmImportOperation::Create(
      base::ScopedFD(dup(in_fd.get())), disk_path, request.source_size(),
      VmId(request.cryptohome_id(), request.vm_name()), bus_,
      vmplugin_service_proxy_);

  response.set_status(op->status());
  response.set_command_uuid(op->uuid());
  response.set_failure_reason(op->failure_reason());

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    std::string uuid = op->uuid();
    disk_image_ops_.emplace_back(DiskOpInfo(std::move(op)));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Service::RunDiskImageOperation,
                       weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }

  return response;
}

void Service::RunDiskImageOperation(std::string uuid) {
  auto iter =
      std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                   [&uuid](auto& info) { return info.op->uuid() == uuid; });

  if (iter == disk_image_ops_.end()) {
    LOG(ERROR) << "RunDiskImageOperation called with unknown uuid";
    return;
  }

  if (iter->canceled) {
    // Operation was cancelled. Now that our posted task is running we can
    // remove it from the list and not reschedule ourselves.
    disk_image_ops_.erase(iter);
    return;
  }

  auto op = iter->op.get();
  op->Run(kDefaultIoLimit);
  if (base::TimeTicks::Now() - iter->last_report_time > kDiskOpReportInterval ||
      op->status() != DISK_STATUS_IN_PROGRESS) {
    LOG(INFO) << "Disk Image Operation: UUID=" << uuid
              << " progress: " << op->GetProgress()
              << " status: " << op->status();

    // Send the D-Bus signal out updating progress of the operation.
    DiskImageStatusResponse status;
    FormatDiskImageStatus(op, &status);
    concierge_adaptor_.SendDiskImageProgressSignal(status);

    // Note the time we sent out the notification.
    iter->last_report_time = base::TimeTicks::Now();
  }

  if (op->status() == DISK_STATUS_IN_PROGRESS) {
    // Reschedule ourselves so we can execute next chunk of work.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Service::RunDiskImageOperation,
                       weak_ptr_factory_.GetWeakPtr(), std::move(uuid)));
  }
}

DiskImageStatusResponse Service::DiskImageStatus(
    const DiskImageStatusRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  DiskImageStatusResponse response;
  response.set_status(DISK_STATUS_FAILED);

  // Locate the pending command in the list.
  auto iter = std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                           [&request](auto& info) {
                             return info.op->uuid() == request.command_uuid();
                           });

  if (iter == disk_image_ops_.end() || iter->canceled) {
    LOG(ERROR) << "Unknown command uuid in DiskImageStatusRequest";
    response.set_failure_reason("Unknown command uuid");
    return response;
  }

  auto op = iter->op.get();
  FormatDiskImageStatus(op, &response);

  // Erase operation form the list if it is no longer in progress.
  if (op->status() != DISK_STATUS_IN_PROGRESS) {
    disk_image_ops_.erase(iter);
  }

  return response;
}

CancelDiskImageResponse Service::CancelDiskImageOperation(
    const CancelDiskImageRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  CancelDiskImageResponse response;

  // Locate the pending command in the list.
  auto iter = std::find_if(disk_image_ops_.begin(), disk_image_ops_.end(),
                           [&request](auto& info) {
                             return info.op->uuid() == request.command_uuid();
                           });

  if (iter == disk_image_ops_.end()) {
    LOG(ERROR) << "Unknown command uuid in CancelDiskImageRequest";
    response.set_failure_reason("Unknown command uuid");
    return response;
  }

  auto op = iter->op.get();
  if (op->status() != DISK_STATUS_IN_PROGRESS) {
    response.set_failure_reason("Command is no longer in progress");
    return response;
  }

  // Mark the operation as canceled. We can't erase it from the list right
  // away as there is a task posted for it. The task will erase this operation
  // when it gets to run.
  iter->canceled = true;

  response.set_success(true);
  return response;
}

ListVmDisksResponse Service::ListVmDisks(const ListVmDisksRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ListVmDisksResponse response;

  if (!ValidateVmNameAndOwner(request, response,
                              true /* Empty VmName allowed*/)) {
    return response;
  }

  response.set_success(true);
  response.set_total_size(0);

  for (int location = StorageLocation_MIN; location <= StorageLocation_MAX;
       location++) {
    if (request.all_locations() || location == request.storage_location()) {
      if (!ListVmDisksInLocation(request.cryptohome_id(),
                                 static_cast<StorageLocation>(location),
                                 request.vm_name(), &response)) {
        break;
      }
    }
  }

  return response;
}

AttachUsbDeviceResponse Service::AttachUsbDevice(
    const AttachUsbDeviceRequest& request, const base::ScopedFD& fd) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  AttachUsbDeviceResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM " << request.vm_name() << " does not exist";
    response.set_reason("Requested VM does not exist");
    return response;
  }

  if (request.bus_number() > 0xFF) {
    LOG(ERROR) << "Bus number out of valid range " << request.bus_number();
    response.set_reason("Invalid bus number");
    return response;
  }

  if (request.port_number() > 0xFF) {
    LOG(ERROR) << "Port number out of valid range " << request.port_number();
    response.set_reason("Invalid port number");
    return response;
  }

  if (request.vendor_id() > 0xFFFF) {
    LOG(ERROR) << "Vendor ID out of valid range " << request.vendor_id();
    response.set_reason("Invalid vendor ID");
    return response;
  }

  if (request.product_id() > 0xFFFF) {
    LOG(ERROR) << "Product ID out of valid range " << request.product_id();
    response.set_reason("Invalid product ID");
    return response;
  }

  uint8_t guest_port{};
  if (!iter->second->AttachUsbDevice(
          request.bus_number(), request.port_number(), request.vendor_id(),
          request.product_id(), fd.get(), &guest_port)) {
    LOG(ERROR) << "Failed to attach USB device.";
    response.set_reason("Error from crosvm");
    return response;
  }
  response.set_success(true);
  response.set_guest_port(guest_port);
  return response;
}

DetachUsbDeviceResponse Service::DetachUsbDevice(
    const DetachUsbDeviceRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  DetachUsbDeviceResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_reason("Requested VM does not exist");
    return response;
  }

  if (request.guest_port() > 0xFF) {
    LOG(ERROR) << "Guest port number out of valid range "
               << request.guest_port();
    response.set_reason("Invalid guest port number");
    return response;
  }

  if (!iter->second->DetachUsbDevice(request.guest_port())) {
    LOG(ERROR) << "Failed to detach USB device";
    return response;
  }
  response.set_success(true);
  return response;
}

ListUsbDeviceResponse Service::ListUsbDevices(
    const ListUsbDeviceRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ListUsbDeviceResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  auto iter = FindVm(request.owner_id(), request.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    return response;
  }

  std::vector<UsbDeviceEntry> usb_list;
  if (!iter->second->ListUsbDevice(&usb_list)) {
    LOG(ERROR) << "Failed to list USB devices";
    return response;
  }
  for (auto usb : usb_list) {
    UsbDeviceMessage* usb_proto = response.add_usb_devices();
    usb_proto->set_guest_port(usb.port);
    usb_proto->set_vendor_id(usb.vendor_id);
    usb_proto->set_product_id(usb.product_id);
  }
  response.set_success(true);
  return response;
}
DnsSettings Service::ComposeDnsResponse() {
  DnsSettings dns_settings;
  for (const auto& server : nameservers_) {
    dns_settings.add_nameservers(server);
  }
  for (const auto& domain : search_domains_) {
    dns_settings.add_search_domains(domain);
  }
  return dns_settings;
}

DnsSettings Service::GetDnsSettings() {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return ComposeDnsResponse();
}

SetVmCpuRestrictionResponse Service::SetVmCpuRestriction(
    const SetVmCpuRestrictionRequest& request) {
  // TODO(yusukes,hashimoto): Instead of allowing Chrome to decide when to
  // restrict each VM's CPU usage, let Concierge itself do that for potentially
  // better security. See crrev.com/c/3564880 for more context.
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  VLOG(3) << "Received SetVmCpuRestriction request";

  SetVmCpuRestrictionResponse response;

  bool success = false;
  const CpuRestrictionState state = request.cpu_restriction_state();
  switch (request.cpu_cgroup()) {
    case CPU_CGROUP_TERMINA:
      success = TerminaVm::SetVmCpuRestriction(state);
      break;
    case CPU_CGROUP_PLUGINVM:
      success = PluginVm::SetVmCpuRestriction(state);
      break;
    case CPU_CGROUP_ARCVM:
      success = ArcVm::SetVmCpuRestriction(state, GetCpuQuota());
      break;
    default:
      LOG(ERROR) << "Unknown cpu_group";
      break;
  }

  response.set_success(success);
  return response;
}

ListVmsResponse Service::ListVms(const ListVmsRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ListVmsResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  for (const auto& vm_entry : vms_) {
    const auto& id = vm_entry.first;
    const auto& vm = vm_entry.second;

    if (id.owner_id() != request.owner_id()) {
      continue;
    }

    VmBaseImpl::Info info = vm->GetInfo();
    ExtendedVmInfo* proto = response.add_vms();
    VmInfo* proto_info = proto->mutable_vm_info();
    proto->set_name(id.name());
    proto->set_owner_id(id.owner_id());
    proto_info->set_ipv4_address(info.ipv4_address);
    proto_info->set_pid(info.pid);
    proto_info->set_cid(info.cid);
    proto_info->set_seneschal_server_handle(info.seneschal_server_handle);
    proto_info->set_vm_type(ToLegacyVmType(info.type));
    proto_info->set_storage_ballooning(info.storage_ballooning);
    // The vms_ member only contains VMs with running crosvm instances. So the
    // STOPPED case below should not be possible.
    switch (info.status) {
      case VmBaseImpl::Status::STARTING: {
        proto->set_status(VM_STATUS_STARTING);
        break;
      }
      case VmBaseImpl::Status::RUNNING: {
        proto->set_status(VM_STATUS_RUNNING);
        break;
      }
      case VmBaseImpl::Status::STOPPED: {
        NOTREACHED();
        proto->set_status(VM_STATUS_STOPPED);
        break;
      }
    }
  }
  response.set_success(true);
  return response;
}

void Service::ReclaimVmMemory(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        ReclaimVmMemoryResponse>> response_sender,
    const ReclaimVmMemoryRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ReclaimVmMemoryResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response_sender->Return(response);
    return;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_failure_reason("Requested VM does not exist");
    response_sender->Return(response);
    return;
  }

  const pid_t pid = iter->second->GetInfo().pid;
  const auto page_limit = request.page_limit();
  reclaim_thread_.task_runner()->PostTaskAndReplyWithResult(
      FROM_HERE, base::BindOnce(&ReclaimVmMemoryInternal, pid, page_limit),
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 ReclaimVmMemoryResponse>> response_sender,
             ReclaimVmMemoryResponse response) {
            std::move(response_sender)->Return(response);
          },
          std::move(response_sender)));
}

void Service::AggressiveBalloon(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        AggressiveBalloonResponse>> response_sender,
    const AggressiveBalloonRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  AggressiveBalloonResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response_sender->Return(response);
    return;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_failure_reason("Requested VM does not exist");
    response_sender->Return(response);
    return;
  }

  if (request.enable()) {
    iter->second->InflateAggressiveBalloon(base::BindOnce(
        [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
               AggressiveBalloonResponse>> response_sender,
           AggressiveBalloonResponse response) {
          std::move(response_sender)->Return(response);
        },
        std::move(response_sender)));
  } else {
    iter->second->StopAggressiveBalloon(response);
    response_sender->Return(response);
  }
}

void Service::OnResolvConfigChanged(std::vector<string> nameservers,
                                    std::vector<string> search_domains) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (nameservers_ == nameservers && search_domains_ == search_domains) {
    return;
  }

  nameservers_ = std::move(nameservers);
  search_domains_ = std::move(search_domains);

  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      // The VM is currently suspended and will not respond to RPCs.
      // SetResolvConfig() will be called when the VM resumes.
      continue;
    }
    vm->SetResolvConfig(nameservers_, search_domains_);
  }

  // Broadcast DnsSettingsChanged signal so Plugin VM dispatcher is aware as
  // well.
  concierge_adaptor_.SendDnsSettingsChangedSignal(ComposeDnsResponse());
}

void Service::OnDefaultNetworkServiceChanged() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->IsSuspended()) {
      continue;
    }
    vm->HostNetworkChanged();
  }
}

void Service::NotifyCiceroneOfVmStarted(const VmId& vm_id,
                                        uint32_t cid,
                                        pid_t pid,
                                        std::string vm_token) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStartedMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStartedRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  request.set_cid(cid);
  request.set_vm_token(std::move(vm_token));
  request.set_pid(pid);
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of VM startup";
  }
}

void Service::HandleVmStarted(const VmId& vm_id,
                              const vm_tools::concierge::VmInfo& vm_info,
                              const std::string&,
                              vm_tools::concierge::VmStatus status) {
  // TODO(b:254164308) forward the vm started notification to the
  // VmMemoryManagement system once it is landed

  if (!balloon_resizing_timer_.IsRunning()) {
    LOG(INFO) << "New VM. Starting balloon resize timer.";
    balloon_resizing_timer_.Start(FROM_HERE, base::Seconds(1), this,
                                  &Service::RunBalloonPolicy);
  }

  SendVmStartedSignal(vm_id, vm_info, status);
}

void Service::SendVmStartedSignal(const VmId& vm_id,
                                  const vm_tools::concierge::VmInfo& vm_info,
                                  vm_tools::concierge::VmStatus status) {
  vm_tools::concierge::VmStartedSignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.mutable_vm_info()->CopyFrom(vm_info);
  proto.set_status(status);
  concierge_adaptor_.SendVmStartedSignalSignal(proto);
}

void Service::SendVmStartingUpSignal(
    const VmId& vm_id, const vm_tools::concierge::VmInfo& vm_info) {
  vm_tools::concierge::ExtendedVmInfo proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.mutable_vm_info()->CopyFrom(vm_info);
  concierge_adaptor_.SendVmStartingUpSignalSignal(proto);
}

void Service::SendVmGuestUserlandReadySignal(
    const VmId& vm_id, const vm_tools::concierge::GuestUserlandReady ready) {
  vm_tools::concierge::VmGuestUserlandReadySignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.set_ready(ready);
  concierge_adaptor_.SendVmGuestUserlandReadySignalSignal(proto);
}

void Service::NotifyVmStopping(const VmId& vm_id, int64_t cid) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Notify cicerone.
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStoppingMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStoppingRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of stopping VM";
  }

  // Send the D-Bus signal out to notify everyone that we are stopping a VM.
  vm_tools::concierge::VmStoppingSignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.set_cid(cid);
  concierge_adaptor_.SendVmStoppingSignalSignal(proto);
}

void Service::NotifyVmStopped(const VmId& vm_id,
                              int64_t cid,
                              VmStopReason reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Notify cicerone.
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kNotifyVmStoppedMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::NotifyVmStoppedRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  writer.AppendProtoAsArrayOfBytes(request);
  if (!brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    LOG(ERROR) << "Failed notifying cicerone of VM stopped";
  }

  // Send the D-Bus signal out to notify everyone that we have stopped a VM.
  vm_tools::concierge::VmStoppedSignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  proto.set_cid(cid);
  proto.set_reason(reason);
  concierge_adaptor_.SendVmStoppedSignalSignal(proto);
}

std::string Service::GetContainerToken(const VmId& vm_id,
                                       const std::string& container_name) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kGetContainerTokenMethod);
  dbus::MessageWriter writer(&method_call);
  vm_tools::cicerone::ContainerTokenRequest request;
  vm_tools::cicerone::ContainerTokenResponse response;
  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name(vm_id.name());
  request.set_container_name(container_name);
  writer.AppendProtoAsArrayOfBytes(request);
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus_, cicerone_service_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed getting container token from cicerone";
    return "";
  }
  dbus::MessageReader reader(dbus_response.get());
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed parsing proto response";
    return "";
  }
  return response.container_token();
}

std::string Service::GetHostTimeZone() {
  base::FilePath system_timezone;
  // Timezone is set by creating a symlink to an existing file at
  // /usr/share/zoneinfo.
  if (!base::NormalizeFilePath(base::FilePath(kLocaltimePath),
                               &system_timezone)) {
    LOG(ERROR) << "Failed to get system timezone";
    return "";
  }

  base::FilePath zoneinfo(kZoneInfoPath);
  base::FilePath system_timezone_name;
  if (!zoneinfo.AppendRelativePath(system_timezone, &system_timezone_name)) {
    LOG(ERROR) << "Could not get name of timezone " << system_timezone.value();
    return "";
  }

  return system_timezone_name.value();
}

void Service::OnLocaltimeFileChanged(const base::FilePath& path, bool error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (error) {
    LOG(WARNING) << "Error while reading system timezone change";
    return;
  }

  LOG(INFO) << "System timezone changed, updating VM timezones";

  std::string timezone = GetHostTimeZone();
  for (auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    std::string error_msg;
    if (!vm->SetTimezone(timezone, &error_msg)) {
      LOG(WARNING) << "Failed to set timezone for " << vm_entry.first.name()
                   << ": " << error_msg;
    }
  }
}

void Service::OnTremplinStartedSignal(dbus::Signal* signal) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(signal->GetInterface(), vm_tools::cicerone::kVmCiceroneInterface);
  DCHECK_EQ(signal->GetMember(), vm_tools::cicerone::kTremplinStartedSignal);

  vm_tools::cicerone::TremplinStartedSignal tremplin_started_signal;
  dbus::MessageReader reader(signal);
  if (!reader.PopArrayOfBytesAsProto(&tremplin_started_signal)) {
    LOG(ERROR) << "Failed to parse TremplinStartedSignal from DBus Signal";
    return;
  }

  auto iter = FindVm(tremplin_started_signal.owner_id(),
                     tremplin_started_signal.vm_name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Received signal from an unknown vm."
               << VmId(tremplin_started_signal.owner_id(),
                       tremplin_started_signal.vm_name());
    return;
  }
  LOG(INFO) << "Received request: " << __func__ << " for " << iter->first;
  iter->second->SetTremplinStarted();
}

void Service::OnVmToolsStateChangedSignal(dbus::Signal* signal) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  string owner_id, vm_name;
  bool running;
  if (!pvm::dispatcher::ParseVmToolsChangedSignal(signal, &owner_id, &vm_name,
                                                  &running)) {
    return;
  }

  auto iter = FindVm(owner_id, vm_name);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Received signal from an unknown vm "
               << VmId(owner_id, vm_name);
    return;
  }
  LOG(INFO) << "Received request: " << __func__ << " for " << iter->first;
  iter->second->VmToolsStateChanged(running);
}

void Service::OnSignalConnected(const std::string& interface_name,
                                const std::string& signal_name,
                                bool is_connected) {
  if (!is_connected) {
    LOG(ERROR) << "Failed to connect to interface name: " << interface_name
               << " for signal " << signal_name;
  } else {
    LOG(INFO) << "Connected to interface name: " << interface_name
              << " for signal " << signal_name;
  }

  if (interface_name == vm_tools::cicerone::kVmCiceroneInterface) {
    DCHECK_EQ(signal_name, vm_tools::cicerone::kTremplinStartedSignal);
    is_tremplin_started_signal_connected_ = is_connected;
  }
}

void Service::HandleSuspendImminent() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  for (const auto& pair : vms_) {
    auto& vm = pair.second;
    if (vm->UsesExternalSuspendSignals()) {
      continue;
    }
    vm->Suspend();
  }
}

void Service::HandleSuspendDone() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  for (const auto& vm_entry : vms_) {
    auto& vm = vm_entry.second;
    if (vm->UsesExternalSuspendSignals()) {
      continue;
    }

    vm->Resume();

    string failure_reason;
    if (!vm->SetTime(&failure_reason)) {
      LOG(ERROR) << "Failed to set VM clock in " << vm_entry.first << ": "
                 << failure_reason;
    }

    vm->SetResolvConfig(nameservers_, search_domains_);
  }
}

Service::VmMap::iterator Service::FindVm(const VmId& vm_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return vms_.find(vm_id);
}

Service::VmMap::iterator Service::FindVm(const std::string& owner_id,
                                         const std::string& vm_name) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return vms_.find(VmId(owner_id, vm_name));
}

base::FilePath Service::GetVmImagePath(const std::string& dlc_id,
                                       std::string* failure_reason) {
  DCHECK(failure_reason);
  std::optional<std::string> dlc_root =
      AsyncNoReject(bus_->GetDBusTaskRunner(),
                    base::BindOnce(
                        [](DlcHelper* dlc_helper, const std::string& dlc_id,
                           std::string* out_failure_reason) {
                          return dlc_helper->GetRootPath(dlc_id,
                                                         out_failure_reason);
                        },
                        dlcservice_client_.get(), dlc_id, failure_reason))
          .Get()
          .val;
  if (!dlc_root.has_value()) {
    // On an error, failure_reason will be set by GetRootPath().
    return {};
  }
  return base::FilePath(dlc_root.value());
}

VMImageSpec Service::GetImageSpec(
    const vm_tools::concierge::VirtualMachineSpec& vm,
    const std::optional<base::ScopedFD>& kernel_fd,
    const std::optional<base::ScopedFD>& rootfs_fd,
    const std::optional<base::ScopedFD>& initrd_fd,
    const std::optional<base::ScopedFD>& bios_fd,
    const std::optional<base::ScopedFD>& pflash_fd,
    bool is_termina,
    string* failure_reason) {
  DCHECK(failure_reason);
  DCHECK(failure_reason->empty());

  // A VM image is trusted when both:
  // 1) This daemon (or a trusted daemon) chooses the kernel and rootfs path.
  // 2) The chosen VM is a first-party VM.
  // In practical terms this is true iff we are booting termina without
  // specifying kernel and rootfs image.
  bool is_trusted_image = is_termina;

  base::FilePath kernel, rootfs, initrd, bios, pflash;
  if (kernel_fd.has_value()) {
    // User-chosen kernel is untrusted.
    is_trusted_image = false;

    int raw_fd = kernel_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    kernel = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    kernel = base::FilePath(vm.kernel());
  }

  if (rootfs_fd.has_value()) {
    // User-chosen rootfs is untrusted.
    is_trusted_image = false;

    int raw_fd = rootfs_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    rootfs = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    rootfs = base::FilePath(vm.rootfs());
  }

  if (initrd_fd.has_value()) {
    // User-chosen initrd is untrusted.
    is_trusted_image = false;

    int raw_fd = initrd_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    initrd = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  } else {
    initrd = base::FilePath(vm.initrd());
  }

  if (bios_fd.has_value()) {
    // User-chosen bios is untrusted.
    is_trusted_image = false;

    int raw_fd = bios_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    bios = base::FilePath(kProcFileDescriptorsPath)
               .Append(base::NumberToString(raw_fd));
  } else if (!vm.bios_dlc_id().empty() &&
             (vm.bios_dlc_id() == kBruschettaBiosDlcId)) {
    bios = GetVmImagePath(vm.bios_dlc_id(), failure_reason);
    if (!failure_reason->empty() || bios.empty())
      return {};
    bios = bios.Append(kBruschettaBiosDlcPath);
  }

  if (pflash_fd.has_value()) {
    // User-chosen pflash is untrusted.
    is_trusted_image = false;

    int raw_fd = pflash_fd.value().get();
    *failure_reason = RemoveCloseOnExec(raw_fd);
    if (!failure_reason->empty())
      return {};
    pflash = base::FilePath(kProcFileDescriptorsPath)
                 .Append(base::NumberToString(raw_fd));
  }

  base::FilePath vm_path;
  // As a legacy fallback, use the component rather than the DLC.
  //
  // TODO(crbug/953544): remove this once we no longer distribute termina as a
  // component.
  if (vm.dlc_id().empty() && is_termina) {
    vm_path = GetLatestVMPath();
    if (vm_path.empty()) {
      *failure_reason = "Termina component is not loaded";
      return {};
    }
  } else if (!vm.dlc_id().empty()) {
    vm_path = GetVmImagePath(vm.dlc_id(), failure_reason);
    if (vm_path.empty())
      return {};
  }

  // Pull in the DLC-provided files if requested.
  if (!kernel_fd.has_value() && !vm_path.empty())
    kernel = vm_path.Append(kVmKernelName);
  if (!rootfs_fd.has_value() && !vm_path.empty())
    rootfs = vm_path.Append(kVmRootfsName);

  base::FilePath tools_disk;
  if (!vm.tools_dlc_id().empty()) {
    base::FilePath tools_disk_path =
        GetVmImagePath(vm.tools_dlc_id(), failure_reason);
    if (tools_disk_path.empty())
      return {};
    tools_disk = tools_disk_path.Append(kVmToolsDiskName);
  }
  if (tools_disk.empty() && !vm_path.empty())
    tools_disk = vm_path.Append(kVmToolsDiskName);

  return VMImageSpec{
      .kernel = std::move(kernel),
      .initrd = std::move(initrd),
      .rootfs = std::move(rootfs),
      .bios = std::move(bios),
      .pflash = std::move(pflash),
      .tools_disk = std::move(tools_disk),
      .is_trusted_image = is_trusted_image,
  };
}

// TODO(b/244486983): move this functionality to shadercached
Service::VMGpuCacheSpec Service::PrepareVmGpuCachePaths(
    const std::string& owner_id,
    const std::string& vm_name,
    bool enable_render_server,
    bool enable_foz_db_list) {
  base::FilePath cache_path = GetVmGpuCachePathInternal(owner_id, vm_name);
  // Cache ID is either boot id or OS build hash
  base::FilePath cache_id_path = cache_path.DirName();
  base::FilePath base_path = cache_id_path.DirName();

  base::FilePath cache_device_path = cache_path.Append("device");
  base::FilePath cache_render_server_path =
      enable_render_server ? cache_path.Append("render_server")
                           : base::FilePath();
  base::FilePath foz_db_list_file =
      enable_render_server ? cache_render_server_path.Append("foz_db_list.txt")
                           : base::FilePath();

  const base::FilePath* cache_subdir_paths[] = {&cache_device_path,
                                                &cache_render_server_path};
  const base::FilePath* permissions_to_update[] = {
      &base_path, &cache_id_path, &cache_path, &cache_device_path,
      &cache_render_server_path};

  base::AutoLock guard(cache_mutex_);

  // In order to always provide an empty GPU shader cache on each boot or
  // build id change, we hash the boot_id or build number, and erase the whole
  // GPU cache if a directory matching the current boot id or build number hash
  // is not found.
  // For example:
  // VM cache dir: /run/daemon-store/crosvm/<uid>/gpucache/<cacheid>/<vmid>/
  // Cache ID dir: /run/daemon-store/crosvm/<uid>/gpucache/<cacheid>/
  // Base dir: /run/daemon-store/crosvm/<uid>/gpucache/
  // If Cache ID dir exists we know another VM has already created a fresh base
  // dir during this boot or OS release. Otherwise, we erase Base dir to wipe
  // out any previous Cache ID dir.
  if (!base::DirectoryExists(cache_id_path)) {
    LOG(INFO) << "GPU cache dir not found, deleting base directory";
    if (!base::DeletePathRecursively(base_path)) {
      LOG(WARNING) << "Failed to delete gpu cache directory: " << base_path
                   << " shader caching will be disabled.";
      return VMGpuCacheSpec{};
    }
  }

  for (const base::FilePath* path : cache_subdir_paths) {
    if (path->empty()) {
      continue;
    }

    if (!base::DirectoryExists(*path)) {
      base::File::Error dir_error;
      if (!base::CreateDirectoryAndGetError(*path, &dir_error)) {
        LOG(WARNING) << "Failed to create crosvm gpu cache directory in "
                     << *path << ": " << base::File::ErrorToString(dir_error);
        base::DeletePathRecursively(cache_path);
        return VMGpuCacheSpec{};
      }
    }
  }

  for (const base::FilePath* path : permissions_to_update) {
    if (base::IsLink(*path)) {
      continue;
    }
    // Group rx permission needed for VM shader cache management by shadercached
    if (!base::SetPosixFilePermissions(*path, 0750)) {
      LOG(WARNING) << "Failed to set directory permissions for " << *path;
    }
  }

  if (!foz_db_list_file.empty()) {
    bool file_exists = base::PathExists(foz_db_list_file);
    if (enable_foz_db_list) {
      // Initiate foz db file, if it already exists, continue using it
      if (!file_exists) {
        if (base::WriteFile(foz_db_list_file, "", 0) != 0) {
          LOG(WARNING) << "Failed to create foz db list file";
          return VMGpuCacheSpec{};
        }
      }
      if (!base::SetPosixFilePermissions(foz_db_list_file, 0774)) {
        LOG(WARNING) << "Failed to set file permissions for "
                     << foz_db_list_file;
        return VMGpuCacheSpec{};
      }
    } else if (file_exists) {
      LOG(WARNING) << "Dynamic GPU RO cache loading is disabled but the "
                      "feature management file exists";
    }
  }

  return VMGpuCacheSpec{.device = std::move(cache_device_path),
                        .render_server = std::move(cache_render_server_path),
                        .foz_db_list = std::move(foz_db_list_file)};
}

void AddGroupPermissionChildren(const base::FilePath& path) {
  auto enumerator = base::FileEnumerator(
      path, true,
      base::FileEnumerator::DIRECTORIES ^ base::FileEnumerator::SHOW_SYM_LINKS);

  for (base::FilePath child_path = enumerator.Next(); !child_path.empty();
       child_path = enumerator.Next()) {
    if (child_path == path) {
      // Do not change permission for the root path
      continue;
    }

    int permission;
    if (!base::GetPosixFilePermissions(child_path, &permission)) {
      LOG(WARNING) << "Failed to get permission for " << path.value();
    } else if (!base::SetPosixFilePermissions(
                   child_path, permission | base::FILE_PERMISSION_GROUP_MASK)) {
      LOG(WARNING) << "Failed to change permission for " << child_path.value();
    }
  }
}

bool Service::AddGroupPermissionMesa(
    brillo::ErrorPtr* error, const AddGroupPermissionMesaRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!ValidateVmNameAndOwner(request,
                              request /* in place of a response proto */)) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   DBUS_ERROR_FAILED,
                                   "Empty or malformed owner ID / VM name");
    return false;
  }

  base::FilePath cache_path =
      GetVmGpuCachePathInternal(request.owner_id(), request.name());

  AddGroupPermissionChildren(cache_path);

  return true;
}

GetVmLaunchAllowedResponse Service::GetVmLaunchAllowed(
    const GetVmLaunchAllowedRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  GetVmLaunchAllowedResponse response;

  bool allowed = true;
  std::string reason;
  bool is_untrusted =
      IsUntrustedVM(request.run_as_untrusted(), request.is_trusted_image(),
                    request.has_custom_kernel_params(), host_kernel_version_);
  if (is_untrusted) {
    allowed = untrusted_vm_utils_->IsUntrustedVMAllowed(host_kernel_version_,
                                                        &reason);
  }

  response.set_allowed(allowed);
  response.set_reason(reason);

  return response;
}

bool Service::GetVmLogs(brillo::ErrorPtr* error,
                        const GetVmLogsRequest& request,
                        GetVmLogsResponse* response) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!ValidateVmNameAndOwner(request, *response)) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   DBUS_ERROR_FAILED,
                                   "Empty or malformed owner ID / VM name");
    return false;
  }

  base::FilePath log_path =
      GetVmLogPath(request.owner_id(), request.name(), kCrosvmLogFileExt);

  std::vector<base::FilePath> paths;
  int64_t remaining_log_space = kMaxGetVmLogsSize;
  if (base::PathExists(log_path)) {
    int64_t size;
    bool ok = base::GetFileSize(log_path, &size);
    if (!ok) {
      *error =
          brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                DBUS_ERROR_FAILED, "Failed to get log size");
      return false;
    }
    remaining_log_space -= size;
    paths.push_back(log_path);

    for (int i = 1; i <= 5; i++) {
      base::FilePath older_log_path =
          log_path.AddExtension(base::NumberToString(i));

      // Don't read older logs if the total log size read is above the limit.
      if (base::PathExists(older_log_path) && remaining_log_space > 0) {
        ok = base::GetFileSize(older_log_path, &size);
        if (!ok) {
          break;
        }

        remaining_log_space -= size;
        paths.push_back(older_log_path);
      } else {
        break;
      }
    }
  }

  for (auto it = paths.rbegin(); it != paths.rend(); it++) {
    std::string file_contents;
    if (!base::ReadFileToString(*it, &file_contents)) {
      continue;
    }

    std::string_view contents_view{file_contents};
    // Truncate the earliest log, if it would exceed the log size limit.
    if (remaining_log_space < 0) {
      contents_view.remove_prefix(-remaining_log_space);
      remaining_log_space = 0;
    }

    response->mutable_log()->append(contents_view);
  }

  return true;
}

void Service::SwapVm(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SwapVmResponse>>
        response_sender,
    const SwapVmRequest& request) {
  LOG(INFO) << "Received request: " << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  SwapVmResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    response_sender->Return(response);
    return;
  }

  auto iter = FindVm(request.owner_id(), request.name());
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    response.set_failure_reason("Requested VM does not exist");
    response_sender->Return(response);
    return;
  }

  iter->second->HandleSwapVmRequest(
      request, base::BindOnce(
                   [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                          SwapVmResponse>> response_sender,
                      SwapVmResponse response) {
                     std::move(response_sender)->Return(response);
                   },
                   std::move(response_sender)));
}

void Service::NotifyVmSwapping(const VmId& vm_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Send the D-Bus signal out to notify everyone that we are swapping a VM.
  vm_tools::concierge::VmSwappingSignal proto;
  proto.set_owner_id(vm_id.owner_id());
  proto.set_name(vm_id.name());
  concierge_adaptor_.SendVmSwappingSignalSignal(proto);
}

InstallPflashResponse Service::InstallPflash(
    const InstallPflashRequest& request, const base::ScopedFD& pflash_src_fd) {
  InstallPflashResponse response;

  if (!ValidateVmNameAndOwner(request, response)) {
    return response;
  }

  std::optional<PflashMetadata> pflash_metadata =
      GetPflashMetadata(request.owner_id(), request.vm_name());
  if (!pflash_metadata) {
    response.set_failure_reason("Failed to get pflash install path");
    return response;
  }

  // We only allow one Pflash file to be allowed during the lifetime of a VM.
  if (pflash_metadata->is_installed) {
    response.set_failure_reason("Pflash already installed");
    return response;
  }

  // No Pflash is installed that means we can associate the given file with the
  // VM by copying it to a file derived from the VM's name itself.
  base::FilePath pflash_src_path =
      base::FilePath(kProcFileDescriptorsPath)
          .Append(base::NumberToString(pflash_src_fd.get()));

  LOG(INFO) << "Installing Pflash file for VM: " << request.vm_name()
            << " to: " << pflash_metadata->path;
  if (!base::CopyFile(pflash_src_path, pflash_metadata->path)) {
    response.set_failure_reason("Failed to copy pflash image");
    return response;
  }

  response.set_success(true);
  return response;
}

// TODO(b/244486983): separate out GPU VM cache methods out of service.cc file
bool Service::GetVmGpuCachePath(brillo::ErrorPtr* error,
                                const GetVmGpuCachePathRequest& request,
                                GetVmGpuCachePathResponse* response) {
  LOG(INFO) << "Received request: " << __func__;

  if (!ValidateVmNameAndOwner(request, *response)) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   DBUS_ERROR_FAILED,
                                   "Empty or malformed owner ID / VM name");
    return false;
  }

  base::FilePath path =
      GetVmGpuCachePathInternal(request.owner_id(), request.name());
  if (!base::DirectoryExists(path)) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   DBUS_ERROR_FAILED,
                                   "GPU cache path does not exist");
    return false;

  } else if (path.empty()) {
    *error =
        brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                              DBUS_ERROR_FAILED, "GPU cache path is empty");
    return false;
  }

  response->set_path(path.value());
  return true;
}

int Service::GetCpuQuota() {
  const feature::PlatformFeatures::ParamsResult& result =
      feature::PlatformFeatures::Get()->GetParamsAndEnabledBlocking(
          {&kArcVmInitialThrottleFeature});

  const auto result_iter = result.find(kArcVmInitialThrottleFeatureName);
  if (result_iter == result.end()) {
    LOG(ERROR) << "Failed to get params for "
               << kArcVmInitialThrottleFeatureName;
    return kCpuPercentUnlimited;
  }

  const auto& entry = result_iter->second;
  if (!entry.enabled) {
    return kCpuPercentUnlimited;  // cfs_quota feature is disabled.
  }

  auto params_iter = entry.params.find(kArcVmInitialThrottleFeatureQuotaParam);
  if (params_iter == entry.params.end()) {
    LOG(ERROR) << "Couldn't find the parameter: "
               << kArcVmInitialThrottleFeatureQuotaParam;
    return kCpuPercentUnlimited;
  }

  int quota;
  if (!base::StringToInt(params_iter->second, &quota)) {
    LOG(ERROR) << "Failed to parse quota parameter as int: "
               << params_iter->second;
    return kCpuPercentUnlimited;
  }
  return std::min(100, std::max(1, quota));
}

void Service::AddStorageBalloonVm(VmId vm_id) {
  storage_balloon_vms_.insert(vm_id);
}

void Service::RemoveStorageBalloonVm(VmId vm_id) {
  storage_balloon_vms_.erase(vm_id);
}

void Service::OnStatefulDiskSpaceUpdate(
    const spaced::StatefulDiskSpaceUpdate& update) {
  for (auto& vm_id : storage_balloon_vms_) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&Service::HandleStatefulDiskSpaceUpdate,
                       weak_ptr_factory_.GetWeakPtr(), vm_id, update));
  }
}

void Service::HandleStatefulDiskSpaceUpdate(
    VmId vm_id, const spaced::StatefulDiskSpaceUpdate update) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto iter = FindVm(vm_id);
  if (iter == vms_.end()) {
    LOG(ERROR) << "Requested VM does not exist";
    storage_balloon_vms_.erase(vm_id);
    return;
  }

  iter->second->HandleStatefulUpdate(update);
}

void Service::OnSiblingVmDead(VmId vm_id) {
  // This function is called from a `TerminaVm` instance. If we don't post
  // `StopVm` as a task, we will destroy it while we're being called from it.
  // This is complicated and we rather do it as a separate task.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&Service::StopVmInternalAsTask,
                                weak_ptr_factory_.GetWeakPtr(), vm_id,
                                VmStopReason::SIBLING_VM_EXITED));
}

}  // namespace concierge
}  // namespace vm_tools
