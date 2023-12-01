// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_BUILDER_H_
#define VM_TOOLS_CONCIERGE_VM_BUILDER_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>
#include <dbus/object_proxy.h>

#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vm_util.h"

namespace vm_tools {
namespace concierge {

class VmBuilder {
 public:
  // Contains the rootfs device and path.
  struct Rootfs {
    std::string device;
    base::FilePath path;
    bool writable;
  };

  // Audio device type enumeration.
  enum class AudioDeviceType {
    kAC97,
    kVirtio,
  };

  VmBuilder();
  VmBuilder(VmBuilder&&);
  VmBuilder& operator=(VmBuilder&& other);
  VmBuilder(const VmBuilder&) = delete;
  VmBuilder& operator=(const VmBuilder&) = delete;
  ~VmBuilder();

  VmBuilder& SetKernel(base::FilePath kernel);
  VmBuilder& SetInitrd(base::FilePath initrd);
  VmBuilder& SetBios(base::FilePath bios);
  VmBuilder& SetPflash(base::FilePath pflash);
  VmBuilder& SetRootfs(const struct Rootfs& rootfs);
  VmBuilder& SetCpus(int32_t cpus);
  VmBuilder& SetVsockCid(uint32_t vsock_cid);
  VmBuilder& AppendDisks(std::vector<Disk> disks);
  VmBuilder& SetMemory(const std::string& memory_in_mb);
  VmBuilder& SetBalloonBias(const std::string& balloon_bias_mib);

  VmBuilder& SetSyslogTag(const std::string& syslog_tag);
  VmBuilder& SetSocketPath(const std::string& socket_path);
  VmBuilder& AppendTapFd(base::ScopedFD tap_fd);
  VmBuilder& AppendKernelParam(const std::string& param);
  VmBuilder& AppendOemString(const std::string& string);
  VmBuilder& AppendAudioDevice(const AudioDeviceType type,
                               const std::string& params);
  VmBuilder& AppendSerialDevice(const std::string& device);
  VmBuilder& AppendSharedDir(SharedDataParam shared_data_param);
  VmBuilder& AppendCustomParam(const std::string& key,
                               const std::string& value);

  // Instructs this VM to use a wayland socket, if the empty string is provided
  // the default path to the socket will be used, otherwise |socket| will be the
  // path.
  VmBuilder& SetWaylandSocket(const std::string& socket = "");
  VmBuilder& AddExtraWaylandSocket(const std::string& socket);

  VmBuilder& EnableGpu(bool enable);
  VmBuilder& EnableDGpuPassthrough(bool enable);
  VmBuilder& EnableVulkan(bool enable);
  VmBuilder& EnableVirtgpuNativeContext(bool enable);
  VmBuilder& EnableCrossDomainContext(bool enable);
  // Make virglrenderer use Big GL instead of the default GLES.
  VmBuilder& EnableBigGl(bool enable);
  // Offload Vulkan use to isolated virglrenderer render server
  VmBuilder& EnableRenderServer(bool enable);
  VmBuilder& SetGpuCachePath(base::FilePath gpu_cache_path);
  VmBuilder& SetGpuCacheSize(std::string gpu_cache_size_str);
  VmBuilder& SetRenderServerCachePath(base::FilePath render_server_cache_path);
  VmBuilder& SetPrecompiledCachePath(base::FilePath precompiled_cache_path);
  VmBuilder& SetFozDbListPath(base::FilePath foz_db_list_path);
  VmBuilder& SetRenderServerCacheSize(std::string render_server_cache_size_str);

  VmBuilder& EnableSoftwareTpm(bool enable);
  VmBuilder& EnableVtpmProxy(bool enable);
  VmBuilder& EnableVideoDecoder(bool enable);
  VmBuilder& EnableVideoEncoder(bool enable);
  VmBuilder& EnableBattery(bool enable);
  VmBuilder& EnableSmt(bool enable);
  VmBuilder& EnableDelayRt(bool enable);
  VmBuilder& EnablePerVmCoreScheduling(bool enable);

  // Override flags for O_DIRECT for already appended disks.
  VmBuilder& EnableODirect(bool enable);
  // Override flags for multiple_workers for already appended disks.
  VmBuilder& EnableMultipleWorkers(bool enable);
  // Override options for the async runtime for already appended disks.
  VmBuilder& SetBlockAsyncExecutor(AsyncExecutor executor);
  // Override block size for already appended disks.
  VmBuilder& SetBlockSize(size_t block_size);

  VmBuilder& SetVmmSwapDir(base::FilePath vmm_swap_dir);

  // Builds the command line required to start a VM. Returns an empty list if
  // the vm args are invalid.
  base::StringPairs BuildVmArgs(
      CustomParametersForDev* dev_params = nullptr) const;

  static void SetValidWaylandRegexForTesting(char* regex);

 private:
  bool HasValidWaylandSockets() const;

  // Builds the parameters for `crosvm run` to start a VM based on this
  // VmBuilder's settings.
  base::StringPairs BuildRunParams() const;

  base::FilePath kernel_;
  base::FilePath initrd_;
  base::FilePath bios_;
  base::FilePath pflash_;
  std::optional<Rootfs> rootfs_;
  int32_t cpus_ = 0;
  std::optional<uint32_t> vsock_cid_;
  std::string memory_in_mib_;
  std::string balloon_bias_mib_;

  std::string syslog_tag_;
  std::string vm_socket_path_;

  bool enable_gpu_ = false;
  bool enable_dgpu_passthrough_ = false;
  bool enable_vulkan_ = false;
  bool enable_virtgpu_native_context_ = false;
  bool enable_cross_domain_context_ = false;
  bool enable_big_gl_ = false;
  bool enable_render_server_ = false;
  base::FilePath gpu_cache_path_;
  std::string gpu_cache_size_str_;
  base::FilePath render_server_cache_path_;
  base::FilePath foz_db_list_path_;
  base::FilePath precompiled_cache_path_;
  std::string render_server_cache_size_str_;

  bool enable_software_tpm_ = false;
  bool enable_vtpm_proxy_ = false;
  bool enable_video_decoder_ = false;
  bool enable_video_encoder_ = false;
  bool enable_battery_ = false;
  std::optional<bool> enable_smt_ = false;
  bool enable_delay_rt_ = false;
  bool enable_per_vm_core_scheduling_ = false;

  std::vector<Disk> disks_;
  std::vector<std::string> kernel_params_;
  std::vector<std::string> oem_strings_;
  std::vector<base::ScopedFD> tap_fds_;

  struct AudioDevice {
    AudioDeviceType type;
    std::string params;
  };
  std::vector<AudioDevice> audio_devices_;
  std::vector<std::string> serial_devices_;
  std::vector<std::string> wayland_sockets_;
  std::vector<SharedDataParam> shared_dirs_;
  std::vector<std::vector<int32_t>> cpu_clusters_;

  base::FilePath vmm_swap_dir_;

  base::StringPairs custom_params_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_BUILDER_H_
