/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "arc/adbd/adbd.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // NOLINT - needs to be after sys/socket.h

#include <memory>

#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/launch.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/values.h>

#include "arc/adbd/arcvm_sock_to_usb.h"
#include "arc/adbd/arcvm_usb_to_sock.h"

namespace adbd {
namespace {

constexpr uint16_t kAdbVsockPort = 5555;
constexpr char kRuntimePath[] = "/run/arc/adbd";
constexpr char kConfigFSPath[] = "/dev/config";
constexpr char kConfigPath[] = "/etc/arc/adbd.json";

// The shifted u/gid of the shell user, used by Android's adbd.
constexpr uid_t kShellUgid = 657360;

// The blob that is sent to FunctionFS to setup the adb gadget. This works for
// newer kernels (>=3.18). This and the following blobs were created by
// https://android.googlesource.com/platform/system/core/+/HEAD/adb/daemon/usb.cpp
constexpr const uint8_t kControlPayloadV2[] = {
    0x03, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x02, 0xFF, 0x42, 0x01,
    0x01, 0x07, 0x05, 0x01, 0x02, 0x40, 0x00, 0x00, 0x07, 0x05, 0x82, 0x02,
    0x40, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x02, 0xFF, 0x42, 0x01, 0x01,
    0x07, 0x05, 0x01, 0x02, 0x00, 0x02, 0x00, 0x07, 0x05, 0x82, 0x02, 0x00,
    0x02, 0x00, 0x09, 0x04, 0x00, 0x00, 0x02, 0xFF, 0x42, 0x01, 0x01, 0x07,
    0x05, 0x01, 0x02, 0x00, 0x04, 0x00, 0x06, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x05, 0x82, 0x02, 0x00, 0x04, 0x00, 0x06, 0x30, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x23, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// The blob that is sent to FunctionFS to setup the adb gadget. This works
// for older kernels.
constexpr const uint8_t kControlPayloadV1[] = {
    0x01, 0x00, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x02, 0xFF,
    0x42, 0x01, 0x01, 0x07, 0x05, 0x01, 0x02, 0x40, 0x00, 0x00, 0x07,
    0x05, 0x82, 0x02, 0x40, 0x00, 0x00, 0x09, 0x04, 0x00, 0x00, 0x02,
    0xFF, 0x42, 0x01, 0x01, 0x07, 0x05, 0x01, 0x02, 0x00, 0x02, 0x00,
    0x07, 0x05, 0x82, 0x02, 0x00, 0x02, 0x00};

// The blob that is sent to FunctionFS to setup the name of the gadget. It is
// "ADB Interface".
constexpr const uint8_t kControlStrings[] = {
    0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x04, 0x41, 0x44, 0x42, 0x20,
    0x49, 0x6E, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x00};

// Bind-mounts a file located in |source| to |target|. It also makes it be owned
// and only writable by Android shell.
bool BindMountFile(const base::FilePath& source, const base::FilePath& target) {
  if (!base::PathExists(target)) {
    base::ScopedFD target_file(
        HANDLE_EINTR(open(target.value().c_str(), O_WRONLY | O_CREAT, 0600)));
    if (!target_file.is_valid()) {
      PLOG(ERROR) << "Failed to touch " << target.value();
      return false;
    }
  }
  if (chown(source.value().c_str(), kShellUgid, kShellUgid) == -1) {
    PLOG(ERROR) << "Failed to chown " << source.value()
                << " to Android's shell user";
    return false;
  }
  if (mount(source.value().c_str(), target.value().c_str(), nullptr, MS_BIND,
            nullptr) == -1) {
    PLOG(ERROR) << "Failed to mount " << target.value();
    return false;
  }
  return true;
}

}  // namespace

bool CreatePipe(const base::FilePath& path) {
  // Create the FIFO at a temporary path. We will call rename(2) later to make
  // the whole operation atomic.
  const base::FilePath tmp_path = path.AddExtension(".tmp");
  if (unlink(tmp_path.value().c_str()) == -1 && errno != ENOENT) {
    PLOG(ERROR) << "Failed to remove stale FIFO at " << tmp_path.value();
    return false;
  }
  if (mkfifo(tmp_path.value().c_str(), 0600) == -1) {
    PLOG(ERROR) << "Failed to create FIFO at " << tmp_path.value();
    return false;
  }
  // base::Unretained is safe since the closure will be run before |tmp_path|
  // goes out of scope.
  base::ScopedClosureRunner unlink_fifo(base::BindOnce(
      base::IgnoreResult(&unlink), base::Unretained(tmp_path.value().c_str())));
  if (chown(tmp_path.value().c_str(), kShellUgid, kShellUgid) == -1) {
    PLOG(ERROR) << "Failed to chown FIFO at " << tmp_path.value()
                << " to Android's shell user";
    return false;
  }
  if (rename(tmp_path.value().c_str(), path.value().c_str()) == -1) {
    PLOG(ERROR) << "Failed to rename FIFO at " << tmp_path.value() << " to "
                << path.value();
    return false;
  }
  unlink_fifo.ReplaceClosure(base::DoNothing());
  return true;
}

bool GetConfiguration(AdbdConfiguration* config) {
  std::string config_json_data;
  if (!base::ReadFileToString(base::FilePath(kConfigPath), &config_json_data)) {
    PLOG(ERROR) << "Failed to read config from " << kConfigPath;
    return false;
  }

  auto config_root = base::JSONReader::ReadAndReturnValueWithError(
      config_json_data, base::JSON_PARSE_RFC);
  if (!config_root.has_value()) {
    LOG(ERROR) << "Failed to parse adb.json: " << config_root.error().message;
    return false;
  }
  if (!config_root->is_dict()) {
    LOG(ERROR) << "Failed to parse root dictionary from adb.json";
    return false;
  }
  const auto& config_root_dict = config_root->GetDict();

  const std::string* usb_product_id =
      config_root_dict.FindString("usbProductId");
  if (!usb_product_id) {
    LOG(ERROR) << "Failed to parse usbProductId";
    return false;
  }
  config->usb_product_id = *usb_product_id;
  // kernelModules are optional.
  const base::Value::List* kernel_module_list =
      config_root_dict.FindList("kernelModules");
  if (kernel_module_list) {
    for (const auto& kernel_module_value : *kernel_module_list) {
      AdbdConfigurationKernelModule module;
      if (!kernel_module_value.is_dict()) {
        LOG(ERROR) << "kernelModules contains a non-dictionary";
        return false;
      }
      const auto& kernel_module_value_dict = kernel_module_value.GetDict();

      const std::string* module_name =
          kernel_module_value_dict.FindString("name");
      if (!module_name) {
        LOG(ERROR) << "Failed to parse kernelModules.name";
        return false;
      }
      module.name = *module_name;
      const base::Value::List* module_parameters =
          kernel_module_value_dict.FindList("parameters");
      if (module_parameters) {
        // Parameters are optional.
        for (const auto& parameter_value : *module_parameters) {
          if (!parameter_value.is_string()) {
            LOG(ERROR) << "kernelModules.parameters contains a non-string";
            return false;
          }
          module.parameters.emplace_back(parameter_value.GetString());
        }
      }
      config->kernel_modules.emplace_back(module);
    }
  }

  return true;
}

std::string GetUDCDriver() {
  base::FileEnumerator udc_enum(
      base::FilePath("/sys/class/udc/"), false /* recursive */,
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS);
  const base::FilePath name = udc_enum.Next();
  if (name.empty())
    return std::string();
  // We expect to only have one UDC driver in the system, so we can just return
  // the first file in the directory.
  return name.BaseName().value();
}

bool SetupConfigFS(const std::string& serialnumber,
                   const std::string& usb_product_id,
                   const std::string& usb_product_name) {
  const base::FilePath configfs_directory(kConfigFSPath);
  if (!base::CreateDirectory(configfs_directory)) {
    PLOG(ERROR) << "Failed to create " << configfs_directory.value();
    return false;
  }
  if (mount("configfs", configfs_directory.value().c_str(), "configfs",
            MS_NOEXEC | MS_NOSUID | MS_NODEV, nullptr) == -1) {
    PLOG(ERROR) << "Failed to mount configfs";
    return false;
  }

  // Setup the gadget.
  const base::FilePath gadget_path = configfs_directory.Append("usb_gadget/g1");
  if (!base::CreateDirectory(gadget_path.Append("functions/ffs.adb"))) {
    PLOG(ERROR) << "Failed to create ffs.adb directory";
    return false;
  }
  if (!base::CreateDirectory(gadget_path.Append("configs/b.1/strings/0x409"))) {
    PLOG(ERROR) << "Failed to create configs/b.1/strings directory";
    return false;
  }
  if (!base::CreateDirectory(gadget_path.Append("strings/0x409"))) {
    PLOG(ERROR) << "Failed to create config strings directory";
    return false;
  }
  const base::FilePath function_symlink_path =
      gadget_path.Append("configs/b.1/f1");
  if (!base::PathExists(function_symlink_path)) {
    if (!base::CreateSymbolicLink(gadget_path.Append("functions/ffs.adb"),
                                  function_symlink_path)) {
      PLOG(ERROR) << "Failed to create symbolic link";
      return false;
    }
  }
  // Argument-dependent lookup puts base::WriteFile into the candidates of
  // overload resolution although this is in the adbd namespace.
  // In libchrome r780000, the variant
  // base::WriteFile(const FilePath& filename, StringPiece data) will be added
  // which causes ambiguity to calling adbd::WriteFile.
  if (!base::WriteFile(gadget_path.Append("idVendor"), "0x18d1"))
    return false;
  if (!base::WriteFile(gadget_path.Append("idProduct"), usb_product_id))
    return false;
  if (!base::WriteFile(gadget_path.Append("strings/0x409/serialnumber"),
                       serialnumber)) {
    return false;
  }
  if (!base::WriteFile(gadget_path.Append("strings/0x409/manufacturer"),
                       "google"))
    return false;
  if (!base::WriteFile(gadget_path.Append("strings/0x409/product"),
                       usb_product_name))
    return false;
  if (!base::WriteFile(gadget_path.Append("configs/b.1/MaxPower"), "500"))
    return false;

  return true;
}

bool BindMountUsbBulkEndpoints() {
  const base::FilePath functionfs_path(kFunctionFSPath);
  const base::FilePath runtime_path(kRuntimePath);

  for (const auto& endpoint : {"ep1", "ep2"}) {
    if (!BindMountFile(functionfs_path.Append(endpoint),
                       runtime_path.Append(endpoint))) {
      return false;
    }
  }
  return true;
}

base::ScopedFD SetupFunctionFS(const std::string& udc_driver_name) {
  const base::FilePath functionfs_path(kFunctionFSPath);

  // Create the FunctionFS mount.
  if (!base::CreateDirectory(functionfs_path)) {
    PLOG(ERROR) << "Failed to create " << functionfs_path.value();
    return base::ScopedFD();
  }
  if (mount("adb", functionfs_path.value().c_str(), "functionfs",
            MS_NOEXEC | MS_NOSUID | MS_NODEV, nullptr) == -1) {
    PLOG(ERROR) << "Failed to mount functionfs";
    return base::ScopedFD();
  }

  // Send the configuration to the real control endpoint.
  base::ScopedFD control_file(HANDLE_EINTR(
      open(functionfs_path.Append("ep0").value().c_str(), O_WRONLY)));
  if (!control_file.is_valid()) {
    PLOG(ERROR) << "Failed to open control file";
    return base::ScopedFD();
  }
  if (!base::WriteFileDescriptor(control_file.get(), kControlPayloadV2)) {
    PLOG(WARNING) << "Failed to write the V2 control payload, "
                     "trying to write the V1 control payload";
    if (!base::WriteFileDescriptor(control_file.get(), kControlPayloadV1)) {
      PLOG(ERROR) << "Failed to write the V1 control payload";
      return base::ScopedFD();
    }
  }
  if (!base::WriteFileDescriptor(control_file.get(), kControlStrings)) {
    PLOG(ERROR) << "Failed to write the control strings";
    return base::ScopedFD();
  }
  if (!base::WriteFile(base::FilePath("/dev/config/usb_gadget/g1/UDC"),
                       udc_driver_name)) {
    return base::ScopedFD();
  }

  return control_file;
}

bool SetupKernelModules(
    const std::vector<AdbdConfigurationKernelModule>& kernel_modules) {
  for (const auto& kernel_module : kernel_modules) {
    std::vector<std::string> argv;
    argv.emplace_back("/sbin/modprobe");
    argv.emplace_back(kernel_module.name);
    argv.insert(std::end(argv), std::begin(kernel_module.parameters),
                std::end(kernel_module.parameters));
    base::Process process(base::LaunchProcess(argv, base::LaunchOptions()));
    if (!process.IsValid()) {
      PLOG(ERROR) << "Failed to invoke /sbin/modprobe " << kernel_module.name;
      return false;
    }
    int exit_code = -1;
    if (!process.WaitForExit(&exit_code)) {
      PLOG(ERROR) << "Failed to wait for /sbin/modprobe " << kernel_module.name;
      return false;
    }
    if (exit_code != 0) {
      LOG(ERROR) << "Invocation of /sbin/modprobe " << kernel_module.name
                 << " exited with non-zero code " << exit_code;
      return false;
    }
  }
  return true;
}

// Initializes vsock connection.
base::ScopedFD InitializeVSockConnection(uint32_t cid) {
  CHECK_GE(cid, adbd::kFirstGuestVmAddr);

  base::ScopedFD vsock_sock(socket(AF_VSOCK, SOCK_STREAM, 0));
  if (!vsock_sock.is_valid()) {
    PLOG(ERROR) << "Failed to create vsock socket";
    return base::ScopedFD();
  }
  struct sockaddr_vm addr_vm = {};
  addr_vm.svm_family = AF_VSOCK;
  addr_vm.svm_port = kAdbVsockPort;
  addr_vm.svm_cid = cid;
  if (HANDLE_EINTR(connect(vsock_sock.get(),
                           reinterpret_cast<const struct sockaddr*>(&addr_vm),
                           sizeof(addr_vm))) < 0) {
    PLOG(WARNING) << "Failed to connect to vsock socket";
    return base::ScopedFD();
  }
  LOG(INFO) << "Connected to ARCVM";
  return vsock_sock;
}

void StartArcVmAdbBridge(uint32_t cid) {
  constexpr base::TimeDelta kConnectInterval = base::Seconds(15);
  constexpr int kMaxRetries = 4;

  int retries = kMaxRetries;
  auto vsock_sock = InitializeVSockConnection(cid);
  while (!vsock_sock.is_valid()) {
    if (--retries < 0) {
      LOG(ERROR) << "Too many retries; giving up";
      _exit(EXIT_FAILURE);
    }
    // This path may be taken when guest's adbd hasn't started listening to the
    // socket yet. To work around the case, retry connecting to the socket after
    // a short sleep.
    // TODO(crbug.com/1126289): Remove the retry hack.
    base::PlatformThread::Sleep(kConnectInterval);
    vsock_sock = InitializeVSockConnection(cid);
  }

  // Channel direction is from device side, instead of USB perspective.
  const base::FilePath ep_out =
      base::FilePath(adbd::kFunctionFSPath).Append("ep1");
  base::ScopedFD ep_out_fd(
      HANDLE_EINTR(open(ep_out.value().c_str(), O_RDONLY)));
  if (!ep_out_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open OUT usb endpoint";
    _exit(EXIT_FAILURE);
  }
  auto sock_fd = vsock_sock.get();
  std::unique_ptr<ArcVmUsbToSock> ch_in =
      std::make_unique<ArcVmUsbToSock>(sock_fd, ep_out_fd.get());
  if (!ch_in->Start()) {
    LOG(ERROR) << "IN Channel failed to start";
    _exit(EXIT_FAILURE);
  }
  const base::FilePath ep_in =
      base::FilePath(adbd::kFunctionFSPath).Append("ep2");
  base::ScopedFD ep_in_fd(HANDLE_EINTR(open(ep_in.value().c_str(), O_WRONLY)));
  if (!ep_in_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open OUT usb endpoint";
    _exit(EXIT_FAILURE);
  }
  std::unique_ptr<ArcVmSockToUsb> ch_out =
      std::make_unique<ArcVmSockToUsb>(sock_fd, ep_in_fd.get());
  if (!ch_out->Start()) {
    LOG(ERROR) << "OUT Channel failed to start";
    _exit(EXIT_FAILURE);
  }
  LOG(INFO) << "arcvm adbd USB bridge started";
  // The function will not return here because the execution is waiting
  // for threads to join but that won't happen in normal cases.
}

}  // namespace adbd
