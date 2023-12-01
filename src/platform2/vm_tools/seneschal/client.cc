// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>

#include <iostream>
#include <limits>
#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/notreached.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <seneschal/proto_bindings/seneschal_service.pb.h>
#include <vm_concierge/concierge_service.pb.h>

using std::string;

namespace {

constexpr char kStorageDownloads[] = "downloads";
constexpr char kStorageMyFiles[] = "myfiles";
constexpr char kStorageMyDrive[] = "mydrive";
constexpr char kStorageTeamDrives[] = "teamdrives";
constexpr char kStorageComputers[] = "computers";
constexpr char kStorageRemovable[] = "removable";
constexpr char kStoragePlayFiles[] = "playfiles";
constexpr char kStoragePlayFilesGuestOs[] = "playfilesguestos";
constexpr char kStorageLinuxFiles[] = "linuxfiles";
constexpr char kStorageGuestOsFiles[] = "guestosfiles";

int StartServer(dbus::ObjectProxy* proxy, uint64_t port, uint64_t accept_cid) {
  if (port == 0) {
    LOG(ERROR) << "--port is required";
    return EXIT_FAILURE;
  }

  if (port > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    LOG(ERROR) << "--port value is too large; maximum value allowed is "
               << std::numeric_limits<uint32_t>::max();
    return EXIT_FAILURE;
  }

  if (accept_cid < 3) {
    LOG(ERROR) << "invalid value for --accept_cid: " << accept_cid;
    return EXIT_FAILURE;
  }
  if (accept_cid >
      static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    LOG(ERROR) << "--accept_cid value is too large; maximum value allowed is "
               << std::numeric_limits<uint32_t>::max();
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Starting server";

  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kStartServerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::StartServerRequest request;
  request.mutable_vsock()->set_port(static_cast<uint32_t>(port));
  request.mutable_vsock()->set_accept_cid(static_cast<uint32_t>(accept_cid));
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartServerRequest protobuf";
    return EXIT_FAILURE;
  }

  std::unique_ptr<dbus::Response> dbus_response = proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to seneschal service";
    return EXIT_FAILURE;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::StartServerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return EXIT_FAILURE;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to start server: " << response.failure_reason();
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Started server with handle: " << response.handle();
  return EXIT_SUCCESS;
}

int StopServer(dbus::ObjectProxy* proxy, uint64_t handle) {
  if (handle == 0) {
    LOG(ERROR) << "--handle is required";
    return EXIT_FAILURE;
  }

  if (handle > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    LOG(ERROR) << "--handle value is too large; maximum value allowed is "
               << std::numeric_limits<uint32_t>::max();
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Stopping server " << handle;
  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kStopServerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::StopServerRequest request;
  request.set_handle(static_cast<uint32_t>(handle));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StopServerRequest protobuf";
    return EXIT_FAILURE;
  }

  std::unique_ptr<dbus::Response> dbus_response = proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to seneschal service";
    return EXIT_FAILURE;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::StopServerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return EXIT_FAILURE;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to stop server: " << response.failure_reason();
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Stopped server " << handle;
  return EXIT_SUCCESS;
}

int SharePath(dbus::ObjectProxy* proxy,
              uint64_t handle,
              string owner_id,
              string mount_name,
              string storage_location,
              string path,
              bool writable) {
  if (handle == 0) {
    LOG(ERROR) << "--handle is required";
    return EXIT_FAILURE;
  }

  if (handle > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    LOG(ERROR) << "--handle value is too large; maximum value allowed is "
               << std::numeric_limits<uint32_t>::max();
    return EXIT_FAILURE;
  }

  vm_tools::seneschal::SharePathRequest_StorageLocation location;
  if (storage_location == kStorageDownloads) {
    if (owner_id.empty()) {
      LOG(ERROR) << "--owner_id is required for --storage_location=downloads";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::DOWNLOADS;
  } else if (storage_location == kStorageMyFiles) {
    if (owner_id.empty()) {
      LOG(ERROR) << "--owner_id is required for --storage_location=myfiles";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::MY_FILES;
  } else if (storage_location == kStorageMyDrive) {
    if (mount_name.empty()) {
      LOG(ERROR) << "--mount_name is required for --storage_location=mydrive";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::DRIVEFS_MY_DRIVE;
  } else if (storage_location == kStorageTeamDrives) {
    if (mount_name.empty()) {
      LOG(ERROR) << "--mount_name is required for "
                    "--storage_location=teamdrives";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::DRIVEFS_TEAM_DRIVES;
  } else if (storage_location == kStorageComputers) {
    if (mount_name.empty()) {
      LOG(ERROR) << "--mount_name is required for "
                    "--storage_location=computers";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::DRIVEFS_COMPUTERS;
  } else if (storage_location == kStorageRemovable) {
    location = vm_tools::seneschal::SharePathRequest::REMOVABLE;
  } else if (storage_location == kStoragePlayFiles) {
    location = vm_tools::seneschal::SharePathRequest::PLAY_FILES;
  } else if (storage_location == kStoragePlayFilesGuestOs) {
    location = vm_tools::seneschal::SharePathRequest::PLAY_FILES_GUEST_OS;
  } else if (storage_location == kStorageLinuxFiles) {
    if (owner_id.empty()) {
      LOG(ERROR) << "--owner_id is required for --storage_location=linuxfiles";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::LINUX_FILES;
  } else if (storage_location == kStorageGuestOsFiles) {
    if (owner_id.empty()) {
      LOG(ERROR)
          << "--owner_id is required for --storage_location=guestosfiles";
      return EXIT_FAILURE;
    }
    if (mount_name.empty()) {
      LOG(ERROR)
          << "--mount_name is required for --storage_location=guestosfiles";
      return EXIT_FAILURE;
    }
    location = vm_tools::seneschal::SharePathRequest::GUEST_OS_FILES;
  } else {
    LOG(ERROR) << "--storage_location is required "
                  "(myfiles|downloads|mydrive|teamdrives|computers|removable|"
                  "playfiles|linuxfiles|guestosfiles)";
    return EXIT_FAILURE;
  }

  // Relative path required, but allow use of '/' to represent root.
  if (path.empty()) {
    LOG(ERROR) << "--path is required";
    return EXIT_FAILURE;
  } else if (path == "/") {
    path = "";
  }

  LOG(INFO) << "Sharing " << storage_location << ":" << path << " with server "
            << handle;

  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kSharePathMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::SharePathRequest request;
  request.set_handle(static_cast<uint32_t>(handle));
  request.set_owner_id(std::move(owner_id));
  request.set_drivefs_mount_name(mount_name);
  request.set_guest_os_mount_name(std::move(mount_name));
  request.set_storage_location(location);

  vm_tools::seneschal::SharedPath* shared_path = request.mutable_shared_path();
  shared_path->set_path(std::move(path));
  shared_path->set_writable(writable);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SharePathRequest protobuf";
    return EXIT_FAILURE;
  }

  std::unique_ptr<dbus::Response> dbus_response = proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to seneschal service";
    return EXIT_FAILURE;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::SharePathResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return EXIT_FAILURE;
  }

  if (!response.success()) {
    std::cout << "Unable to share path: " << response.failure_reason()
              << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << request.shared_path().path() << " is available at path "
            << "/mnt/chromeos/" << response.path() << std::endl;
  return EXIT_SUCCESS;
}

int UnsharePath(dbus::ObjectProxy* proxy, uint64_t handle, string path) {
  if (handle == 0) {
    LOG(ERROR) << "--handle is required";
    return EXIT_FAILURE;
  }

  if (handle > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
    LOG(ERROR) << "--handle value is too large; maximum value allowed is "
               << std::numeric_limits<uint32_t>::max();
    return EXIT_FAILURE;
  }

  if (path.empty()) {
    LOG(ERROR) << "--path is required";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Unsharing " << path << " with server " << handle;

  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kUnsharePathMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::UnsharePathRequest request;
  request.set_handle(static_cast<uint32_t>(handle));
  request.set_path(std::move(path));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UnsharePathRequest protobuf";
    return EXIT_FAILURE;
  }

  std::unique_ptr<dbus::Response> dbus_response = proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to seneschal service";
    return EXIT_FAILURE;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::UnsharePathResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return EXIT_FAILURE;
  }

  if (!response.success()) {
    std::cout << "Unable to unshare path: " << response.failure_reason()
              << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << request.path() << " unshared successfully" << std::endl;
  return EXIT_SUCCESS;
}

bool GetServerHandle(scoped_refptr<dbus::Bus> bus,
                     const string& owner_id,
                     string vm_name,
                     uint64_t* handle) {
  dbus::ObjectProxy* concierge_proxy = bus->GetObjectProxy(
      vm_tools::concierge::kVmConciergeServiceName,
      dbus::ObjectPath(vm_tools::concierge::kVmConciergeServicePath));
  dbus::MethodCall method_call(vm_tools::concierge::kVmConciergeInterface,
                               vm_tools::concierge::kGetVmInfoMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::concierge::GetVmInfoRequest request;
  request.set_owner_id(owner_id);
  request.set_name(vm_name);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetVmInfo protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      concierge_proxy->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to concierge service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::concierge::GetVmInfoResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return false;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to get VM info for " << vm_name;
    return false;
  }

  *handle = response.vm_info().seneschal_server_handle();
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;

  // Operations.
  DEFINE_bool(start, false, "Start a new server");
  DEFINE_bool(stop, false, "Stop a running server");
  DEFINE_bool(share_path, false, "Share a path with a running server");
  DEFINE_bool(unshare_path, false, "Unshare a path with a running server");

  // Parameters.
  DEFINE_string(vm_name, "", "The name for the VM");
  DEFINE_string(owner_id, "", "The cryptohome id of the user");
  DEFINE_string(
      mount_name, "",
      "The mount directory name within /media/fuse for DriveFS or GuestOs");
  DEFINE_string(storage_location, kStorageMyFiles,
                "The storage location of path to share "
                "(myfiles|downloads|mydrive|teamdrives|computers|removable|"
                "playfiles|linuxfiles|guestosfiles)");
  DEFINE_uint64(handle, 0, "The handle for the server");
  DEFINE_uint64(port, 0, "Port number on which the server should listen");
  DEFINE_uint64(
      accept_cid, 0,
      "The vsock context id from which the server should accept connections");
  DEFINE_string(path, "", "Path to share with a running server");
  DEFINE_bool(writable, false, "Whether the shared path should be writable");

  brillo::FlagHelper::Init(argc, argv, "seneschal client tool");
  brillo::InitLog(brillo::kLogToStderrIfTty);

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(std::move(opts)));

  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return EXIT_FAILURE;
  }

  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      vm_tools::seneschal::kSeneschalServiceName,
      dbus::ObjectPath(vm_tools::seneschal::kSeneschalServicePath));
  if (!proxy) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::seneschal::kSeneschalServiceName;
    return EXIT_FAILURE;
  }

  if (FLAGS_start + FLAGS_stop + FLAGS_share_path + FLAGS_unshare_path != 1) {
    LOG(ERROR) << "Exactly one of --start, --stop, --share_path, or "
                  "--unshare_path is required";
    return EXIT_FAILURE;
  }

  if (FLAGS_start) {
    return StartServer(proxy, FLAGS_port, FLAGS_accept_cid);
  } else if (FLAGS_stop) {
    return StopServer(proxy, FLAGS_handle);
  } else if (FLAGS_share_path || FLAGS_unshare_path) {
    if (FLAGS_handle == 0 && FLAGS_vm_name.empty()) {
      LOG(ERROR) << "--handle or --vm_name is required";
      return EXIT_FAILURE;
    }

    uint64_t handle = FLAGS_handle;
    if (handle == 0) {
      if (FLAGS_owner_id.empty()) {
        LOG(ERROR) << "--owner_id is required if --handle not set";
        return EXIT_FAILURE;
      }

      if (!GetServerHandle(bus, FLAGS_owner_id, std::move(FLAGS_vm_name),
                           &handle)) {
        LOG(ERROR) << "Failed to get server handle";
        return EXIT_FAILURE;
      }
    }

    if (FLAGS_share_path) {
      return SharePath(proxy, handle, std::move(FLAGS_owner_id),
                       std::move(FLAGS_mount_name),
                       std::move(FLAGS_storage_location), std::move(FLAGS_path),
                       FLAGS_writable);
    } else if (FLAGS_unshare_path) {
      return UnsharePath(proxy, handle, std::move(FLAGS_path));
    }
  }

  NOTREACHED();
  return EXIT_FAILURE;
}
