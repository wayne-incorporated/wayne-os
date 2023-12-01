// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <base/at_exit.h>
#include <base/check_op.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/message_loop/message_pump_type.h>
#include <base/notreached.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <crosvm/qcow_utils.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <vm_cicerone/cicerone_service.pb.h>

using std::string;

namespace {

constexpr int kDefaultTimeoutMs = 120 * 1000;

void OnSignalConnected(const std::string& interface_name,
                       const std::string& signal_name,
                       bool is_connected) {
  LOG(INFO) << "D-Bus signal " << (is_connected ? "" : "NOT ")
            << "connected for " << interface_name << ":" << signal_name;
}

void OnContainerCreatedCallback(
    base::RunLoop* run_loop,
    vm_tools::cicerone::LxdContainerCreatedSignal::Status* final_status,
    std::string* failure_reason,
    dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  vm_tools::cicerone::LxdContainerCreatedSignal lccs;
  if (!reader.PopArrayOfBytesAsProto(&lccs)) {
    LOG(ERROR) << "Failed parsing LxdContainerCreatedSignal proto";
    return;
  }

  *final_status = lccs.status();
  *failure_reason = lccs.failure_reason();
  run_loop->Quit();
}

void OnContainerStartingCallback(
    base::RunLoop* run_loop,
    vm_tools::cicerone::LxdContainerStartingSignal::Status* final_status,
    std::string* failure_reason,
    dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  vm_tools::cicerone::LxdContainerStartingSignal lcss;
  if (!reader.PopArrayOfBytesAsProto(&lcss)) {
    LOG(ERROR) << "Failed parsing LxdContainerStartingSignal proto";
    return;
  }

  switch (lcss.status()) {
    case vm_tools::cicerone::LxdContainerStartingSignal::STARTED:
    case vm_tools::cicerone::LxdContainerStartingSignal::CANCELLED:
    case vm_tools::cicerone::LxdContainerStartingSignal::FAILED:
      *final_status = lcss.status();
      *failure_reason = lcss.failure_reason();
      run_loop->Quit();
      break;
    default:
      break;
  }
}

int CreateLxdContainer(dbus::ObjectProxy* proxy,
                       const string& vm_name,
                       const string& container_name,
                       const string& owner_id,
                       string image_server,
                       string image_alias,
                       string rootfs_path,
                       string metadata_path) {
  LOG(INFO) << "Creating LXD container";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kCreateLxdContainerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::CreateLxdContainerRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_image_server(std::move(image_server));
  request.set_image_alias(std::move(image_alias));
  request.set_rootfs_path(std::move(rootfs_path));
  request.set_metadata_path(std::move(metadata_path));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode CreateLxdContainer protobuf";
    return -1;
  }

  // RunLoop so we can monitor the D-Bus signals coming back to determine when
  // container creation has actually finished.
  base::RunLoop run_loop;
  vm_tools::cicerone::LxdContainerCreatedSignal::Status final_status =
      vm_tools::cicerone::LxdContainerCreatedSignal::UNKNOWN;
  std::string failure_reason = "Timed out waiting for reply";
  proxy->ConnectToSignal(vm_tools::cicerone::kVmCiceroneInterface,
                         vm_tools::cicerone::kLxdContainerCreatedSignal,
                         base::BindRepeating(&OnContainerCreatedCallback,
                                             base::Unretained(&run_loop),
                                             &final_status, &failure_reason),
                         base::BindOnce(&OnSignalConnected));

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::CreateLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  vm_tools::cicerone::CreateLxdContainerResponse::Status status =
      response.status();
  if (status != vm_tools::cicerone::CreateLxdContainerResponse::CREATING &&
      status != vm_tools::cicerone::CreateLxdContainerResponse::EXISTS) {
    LOG(ERROR) << "Failed to create LXD container: "
               << response.failure_reason();
    return -1;
  }

  if (status == vm_tools::cicerone::CreateLxdContainerResponse::EXISTS) {
    LOG(INFO) << "Container " << container_name << " already existed";
    return 0;
  } else {
    // Start the RunLoop which'll get the D-Bus signal callbacks and set the
    // final result for us.
    LOG(INFO) << "Waiting for D-Bus signal for container creation status";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), base::Minutes(10));
    run_loop.Run();

    if (final_status ==
        vm_tools::cicerone::LxdContainerCreatedSignal::CREATED) {
      LOG(INFO) << "Created container " << container_name << " successfully";
      return 0;
    } else {
      LOG(ERROR) << "Failed to create LXD container: " << failure_reason;
      return -1;
    }
  }
}

int StartLxdContainer(dbus::ObjectProxy* proxy,
                      const string& vm_name,
                      const string& container_name,
                      const string& owner_id) {
  LOG(INFO) << "Starting LXD container";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kStartLxdContainerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::StartLxdContainerRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartLxdContainer protobuf";
    return -1;
  }

  // RunLoop so we can monitor the D-Bus signals coming back to determine when
  // starting the container has actually finished.
  base::RunLoop run_loop;
  vm_tools::cicerone::LxdContainerStartingSignal::Status final_status =
      vm_tools::cicerone::LxdContainerStartingSignal::UNKNOWN;
  std::string failure_reason = "Timed out waiting for reply";
  proxy->ConnectToSignal(vm_tools::cicerone::kVmCiceroneInterface,
                         vm_tools::cicerone::kLxdContainerStartingSignal,
                         base::BindRepeating(&OnContainerStartingCallback,
                                             base::Unretained(&run_loop),
                                             &final_status, &failure_reason),
                         base::BindOnce(&OnSignalConnected));

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::StartLxdContainerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  vm_tools::cicerone::StartLxdContainerResponse::Status status =
      response.status();
  if (status == vm_tools::cicerone::StartLxdContainerResponse::FAILED ||
      status == vm_tools::cicerone::StartLxdContainerResponse::UNKNOWN) {
    LOG(ERROR) << "Failed to start LXD container: "
               << response.failure_reason();
    return -1;
  }

  if (status == vm_tools::cicerone::StartLxdContainerResponse::RUNNING) {
    LOG(INFO) << "Container " << container_name << " already running";
    return 0;
  } else {
    if (status == vm_tools::cicerone::StartLxdContainerResponse::REMAPPING) {
      LOG(INFO) << "Container is remapping filesystem; this can take a while";
    } else {
      DCHECK_EQ(status,
                vm_tools::cicerone::StartLxdContainerResponse::STARTING);
    }
    // Start the RunLoop which'll get the D-Bus signal callbacks and set the
    // final result for us.
    LOG(INFO) << "Waiting for D-Bus signal for container start status";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE, run_loop.QuitClosure(), base::Minutes(10));
    run_loop.Run();

    if (final_status ==
        vm_tools::cicerone::LxdContainerStartingSignal::STARTED) {
      LOG(INFO) << "Started container " << container_name << " successfully";
      return 0;
    } else {
      LOG(ERROR) << "Failed to start LXD container: " << failure_reason;
      return -1;
    }

    LOG(INFO) << "Started container: " << container_name;
    return 0;
  }
}

int SetTimezone(dbus::ObjectProxy* proxy, const string& timezone_name) {
  LOG(INFO) << "Setting timezone for VMs to " << timezone_name;

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kSetTimezoneMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::SetTimezoneRequest request;
  request.set_timezone_name(timezone_name);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SetTimezone protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::SetTimezoneResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  LOG(INFO) << "Successfully set timezone for " << response.successes()
            << " containers to " << timezone_name;

  int failure_count = response.failure_reasons_size();
  if (failure_count != 0) {
    LOG(ERROR) << "Received " << failure_count << " failures:";
    for (int i = 0; i < failure_count; i++) {
      LOG(ERROR) << response.failure_reasons(i);
    }
    return -1;
  }
  return 0;
}

int GetLxdContainerUsername(dbus::ObjectProxy* proxy,
                            const string& vm_name,
                            const string& container_name,
                            const string& owner_id) {
  LOG(INFO) << "Getting LXD container primary username";

  dbus::MethodCall method_call(
      vm_tools::cicerone::kVmCiceroneInterface,
      vm_tools::cicerone::kGetLxdContainerUsernameMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::GetLxdContainerUsernameRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetLxdContainerUsernameRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::GetLxdContainerUsernameResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  vm_tools::cicerone::GetLxdContainerUsernameResponse::Status status =
      response.status();
  if (status != vm_tools::cicerone::GetLxdContainerUsernameResponse::SUCCESS) {
    LOG(ERROR) << "Failed to get primary username: "
               << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Container primary user is: " << response.username();
  return 0;
}

int SetUpLxdContainerUser(dbus::ObjectProxy* proxy,
                          const string& vm_name,
                          const string& container_name,
                          const string& owner_id,
                          string container_username) {
  LOG(INFO) << "Setting up LXD container user";

  dbus::MethodCall method_call(
      vm_tools::cicerone::kVmCiceroneInterface,
      vm_tools::cicerone::kSetUpLxdContainerUserMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::SetUpLxdContainerUserRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_container_username(std::move(container_username));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SetUpLxdContainerUser protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::SetUpLxdContainerUserResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  vm_tools::cicerone::SetUpLxdContainerUserResponse::Status status =
      response.status();
  if (status != vm_tools::cicerone::SetUpLxdContainerUserResponse::EXISTS &&
      status != vm_tools::cicerone::SetUpLxdContainerUserResponse::SUCCESS) {
    LOG(ERROR) << "Failed to set up user: " << response.failure_reason();
    return -1;
  }

  if (status == vm_tools::cicerone::SetUpLxdContainerUserResponse::EXISTS) {
    LOG(INFO) << "Container user already exists";
    return 0;
  } else {
    LOG(INFO) << "Created user in container";
    return 0;
  }
}

int LaunchApplication(dbus::ObjectProxy* proxy,
                      string owner_id,
                      string name,
                      string container_name,
                      string application) {
  if (application.empty()) {
    LOG(ERROR) << "--application is required";
    return -1;
  }

  LOG(INFO) << "Starting application " << application << " in '" << name << ":"
            << container_name << "'";

  dbus::MethodCall method_call(
      vm_tools::cicerone::kVmCiceroneInterface,
      vm_tools::cicerone::kLaunchContainerApplicationMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::LaunchContainerApplicationRequest request;
  request.set_owner_id(owner_id);
  request.set_vm_name(name);
  request.set_container_name(container_name);
  request.set_desktop_file_id(application);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode LaunchContainerApplicationRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::LaunchContainerApplicationResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to launch application: " << response.failure_reason();
    return -1;
  }

  LOG(INFO) << "Launched application " << application << " in '" << name << ":"
            << container_name << "'";

  return 0;
}

void Write(const std::string& output_filepath, const std::string& content) {
  int content_size = content.size();
  if (content_size != base::WriteFile(base::FilePath(output_filepath),
                                      content.c_str(), content_size)) {
    LOG(ERROR) << "Failed to write to file " << output_filepath;
  }
}

int GetIcon(dbus::ObjectProxy* proxy,
            string owner_id,
            string name,
            string container_name,
            string application,
            int icon_size,
            int scale,
            string output_filepath) {
  if (application.empty()) {
    LOG(ERROR) << "--application is required";
    return -1;
  }

  if (output_filepath.empty()) {
    LOG(ERROR) << "--output_filepath is required";
    return -1;
  }

  LOG(INFO) << "Getting icon for " << application << " in '" << name << ":"
            << container_name << "'";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kGetContainerAppIconMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::ContainerAppIconRequest request;
  request.set_owner_id(owner_id);
  request.set_vm_name(name);
  request.set_container_name(container_name);
  request.add_desktop_file_ids(application);
  request.set_size(icon_size);
  request.set_scale(scale);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ContainerAppIconRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::ContainerAppIconResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  // This should have up to one icon since the input has only one application
  // file ID.
  CHECK_LE(response.icons_size(), 1);
  for (vm_tools::cicerone::DesktopIcon icon : response.icons()) {
    if (!icon.icon().empty())
      Write(output_filepath, icon.icon());
  }

  return 0;
}

int GetInfo(dbus::ObjectProxy* proxy) {
  LOG(INFO) << "Getting information";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kGetDebugInformationMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::GetDebugInformationRequest request;

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetDebugInformationRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::GetDebugInformationResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }

  std::cout << response.debug_information();

  return 0;
}

int GetLinuxPackageInfo(dbus::ObjectProxy* proxy,
                        const string& vm_name,
                        const string& container_name,
                        const string& owner_id,
                        string file_path) {
  if (file_path.empty()) {
    LOG(ERROR) << "--file_path is required";
    return -1;
  }
  LOG(INFO) << "Getting Linux package info";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kGetLinuxPackageInfoMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::LinuxPackageInfoRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_file_path(file_path);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode LinuxPackageInfoRequest protobuf";
    return -1;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::LinuxPackageInfoResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  if (!response.success()) {
    LOG(ERROR) << "Failure getting Linux package info: "
               << response.failure_reason();
    return -1;
  }
  LOG(INFO) << "Linux package info for: " << file_path;
  LOG(INFO) << "Package ID: " << response.package_id();
  LOG(INFO) << "License: " << response.license();
  LOG(INFO) << "Description: " << response.description();
  LOG(INFO) << "Project URL: " << response.project_url();
  LOG(INFO) << "Size(bytes): " << response.size();
  LOG(INFO) << "Summary: " << response.summary();
  return 0;
}

void OnApplicationInstalledCallback(
    base::RunLoop* run_loop,
    vm_tools::cicerone::InstallLinuxPackageProgressSignal::Status* final_status,
    std::string* failure_details,
    dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  vm_tools::cicerone::InstallLinuxPackageProgressSignal ilpps;
  if (!reader.PopArrayOfBytesAsProto(&ilpps)) {
    LOG(ERROR) << "Failed parsing InstallLinuxPackageProgressSignal proto";
    return;
  }

  if (ilpps.status() ==
      vm_tools::cicerone::InstallLinuxPackageProgressSignal::DOWNLOADING) {
    LOG(INFO) << "Downloading install packages, progress: "
              << ilpps.progress_percent();
    return;
  } else if (ilpps.status() ==
             vm_tools::cicerone::InstallLinuxPackageProgressSignal::
                 INSTALLING) {
    LOG(INFO) << "Installing packages, progress: " << ilpps.progress_percent();
    return;
  }

  *final_status = ilpps.status();
  *failure_details = ilpps.failure_details();
  run_loop->Quit();
}

int InstallLinuxPackage(dbus::ObjectProxy* proxy,
                        const string& vm_name,
                        const string& container_name,
                        const string& owner_id,
                        string file_path) {
  if (file_path.empty()) {
    LOG(ERROR) << "--file_path is required";
    return -1;
  }
  LOG(INFO) << "Installing Linux package";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kInstallLinuxPackageMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::InstallLinuxPackageRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_file_path(std::move(file_path));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode InstallLinuxPackageRequest protobuf";
    return -1;
  }

  // RunLoop so we can monitor the D-Bus signals coming back to determine when
  // application install has actually finished.
  base::RunLoop run_loop;
  vm_tools::cicerone::InstallLinuxPackageProgressSignal::Status final_status =
      vm_tools::cicerone::InstallLinuxPackageProgressSignal::FAILED;
  std::string failure_details = "Timed out waiting for reply";
  proxy->ConnectToSignal(vm_tools::cicerone::kVmCiceroneInterface,
                         vm_tools::cicerone::kInstallLinuxPackageProgressSignal,
                         base::BindRepeating(&OnApplicationInstalledCallback,
                                             base::Unretained(&run_loop),
                                             &final_status, &failure_details),
                         base::BindOnce(&OnSignalConnected));

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::InstallLinuxPackageResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  switch (response.status()) {
    case vm_tools::cicerone::InstallLinuxPackageResponse::STARTED:
      LOG(INFO) << "Successfully started the package install";
      // Start the RunLoop which'll get the D-Bus signal callbacks and set the
      // final result for us.
      LOG(INFO) << "Waiting for D-Bus signal for application install status";
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE, run_loop.QuitClosure(), base::Minutes(10));
      run_loop.Run();

      if (final_status ==
          vm_tools::cicerone::InstallLinuxPackageProgressSignal::SUCCEEDED) {
        LOG(INFO) << "Finished application install successfully";
        return 0;
      } else {
        LOG(ERROR) << "Failed to install application: " << failure_details;
        return -1;
      }
    case vm_tools::cicerone::InstallLinuxPackageResponse::
        INSTALL_ALREADY_ACTIVE:
      LOG(ERROR) << "Failed starting the package install because one is "
                    "already active";
      return -1;
    default:
      LOG(ERROR) << "Failed starting the package install, reason: "
                 << response.failure_reason();
      return -1;
  }
}

void OnApplicationUninstalledCallback(
    base::RunLoop* run_loop,
    vm_tools::cicerone::UninstallPackageProgressSignal::Status* final_status,
    std::string* failure_details,
    dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  vm_tools::cicerone::UninstallPackageProgressSignal progress_signal;
  if (!reader.PopArrayOfBytesAsProto(&progress_signal)) {
    LOG(ERROR) << "Failed parsing UninstallPackageProgressSignal proto";
    return;
  }

  if (progress_signal.status() ==
      vm_tools::cicerone::UninstallPackageProgressSignal::UNINSTALLING) {
    LOG(INFO) << "Uninstall packages, progress: "
              << progress_signal.progress_percent();
    return;
  }

  *final_status = progress_signal.status();
  *failure_details = progress_signal.failure_details();
  run_loop->Quit();
}

int UninstallApplication(dbus::ObjectProxy* proxy,
                         const string& vm_name,
                         const string& container_name,
                         const string& owner_id,
                         const string& application) {
  if (application.empty()) {
    LOG(ERROR) << "--application is required";
    return -1;
  }
  LOG(INFO) << "Uninstalling application";

  dbus::MethodCall method_call(
      vm_tools::cicerone::kVmCiceroneInterface,
      vm_tools::cicerone::kUninstallPackageOwningFileMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::UninstallPackageOwningFileRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_desktop_file_id(application);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UninstallPackageOwningFileRequest protobuf";
    return -1;
  }

  // RunLoop so we can monitor the D-Bus signals coming back to determine when
  // application uninstall has actually finished.
  base::RunLoop run_loop;
  vm_tools::cicerone::UninstallPackageProgressSignal::Status final_status =
      vm_tools::cicerone::UninstallPackageProgressSignal::FAILED;
  std::string failure_details = "Timed out waiting for reply";
  proxy->ConnectToSignal(vm_tools::cicerone::kVmCiceroneInterface,
                         vm_tools::cicerone::kUninstallPackageProgressSignal,
                         base::BindRepeating(&OnApplicationUninstalledCallback,
                                             base::Unretained(&run_loop),
                                             &final_status, &failure_details),
                         base::BindOnce(&OnSignalConnected));

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::UninstallPackageOwningFileResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  switch (response.status()) {
    case vm_tools::cicerone::UninstallPackageOwningFileResponse::STARTED:
      LOG(INFO) << "Successfully started the package uninstall";
      // Start the RunLoop which'll get the D-Bus signal callbacks and set the
      // final result for us.
      LOG(INFO) << "Waiting for D-Bus signal for application uninstall status";
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE, run_loop.QuitClosure(), base::Minutes(10));
      run_loop.Run();

      if (final_status ==
          vm_tools::cicerone::UninstallPackageProgressSignal::SUCCEEDED) {
        LOG(INFO) << "Finished application uninstall successfully";
        return 0;
      } else {
        LOG(ERROR) << "Failed to uninstall application: " << failure_details;
        return -1;
      }
    case vm_tools::cicerone::UninstallPackageOwningFileResponse::
        BLOCKING_OPERATION_IN_PROGRESS:
      LOG(ERROR) << "Failed starting the package uninstall because one is "
                    "already active";
      return -1;
    default:
      LOG(ERROR) << "Failed starting the package uninstall, reason: "
                 << response.failure_reason();
      return -1;
  }
}

void OnPlaybookAppliedCallback(
    base::RunLoop* run_loop,
    vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal::Status*
        final_status,
    std::string* failure_details,
    dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal progress_signal;
  if (!reader.PopArrayOfBytesAsProto(&progress_signal)) {
    LOG(ERROR) << "Failed parsing ApplyAnsiblePlaybookProgressSignal proto";
    return;
  }

  if (progress_signal.status() ==
      vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal::IN_PROGRESS) {
    LOG(INFO) << "Applying playbook...";
    return;
  }

  *final_status = progress_signal.status();
  *failure_details = progress_signal.failure_details();
  run_loop->Quit();
}

int ApplyAnsiblePlaybook(dbus::ObjectProxy* proxy,
                         const string& vm_name,
                         const string& container_name,
                         const string& owner_id,
                         string playbook) {
  if (playbook.empty()) {
    LOG(ERROR) << "--playbook is required";
    return -1;
  }
  LOG(INFO) << "Applying Ansible playbook";

  dbus::MethodCall method_call(vm_tools::cicerone::kVmCiceroneInterface,
                               vm_tools::cicerone::kApplyAnsiblePlaybookMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::cicerone::ApplyAnsiblePlaybookRequest request;
  request.set_vm_name(vm_name);
  request.set_container_name(container_name);
  request.set_owner_id(owner_id);
  request.set_playbook(std::move(playbook));

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ApplyAnsiblePlaybookRequest protobuf";
    return -1;
  }

  // RunLoop so we can monitor the D-Bus signals coming back to determine when
  // playbook application has actually finished.
  base::RunLoop run_loop;
  vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal::Status final_status =
      vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal::FAILED;
  std::string failure_details = "Timed out waiting for reply";
  proxy->ConnectToSignal(
      vm_tools::cicerone::kVmCiceroneInterface,
      vm_tools::cicerone::kApplyAnsiblePlaybookProgressSignal,
      base::BindRepeating(&OnPlaybookAppliedCallback,
                          base::Unretained(&run_loop), &final_status,
                          &failure_details),
      base::BindOnce(&OnSignalConnected));

  std::unique_ptr<dbus::Response> dbus_response =
      proxy->CallMethodAndBlock(&method_call, kDefaultTimeoutMs);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send dbus message to cicerone service";
    return -1;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::cicerone::ApplyAnsiblePlaybookResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse response protobuf";
    return -1;
  }
  switch (response.status()) {
    case vm_tools::cicerone::ApplyAnsiblePlaybookResponse::STARTED:
      LOG(INFO) << "Successfully started the playbook application";
      // Start the RunLoop which'll get the D-Bus signal callbacks and set the
      // final result for us.
      LOG(INFO) << "Waiting for D-Bus signal for playbook application status";
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
          FROM_HERE, run_loop.QuitClosure(), base::Minutes(10));
      run_loop.Run();

      if (final_status ==
          vm_tools::cicerone::ApplyAnsiblePlaybookProgressSignal::SUCCEEDED) {
        LOG(INFO) << "Finished playbook application successfully";
        return 0;
      }
      LOG(ERROR) << "Failed to apply playbook: " << failure_details;
      return -1;
    case vm_tools::cicerone::ApplyAnsiblePlaybookResponse::FAILED:
      LOG(ERROR) << "Failed starting the playbook application, reason: "
                 << response.failure_reason();
      return -1;
    default:
      NOTREACHED();
      return -1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;

  // Operations.
  DEFINE_bool(create_lxd_container, false, "Create an LXD container");
  DEFINE_bool(start_lxd_container, false, "Start an LXD container");
  DEFINE_bool(set_timezone, false, "Set timezone for all known LXD containers");
  DEFINE_bool(get_username, false, "Get the primary username in a container");
  DEFINE_bool(set_up_lxd_user, false, "Set up a user in an LXD container");
  DEFINE_bool(launch_application, false,
              "Launches an application in a container");
  DEFINE_bool(get_icon, false, "Get an app icon from a container within a VM");
  DEFINE_bool(get_info, false, "Get debug information about all running VMs");
  DEFINE_bool(install_package, false, "Install a Linux package file");
  DEFINE_bool(uninstall_application, false, "Uninstall an application");
  DEFINE_bool(package_info, false, "Gets information on a Linux package file");
  DEFINE_bool(apply_playbook, false, "Apply an Ansible playbook");

  // Parameters.
  DEFINE_string(vm_name, "", "VM name");
  DEFINE_string(container_name, "", "Container name");
  DEFINE_string(owner_id, "", "User id");
  DEFINE_string(image_server, "", "Image server to pull a container from");
  DEFINE_string(image_alias, "", "Container image alias");
  DEFINE_string(rootfs_path, "", "Path to rootfs tarball");
  DEFINE_string(metadata_path, "", "Path to metadata tarball");
  DEFINE_string(container_username, "", "Container username");
  DEFINE_string(application, "", "Name of the application to launch");
  DEFINE_string(output_filepath, "",
                "Filename with path to write appliction icon to");
  DEFINE_string(timezone_name, "",
                "The timezone to set, for example 'America/Denver'. "
                "See /usr/share/zoneinfo for other valid names.");
  DEFINE_int32(icon_size, 48,
               "The size of the icon to get is this icon_size by icon_size");
  DEFINE_int32(scale, 1, "The scale that the icon is designed to use with");
  DEFINE_string(file_path, "", "Package file path");
  DEFINE_string(playbook, "", "Ansible playbook content");

  brillo::FlagHelper::Init(argc, argv, "vm_cicerone client tool");
  brillo::InitLog(brillo::kLogToStderrIfTty);

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(std::move(opts)));

  if (!bus->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return -1;
  }

  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      vm_tools::cicerone::kVmCiceroneServiceName,
      dbus::ObjectPath(vm_tools::cicerone::kVmCiceroneServicePath));
  if (!proxy) {
    LOG(ERROR) << "Unable to get dbus proxy for "
               << vm_tools::cicerone::kVmCiceroneServiceName;
    return -1;
  }

  // The standard says that bool to int conversion is implicit and that
  // false => 0 and true => 1.
  // clang-format off
  if (FLAGS_create_lxd_container + FLAGS_start_lxd_container +
      FLAGS_set_timezone + FLAGS_set_up_lxd_user + FLAGS_get_username +
      FLAGS_launch_application + FLAGS_get_icon + FLAGS_get_info +
      FLAGS_install_package + FLAGS_uninstall_application +
      FLAGS_package_info + FLAGS_apply_playbook != 1) {
    // clang-format on
    LOG(ERROR) << "Exactly one of --create_lxd_container, "
               << "--start_lxd_container, --set_up_lxd_user, --set_timezone, "
               << "--get_username, --launch_application, --get_icon, "
               << "--get_info, --install_package, --uninstall_application, "
               << "--apply_playbook, or --package_info must be provided";
    return -1;
  }

  // Check for the get_info and set_timezone commands early because they do
  // not require owner ID, VM name, or container name.
  if (FLAGS_get_info) {
    return GetInfo(proxy);
  }

  if (FLAGS_set_timezone) {
    return SetTimezone(proxy, FLAGS_timezone_name);
  }

  // Every other D-Bus method for cicerone requires owner ID, VM name, and
  // container name.
  if (FLAGS_owner_id.empty()) {
    LOG(ERROR) << "--owner_id is required";
    return -1;
  }

  if (FLAGS_vm_name.empty()) {
    LOG(ERROR) << "--vm_name is required";
    return -1;
  }

  if (FLAGS_container_name.empty()) {
    LOG(ERROR) << "--container_name is required";
    return -1;
  }

  if (FLAGS_create_lxd_container) {
    return CreateLxdContainer(
        proxy, FLAGS_vm_name, FLAGS_container_name, FLAGS_owner_id,
        std::move(FLAGS_image_server), std::move(FLAGS_image_alias),
        std::move(FLAGS_rootfs_path), std::move(FLAGS_metadata_path));
  } else if (FLAGS_start_lxd_container) {
    return StartLxdContainer(proxy, FLAGS_vm_name, FLAGS_container_name,
                             FLAGS_owner_id);
  } else if (FLAGS_set_up_lxd_user) {
    return SetUpLxdContainerUser(proxy, FLAGS_vm_name, FLAGS_container_name,
                                 FLAGS_owner_id,
                                 std::move(FLAGS_container_username));
  } else if (FLAGS_get_username) {
    return GetLxdContainerUsername(proxy, FLAGS_vm_name, FLAGS_container_name,
                                   FLAGS_owner_id);
  } else if (FLAGS_launch_application) {
    return LaunchApplication(
        proxy, std::move(FLAGS_owner_id), std::move(FLAGS_vm_name),
        std::move(FLAGS_container_name), std::move(FLAGS_application));
  } else if (FLAGS_get_icon) {
    return GetIcon(proxy, std::move(FLAGS_owner_id), std::move(FLAGS_vm_name),
                   std::move(FLAGS_container_name),
                   std::move(FLAGS_application), FLAGS_icon_size, FLAGS_scale,
                   std::move(FLAGS_output_filepath));
  } else if (FLAGS_install_package) {
    return InstallLinuxPackage(proxy, FLAGS_vm_name, FLAGS_container_name,
                               FLAGS_owner_id, std::move(FLAGS_file_path));
  } else if (FLAGS_uninstall_application) {
    return UninstallApplication(proxy, FLAGS_vm_name, FLAGS_container_name,
                                FLAGS_owner_id, FLAGS_application);
  } else if (FLAGS_package_info) {
    return GetLinuxPackageInfo(proxy, FLAGS_vm_name, FLAGS_container_name,
                               FLAGS_owner_id, std::move(FLAGS_file_path));
  } else if (FLAGS_apply_playbook) {
    return ApplyAnsiblePlaybook(proxy, FLAGS_vm_name, FLAGS_container_name,
                                FLAGS_owner_id, std::move(FLAGS_playbook));
  }

  // Unreachable.
  return 0;
}
