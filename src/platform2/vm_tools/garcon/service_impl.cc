// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/service_impl.h"

#include <sys/socket.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket

#include <algorithm>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/environment.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "vm_tools/common/spawn_util.h"
#include "vm_tools/garcon/ansible_playbook_application.h"
#include "vm_tools/garcon/arc_sideload.h"
#include "vm_tools/garcon/desktop_file.h"
#include "vm_tools/garcon/host_notifier.h"
#include "vm_tools/garcon/icon_finder.h"
#include "vm_tools/garcon/package_kit_proxy.h"

namespace vm_tools {
namespace garcon {
namespace {

constexpr char kStartupIDEnv[] = "DESKTOP_STARTUP_ID";
constexpr char kXDisplayEnv[] = "DISPLAY";
constexpr char kXLowDensityDisplayEnv[] = "DISPLAY_LOW_DENSITY";
constexpr char kWaylandDisplayEnv[] = "WAYLAND_DISPLAY";
constexpr char kWaylandLowDensityDisplayEnv[] = "WAYLAND_DISPLAY_LOW_DENSITY";
constexpr char kXCursorSizeEnv[] = "XCURSOR_SIZE";
constexpr char kLowDensityXCursorSizeEnv[] = "XCURSOR_SIZE_LOW_DENSITY";
constexpr char kGtkImModuleEnv[] = "GTK_IM_MODULE";
constexpr char kQtImModuleEnv[] = "QT_IM_MODULE";
constexpr char kImModuleName[] = "cros";
constexpr char kVirtualKeyboardEnv[] = "CROS_IM_VIRTUAL_KEYBOARD";
constexpr char kVirtualKeyboardEnabled[] = "1";
constexpr size_t kMaxIconSize = 1048576;  // 1MB, very large for an icon

void SetEnvForContainerFeatures(std::map<std::string, std::string>& env,
                                google::protobuf::RepeatedField<int> features) {
  for (int feature : features) {
    switch (feature) {
      case vm_tools::container::ContainerFeature::ENABLE_GTK3_IME_SUPPORT:
        if (!std::getenv(kGtkImModuleEnv)) {
          // Users may have manually set this so they can use a Linux IME.
          // Don't override that until our IME support is on par.
          env[kGtkImModuleEnv] = kImModuleName;
        }
        break;
      case vm_tools::container::ContainerFeature::ENABLE_QT_IME_SUPPORT:
        if (!std::getenv(kQtImModuleEnv)) {
          env[kQtImModuleEnv] = kImModuleName;
        }
        break;
      case vm_tools::container::ContainerFeature::
          ENABLE_VIRTUAL_KEYBOARD_SUPPORT:
        env[kVirtualKeyboardEnv] = kVirtualKeyboardEnabled;
        break;
      default:
        LOG(WARNING) << "Received unknown container feature: " << feature;
        break;
    }
  }
}

}  // namespace

ServiceImpl::ServiceImpl(PackageKitProxy* package_kit_proxy,
                         base::TaskRunner* task_runner,
                         HostNotifier* host_notifier)
    : package_kit_proxy_(package_kit_proxy),
      task_runner_(task_runner),
      host_notifier_(host_notifier) {
  CHECK(package_kit_proxy_);
}

grpc::Status ServiceImpl::LaunchApplication(
    grpc::ServerContext* ctx,
    const vm_tools::container::LaunchApplicationRequest* request,
    vm_tools::container::LaunchApplicationResponse* response) {
  LOG(INFO) << "Received request to launch application in container";

  if (request->desktop_file_id().empty()) {
    LOG(ERROR) << "Failed to launch application: missing desktop_file_id";
    return grpc::Status(grpc::INVALID_ARGUMENT, "missing desktop_file_id");
  }

  // Find the actual file path that corresponds to this desktop file id.
  base::FilePath file_path =
      DesktopFile::FindFileForDesktopId(request->desktop_file_id());
  if (file_path.empty()) {
    LOG(ERROR) << "Failed to launch application: missing file_path";
    response->set_success(false);
    response->set_failure_reason("Desktop file does not exist");
    return grpc::Status::OK;
  }

  // Now parse the actual desktop file.
  std::unique_ptr<DesktopFile> desktop_file =
      DesktopFile::ParseDesktopFile(file_path);
  if (!desktop_file) {
    LOG(ERROR)
        << "Failed to launch application: Desktop file contents are invalid";
    response->set_success(false);
    response->set_failure_reason("Desktop file contents are invalid");
    return grpc::Status::OK;
  }

  // Make sure this desktop file is for an application.
  if (!desktop_file->IsApplication()) {
    LOG(ERROR) << "Failed to launch application: Isn't application";
    response->set_success(false);
    response->set_failure_reason("Desktop file is not for an application");
    return grpc::Status::OK;
  }

  std::vector<std::string> files(request->files().begin(),
                                 request->files().end());

  // Get the argv string from the desktop file we need for execution.
  // TODO(timloh): Desktop files using %u/%f should execute multiple copies of
  // the program for multiple files.
  std::vector<std::string> argv = desktop_file->GenerateArgvWithFiles(files);
  if (argv.empty()) {
    LOG(ERROR) << "Failed to launch application: Failed to generate argv list "
                  "for application";
    response->set_success(false);
    response->set_failure_reason(
        "Failure in generating argv list for application");
    return grpc::Status::OK;
  }

  std::map<std::string, std::string> env;
  if (desktop_file->startup_notify()) {
    env[kStartupIDEnv] = request->desktop_file_id();
  }

  if (request->display_scaling() ==
      vm_tools::container::LaunchApplicationRequest::SCALED) {
    env[kXDisplayEnv] = std::getenv(kXLowDensityDisplayEnv);
    env[kWaylandDisplayEnv] = std::getenv(kWaylandLowDensityDisplayEnv);
    env[kXCursorSizeEnv] = std::getenv(kLowDensityXCursorSizeEnv);
  }

  SetEnvForContainerFeatures(env, request->container_features());

  // Discard child's process stdio,
  int stdio_fd[] = {-1, -1, -1};

  if (!Spawn(std::move(argv), std::move(env), desktop_file->path(), stdio_fd)) {
    LOG(ERROR) << "Failed to launch application: Failed to execute application";
    response->set_success(false);
    response->set_failure_reason("Failure in execution of application");
  } else {
    response->set_success(true);
  }

  // Return OK no matter what because the RPC itself succeeded even if there
  // was an issue with launching the process.
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::GetIcon(
    grpc::ServerContext* ctx,
    const vm_tools::container::IconRequest* request,
    vm_tools::container::IconResponse* response) {
  LOG(INFO) << "Received request to get application icons in container";

  for (const std::string& desktop_file_id : request->desktop_file_ids()) {
    std::string icon_data;
    base::FilePath icon_filepath =
        LocateIconFile(desktop_file_id, request->icon_size(), request->scale());
    if (icon_filepath.empty()) {
      continue;
    }
    if (!base::ReadFileToStringWithMaxSize(icon_filepath, &icon_data,
                                           kMaxIconSize)) {
      LOG(ERROR) << "Failed to read icon data file " << icon_filepath.value();
      continue;
    }
    container::DesktopIcon* desktop_icon = response->add_desktop_icons();
    desktop_icon->set_desktop_file_id(desktop_file_id);
    desktop_icon->set_icon(icon_data);
    if (icon_filepath.Extension() == ".svg") {
      desktop_icon->set_format(container::DesktopIcon::SVG);
    } else {
      desktop_icon->set_format(container::DesktopIcon::PNG);
    }
  }

  return grpc::Status::OK;
}

grpc::Status ServiceImpl::LaunchVshd(
    grpc::ServerContext* ctx,
    const vm_tools::container::LaunchVshdRequest* request,
    vm_tools::container::LaunchVshdResponse* response) {
  LOG(INFO) << "Received request to launch vshd in container";

  if (request->port() == 0) {
    return grpc::Status(grpc::INVALID_ARGUMENT, "vshd port cannot be 0");
  }

  std::vector<std::string> argv{
      "/opt/google/cros-containers/bin/vshd", "--inherit_env",
      base::StringPrintf("--forward_to_host_port=%u", request->port())};

  std::map<std::string, std::string> env;
  SetEnvForContainerFeatures(env, request->container_features());

  // Discard child's process stdio,
  int stdio_fd[] = {-1, -1, -1};

  if (!Spawn(std::move(argv), std::move(env), "", stdio_fd)) {
    response->set_success(false);
    response->set_failure_reason("Failed to spawn vshd");
  } else {
    response->set_success(true);
  }

  // Return OK no matter what because the RPC itself succeeded even if there
  // was an issue with launching the process.
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::GetLinuxPackageInfo(
    grpc::ServerContext* ctx,
    const vm_tools::container::LinuxPackageInfoRequest* request,
    vm_tools::container::LinuxPackageInfoResponse* response) {
  LOG(INFO) << "Received request to get Linux package info";
  if (request->file_path().empty() && request->package_name().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT,
                        "file_path and package_name cannot both be empty");
  }

  std::string error_msg;
  std::shared_ptr<PackageKitProxy::LinuxPackageInfo> pkg_info =
      std::make_shared<PackageKitProxy::LinuxPackageInfo>();

  if (request->file_path().empty()) {
    response->set_success(
        package_kit_proxy_->GetLinuxPackageInfoFromPackageName(
            request->package_name(), pkg_info, &error_msg));
  } else {
    base::FilePath file_path(request->file_path());
    if (!base::PathExists(file_path)) {
      return grpc::Status(grpc::INVALID_ARGUMENT, "file_path does not exist");
    }
    response->set_success(package_kit_proxy_->GetLinuxPackageInfoFromFilePath(
        file_path, pkg_info, &error_msg));
  }

  if (response->success()) {
    response->set_package_id(std::move(pkg_info->package_id));
    response->set_license(std::move(pkg_info->license));
    response->set_description(std::move(pkg_info->description));
    response->set_project_url(std::move(pkg_info->project_url));
    response->set_size(pkg_info->size);
    response->set_summary(std::move(pkg_info->summary));
  } else {
    response->set_failure_reason(error_msg);
  }
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::InstallLinuxPackage(
    grpc::ServerContext* ctx,
    const vm_tools::container::InstallLinuxPackageRequest* request,
    vm_tools::container::InstallLinuxPackageResponse* response) {
  LOG(INFO) << "Received request to install Linux package";
  if (request->file_path().empty() && request->package_id().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT,
                        "file_path and package_id cannot both be empty");
  }
  std::string error_msg;
  if (request->file_path().empty()) {
    response->set_status(package_kit_proxy_->InstallLinuxPackageFromPackageId(
        request->package_id(), request->command_uuid(), &error_msg));
  } else {
    base::FilePath file_path(request->file_path());
    if (!base::PathExists(file_path)) {
      return grpc::Status(grpc::INVALID_ARGUMENT, "file_path does not exist");
    }
    response->set_status(package_kit_proxy_->InstallLinuxPackageFromFilePath(
        file_path, request->command_uuid(), &error_msg));
  }
  response->set_failure_reason(error_msg);
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::UninstallPackageOwningFile(
    grpc::ServerContext* ctx,
    const vm_tools::container::UninstallPackageOwningFileRequest* request,
    vm_tools::container::UninstallPackageOwningFileResponse* response) {
  LOG(INFO) << "Received request to uninstall package owning a file";
  if (request->desktop_file_id().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT, "missing desktop_file_id");
  }

  // Find the actual file path that corresponds to this desktop file id.
  base::FilePath file_path =
      DesktopFile::FindFileForDesktopId(request->desktop_file_id());
  if (file_path.empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT,
                        "desktop_file_id does not exist");
  }

  std::string error;
  response->set_status(
      package_kit_proxy_->UninstallPackageOwningFile(file_path, &error));
  response->set_failure_reason(error);

  return grpc::Status::OK;
}

grpc::Status ServiceImpl::GetDebugInformation(
    grpc::ServerContext* ctx,
    const vm_tools::container::GetDebugInformationRequest* request,
    vm_tools::container::GetDebugInformationResponse* response) {
  LOG(INFO) << "Received request to get container debug information";

  std::string* debug_information = response->mutable_debug_information();

  *debug_information += "Installed Crostini Packages:\n";
  std::string dpkg_out;
  base::GetAppOutput({"dpkg", "-l", "cros-*"}, &dpkg_out);
  std::vector<base::StringPiece> dpkg_lines = base::SplitStringPiece(
      dpkg_out, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& pkg_line : dpkg_lines) {
    std::vector<base::StringPiece> pkg_info = base::SplitStringPiece(
        pkg_line, base::kWhitespaceASCII, base::TRIM_WHITESPACE,
        base::SPLIT_WANT_NONEMPTY);
    // Filter out unrelated lines.
    if (pkg_info.size() < 3)
      continue;
    // Only collect installed packages.
    if (pkg_info[0] != "ii")
      continue;

    base::StringPiece pkg_name = pkg_info[1];
    base::StringPiece pkg_version = pkg_info[2];

    *debug_information += "\t";
    debug_information->append(pkg_name.data(), pkg_name.size());
    *debug_information += "-";
    debug_information->append(pkg_version.data(), pkg_version.size());
    *debug_information += "\n";
  }

  *debug_information += "systemctl status:\n";
  std::string systemctl_out;
  base::GetAppOutput({"systemctl", "--no-legend"}, &systemctl_out);
  std::vector<base::StringPiece> systemctl_out_lines = base::SplitStringPiece(
      systemctl_out, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const auto& line : systemctl_out_lines) {
    *debug_information += "\t";
    debug_information->append(line.data(), line.size());
    *debug_information += "\n";
  }

  *debug_information += "systemctl user status:\n";
  std::string systemctl_user_out;
  base::GetAppOutput({"systemctl", "--user", "--no-legend"},
                     &systemctl_user_out);
  std::vector<base::StringPiece> systemctl_user_out_lines =
      base::SplitStringPiece(systemctl_user_out, "\n", base::TRIM_WHITESPACE,
                             base::SPLIT_WANT_NONEMPTY);
  for (const auto& line : systemctl_user_out_lines) {
    *debug_information += "\t";
    debug_information->append(line.data(), line.size());
    *debug_information += "\n";
  }

  auto user_services =
      std::vector<std::string>{"cros-garcon", "sommelier@0", "sommelier@1",
                               "sommelier-x@0", "sommelier-x@1"};
  for (const auto& service : user_services) {
    *debug_information += "Filtered journalctl for " + service + ":\n";
    std::string journalctl_user_out;
    base::GetAppOutput(
        {"journalctl", "--user-unit", service, "--since", "1 day ago"},
        &journalctl_user_out);
    std::vector<base::StringPiece> systemctl_user_out_lines =
        base::SplitStringPiece(journalctl_user_out, "\n", base::TRIM_WHITESPACE,
                               base::SPLIT_WANT_NONEMPTY);
    for (const auto& line : systemctl_user_out_lines) {
      *debug_information += "\t";
      debug_information->append(line.data(), line.size());
      *debug_information += "\n";
    }
  }

  // Their username might be PII so filter it out of the logs.
  std::unique_ptr<base::Environment> env = base::Environment::Create();
  std::string username;
  if (!env->GetVar("USER", &username)) {
    LOG(ERROR) << "Unable to retrieve username from environment";
  } else {
    base::ReplaceSubstringsAfterOffset(debug_information, 0, username,
                                       "$USERNAME");
  }
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::ConnectChunnel(
    grpc::ServerContext* ctx,
    const vm_tools::container::ConnectChunnelRequest* request,
    vm_tools::container::ConnectChunnelResponse* response) {
  LOG(INFO) << "Received request to connect to chunnel";

  if (request->chunneld_port() == 0)
    return grpc::Status(grpc::INVALID_ARGUMENT, "invalid chunneld port");

  if (request->target_tcp4_port() == 0)
    return grpc::Status(grpc::INVALID_ARGUMENT, "invalid target TCP4 port");

  std::vector<std::string> argv{
      "/opt/google/cros-containers/bin/chunnel", "--remote",
      base::StringPrintf("vsock:%u:%u", VMADDR_CID_HOST,
                         request->chunneld_port()),
      "--local",
      base::StringPrintf("localhost:%u", request->target_tcp4_port())};

  // Discard child's process stdio,
  int stdio_fd[] = {-1, -1, -1};

  if (!Spawn(std::move(argv), {}, "", stdio_fd)) {
    response->set_success(false);
    response->set_failure_reason("Failed to spawn chunnel");
  } else {
    response->set_success(true);
  }

  return grpc::Status::OK;
}

grpc::Status ServiceImpl::ApplyAnsiblePlaybook(
    grpc::ServerContext* ctx,
    const vm_tools::container::ApplyAnsiblePlaybookRequest* request,
    vm_tools::container::ApplyAnsiblePlaybookResponse* response) {
  LOG(INFO) << "Received request to apply Ansible playbook";
  if (request->playbook().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT, "playbook cannot be empty");
  }

  AnsiblePlaybookApplication* ansible_playbook_application;
  std::string error_msg;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  // AnsiblePlaybookApplication is created on garcon service tasks thread,
  // because Ansible playbook application task is using
  // base::FileDescriptorWatcher to watch ansible-playbook process stdio.
  bool ret = task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&HostNotifier::CreateAnsiblePlaybookApplication,
                                base::Unretained(host_notifier_), &event,
                                &ansible_playbook_application));
  if (!ret) {
    error_msg =
        "Failed to post AnsiblePlaybookApplication creation to garcon "
        "service tasks thread";
    LOG(ERROR) << "Failed to start Ansible playbook application: " << error_msg;
    response->set_status(
        vm_tools::container::ApplyAnsiblePlaybookResponse::FAILED);
    response->set_failure_reason(error_msg);
    return grpc::Status::OK;
  }
  // Wait for the creation to complete.
  event.Wait();
  if (!ansible_playbook_application) {
    error_msg = "Failed in creating the AnsiblePlaybookApplication";
    LOG(ERROR) << "Failed to start Ansible playbook application: " << error_msg;
    response->set_status(
        vm_tools::container::ApplyAnsiblePlaybookResponse::FAILED);
    response->set_failure_reason(error_msg);
    return grpc::Status::OK;
  }
  event.Reset();
  ansible_playbook_application->AddObserver(host_notifier_);

  base::FilePath ansible_playbook_file_path =
      ansible_playbook_application->CreateAnsiblePlaybookFile(
          request->playbook(), &error_msg);

  if (ansible_playbook_file_path.empty()) {
    LOG(ERROR) << "Failed to create valid file with Ansible playbook, "
               << "error: " << error_msg;
    host_notifier_->RemoveAnsiblePlaybookApplication();
    response->set_status(
        vm_tools::container::ApplyAnsiblePlaybookResponse::FAILED);
    response->set_failure_reason(error_msg);
    return grpc::Status::OK;
  }

  LOG(INFO) << "Ansible playbook file created at "
            << ansible_playbook_file_path.value();

  bool success = ansible_playbook_application->ExecuteAnsiblePlaybook(
      ansible_playbook_file_path, &error_msg);

  if (!success) {
    LOG(ERROR) << "Failed to start Ansible playbook application: " << error_msg;
    host_notifier_->RemoveAnsiblePlaybookApplication();
    response->set_status(
        vm_tools::container::ApplyAnsiblePlaybookResponse::FAILED);
    response->set_failure_reason(error_msg);
    return grpc::Status::OK;
  }

  LOG(INFO) << "Ansible playbook application started";
  response->set_status(
      vm_tools::container::ApplyAnsiblePlaybookResponse::STARTED);
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::ConfigureForArcSideload(
    grpc::ServerContext* ctx,
    const vm_tools::container::ConfigureForArcSideloadRequest* request,
    vm_tools::container::ConfigureForArcSideloadResponse* response) {
  bool success = ArcSideload::Enable(response->mutable_failure_reason());
  response->set_status(
      success ? vm_tools::container::ConfigureForArcSideloadResponse::SUCCEEDED
              : vm_tools::container::ConfigureForArcSideloadResponse::FAILED);
  if (!success) {
    LOG(ERROR) << "Arc sideload configuration failed: "
               << response->failure_reason();
  }
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::AddFileWatch(
    grpc::ServerContext* ctx,
    const vm_tools::container::AddFileWatchRequest* request,
    vm_tools::container::AddFileWatchResponse* response) {
  std::string error_msg;
  if (host_notifier_->AddFileWatch(base::FilePath(request->path()),
                                   &error_msg)) {
    response->set_status(vm_tools::container::AddFileWatchResponse::SUCCEEDED);
  } else {
    response->set_status(vm_tools::container::AddFileWatchResponse::FAILED);
    response->set_failure_reason(error_msg);
  }
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::RemoveFileWatch(
    grpc::ServerContext* ctx,
    const vm_tools::container::RemoveFileWatchRequest* request,
    vm_tools::container::RemoveFileWatchResponse* response) {
  std::string error_msg;
  if (host_notifier_->RemoveFileWatch(base::FilePath(request->path()),
                                      &error_msg)) {
    response->set_status(
        vm_tools::container::RemoveFileWatchResponse::SUCCEEDED);
  } else {
    response->set_status(vm_tools::container::RemoveFileWatchResponse::FAILED);
    response->set_failure_reason(error_msg);
  }
  return grpc::Status::OK;
}

grpc::Status ServiceImpl::GetGarconSessionInfo(
    grpc::ServerContext* ctx,
    const vm_tools::container::GetGarconSessionInfoRequest* request,
    vm_tools::container::GetGarconSessionInfoResponse* response) {
  LOG(INFO) << "Getting session info";
  if (host_notifier_->sftp_vsock_port() == 0) {
    response->set_failure_reason(
        "sftp_vsock_port not set, container probably hasn't finished "
        "booting so unable to get info");
    LOG(ERROR) << response->failure_reason();
    response->set_status(container::GetGarconSessionInfoResponse::FAILED);
    return grpc::Status::OK;
  }
  response->set_sftp_vsock_port(host_notifier_->sftp_vsock_port());
  auto env = base::Environment::Create();
  if (!env->GetVar("USER", response->mutable_container_username())) {
    LOG(ERROR) << "$USER not set";
  }
  if (!env->GetVar("HOME", response->mutable_container_homedir())) {
    LOG(ERROR) << "$HOME not set";
  }
  response->set_status(
      vm_tools::container::GetGarconSessionInfoResponse::SUCCEEDED);
  return grpc::Status::OK;
}

}  // namespace garcon
}  // namespace vm_tools
