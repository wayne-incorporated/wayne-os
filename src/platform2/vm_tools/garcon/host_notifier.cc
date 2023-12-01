// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <arpa/inet.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/socket.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/constants/vm_tools.h>
#include <vm_protos/proto_bindings/common.pb.h>
#include <vm_protos/proto_bindings/container_host.pb.h>

#include "vm_tools/garcon/desktop_file.h"
#include "vm_tools/garcon/host_notifier.h"
#include "vm_tools/garcon/mime_types_parser.h"

namespace {

// File extension for desktop files.
constexpr char kDesktopFileExtension[] = ".desktop";
// Directory where the MIME types file is stored for watching with inotify.
constexpr char kMimeTypesDir[] = "/usr/share/mime";
// User directory where the MIME types file is stored for watching with inotify.
constexpr char kUserMimeTypesDir[] = ".local/share/mime";
// File where MIME type information is stored in the container.
constexpr char kMimeTypesFilePath[] = "/usr/share/mime/mime.cache";
// Filename for the user's MIME types file in their home dir.
constexpr char kUserMimeTypesFile[] = ".local/share/mime/mime.cache";
// Duration over which we coalesce changes to the desktop file system.
constexpr base::TimeDelta kFilesystemChangeCoalesceTime = base::Seconds(3);
// Delimiter for the end of a URL scheme.
constexpr char kUrlSchemeDelimiter[] = "://";
// Periodic interval for checking free disk space.
constexpr base::TimeDelta kDiskSpaceCheckInterval = base::Minutes(2);
constexpr int64_t kDiskSpaceCheckThreshold = 1 * 1024 * 1024 * 1024;  // 1GiB

void SendInstallStatusToHost(
    vm_tools::container::ContainerListener::Stub* stub,
    vm_tools::container::InstallLinuxPackageProgressInfo progress_info) {
  grpc::ClientContext ctx;
  vm_tools::EmptyMessage empty;
  grpc::Status grpc_status =
      stub->InstallLinuxPackageProgress(&ctx, progress_info, &empty);
  if (!grpc_status.ok()) {
    LOG(WARNING) << "Failed to notify host system about install status: "
                 << grpc_status.error_message();
  }
}

void SendUninstallStatusToHost(
    vm_tools::container::ContainerListener::Stub* stub,
    vm_tools::container::UninstallPackageProgressInfo info) {
  grpc::ClientContext ctx;
  vm_tools::EmptyMessage empty;
  grpc::Status grpc_status = stub->UninstallPackageProgress(&ctx, info, &empty);
  if (!grpc_status.ok()) {
    LOG(WARNING) << "Failed to notify host system about uninstall status: "
                 << grpc_status.error_message() << " (code "
                 << grpc_status.error_code() << ")";
  }
}

void SendApplyAnsiblePlaybookStatusToHost(
    vm_tools::container::ContainerListener::Stub* stub,
    vm_tools::container::ApplyAnsiblePlaybookProgressInfo info) {
  grpc::ClientContext ctx;
  vm_tools::EmptyMessage empty;
  grpc::Status grpc_status =
      stub->ApplyAnsiblePlaybookProgress(&ctx, info, &empty);
  if (!grpc_status.ok()) {
    LOG(WARNING) << "Failed to notify host system about ansible playbook "
                 << "application status: " << grpc_status.error_message()
                 << " (code " << grpc_status.error_code() << ")";
  }
}

}  // namespace

namespace vm_tools {
namespace garcon {

// static
std::unique_ptr<HostNotifier> HostNotifier::Create(const std::string& token) {
  return base::WrapUnique(new HostNotifier(token));
}

// static
bool HostNotifier::OpenUrlInHost(const std::string& url) {
  grpc::ClientContext ctx;
  vm_tools::container::OpenUrlRequest url_request;
  url_request.set_token(token_);
  url_request.set_url(url);
  // If url has no scheme, but matches a local file, then convert to file://.
  auto front = url.find(kUrlSchemeDelimiter);
  if (front == std::string::npos) {
    base::FilePath path(url);
    base::FilePath abs = base::MakeAbsoluteFilePath(path);
    if (!abs.empty()) {
      url_request.set_url("file://" + abs.value());
    }
  }
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->OpenUrl(&ctx, url_request, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to request host system to open url \"" << url
                 << "\" error: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::OpenTerminal(std::vector<std::string> args) {
  grpc::ClientContext ctx;
  vm_tools::container::OpenTerminalRequest terminal_request;
  std::copy(std::make_move_iterator(args.begin()),
            std::make_move_iterator(args.end()),
            google::protobuf::RepeatedFieldBackInserter(
                terminal_request.mutable_params()));
  terminal_request.set_token(token_);

  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->OpenTerminal(&ctx, terminal_request, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed request to open terminal, error: "
                 << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::SelectFile(const std::string& type,
                              const std::string& title,
                              const std::string& default_path,
                              const std::string& allowed_extensions,
                              std::vector<std::string>* files) {
  grpc::ClientContext ctx;
  vm_tools::container::SelectFileRequest select_file_request;
  select_file_request.set_token(token_);
  select_file_request.set_type(type);
  select_file_request.set_title(title);
  select_file_request.set_default_path(default_path);
  select_file_request.set_allowed_extensions(allowed_extensions);

  vm_tools::container::SelectFileResponse select_file_response;
  grpc::Status status =
      stub_->SelectFile(&ctx, select_file_request, &select_file_response);
  if (!status.ok()) {
    LOG(WARNING) << "Failed request to select file, error: "
                 << status.error_message();
    return false;
  }

  std::copy(
      std::make_move_iterator(select_file_response.mutable_files()->begin()),
      std::make_move_iterator(select_file_response.mutable_files()->end()),
      std::back_inserter(*files));
  return true;
}

bool HostNotifier::GetDiskInfo(
    vm_tools::container::GetDiskInfoResponse* response) {
  grpc::ClientContext ctx;
  vm_tools::container::GetDiskInfoRequest request;
  request.set_token(token_);
  grpc::Status status = stub_->GetDiskInfo(&ctx, request, response);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to get disk info: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::RequestSpace(
    uint64_t space_requested,
    vm_tools::container::RequestSpaceResponse* response) {
  grpc::ClientContext ctx;
  vm_tools::container::RequestSpaceRequest request;
  request.set_token(token_);
  request.set_space_requested(space_requested);
  grpc::Status status = stub_->RequestSpace(&ctx, request, response);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to expand the disk: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::InstallShaderCache(uint64_t steam_app_id,
                                      bool mount,
                                      bool wait) {
  grpc::ClientContext ctx;

  vm_tools::container::InstallShaderCacheRequest request;
  EmptyMessage response;
  request.set_token(token_);
  request.set_steam_app_id(steam_app_id);
  request.set_mount(mount);
  request.set_wait(wait);

  // Request Cicerone to download and install shader cache
  grpc::Status status = stub_->InstallShaderCache(&ctx, request, &response);

  if (!status.ok()) {
    if (mount) {
      LOG(ERROR) << "Failed to install and mount shader cache: "
                 << status.error_message();
    } else {
      LOG(ERROR) << "Failed to trigger shader cache installation: "
                 << status.error_message();
    }
    return false;
  }
  if (mount) {
    LOG(INFO) << "Successfully installed and mounted shader cache DLC";
  } else {
    LOG(INFO) << "Successfully triggered shader cache DLC installation";
  }
  return true;
}

bool HostNotifier::UninstallShaderCache(uint64_t steam_app_id) {
  grpc::ClientContext ctx;

  vm_tools::container::UninstallShaderCacheRequest request;
  EmptyMessage response;
  request.set_token(token_);
  request.set_steam_app_id(steam_app_id);

  grpc::Status status = stub_->UninstallShaderCache(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to unmount and uninstall shader cache: "
               << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::UnmountShaderCache(uint64_t steam_app_id, bool wait) {
  grpc::ClientContext ctx;

  vm_tools::container::UnmountShaderCacheRequest request;
  EmptyMessage response;
  request.set_token(token_);
  request.set_steam_app_id(steam_app_id);
  request.set_wait(wait);

  grpc::Status status = stub_->UnmountShaderCache(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to queue unmount shader cache: "
               << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::ReleaseSpace(
    uint64_t space_to_release,
    vm_tools::container::ReleaseSpaceResponse* response) {
  grpc::ClientContext ctx;
  vm_tools::container::ReleaseSpaceRequest request;
  request.set_token(token_);
  request.set_space_to_release(space_to_release);
  grpc::Status status = stub_->ReleaseSpace(&ctx, request, response);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to shrink the disk: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::ReportMetrics(
    vm_tools::container::ReportMetricsRequest request,
    vm_tools::container::ReportMetricsResponse* response) {
  grpc::ClientContext ctx;
  request.set_token(token_);
  grpc::Status status = stub_->ReportMetrics(&ctx, request, response);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to report metrics: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::InhibitScreensaver(
    vm_tools::container::InhibitScreensaverInfo info) {
  grpc::ClientContext ctx;
  info.set_token(token_);
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->InhibitScreensaver(&ctx, info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to inhibit screensaver: " << status.error_message();
    return false;
  }
  return true;
}

bool HostNotifier::UninhibitScreensaver(
    vm_tools::container::UninhibitScreensaverInfo info) {
  vm_tools::EmptyMessage empty;
  grpc::ClientContext ctx;
  info.set_token(token_);
  grpc::Status status = stub_->UninhibitScreensaver(&ctx, info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to uninhibit screensaver: "
                 << status.error_message();
    return false;
  }
  return true;
}

HostNotifier::HostNotifier(const std::string& token)
    : token_(token),
      update_app_list_posted_(false),
      send_app_list_to_host_in_progress_(false),
      update_mime_types_posted_(false) {
  SetUpContainerListenerStub();
}

HostNotifier::~HostNotifier() = default;

void HostNotifier::OnSignalReadable() {
  signalfd_siginfo info;
  if (read(signal_fd_.get(), &info, sizeof(info)) != sizeof(info)) {
    PLOG(ERROR) << "Failed to read from signalfd";
  }
  DCHECK_EQ(info.ssi_signo, SIGTERM);
  // Notify the host we are shutting down, then inform our run loop to terminate
  // which should then shut us down, deallocate us and then also terminate the
  // gRPC thread.
  NotifyHostOfContainerShutdown();
  if (shutdown_closure_) {
    task_runner_->PostTask(FROM_HERE, std::move(shutdown_closure_));
  }
}

void HostNotifier::OnInstallCompletion(const std::string& command_uuid,
                                       bool success,
                                       const std::string& failure_reason) {
  vm_tools::container::InstallLinuxPackageProgressInfo progress_info;
  progress_info.set_token(token_);
  progress_info.set_status(
      success ? vm_tools::container::InstallLinuxPackageProgressInfo::SUCCEEDED
              : vm_tools::container::InstallLinuxPackageProgressInfo::FAILED);
  progress_info.set_failure_details(failure_reason);
  progress_info.set_command_uuid(command_uuid);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendInstallStatusToHost, base::Unretained(stub_.get()),
                     std::move(progress_info)));
}

void HostNotifier::OnInstallProgress(
    const std::string& command_uuid,
    vm_tools::container::InstallLinuxPackageProgressInfo::Status status,
    uint32_t percent_progress) {
  vm_tools::container::InstallLinuxPackageProgressInfo progress_info;
  progress_info.set_token(token_);
  progress_info.set_status(status);
  progress_info.set_progress_percent(percent_progress);
  progress_info.set_command_uuid(command_uuid);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendInstallStatusToHost, base::Unretained(stub_.get()),
                     std::move(progress_info)));
}

void HostNotifier::OnUninstallCompletion(bool success,
                                         const std::string& failure_reason) {
  LOG(INFO) << "Got HostNotifier::OnUninstallCompletion(" << success << ", "
            << failure_reason << ")";
  vm_tools::container::UninstallPackageProgressInfo info;
  info.set_token(token_);
  if (success) {
    info.set_status(
        vm_tools::container::UninstallPackageProgressInfo::SUCCEEDED);
  } else {
    info.set_status(vm_tools::container::UninstallPackageProgressInfo::FAILED);
    info.set_failure_details(failure_reason);
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendUninstallStatusToHost, base::Unretained(stub_.get()),
                     std::move(info)));
}

void HostNotifier::OnUninstallProgress(uint32_t percent_progress) {
  VLOG(3) << "Got HostNotifier::OnUninstallProgress(" << percent_progress
          << ")";
  vm_tools::container::UninstallPackageProgressInfo info;
  info.set_token(token_);
  info.set_status(
      vm_tools::container::UninstallPackageProgressInfo::UNINSTALLING);
  info.set_progress_percent(percent_progress);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendUninstallStatusToHost, base::Unretained(stub_.get()),
                     std::move(info)));
}

void HostNotifier::OnApplyAnsiblePlaybookCompletion(
    bool success, const std::string& failure_reason) {
  LOG(INFO) << "Got HostNotifier::OnApplyAnsiblePlaybookCompletion(" << success
            << ", " << failure_reason << ")";
  RemoveAnsiblePlaybookApplication();

  vm_tools::container::ApplyAnsiblePlaybookProgressInfo info;
  info.set_token(token_);
  if (success) {
    info.set_status(
        vm_tools::container::ApplyAnsiblePlaybookProgressInfo::SUCCEEDED);
  } else {
    info.set_status(
        vm_tools::container::ApplyAnsiblePlaybookProgressInfo::FAILED);
    info.set_failure_details(failure_reason);
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendApplyAnsiblePlaybookStatusToHost,
                     base::Unretained(stub_.get()), std::move(info)));
}

void HostNotifier::OnApplyAnsiblePlaybookProgress(
    const std::vector<std::string>& status_lines) {
  LOG(INFO) << "Got HostNotifier::OnApplyAnsaiblePlaybookProgress: "
            << status_lines[0];

  vm_tools::container::ApplyAnsiblePlaybookProgressInfo info;
  info.set_token(token_);
  info.set_status(
      vm_tools::container::ApplyAnsiblePlaybookProgressInfo::IN_PROGRESS);
  for (auto line : status_lines)
    info.add_status_string(line);

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&SendApplyAnsiblePlaybookStatusToHost,
                     base::Unretained(stub_.get()), std::move(info)));
}

void HostNotifier::CreateAnsiblePlaybookApplication(
    base::WaitableEvent* event,
    AnsiblePlaybookApplication** ansible_playbook_application_ptr) {
  DCHECK(!ansible_playbook_application_);
  ansible_playbook_application_ =
      std::make_unique<vm_tools::garcon::AnsiblePlaybookApplication>();
  *ansible_playbook_application_ptr = ansible_playbook_application_.get();
  event->Signal();
}

void HostNotifier::RemoveAnsiblePlaybookApplication() {
  ansible_playbook_application_->RemoveObserver(this);
  ansible_playbook_application_.reset();
}

bool HostNotifier::InitServer(base::OnceClosure shutdown_closure,
                              uint32_t garcon_port,
                              uint32_t sftp_port,
                              PackageKitProxy* package_kit_proxy) {
  CHECK(package_kit_proxy);
  package_kit_proxy_ = package_kit_proxy;
  shutdown_closure_ = std::move(shutdown_closure);
  task_runner_ = base::SingleThreadTaskRunner::GetCurrentDefault();
  sftp_vsock_port_ = sftp_port;
  if (!NotifyHostGarconIsReady(garcon_port, sftp_port)) {
    return false;
  }

  // Start listening for SIGTERM.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);

  signal_fd_.reset(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
  if (!signal_fd_.is_valid()) {
    PLOG(ERROR) << "Unable to create signalfd";
    return false;
  }

  signal_controller_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(), base::BindRepeating(&HostNotifier::OnSignalReadable,
                                            base::Unretained(this)));
  if (!signal_controller_) {
    LOG(ERROR) << "Failed to watch signal file descriptor";
    return false;
  }

  // Block the standard SIGTERM handler since we will be getting it via the
  // signalfd. We have to do this before we setup the file path watcher
  // because that will end up spawning another thread for each watcher.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
    PLOG(ERROR) << "Failed blocking standard SIGTERM handler";
    return false;
  }

  // Setup all of our watchers for changes to any of the paths where .desktop
  // files may reside.
  std::vector<base::FilePath> watch_paths =
      DesktopFile::GetPathsForDesktopFiles();
  for (auto& path : watch_paths) {
    std::unique_ptr<base::FilePathWatcher> watcher =
        std::make_unique<base::FilePathWatcher>();
    if (!watcher->Watch(path, base::FilePathWatcher::Type::kRecursive,
                        base::BindRepeating(&HostNotifier::DesktopPathsChanged,
                                            base::Unretained(this)))) {
      LOG(ERROR) << "Failed setting up filesystem path watcher for dir: "
                 << path.value();
      // Probably better to just watch the dirs we can rather than terminate
      // garcon altogether.
      continue;
    }
    watchers_.emplace_back(std::move(watcher));
  }

  // We can only watch directories and on changes we aren't notified which
  // file changes, so we end up watching for any changes in /etc or $HOME.

  // Also setup the watcher for the /usr/local/share/mime/mime.cache file.
  std::unique_ptr<base::FilePathWatcher> mime_type_watcher =
      std::make_unique<base::FilePathWatcher>();
  base::FilePath mime_type_path(kMimeTypesDir);
  if (!mime_type_watcher->Watch(
          mime_type_path, base::FilePathWatcher::Type::kNonRecursive,
          base::BindRepeating(&HostNotifier::MimeTypesChanged,
                              base::Unretained(this)))) {
    LOG(ERROR) << "Failed setting up filesystem path watcher for: "
               << kMimeTypesDir;
  }
  watchers_.emplace_back(std::move(mime_type_watcher));

  // Also setup the watcher for the $HOME/.local/share/mime/mime.cache file.
  std::unique_ptr<base::FilePathWatcher> home_mime_type_watcher =
      std::make_unique<base::FilePathWatcher>();
  if (!home_mime_type_watcher->Watch(
          base::GetHomeDir().Append(kUserMimeTypesDir),
          base::FilePathWatcher::Type::kNonRecursive,
          base::BindRepeating(&HostNotifier::MimeTypesChanged,
                              base::Unretained(this)))) {
    LOG(ERROR) << "Failed setting up filesystem path watcher for: "
               << base::GetHomeDir().value();
  }
  watchers_.emplace_back(std::move(home_mime_type_watcher));

  // If this fails, don't terminate ourself, this could be some kind of
  // transient failure.
  SendAppListToHost();
  SendMimeTypesToHost();

  // Start the disk space watcher.
  free_disk_space_timer_.Start(
      FROM_HERE, kDiskSpaceCheckInterval,
      base::BindRepeating(&HostNotifier::CheckDiskSpace,
                          weak_ptr_factory_.GetWeakPtr()));

  return true;
}

void HostNotifier::CheckDiskSpace() {
  grpc::ClientContext ctx;
  vm_tools::container::LowDiskSpaceTriggeredInfo info;
  auto free_bytes = base::SysInfo::AmountOfFreeDiskSpace(base::FilePath("/"));
  if (free_bytes >= kDiskSpaceCheckThreshold) {
    // Plenty of free space, nothing more to do.
    return;
  }
  info.set_token(token_);
  info.set_free_bytes(free_bytes);
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->LowDiskSpaceTriggered(&ctx, info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host system that disk space is low: "
                 << status.error_message();
  }
}

bool HostNotifier::NotifyHostGarconIsReady(uint32_t garcon_port,
                                           uint32_t sftp_port) {
  // Notify the host system that we are ready.
  grpc::ClientContext ctx;
  vm_tools::container::ContainerStartupInfo startup_info;
  startup_info.set_token(token_);
  startup_info.set_garcon_port(garcon_port);
  startup_info.set_sftp_port(sftp_port);
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->ContainerReady(&ctx, startup_info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host system that container is ready: "
                 << status.error_message();
    return false;
  }
  return true;
}

void HostNotifier::NotifyHostOfContainerShutdown() {
  // Notify the host system that we are shutting down.
  grpc::ClientContext ctx;
  vm_tools::container::ContainerShutdownInfo shutdown_info;
  shutdown_info.set_token(token_);
  vm_tools::EmptyMessage empty;
  grpc::Status status = stub_->ContainerShutdown(&ctx, shutdown_info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host system that container is shutting "
                 << "down: " << status.error_message();
  }
}

void HostNotifier::NotifyHostOfPendingAppListUpdates() {
  grpc::ClientContext ctx;
  vm_tools::container::PendingAppListUpdateCount msg;
  msg.set_token(token_);
  msg.set_count(update_app_list_posted_ + send_app_list_to_host_in_progress_);
  vm_tools::EmptyMessage empty;
  grpc::Status status =
      stub_->PendingUpdateApplicationListCalls(&ctx, msg, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host system of pending app list updates: "
                 << status.error_message();
  }
}

void HostNotifier::HandleSteamApp(
    std::unordered_set<uint64_t> found_steam_apps) {
  for (auto app_id : found_steam_apps) {
    if (installed_steam_apps_.find(app_id) == installed_steam_apps_.end()) {
      LOG(INFO) << "Attempting to install shader cache for newly installed "
                << "steam app";
      InstallShaderCache(app_id, false, false);
    }
  }
  for (auto app_id : installed_steam_apps_) {
    if (found_steam_apps.find(app_id) == found_steam_apps.end()) {
      LOG(INFO) << "Attempting to uninstall shader cache for removed steam app";
      UninstallShaderCache(app_id);
    }
  }

  installed_steam_apps_ = found_steam_apps;
}

void HostNotifier::SendAppListToHost() {
  if (send_app_list_to_host_in_progress_) {
    // Don't have multiple SendAppListToHost callback chains happening at the
    // same time. Delay the next run a little longer.
    //
    // Checking a boolean isn't a race condition because all the callbacks are
    // on the same thread.
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&HostNotifier::SendAppListToHost,
                       base::Unretained(this)),
        kFilesystemChangeCoalesceTime);
    return;
  }

  auto callback_state = std::make_unique<AppListBuilderState>();
  callback_state->request.set_token(token_);

  // If we hit duplicate IDs, then we are supposed to use the first one only.
  std::set<std::string> unique_app_ids;

  std::unordered_set<uint64_t> found_steam_apps;

  // Get the list of directories that we should search for .desktop files
  // recursively and then perform the search.
  std::vector<base::FilePath> search_paths =
      DesktopFile::GetPathsForDesktopFiles();
  for (auto curr_path : search_paths) {
    base::FileEnumerator file_enum(curr_path, true,
                                   base::FileEnumerator::FILES);
    for (base::FilePath enum_path = file_enum.Next(); !enum_path.empty();
         enum_path = file_enum.Next()) {
      if (enum_path.FinalExtension() != kDesktopFileExtension) {
        continue;
      }
      // We have a .desktop file path, parse it and then add it to the
      // protobuf if it parses successfully.
      std::unique_ptr<DesktopFile> desktop_file =
          DesktopFile::ParseDesktopFile(enum_path);
      if (!desktop_file) {
        LOG(WARNING) << "Failed parsing the .desktop file: "
                     << enum_path.value();
        continue;
      }

      // Found steam apps
      if (desktop_file->steam_app_id()) {
        found_steam_apps.emplace(desktop_file->steam_app_id());
      }

      // If we have already seen this desktop file ID then don't analyze this
      // one. We want to check this before we do the filtering to allow users
      // to put .desktop files in local locations to hide applications in
      // system locations.
      if (!unique_app_ids.insert(desktop_file->app_id()).second) {
        continue;
      }
      // Make sure this .desktop file is one we should send to the host.
      // There are various cases where we do not want to transmit certain
      // .desktop files.
      if (!desktop_file->ShouldPassToHost()) {
        continue;
      }
      // Add this app to the list in the protobuf and populate all of its
      // fields.
      vm_tools::container::Application* app =
          callback_state->request.add_application();
      app->set_desktop_file_id(desktop_file->app_id());
      const std::map<std::string, std::string>& name_map =
          desktop_file->locale_name_map();
      vm_tools::container::Application::LocalizedString* names =
          app->mutable_name();
      for (const auto& name_entry : name_map) {
        vm_tools::container::Application::LocalizedString::StringWithLocale*
            locale_string = names->add_values();
        locale_string->set_locale(name_entry.first);
        locale_string->set_value(name_entry.second);
      }
      const std::map<std::string, std::string>& comment_map =
          desktop_file->locale_comment_map();
      vm_tools::container::Application::LocalizedString* comments =
          app->mutable_comment();
      for (const auto& comment_entry : comment_map) {
        vm_tools::container::Application::LocalizedString::StringWithLocale*
            locale_string = comments->add_values();
        locale_string->set_locale(comment_entry.first);
        locale_string->set_value(comment_entry.second);
      }
      const std::map<std::string, std::vector<std::string>>& keywords_map =
          desktop_file->locale_keywords_map();
      vm_tools::container::Application::LocaleStrings* keyword =
          app->mutable_keywords();
      for (const auto& keywords_entry : keywords_map) {
        vm_tools::container::Application::LocaleStrings::StringsWithLocale*
            locale_string = keyword->add_values();
        locale_string->set_locale(keywords_entry.first);
        for (const auto& curr_keyword : keywords_entry.second) {
          locale_string->add_value(curr_keyword);
        }
      }
      for (const auto& mime_type : desktop_file->mime_types()) {
        app->add_mime_types(mime_type);
      }

      app->set_no_display(desktop_file->no_display());
      app->set_startup_wm_class(desktop_file->startup_wm_class());
      app->set_startup_notify(desktop_file->startup_notify());
      app->set_exec(desktop_file->exec());
      app->set_executable_file_name(desktop_file->GenerateExecutableFileName());
      app->set_terminal(desktop_file->terminal());

      callback_state->desktop_files_for_application.push_back(enum_path);
    }
  }

  CHECK_EQ(callback_state->desktop_files_for_application.size(),
           callback_state->request.application_size());

  // We now want to query all the .desktop files to see what package owns them.
  // Unforuntately, this requires D-Bus calls to the PackageKit, and we are on
  // the D-Bus thread. So we can't receive the results until this function
  // returns, so we need to set up a series of callbacks.
  //
  // Query each .desktop file in turn. The callback will record the info for
  // that file and also kick off the query for the next file until all files
  // have been queried.
  callback_state->num_package_id_queries_completed = 0;

  // Clear this in case it was set, this all happens on the same thread.
  // Clear this now, not when the package_id callbacks are complete, in case
  // we get another notification while this is still in flight; we'd want to run
  // this function again in that case.
  update_app_list_posted_ = false;

  // Don't start another round of callbacks while still trying to finish this
  // round.
  send_app_list_to_host_in_progress_ = true;

  HandleSteamApp(found_steam_apps);
  RequestNextPackageIdOrCompleteUpdateApplicationList(
      std::move(callback_state));
}

void HostNotifier::RequestNextPackageIdOrCompleteUpdateApplicationList(
    std::unique_ptr<AppListBuilderState> state) {
  if ((state->num_package_id_queries_completed >=
       state->desktop_files_for_application.size())) {
    // We have finished all package_id queries. This data is ready to send to
    // the host.
    send_app_list_to_host_in_progress_ = false;
    vm_tools::EmptyMessage empty;
    grpc::ClientContext ctx;
    grpc::Status status =
        stub_->UpdateApplicationList(&ctx, state->request, &empty);
    VLOG(3) << "UpdatedApplicationList\n" << state->request.DebugString();
    if (!status.ok()) {
      LOG(WARNING) << "Failed to notify host of the application list: "
                   << status.error_message();
    }
    NotifyHostOfPendingAppListUpdates();
    return;
  }
  // else we still need to do more package_id queries
  package_kit_proxy_->SearchLinuxPackagesForFile(
      state->desktop_files_for_application
          [state->num_package_id_queries_completed],
      base::BindOnce(&HostNotifier::PackageIdCallback, base::Unretained(this),
                     std::move(state)));
}

void HostNotifier::PackageIdCallback(
    std::unique_ptr<AppListBuilderState> state,
    bool success,
    bool pkg_found,
    const PackageKitProxy::LinuxPackageInfo& pkg_info,
    const std::string& error) {
  // The data passed in the parameters is for the Application at
  // state->request.application[state->num_package_id_queries_completed]
  CHECK_LT(state->num_package_id_queries_completed,
           state->request.application_size());
  if (success && pkg_found) {
    vm_tools::container::Application* application =
        state->request.mutable_application(
            state->num_package_id_queries_completed);
    application->set_package_id(pkg_info.package_id);
  } else if (!success) {
    LOG(ERROR) << "Failed to get Package Info: " << error;
  }

  state->num_package_id_queries_completed++;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &HostNotifier::RequestNextPackageIdOrCompleteUpdateApplicationList,
          base::Unretained(this), std::move(state)));
}

void HostNotifier::SendMimeTypesToHost() {
  vm_tools::container::UpdateMimeTypesRequest request;
  request.set_token(token_);
  vm_tools::EmptyMessage empty;

  // Clear this in case it was set, this all happens on the same thread.
  update_mime_types_posted_ = false;

  MimeTypeMap mime_type_map;
  if (!ParseMimeTypes(kMimeTypesFilePath, &mime_type_map)) {
    LOG(ERROR) << "Failed parsing system mime types, will not send the list to "
               << "host";
    return;
  }
  // The user MIME types may not be set up, so we ignore failures here. User
  // values override system values, so parse this one second so they get
  // overridden.
  ParseMimeTypes(base::GetHomeDir().Append(kUserMimeTypesFile).value(),
                 &mime_type_map);

  request.mutable_mime_type_mappings()->insert(
      std::make_move_iterator(mime_type_map.begin()),
      std::make_move_iterator(mime_type_map.end()));
  // Now make the gRPC call to send this list to the host.
  grpc::ClientContext ctx;
  grpc::Status status = stub_->UpdateMimeTypes(&ctx, request, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host of the MIME types: "
                 << status.error_message();
  }
}

void HostNotifier::DesktopPathsChanged(const base::FilePath& path, bool error) {
  if (error) {
    // This should never occur because the implementation for Linux never calls
    // this with an error.
    LOG(ERROR) << "Error detected in file path watching for path: "
               << path.value();
    return;
  }

  // We don't want to trigger an update every time there's a change, instead
  // wait a bit and coalesce potential groups of changes that may occur. We
  // don't want to wait too long though because then the user may feel that it
  // is unresponsive in newly installed applications not showing up in the
  // launcher when they check.
  if (update_app_list_posted_) {
    return;
  }
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&HostNotifier::SendAppListToHost, base::Unretained(this)),
      kFilesystemChangeCoalesceTime);
  update_app_list_posted_ = true;
  NotifyHostOfPendingAppListUpdates();
}

void HostNotifier::MimeTypesChanged(const base::FilePath& path, bool error) {
  if (error) {
    // This should never occur because the implementation for Linux never calls
    // this with an error.
    LOG(ERROR) << "Error detected in file path watching for path: "
               << path.value();
    return;
  }

  // Coalesce these calls if we have one pending.
  if (update_mime_types_posted_) {
    return;
  }
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&HostNotifier::SendMimeTypesToHost,
                     base::Unretained(this)),
      kFilesystemChangeCoalesceTime);
  update_mime_types_posted_ = true;
}

void HostNotifier::SetUpContainerListenerStub() {
  stub_ = std::make_unique<vm_tools::container::ContainerListener::Stub>(
      grpc::CreateChannel(base::StringPrintf("vsock:%d:%u", VMADDR_CID_HOST,
                                             vm_tools::kGarconPort),
                          grpc::InsecureChannelCredentials()));
}

bool HostNotifier::AddFileWatch(const base::FilePath& path,
                                std::string* error_msg) {
  if (path.IsAbsolute() || path.ReferencesParent()) {
    LOG(ERROR) << "Invalid path";
    *error_msg = "invalid path";
    return false;
  }
  if (file_path_watchers_.count(path) > 0) {
    LOG(ERROR) << "Already watching path";
    *error_msg = "already watching path";
    return false;
  }
  std::unique_ptr<base::FilePathWatcher> watcher =
      std::make_unique<base::FilePathWatcher>();
  base::FilePath path_in_home = base::GetHomeDir().Append(path);

  task_runner_->PostTask(
      FROM_HERE,
      // TODO(crbug.com/1179608): after libchrome is upreved to r860220,
      // base::FilePathWatcher will not be overloaded and could be simplified to
      // base::IgnoreResult(&base::FilePathWatcher::Watch).
      base::BindOnce(base::IgnoreResult<bool (  // NOLINT(whitespace/parens)
                         base::FilePathWatcher::*)(
                         const base::FilePath&, base::FilePathWatcher::Type,
                         const base::FilePathWatcher::Callback&)>(
                         &base::FilePathWatcher::Watch),
                     base::Unretained(watcher.get()), path_in_home,
                     base::FilePathWatcher::Type::kNonRecursive,
                     base::BindRepeating(&HostNotifier::FileWatchTriggered,
                                         base::Unretained(this))));

  file_path_watchers_[path] = std::move(watcher);
  return true;
}

bool HostNotifier::RemoveFileWatch(const base::FilePath& path,
                                   std::string* error_msg) {
  if (path.IsAbsolute() || path.ReferencesParent()) {
    LOG(ERROR) << "Invalid path";
    *error_msg = "invalid path";
    return false;
  }
  if (file_path_watchers_.count(path) == 0) {
    LOG(ERROR) << "Not watching path";
    *error_msg = "not watching path";
    return false;
  }
  task_runner_->DeleteSoon(FROM_HERE, file_path_watchers_[path].release());
  file_path_watchers_.erase(path);
  file_watch_last_change_.erase(path);
  return true;
}

void HostNotifier::SendFileWatchTriggeredToHost(const base::FilePath& path) {
  vm_tools::container::FileWatchTriggeredInfo info;
  info.set_token(token_);
  info.set_path(path.value());
  vm_tools::EmptyMessage empty;

  // Update pending flag and time when last sent.
  file_watch_change_posted_.erase(path);
  file_watch_last_change_[path] = base::TimeTicks::Now();

  // Now make the gRPC call to notify the host.
  grpc::ClientContext ctx;
  grpc::Status status = stub_->FileWatchTriggered(&ctx, info, &empty);
  if (!status.ok()) {
    LOG(WARNING) << "Failed to notify host of FilePathWatcher change: "
                 << status.error_message();
  }
}

void HostNotifier::FileWatchTriggered(const base::FilePath& absolute_path,
                                      bool error) {
  if (error) {
    // This should never occur because the implementation for Linux never calls
    // this with an error.
    LOG(ERROR) << "Error detected in file path watcher";
    return;
  }

  base::FilePath home = base::GetHomeDir();
  base::FilePath path;
  if (absolute_path != home && !home.AppendRelativePath(absolute_path, &path)) {
    LOG(ERROR) << "Unexpected path not under $HOME";
    return;
  }

  // Coalesce these calls if we have one pending.
  if (file_watch_change_posted_.count(path) > 0) {
    return;
  }

  // Send right away if it has been long enough since the last one, else post
  // delayed task.
  base::TimeDelta time_since_last =
      base::TimeTicks::Now() - file_watch_last_change_[path];
  if (time_since_last > kFilesystemChangeCoalesceTime) {
    SendFileWatchTriggeredToHost(path);
  } else {
    task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&HostNotifier::SendFileWatchTriggeredToHost,
                       base::Unretained(this), path),
        kFilesystemChangeCoalesceTime - time_since_last);
    file_watch_change_posted_.insert(path);
  }
}

}  // namespace garcon
}  // namespace vm_tools
