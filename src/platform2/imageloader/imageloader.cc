// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "imageloader/imageloader.h"

#include <libminijail.h>
#include <scoped_minijail.h>
#include <sysexits.h>

#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/constants/imageloader.h>
#include <chromeos/dbus/service_constants.h>

namespace imageloader {

namespace {
constexpr char kSeccompFilterPath[] =
    "/usr/share/policy/imageloader-seccomp.policy";
}  // namespace

// static
const char ImageLoader::kImageLoaderGroupName[] = "imageloaderd";
const char ImageLoader::kImageLoaderUserName[] = "imageloaderd";
constexpr base::TimeDelta kShutdownTimeout = base::Seconds(20);

ImageLoader::ImageLoader(ImageLoaderConfig config,
                         std::unique_ptr<HelperProcessProxy> proxy)
    : DBusServiceDaemon(kImageLoaderServiceName),
      impl_(std::move(config)),
      helper_process_proxy_(std::move(proxy)) {}

ImageLoader::~ImageLoader() = default;

// static
void ImageLoader::EnterSandbox() {
  ScopedMinijail jail(minijail_new());
  minijail_no_new_privs(jail.get());
  minijail_use_seccomp_filter(jail.get());
  minijail_parse_seccomp_filters(jail.get(), kSeccompFilterPath);
  minijail_reset_signal_mask(jail.get());
  minijail_namespace_ipc(jail.get());
  minijail_namespace_net(jail.get());
  minijail_remount_proc_readonly(jail.get());
  CHECK_EQ(0, minijail_change_user(jail.get(), kImageLoaderUserName));
  CHECK_EQ(0, minijail_change_group(jail.get(), kImageLoaderGroupName));
  minijail_inherit_usergroups(jail.get());
  minijail_enter(jail.get());
}

int ImageLoader::OnInit() {
  // Run with minimal privileges.
  EnterSandbox();

  int return_code = brillo::DBusServiceDaemon::OnInit();
  if (return_code != EX_OK)
    return return_code;

  process_reaper_.Register(this);
  process_reaper_.WatchForChild(
      FROM_HERE, helper_process_proxy_->pid(),
      base::BindOnce(&ImageLoader::OnSubprocessExited,
                     weak_factory_.GetWeakPtr(), helper_process_proxy_->pid()));

  PostponeShutdown();

  return EX_OK;
}

void ImageLoader::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_object_.reset(new brillo::dbus_utils::DBusObject(
      nullptr, bus_,
      org::chromium::ImageLoaderInterfaceAdaptor::GetObjectPath()));
  dbus_adaptor_.RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(
      sequencer->GetHandler("ImageLoader.RegisterAsync() failed.", true));
}

void ImageLoader::OnShutdown(int* return_code) {
  brillo::DBusServiceDaemon::OnShutdown(return_code);
}

void ImageLoader::OnSubprocessExited(pid_t pid, const siginfo_t& info) {
  LOG(FATAL) << "Subprocess " << pid << " exited unexpectedly.";
}

void ImageLoader::PostponeShutdown() {
  shutdown_callback_.Reset(
      base::BindOnce(&brillo::Daemon::Quit, weak_factory_.GetWeakPtr()));
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, shutdown_callback_.callback(), kShutdownTimeout);
}

bool ImageLoader::RegisterComponent(
    brillo::ErrorPtr* err,
    const std::string& name,
    const std::string& version,
    const std::string& component_folder_abs_path,
    bool* out_success) {
  *out_success =
      impl_.RegisterComponent(name, version, component_folder_abs_path);
  PostponeShutdown();
  return true;
}

bool ImageLoader::GetComponentVersion(brillo::ErrorPtr* err,
                                      const std::string& name,
                                      std::string* out_version) {
  *out_version = impl_.GetComponentVersion(name);
  PostponeShutdown();
  return true;
}

bool ImageLoader::LoadComponent(brillo::ErrorPtr* err,
                                const std::string& name,
                                std::string* out_mount_point) {
  *out_mount_point = impl_.LoadComponent(name, helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

bool ImageLoader::LoadComponentAtPath(brillo::ErrorPtr* err,
                                      const std::string& name,
                                      const std::string& absolute_path,
                                      std::string* out_mount_point) {
  *out_mount_point = impl_.LoadComponentAtPath(
      name, base::FilePath(absolute_path), helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

bool ImageLoader::LoadDlcImage(brillo::ErrorPtr* err,
                               const std::string& id,
                               const std::string& package,
                               const std::string& a_or_b,
                               std::string* out_mount_point) {
  *out_mount_point =
      impl_.LoadDlcImage(id, package, a_or_b, helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

bool ImageLoader::LoadDlc(brillo::ErrorPtr* err,
                          const LoadDlcRequest& request,
                          std::string* out_mount_point) {
  *out_mount_point = impl_.LoadDlc(request, helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

bool ImageLoader::RemoveComponent(brillo::ErrorPtr* err,
                                  const std::string& name,
                                  bool* out_success) {
  *out_success = impl_.RemoveComponent(name);
  PostponeShutdown();
  return true;
}

bool ImageLoader::GetComponentMetadata(
    brillo::ErrorPtr* err,
    const std::string& name,
    std::map<std::string, std::string>* out_metadata) {
  if (!impl_.GetComponentMetadata(name, out_metadata))
    out_metadata->clear();
  PostponeShutdown();
  return true;
}

bool ImageLoader::UnmountComponent(brillo::ErrorPtr* err,
                                   const std::string& name,
                                   bool* out_success) {
  base::FilePath component_mount_root =
      base::FilePath(imageloader::kImageloaderMountBase).Append(name);
  *out_success = impl_.CleanupAll(false, component_mount_root, nullptr,
                                  helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

bool ImageLoader::UnloadDlcImage(brillo::ErrorPtr* err,
                                 const std::string& id,
                                 const std::string& package,
                                 bool* out_success) {
  *out_success = impl_.UnloadDlcImage(id, package, helper_process_proxy_.get());
  PostponeShutdown();
  return true;
}

}  // namespace imageloader
