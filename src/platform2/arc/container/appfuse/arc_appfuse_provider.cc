// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>

#include "appfuse/dbus_adaptors/org.chromium.ArcAppfuseProvider.h"
#include "arc/container/appfuse/appfuse_mount.h"

namespace {

constexpr char kMountRoot[] = "mount_root";

brillo::ErrorPtr CreateDBusError(const std::string& code,
                                 const std::string& message) {
  return brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain, code,
                               message);
}

class DBusAdaptor : public org::chromium::ArcAppfuseProviderAdaptor,
                    public org::chromium::ArcAppfuseProviderInterface,
                    public arc::appfuse::AppfuseMount::Delegate {
 public:
  explicit DBusAdaptor(scoped_refptr<dbus::Bus> bus)
      : org::chromium::ArcAppfuseProviderAdaptor(this),
        mount_root_(base::CommandLine::ForCurrentProcess()->GetSwitchValuePath(
            kMountRoot)),
        dbus_object_(
            nullptr,
            bus,
            dbus::ObjectPath(arc::appfuse::kArcAppfuseProviderServicePath)) {}
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  ~DBusAdaptor() override = default;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
    RegisterWithDBusObject(&dbus_object_);
    dbus_object_.RegisterAsync(std::move(cb));
  }

  // org::chromium::ArcAppfuseProviderInterface overrides:
  bool Mount(brillo::ErrorPtr* error,
             uint32_t uid,
             int32_t mount_id,
             base::ScopedFD* out_fd) override {
    // Remove existing mount.
    auto it = mounts_.find(std::make_pair(uid, mount_id));
    if (it != mounts_.end()) {
      LOG(INFO) << "Unmounting an existing mount for a new mount: " << uid
                << " " << mount_id;
      if (!it->second->Unmount()) {
        LOG(ERROR) << "Failed to unmount an existing mount for a new mount: "
                   << uid << " " << mount_id;
        *error = CreateDBusError(DBUS_ERROR_FAILED, "Failed to unmount");
        return false;
      }
      mounts_.erase(it);
    }
    // Create a new mount.
    auto mount = std::make_unique<arc::appfuse::AppfuseMount>(mount_root_, uid,
                                                              mount_id, this);
    base::ScopedFD fd = mount->Mount();
    if (!fd.is_valid()) {
      LOG(ERROR) << "Failed to mount: " << uid << " " << mount_id;
      *error = CreateDBusError(DBUS_ERROR_FAILED, "Failed to mount");
      return false;
    }
    mounts_[std::make_pair(uid, mount_id)] = std::move(mount);
    *out_fd = std::move(fd);
    return true;
  }

  bool Unmount(brillo::ErrorPtr* error,
               uint32_t uid,
               int32_t mount_id) override {
    auto it = mounts_.find(std::make_pair(uid, mount_id));
    if (it == mounts_.end()) {
      LOG(ERROR) << "No mount found: " << uid << " " << mount_id;
      *error = CreateDBusError(DBUS_ERROR_FAILED, "No mount found");
      return false;
    }
    if (!it->second->Unmount()) {
      LOG(ERROR) << "Failed to unmount: " << uid << " " << mount_id;
      *error = CreateDBusError(DBUS_ERROR_FAILED, "Failed to unmount");
      return false;
    }
    mounts_.erase(it);
    return true;
  }

  bool OpenFile(brillo::ErrorPtr* error,
                uint32_t uid,
                int32_t mount_id,
                int32_t file_id,
                int32_t flags,
                base::ScopedFD* out_fd) override {
    auto it = mounts_.find(std::make_pair(uid, mount_id));
    if (it == mounts_.end()) {
      LOG(ERROR) << "No mount found: " << uid << " " << mount_id;
      *error = CreateDBusError(DBUS_ERROR_FAILED, "No mount found");
      return false;
    }
    base::ScopedFD fd = it->second->OpenFile(file_id, flags);
    if (!fd.is_valid()) {
      LOG(ERROR) << "Failed to open: " << uid << " " << mount_id;
      *error = CreateDBusError(DBUS_ERROR_FAILED, "Failed to open");
      return false;
    }
    *out_fd = std::move(fd);
    return true;
  }

  // AppfuseMount::Delegate override:
  void OnAppfuseMountAborted(arc::appfuse::AppfuseMount* mount) override {
    mounts_.erase(std::make_pair(mount->uid(), mount->mount_id()));
  }

 private:
  const base::FilePath mount_root_;
  brillo::dbus_utils::DBusObject dbus_object_;

  // Maps (UID, mount ID) to AppfuseMount.
  using UIDMountIDPair = std::pair<uid_t, int>;
  using AppfuseMountMap =
      std::map<UIDMountIDPair, std::unique_ptr<arc::appfuse::AppfuseMount>>;
  AppfuseMountMap mounts_;
};

class Daemon : public brillo::DBusServiceDaemon {
 public:
  Daemon() : DBusServiceDaemon(arc::appfuse::kArcAppfuseProviderServiceName) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override = default;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    adaptor_ = std::make_unique<DBusAdaptor>(bus_);
    adaptor_->RegisterAsync(
        sequencer->GetHandler("RegisterAsync() failed.", true));
  }

 private:
  std::unique_ptr<DBusAdaptor> adaptor_;
};

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  CHECK(base::CommandLine::ForCurrentProcess()->HasSwitch(kMountRoot))
      << "--" << kMountRoot << " must be specified.";
  return Daemon().Run();
}
