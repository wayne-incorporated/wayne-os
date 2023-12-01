// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/dlp_daemon.h"

#include <utility>

#include <base/check.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/dlp/dbus-constants.h>
#include <featured/feature_library.h>

#include "dlp/dlp_adaptor.h"

namespace dlp {

namespace {
const char kObjectServicePath[] = "/org/chromium/Dlp/ObjectManager";
}  // namespace

DlpDaemon::DlpDaemon(int fanotify_perm_fd,
                     int fanotify_notif_fd,
                     const base::FilePath& home_path,
                     const base::FilePath& database_path)
    : DBusServiceDaemon(kDlpServiceName, kObjectServicePath),
      fanotify_perm_fd_(fanotify_perm_fd),
      fanotify_notif_fd_(fanotify_notif_fd),
      home_path_(home_path),
      database_path_(database_path) {}
DlpDaemon::~DlpDaemon() = default;

void DlpDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  auto dbus_object = std::make_unique<brillo::dbus_utils::DBusObject>(
      object_manager_.get(), object_manager_->GetBus(),
      org::chromium::DlpAdaptor::GetObjectPath());
  DCHECK(!adaptor_);
  feature::PlatformFeatures* feature_lib;
  if (!feature::PlatformFeatures::Initialize(dbus_object->GetBus())) {
    feature_lib = nullptr;
  } else {
    feature_lib = feature::PlatformFeatures::Get();
  }
  adaptor_ = std::make_unique<DlpAdaptor>(std::move(dbus_object), feature_lib,
                                          fanotify_perm_fd_, fanotify_notif_fd_,
                                          home_path_);
  adaptor_->InitDatabase(database_path_, base::DoNothing());
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace dlp
