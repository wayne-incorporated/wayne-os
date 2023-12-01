// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crosdns/crosdns_daemon.h"

#include <sysexits.h>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "crosdns/hosts_modifier.h"

namespace {

// Domain for D-Bus error messages.
constexpr char kErrorDomain[] = "crosdns";
// Type for D-Bus error messages.
constexpr char kInternalError[] = "internal_error";
// Path to our modifiable /etc/hosts file, the parent dir is bind mounted
// on top of the dir where the real hosts file is at.
constexpr char kEtcHostsPath[] = "/run/crosdns/hosts";

}  // namespace

namespace crosdns {

CrosDnsDaemon::CrosDnsDaemon()
    : brillo::DBusServiceDaemon(kCrosDnsServiceName), dbus_adaptor_(this) {}

CrosDnsDaemon::~CrosDnsDaemon() = default;

int CrosDnsDaemon::OnInit() {
  int exit_code = DBusServiceDaemon::OnInit();
  if (exit_code == EX_OK) {
    if (!hosts_modifier_.Init(base::FilePath(kEtcHostsPath))) {
      return EX_IOERR;
    }
  }

  return exit_code;
}

void CrosDnsDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr, bus_, org::chromium::CrosDnsAdaptor::GetObjectPath());
  dbus_adaptor_.RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(
      sequencer->GetHandler("CrosDns.RegisterAsync() failed.", true));
}

bool CrosDnsDaemon::SetHostnameIpMapping(brillo::ErrorPtr* err,
                                         const std::string& hostname,
                                         const std::string& ipv4,
                                         const std::string& ipv6) {
  std::string err_str;
  if (!hosts_modifier_.SetHostnameIpMapping(hostname, ipv4, ipv6, &err_str)) {
    *err =
        brillo::Error::Create(FROM_HERE, kErrorDomain, kInternalError, err_str);
    return false;
  }

  return true;
}

bool CrosDnsDaemon::RemoveHostnameIpMapping(brillo::ErrorPtr* err,
                                            const std::string& hostname) {
  std::string err_str;
  if (!hosts_modifier_.RemoveHostnameIpMapping(hostname, &err_str)) {
    *err =
        brillo::Error::Create(FROM_HERE, kErrorDomain, kInternalError, err_str);
    return false;
  }

  return true;
}

}  // namespace crosdns
