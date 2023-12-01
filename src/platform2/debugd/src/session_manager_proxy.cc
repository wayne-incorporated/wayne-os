// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/session_manager_proxy.h"

#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace {

// Strings for states from the session manager's SessionStateChanged signal
// that debugd will take action on. These values are defined in the
// session_manager codebase.
const char kSessionStarted[] = "started";
const char kSessionStopped[] = "stopped";

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to signal " << signal << " on interface "
               << interface;
  }
}

}  // namespace

namespace debugd {

SessionManagerProxy::SessionManagerProxy(scoped_refptr<dbus::Bus> bus)
    : bus_(bus),
      proxy_(bus->GetObjectProxy(
          login_manager::kSessionManagerServiceName,
          dbus::ObjectPath(login_manager::kSessionManagerServicePath))),
      weak_ptr_factory_(this) {
  proxy_->ConnectToSignal(
      login_manager::kSessionManagerInterface,
      login_manager::kLoginPromptVisibleSignal,
      base::BindRepeating(&SessionManagerProxy::OnLoginPromptVisible,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
  proxy_->ConnectToSignal(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionStateChangedSignal,
      base::BindRepeating(&SessionManagerProxy::OnSessionStateChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
}

void SessionManagerProxy::AddObserver(
    SessionManagerObserverInterface* observer) {
  CHECK(observer) << "Invalid observer object";
  observer_list_.AddObserver(observer);
}

void SessionManagerProxy::RemoveObserver(
    SessionManagerObserverInterface* observer) {
  CHECK(observer) << "Invalid observer object";
  observer_list_.RemoveObserver(observer);
}

void SessionManagerProxy::OnLoginPromptVisible(dbus::Signal*) {
  // Try to enable Chrome remote debugging again on Login prompt.
  // Theoretically it should already be enabled during debugd Init().  But
  // There might be a timing issue if debugd started too fast.  We try again
  // here if the first attempt in Init() failed.
  EnableChromeRemoteDebuggingInternal();
}

void SessionManagerProxy::OnSessionStateChanged(dbus::Signal* signal) {
  dbus::MessageReader reader(signal);
  std::string state;
  if (!reader.PopString(&state)) {
    LOG(ERROR) << "Unable to read " << login_manager::kSessionStateChangedSignal
               << " args";
    return;
  }

  if (state == kSessionStarted) {
    for (SessionManagerObserverInterface& o : observer_list_)
      o.OnSessionStarted();
  } else if (state == kSessionStopped) {
    for (SessionManagerObserverInterface& o : observer_list_)
      o.OnSessionStopped();
  }
}

void SessionManagerProxy::EnableChromeRemoteDebugging() {
  VLOG(1) << "Enable Chrome remote debugging: "
          << should_enable_chrome_remote_debugging_ << " "
          << is_chrome_remote_debugging_enabled_;
  should_enable_chrome_remote_debugging_ = true;
  EnableChromeRemoteDebuggingInternal();
}

void SessionManagerProxy::EnableChromeRemoteDebuggingInternal() {
  VLOG(1) << "Enable Chrome remote debugging internal: "
          << should_enable_chrome_remote_debugging_ << " "
          << is_chrome_remote_debugging_enabled_;
  if (!should_enable_chrome_remote_debugging_ ||
      is_chrome_remote_debugging_enabled_) {
    return;
  }

  dbus::MethodCall method_call(
      login_manager::kSessionManagerInterface,
      login_manager::kSessionManagerEnableChromeTesting);
  dbus::MessageWriter writer(&method_call);
  writer.AppendBool(true);  // force_restart
  writer.AppendArrayOfStrings({"--remote-debugging-port=9222"});
  writer.AppendArrayOfStrings({});  // extra_environment_variables
  if (proxy_->CallMethodAndBlock(&method_call,
                                 dbus::ObjectProxy::TIMEOUT_USE_DEFAULT)) {
    is_chrome_remote_debugging_enabled_ = true;
  } else {
    LOG(ERROR) << "Failed to enable Chrome remote debugging";
  }
}

}  // namespace debugd
