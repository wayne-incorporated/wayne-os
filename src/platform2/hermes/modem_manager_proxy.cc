// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <utility>

#include <base/containers/contains.h>
#include <ModemManager/ModemManager.h>

#include "hermes/modem_manager_proxy.h"

namespace {

constexpr auto kInhibitTimeout = base::Minutes(1);

}

namespace hermes {

ModemManagerProxy::ModemManagerProxy(const scoped_refptr<dbus::Bus>& bus)
    : bus_(bus),
      object_manager_proxy_(
          std::make_unique<org::freedesktop::DBus::ObjectManagerProxy>(
              bus,
              modemmanager::kModemManager1ServiceName,
              dbus::ObjectPath(modemmanager::kModemManager1ServicePath))),
      mm_proxy_(std::make_unique<org::freedesktop::ModemManager1Proxy>(
          bus, modemmanager::kModemManager1ServiceName)),
      modem_appeared_(false),
      weak_factory_(this) {
  auto on_interface_added = base::BindRepeating(
      &ModemManagerProxy::OnInterfaceAdded, weak_factory_.GetWeakPtr());
  auto on_interface_removed = base::BindRepeating(
      &ModemManagerProxy::OnInterfaceRemoved, weak_factory_.GetWeakPtr());
  auto on_dbus_signal_connected =
      base::BindRepeating([](const std::string& interface,
                             const std::string& signal, bool success) {
        if (!success)
          LOG(ERROR) << "Failed to connect to signal " << interface << "."
                     << signal;
      });
  object_manager_proxy_->RegisterInterfacesAddedSignalHandler(
      std::move(on_interface_added), on_dbus_signal_connected);
  object_manager_proxy_->RegisterInterfacesRemovedSignalHandler(
      std::move(on_interface_removed), on_dbus_signal_connected);
}

ModemManagerProxy::ModemManagerProxy() : weak_factory_(this) {}

void ModemManagerProxy::RegisterModemAppearedCallback(base::OnceClosure cb) {
  VLOG(2) << __func__;
  on_modem_appeared_cb_ = std::move(cb);
}

void ModemManagerProxy::WaitForModem(base::OnceClosure cb) {
  VLOG(2) << __func__;
  if (modem_proxy_) {
    std::move(cb).Run();
    return;
  }
  auto on_service_available =
      base::BindOnce(&ModemManagerProxy::WaitForModemStepGetObjects,
                     weak_factory_.GetWeakPtr(), std::move(cb));
  object_manager_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      std::move((on_service_available)));
}

void ModemManagerProxy::WaitForModemStepGetObjects(base::OnceClosure cb, bool) {
  VLOG(2) << __func__;
  auto error_cb = base::BindOnce([](brillo::Error* err) {
    LOG(ERROR) << "Could not get MM managed objects: " << err->GetDomain()
               << ": " << err->GetCode() << ": " << err->GetMessage();
  });
  object_manager_proxy_->GetManagedObjectsAsync(
      base::BindOnce(&ModemManagerProxy::WaitForModemStepLast,
                     weak_factory_.GetWeakPtr(), std::move(cb)),
      std::move(error_cb));
}

void ModemManagerProxy::WaitForModemStepLast(
    base::OnceClosure cb,
    const DBusObjectsWithProperties& dbus_objects_with_properties) {
  VLOG(2) << __func__;
  for (const auto& object_properties_pair : dbus_objects_with_properties) {
    VLOG(2) << __func__ << ": " << object_properties_pair.first.value();
    if (!base::Contains(object_properties_pair.second,
                        modemmanager::kModemManager1ModemInterface)) {
      continue;
    }
    LOG(INFO) << __func__ << ": Found " << object_properties_pair.first.value();
    RegisterModemAppearedCallback(std::move(cb));
    OnNewModemDetected(dbus::ObjectPath{object_properties_pair.first.value()});
    return;
  }
  LOG(INFO) << __func__ << ": Waiting for modem...";
  RegisterModemAppearedCallback(std::move(cb));
}

void ModemManagerProxy::OnInterfaceAdded(
    const dbus::ObjectPath& object_path,
    const DBusInterfaceToProperties& properties) {
  brillo::ErrorPtr error;
  VLOG(2) << __func__ << ": " << object_path.value();
  if (!base::Contains(properties, modemmanager::kModemManager1ModemInterface)) {
    VLOG(2) << __func__ << "Interfaces added, but not modem interface.";
    return;
  }
  OnNewModemDetected(object_path);
}

void ModemManagerProxy::OnInterfaceRemoved(
    const dbus::ObjectPath& object_path,
    const std::vector<std::string>& iface) {
  brillo::ErrorPtr error;
  VLOG(2) << __func__ << ": " << object_path.value();
  if (!base::Contains(iface, modemmanager::kModemManager1ModemInterface)) {
    VLOG(2) << __func__ << "Interfaces removed, but not modem interface.";
    return;
  }
  if (!modem_proxy_) {
    VLOG(2) << "Not tracking any modem. Ignoring removal of modem interface on "
            << object_path.value();
    return;
  }
  if (modem_proxy_->GetObjectPath() != object_path)
    return;
  LOG(INFO) << "Clearing modem proxy for "
            << modem_proxy_->GetObjectPath().value();
  modem_proxy_.reset();
  pending_inhibit_cb_.Reset();
}

void ModemManagerProxy::OnNewModemDetected(dbus::ObjectPath object_path) {
  LOG(INFO) << __func__ << ": New modem detected at " << object_path.value();
  // TODO(b/229183415): Listen for dbus name owner changes instead of
  // kFirstModemAfterRestart
  const char kFirstModemAfterMMRestart[] =
      "/org/freedesktop/ModemManager1/Modem/0";
  if (modem_proxy_ && object_path.value() != kFirstModemAfterMMRestart) {
    LOG(INFO) << "Already tracking " << modem_proxy_->GetObjectPath().value()
              << ". Ignoring " << object_path.value();
    return;
  }
  modem_appeared_ = true;
  modem_proxy_ = std::make_unique<org::freedesktop::ModemManager1::ModemProxy>(
      bus_, modemmanager::kModemManager1ServiceName, object_path);
  modem_proxy_->InitializeProperties(base::BindRepeating(
      &ModemManagerProxy::OnPropertiesChanged, weak_factory_.GetWeakPtr()));
}

void ModemManagerProxy::OnPropertiesChanged(
    org::freedesktop::ModemManager1::ModemProxyInterface* modem_proxy_interface,
    const std::string& prop) {
  VLOG(3) << __func__ << " : " << prop << " changed.";

  // wait for all properties that we will be read by ModemMbim.
  if (!modem_proxy_->GetProperties()->ports.is_valid() ||
      !modem_proxy_->GetProperties()->state.is_valid())
    return;

  if (prop == MM_MODEM_PROPERTY_STATE && pending_inhibit_cb_ &&
      IsModemSafeToInhibit()) {
    std::move(pending_inhibit_cb_).Run();
    return;
  }

  // Ignore on_modem_appeared_cb if a property update on an existing
  // modem_proxy_ triggered this call.
  if (!modem_appeared_)
    return;
  modem_appeared_ = false;
  std::string mbim_port;
  for (const auto& [port, port_type] : modem_proxy_->ports()) {
    if (port_type == MM_MODEM_PORT_TYPE_MBIM) {
      mbim_port = port;
      break;
    }
  }
  if (cached_mbim_port_.has_value() && cached_mbim_port_ != mbim_port) {
    LOG(ERROR) << "Unexpected modem appeared at " << mbim_port;
    return;
  }
  cached_mbim_port_ = mbim_port;
  if (!on_modem_appeared_cb_.is_null())
    std::move(on_modem_appeared_cb_).Run();
}

std::string ModemManagerProxy::GetMbimPort() const {
  if (!cached_mbim_port_.has_value()) {
    LOG(ERROR) << __func__ << ": Primary port has never been read.";
    return "";
  }
  return cached_mbim_port_.value();
}

void ModemManagerProxy::Uninhibit() {
  uninhibit_cb_.Cancel();
  if (inhibited_uid_.has_value()) {
    InhibitDevice(false, base::BindOnce([](int err) {
                    VLOG(2) << "Uninhibit completed with err: " << err;
                  }));
  }
}

void ModemManagerProxy::ScheduleUninhibit(base::TimeDelta timeout) {
  LOG(INFO) << "Uninhibiting in " << timeout.InSeconds() << " seconds.";
  uninhibit_cb_.Cancel();

  uninhibit_cb_.Reset(base::BindOnce(&ModemManagerProxy::Uninhibit,
                                     weak_factory_.GetWeakPtr()));
  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, uninhibit_cb_.callback(), timeout);
}

void ModemManagerProxy::WaitForModemAndInhibit(ResultCallback cb) {
  // wait for modem if another daemon has inhibited MM. If Hermes has inhibited
  // MM, then we needn't wait for the modem.
  if (inhibited_uid_.has_value()) {
    LOG(INFO) << inhibited_uid_.value() << " is already inhibited.";
    OnInhibitSuccess(/*inhibit*/ true, inhibited_uid_.value(), std::move(cb));
    return;
  }
  WaitForModem(base::BindOnce(&ModemManagerProxy::InhibitDevice,
                              weak_factory_.GetWeakPtr(), true, std::move(cb)));
}

void ModemManagerProxy::InhibitDevice(bool inhibit, ResultCallback cb) {
  LOG(INFO) << __func__ << ": inhibit = " << inhibit;
  if (!inhibit && !inhibited_uid_.has_value()) {
    LOG(ERROR) << "No inhibited device found.";
    std::move(cb).Run(kModemManagerError);
    return;
  }

  if (inhibit && (!modem_proxy_ || modem_proxy_->device().empty())) {
    LOG(ERROR) << __func__ << ": Device identifier unavailable.";
    std::move(cb).Run(kModemManagerError);
    return;
  }

  // convert cb into a repeating callback, so that it can be used by either
  // on_inhibit_success or on_inhibit_fail or FinalInhibitAttempt
  auto return_inhibit_result = base::BindRepeating(
      [](ResultCallback cb, int err) { std::move(cb).Run(err); },
      base::Passed(std::move(cb)));

  if (inhibit && !IsModemSafeToInhibit()) {
    LOG(INFO) << "Waiting for modem to become safe to inhibit";
    pending_inhibit_cb_ = base::BindOnce(&ModemManagerProxy::InhibitDevice,
                                         weak_factory_.GetWeakPtr(), inhibit,
                                         return_inhibit_result);
    base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&ModemManagerProxy::InhibitTimeout,
                       weak_factory_.GetWeakPtr(), return_inhibit_result),
        kInhibitTimeout);
    return;
  }

  auto uid = inhibit ? modem_proxy_->device() : inhibited_uid_.value();

  constexpr int kInhibitTimeoutMilliseconds = 15000;

  auto on_inhibit_success = base::BindOnce(&ModemManagerProxy::OnInhibitSuccess,
                                           weak_factory_.GetWeakPtr(), inhibit,
                                           uid, return_inhibit_result);
  auto on_inhibit_fail = base::BindOnce(
      [](ResultCallback cb, brillo::Error* error) {
        LOG(ERROR) << error->GetMessage();
        std::move(cb).Run(kModemManagerError);
      },
      return_inhibit_result);

  mm_proxy_->InhibitDeviceAsync(uid, inhibit, std::move(on_inhibit_success),
                                std::move(on_inhibit_fail),
                                kInhibitTimeoutMilliseconds);
}

void ModemManagerProxy::InhibitTimeout(ResultCallback cb) {
  if (pending_inhibit_cb_ && !IsModemSafeToInhibit()) {
    std::move(cb).Run(kModemManagerError);
    return;
  }
  if (pending_inhibit_cb_) {
    std::move(pending_inhibit_cb_).Run();
  }
}

void ModemManagerProxy::OnInhibitSuccess(bool inhibit,
                                         std::basic_string<char> uid,
                                         ResultCallback cb) {
  VLOG(2) << __func__;
  inhibited_uid_ =
      inhibit ? std::optional<std::basic_string<char>>{uid} : std::nullopt;

  // uninhibit automatically if we exceed the max duration allowed for a
  // Hermes operation.
  uninhibit_cb_.Cancel();
  if (inhibit) {
    ScheduleUninhibit(kHermesTimeout);
    std::move(cb).Run(kSuccess);
    return;
  }

  std::move(cb).Run(kSuccess);
}

bool ModemManagerProxy::IsModemSafeToInhibit() {
  if (!modem_proxy_)
    return false;

  // modem_proxy_ seems to miss property updates at times. If property updates
  // were working perfectly, one could check modem_proxy_->state() instead of
  // reading the state from MM.
  brillo::ErrorPtr error;
  auto resp = brillo::dbus_utils::CallMethodAndBlock(
      modem_proxy_->GetObjectProxy(), dbus::kDBusPropertiesInterface,
      dbus::kDBusPropertiesGet, &error,
      std::string(modemmanager::kModemManager1ModemInterface),
      std::string(MM_MODEM_PROPERTY_STATE));
  if (!resp)
    return false;
  std::int32_t state;
  if (!brillo::dbus_utils::ExtractMethodCallResults(resp.get(), &error,
                                                    &state)) {
    return false;
  }

  if (state == MM_MODEM_STATE_ENABLING || state == MM_MODEM_STATE_DISABLING ||
      state == MM_MODEM_STATE_INITIALIZING ||
      state == MM_MODEM_STATE_CONNECTING ||
      state == MM_MODEM_STATE_DISCONNECTING) {
    LOG(INFO) << "Modem in a transitional state, state = " << state;
    return false;
  }
  return true;
}

}  // namespace hermes
