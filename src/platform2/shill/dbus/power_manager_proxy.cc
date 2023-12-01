// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/power_manager_proxy.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <google/protobuf/message_lite.h>

#include "power_manager/proto_bindings/suspend.pb.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"

namespace shill {

namespace {

// Serializes |protobuf| to |out| and returns true on success.
bool SerializeProtocolBuffer(const google::protobuf::MessageLite& protobuf,
                             std::vector<uint8_t>* out) {
  CHECK(out);
  out->clear();
  std::string serialized_protobuf;
  if (!protobuf.SerializeToString(&serialized_protobuf))
    return false;
  out->assign(serialized_protobuf.begin(), serialized_protobuf.end());
  return true;
}

// Deserializes |serialized_protobuf| to |protobuf_out| and returns true on
// success.
bool DeserializeProtocolBuffer(const std::vector<uint8_t>& serialized_protobuf,
                               google::protobuf::MessageLite* protobuf_out) {
  CHECK(protobuf_out);
  if (serialized_protobuf.empty())
    return false;
  return protobuf_out->ParseFromArray(&serialized_protobuf.front(),
                                      serialized_protobuf.size());
}

}  // namespace

PowerManagerProxy::PowerManagerProxy(
    EventDispatcher* dispatcher,
    const scoped_refptr<dbus::Bus>& bus,
    PowerManagerProxyDelegate* delegate,
    const base::RepeatingClosure& service_appeared_callback,
    const base::RepeatingClosure& service_vanished_callback)
    : proxy_(new org::chromium::PowerManagerProxy(bus)),
      dispatcher_(dispatcher),
      delegate_(delegate),
      service_appeared_callback_(service_appeared_callback),
      service_vanished_callback_(service_vanished_callback),
      service_available_(false) {
  // Register signal handlers.
  proxy_->RegisterSuspendImminentSignalHandler(
      base::BindRepeating(&PowerManagerProxy::SuspendImminent,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
  proxy_->RegisterSuspendDoneSignalHandler(
      base::BindRepeating(&PowerManagerProxy::SuspendDone,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
  proxy_->RegisterDarkSuspendImminentSignalHandler(
      base::BindRepeating(&PowerManagerProxy::DarkSuspendImminent,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerProxy::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));

  // One time callback when service becomes available.
  proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(base::BindOnce(
      &PowerManagerProxy::OnServiceAvailable, weak_factory_.GetWeakPtr()));
}

PowerManagerProxy::~PowerManagerProxy() = default;

bool PowerManagerProxy::RegisterSuspendDelay(base::TimeDelta timeout,
                                             const std::string& description,
                                             int* delay_id_out) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return RegisterSuspendDelayInternal(false, timeout, description,
                                      delay_id_out);
}

bool PowerManagerProxy::UnregisterSuspendDelay(int delay_id) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return UnregisterSuspendDelayInternal(false, delay_id);
}

bool PowerManagerProxy::ReportSuspendReadiness(int delay_id, int suspend_id) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return ReportSuspendReadinessInternal(false, delay_id, suspend_id);
}

bool PowerManagerProxy::RegisterDarkSuspendDelay(base::TimeDelta timeout,
                                                 const std::string& description,
                                                 int* delay_id_out) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return RegisterSuspendDelayInternal(true, timeout, description, delay_id_out);
}

bool PowerManagerProxy::UnregisterDarkSuspendDelay(int delay_id) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return UnregisterSuspendDelayInternal(true, delay_id);
}

bool PowerManagerProxy::ReportDarkSuspendReadiness(int delay_id,
                                                   int suspend_id) {
  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }
  return ReportSuspendReadinessInternal(true, delay_id, suspend_id);
}

bool PowerManagerProxy::RecordDarkResumeWakeReason(
    const std::string& wake_reason) {
  LOG(INFO) << __func__;

  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return false;
  }

  power_manager::DarkResumeWakeReason proto;
  proto.set_wake_reason(wake_reason);
  std::vector<uint8_t> serialized_proto;
  CHECK(SerializeProtocolBuffer(proto, &serialized_proto));

  brillo::ErrorPtr error;
  if (!proxy_->RecordDarkResumeWakeReason(serialized_proto, &error)) {
    LOG(ERROR) << "Failed tp record dark resume wake reason: "
               << error->GetCode() << " " << error->GetMessage();
    return false;
  }
  return true;
}

void PowerManagerProxy::ChangeRegDomain(
    power_manager::WifiRegDomainDbus domain) {
  LOG(INFO) << __func__;

  if (!service_available_) {
    LOG(ERROR) << "PowerManager service not available";
    return;
  }

  proxy_->ChangeWifiRegDomainAsync(
      domain, base::DoNothing(),
      base::BindOnce(
          [](power_manager::WifiRegDomainDbus domain, brillo::Error* error) {
            LOG(ERROR) << "Failed to change reg domain to " << domain
                       << ", reason : " << error->GetCode() << " "
                       << error->GetMessage();
          },
          domain));
}

bool PowerManagerProxy::RegisterSuspendDelayInternal(
    bool is_dark,
    base::TimeDelta timeout,
    const std::string& description,
    int* delay_id_out) {
  const std::string is_dark_arg = (is_dark ? "dark=true" : "dark=false");
  LOG(INFO) << __func__ << "(" << timeout.InMilliseconds() << ", "
            << is_dark_arg << ")";

  power_manager::RegisterSuspendDelayRequest request_proto;
  request_proto.set_timeout(timeout.ToInternalValue());
  request_proto.set_description(description);
  std::vector<uint8_t> serialized_request;
  CHECK(SerializeProtocolBuffer(request_proto, &serialized_request));

  std::vector<uint8_t> serialized_reply;
  brillo::ErrorPtr error;
  if (is_dark) {
    proxy_->RegisterDarkSuspendDelay(serialized_request, &serialized_reply,
                                     &error);
  } else {
    proxy_->RegisterSuspendDelay(serialized_request, &serialized_reply, &error);
  }
  if (error) {
    LOG(ERROR) << "Failed to register suspend delay: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }

  power_manager::RegisterSuspendDelayReply reply_proto;
  if (!DeserializeProtocolBuffer(serialized_reply, &reply_proto)) {
    LOG(ERROR) << "Failed to register " << (is_dark ? "dark " : "")
               << "suspend delay.  Couldn't parse response.";
    return false;
  }
  *delay_id_out = reply_proto.delay_id();
  return true;
}

bool PowerManagerProxy::UnregisterSuspendDelayInternal(bool is_dark,
                                                       int delay_id) {
  const std::string is_dark_arg = (is_dark ? "dark=true" : "dark=false");
  LOG(INFO) << __func__ << "(" << delay_id << ", " << is_dark_arg << ")";

  power_manager::UnregisterSuspendDelayRequest request_proto;
  request_proto.set_delay_id(delay_id);
  std::vector<uint8_t> serialized_request;
  CHECK(SerializeProtocolBuffer(request_proto, &serialized_request));

  brillo::ErrorPtr error;
  if (is_dark) {
    proxy_->UnregisterDarkSuspendDelay(serialized_request, &error);
  } else {
    proxy_->UnregisterSuspendDelay(serialized_request, &error);
  }
  if (error) {
    LOG(ERROR) << "Failed to unregister suspend delay: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }
  return true;
}

bool PowerManagerProxy::ReportSuspendReadinessInternal(bool is_dark,
                                                       int delay_id,
                                                       int suspend_id) {
  const std::string is_dark_arg = (is_dark ? "dark=true" : "dark=false");
  LOG(INFO) << __func__ << "(" << delay_id << ", " << suspend_id << ", "
            << is_dark_arg << ")";

  power_manager::SuspendReadinessInfo proto;
  proto.set_delay_id(delay_id);
  proto.set_suspend_id(suspend_id);
  std::vector<uint8_t> serialized_proto;
  CHECK(SerializeProtocolBuffer(proto, &serialized_proto));

  brillo::ErrorPtr error;
  if (is_dark) {
    proxy_->HandleDarkSuspendReadiness(serialized_proto, &error);
  } else {
    proxy_->HandleSuspendReadiness(serialized_proto, &error);
  }
  if (error) {
    LOG(ERROR) << "Failed to report suspend readiness: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }
  return true;
}

void PowerManagerProxy::SuspendImminent(
    const std::vector<uint8_t>& serialized_proto) {
  LOG(INFO) << __func__;
  power_manager::SuspendImminent proto;
  if (!DeserializeProtocolBuffer(serialized_proto, &proto)) {
    LOG(ERROR) << "Failed to parse SuspendImminent signal.";
    return;
  }
  delegate_->OnSuspendImminent(proto.suspend_id());
}

void PowerManagerProxy::SuspendDone(
    const std::vector<uint8_t>& serialized_proto) {
  LOG(INFO) << __func__;
  power_manager::SuspendDone proto;
  if (!DeserializeProtocolBuffer(serialized_proto, &proto)) {
    LOG(ERROR) << "Failed to parse SuspendDone signal.";
    return;
  }
  CHECK_GE(proto.suspend_duration(), 0);
  LOG(INFO) << "Suspend: ID " << proto.suspend_id() << " duration "
            << proto.suspend_duration();
  delegate_->OnSuspendDone(proto.suspend_id(), proto.suspend_duration());
}

void PowerManagerProxy::DarkSuspendImminent(
    const std::vector<uint8_t>& serialized_proto) {
  LOG(INFO) << __func__;
  power_manager::SuspendImminent proto;
  if (!DeserializeProtocolBuffer(serialized_proto, &proto)) {
    LOG(ERROR) << "Failed to parse DarkSuspendImminent signal.";
    return;
  }
  delegate_->OnDarkSuspendImminent(proto.suspend_id());
}

void PowerManagerProxy::OnServiceAppeared() {
  if (!service_appeared_callback_.is_null()) {
    service_appeared_callback_.Run();
  }
}

void PowerManagerProxy::OnServiceVanished() {
  if (!service_vanished_callback_.is_null()) {
    service_vanished_callback_.Run();
  }
}

void PowerManagerProxy::OnServiceAvailable(bool available) {
  // The only time this function will ever be invoked with |available| set to
  // false is when we failed to connect the signals, either bus is not setup
  // yet or we failed to add match rules, and both of these errors are
  // considered fatal.
  CHECK(available);

  // Service is available now, continuously monitor the service owner changes.
  proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(base::BindRepeating(
      &PowerManagerProxy::OnServiceOwnerChanged, weak_factory_.GetWeakPtr()));

  // The callback might invoke calls to the ObjectProxy, so defer the callback
  // to event loop.
  dispatcher_->PostTask(FROM_HERE,
                        base::BindOnce(&PowerManagerProxy::OnServiceAppeared,
                                       weak_factory_.GetWeakPtr()));

  service_available_ = true;
}

void PowerManagerProxy::OnServiceOwnerChanged(const std::string& old_owner,
                                              const std::string& new_owner) {
  LOG(INFO) << __func__ << " old: " << old_owner << " new: " << new_owner;

  if (new_owner.empty()) {
    // The callback might invoke calls to the ObjectProxy, so defer the
    // callback to event loop.
    dispatcher_->PostTask(FROM_HERE,
                          base::BindOnce(&PowerManagerProxy::OnServiceVanished,
                                         weak_factory_.GetWeakPtr()));
    service_available_ = false;
  } else {
    // The callback might invoke calls to the ObjectProxy, so defer the
    // callback to event loop.
    dispatcher_->PostTask(FROM_HERE,
                          base::BindOnce(&PowerManagerProxy::OnServiceAppeared,
                                         weak_factory_.GetWeakPtr()));
    service_available_ = true;
  }
}

void PowerManagerProxy::OnSignalConnected(const std::string& interface_name,
                                          const std::string& signal_name,
                                          bool success) {
  LOG(INFO) << __func__ << " interface: " << interface_name
            << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace shill
