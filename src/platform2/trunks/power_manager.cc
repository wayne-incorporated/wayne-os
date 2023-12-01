// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <google/protobuf/message_lite.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "trunks/power_manager.h"

namespace {

// Max amount of time powerd will wait for our suspend (in seconds).
const int64_t kSuspendDelayTimeoutSec = 3;
// Desciption for SuspendDelay.
const char kSuspendDelayDescription[] = "trunksd";

// Serializes |proto| to |raw_buf| that can be passed to D-Bus routines.
// Returns true, if successful.
void SerializeProto(const google::protobuf::MessageLite& proto,
                    std::vector<uint8_t>* raw_buf) {
  std::string serialized_proto;
  CHECK(proto.SerializeToString(&serialized_proto));
  raw_buf->assign(serialized_proto.begin(), serialized_proto.end());
}

// Deserializes |raw_buf| received from D-Bus to |proto|.
// Returns true, if successful.
bool DeserializeProto(const std::vector<uint8_t>& raw_buf,
                      google::protobuf::MessageLite* proto) {
  return proto->ParseFromArray(&raw_buf.front(), raw_buf.size());
}

}  // namespace

namespace trunks {

void PowerManager::Init(const scoped_refptr<dbus::Bus>& bus) {
  VLOG(1) << "Initializing PowerManager.";
  if (!proxy_) {
    dbus_proxy_.reset(new org::chromium::PowerManagerProxy(bus));
    proxy_ = dbus_proxy_.get();
  }

  RegisterSignalHandlers();

  proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      base::BindRepeating(&PowerManager::OnServiceAvailable, ThisForBind()));
}

void PowerManager::TearDown() {
  if (suspend_delay_registered_) {
    // Unregister SuspendDelay.
    power_manager::UnregisterSuspendDelayRequest request;
    request.set_delay_id(delay_id_);
    std::vector<uint8_t> serialized_request;
    SerializeProto(request, &serialized_request);
    brillo::ErrorPtr error;
    if (proxy_->UnregisterSuspendDelay(serialized_request, &error)) {
      suspend_delay_registered_ = false;
      VLOG(1) << "Successfully unregistered SuspendDelay.";
    } else {
      OnRequestError("UnregisterSuspendDelayRequest", error.get());
    }
  }
}

void PowerManager::RegisterSignalHandlers() {
  if (!proxy_) {
    return;
  }
  VLOG(1) << "Registering PowerManager signal handlers.";
  auto resume_signal_handler =
      base::BindRepeating(&PowerManager::OnResume, ThisForBind());
  auto resume_signal_connect =
      base::BindRepeating(&PowerManager::OnResumeConnect, ThisForBind());
  proxy_->RegisterSuspendDoneSignalHandler(resume_signal_handler,
                                           resume_signal_connect);

  auto suspend_signal_handler =
      base::BindRepeating(&PowerManager::OnSuspend, ThisForBind());
  auto suspend_signal_connect =
      base::BindRepeating(&PowerManager::OnSignalConnect, ThisForBind());
  proxy_->RegisterSuspendImminentSignalHandler(suspend_signal_handler,
                                               suspend_signal_connect);
  proxy_->RegisterDarkSuspendImminentSignalHandler(suspend_signal_handler,
                                                   suspend_signal_connect);
}

void PowerManager::OnServiceAvailable(bool available) {
  if (available) {
    VLOG(1) << "PowerManager service available.";
    proxy_->GetObjectProxy()->SetNameOwnerChangedCallback(
        base::BindRepeating(&PowerManager::OnOwnerChanged, ThisForBind()));
    Start();
  } else {
    LOG(ERROR) << "PowerManager service unavailable.";
  }
}

void PowerManager::OnOwnerChanged(const std::string& old_owner,
                                  const std::string& new_owner) {
  VLOG(2) << "PowerManager detected owner change: \"" << old_owner << "\" -> \""
          << new_owner << "\".";
  if (new_owner.empty()) {
    LOG(WARNING) << "PowerManager service lost.";
    Stop();
  } else {
    LOG(INFO) << "PowerManager service restored.";
    Start();
  }
}

void PowerManager::Start() {
  // Make sure we clean up in case we missed that the previous service
  // disappeared.
  Stop();
  // Register SuspendDelay.
  power_manager::RegisterSuspendDelayRequest request;
  request.set_timeout(base::Seconds(kSuspendDelayTimeoutSec).ToInternalValue());
  request.set_description(kSuspendDelayDescription);
  std::vector<uint8_t> serialized_request;
  SerializeProto(request, &serialized_request);
  auto success_callback = base::BindRepeating(
      &PowerManager::OnRegisterSuspendDelaySuccess, ThisForBind());
  auto error_callback =
      base::BindRepeating(&PowerManager::OnRequestError, ThisForBind(),
                          std::string("RegisterSuspendDelayRequest"));
  proxy_->RegisterSuspendDelayAsync(serialized_request, success_callback,
                                    error_callback);
}

void PowerManager::Stop() {
  if (suspend_delay_registered_) {
    suspend_delay_registered_ = false;
    VLOG(1) << "SuspendDelay abandoned.";
    // Make sure we don't block resource manager.
    if (resource_manager_) {
      base::WaitableEvent event(
          base::WaitableEvent::ResetPolicy::MANUAL,
          base::WaitableEvent::InitialState::NOT_SIGNALED);
      task_runner_->PostNonNestableTask(
          FROM_HERE, base::BindOnce(
                         [](ResourceManager* resource_manager,
                            base::WaitableEvent* event) {
                           resource_manager->Resume();
                           event->Signal();
                         },
                         base::Unretained(resource_manager_), &event));
      event.Wait();
    }
  }
}

void PowerManager::OnResume(const std::vector<uint8_t>& serialized_proto) {
  power_manager::SuspendDone signal;
  if (!DeserializeProto(serialized_proto, &signal)) {
    LOG(WARNING) << "Failed to parse SuspendDone signal.";
    return;
  }
  VLOG(1) << "SuspendDone(" << signal.suspend_id() << ")";
  if (resource_manager_) {
    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostNonNestableTask(
        FROM_HERE,
        base::BindOnce(
            [](ResourceManager* resource_manager, base::WaitableEvent* event) {
              resource_manager->Resume();
              event->Signal();
            },
            base::Unretained(resource_manager_), &event));
    event.Wait();
  }
}

void PowerManager::OnSuspend(const std::vector<uint8_t>& serialized_proto) {
  power_manager::SuspendImminent signal;
  if (!DeserializeProto(serialized_proto, &signal)) {
    LOG(WARNING) << "Failed to parse SuspendImminent signal.";
    return;
  }
  VLOG(1) << "SuspendImminent(" << signal.suspend_id() << ")";
  if (!suspend_allowed_) {
    LOG(WARNING) << "Suspend handling is not allowed.";
  } else if (resource_manager_) {
    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    task_runner_->PostNonNestableTask(
        FROM_HERE,
        base::BindOnce(
            [](ResourceManager* resource_manager, base::WaitableEvent* event) {
              resource_manager->Suspend();
              event->Signal();
            },
            base::Unretained(resource_manager_), &event));
    event.Wait();
  }
  if (!suspend_delay_registered_) {
    LOG(WARNING) << "SuspendDelay is not registered.";
    return;
  }
  // Send SuspendReadinessInfo once done suspending.
  power_manager::SuspendReadinessInfo request;
  request.set_delay_id(delay_id_);
  request.set_suspend_id(signal.suspend_id());
  std::vector<uint8_t> serialized_request;
  SerializeProto(request, &serialized_request);
  auto success_callback =
      base::BindRepeating(&PowerManager::OnRequestSuccess, ThisForBind(),
                          std::string("SuspendReadinessInfo"));
  auto error_callback =
      base::BindRepeating(&PowerManager::OnRequestError, ThisForBind(),
                          std::string("SuspendReadinessInfo"));
  proxy_->HandleSuspendReadinessAsync(serialized_request, success_callback,
                                      error_callback);
}

void PowerManager::OnResumeConnect(const std::string& interface_name,
                                   const std::string& signal_name,
                                   bool success) {
  OnSignalConnect(interface_name, signal_name, success);
  if (success) {
    VLOG(1) << "Allowing suspend.";
    suspend_allowed_ = true;
  }
}

void PowerManager::OnSignalConnect(const std::string& /* interface_name */,
                                   const std::string& signal_name,
                                   bool success) {
  if (success) {
    VLOG(1) << "Connected to signal " << signal_name;
  } else {
    LOG(ERROR) << "Failed to connect to signal " << signal_name;
  }
}

void PowerManager::OnRegisterSuspendDelaySuccess(
    const std::vector<uint8_t>& serialized_proto) {
  power_manager::RegisterSuspendDelayReply reply;
  if (!DeserializeProto(serialized_proto, &reply)) {
    LOG(ERROR) << "Failed to parse RegisterSuspendDelayReply.";
    return;
  }
  VLOG(2) << "RegisterSuspendDelayReply(" << reply.delay_id() << ").";
  delay_id_ = reply.delay_id();
  suspend_delay_registered_ = true;
  VLOG(1) << "Successfully registered SuspendDelay.";
}

void PowerManager::OnRequestSuccess(const std::string& message_name) {
  VLOG(2) << "Successfully sent " << message_name;
}

void PowerManager::OnRequestError(const std::string& message_name,
                                  brillo::Error* error) {
  LOG(WARNING) << "Sending " << message_name << " failed(" << error->GetCode()
               << "): " << error->GetMessage();
}

}  // namespace trunks
