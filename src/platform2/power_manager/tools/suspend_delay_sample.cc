// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "power_manager/proto_bindings/suspend.pb.h"

namespace {

// Passes |request| to powerd's |method_name| D-Bus method.
// Copies the returned protocol buffer to |reply_out|, which may be NULL if no
// reply is expected.
bool CallMethod(dbus::ObjectProxy* powerd_proxy,
                const std::string& method_name,
                const google::protobuf::MessageLite& request,
                google::protobuf::MessageLite* reply_out) {
  LOG(INFO) << "Calling " << method_name << " method";
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               method_name);
  dbus::MessageWriter writer(&method_call);
  writer.AppendProtoAsArrayOfBytes(request);

  std::unique_ptr<dbus::Response> response(powerd_proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  if (!response)
    return false;
  if (!reply_out)
    return true;

  dbus::MessageReader reader(response.get());
  CHECK(reader.PopArrayOfBytesAsProto(reply_out))
      << "Unable to parse response from call to " << method_name;
  return true;
}

// Human-readable description of the delay's purpose.
const char kSuspendDelayDescription[] = "suspend_delay_sample";

}  // namespace

class SuspendDelayRegisterer {
 public:
  SuspendDelayRegisterer(int delay_ms, int timeout_ms, bool dark_suspend_delay)
      : delay_ms_(delay_ms),
        timeout_ms_(timeout_ms),
        dark_suspend_delay_(dark_suspend_delay),
        weak_ptr_factory_(this) {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    bus_ = new dbus::Bus(options);
    CHECK(bus_->Connect());
    powerd_proxy_ = bus_->GetObjectProxy(
        power_manager::kPowerManagerServiceName,
        dbus::ObjectPath(power_manager::kPowerManagerServicePath));
    RegisterSuspendDelay();
    powerd_proxy_->SetNameOwnerChangedCallback(
        base::BindRepeating(&SuspendDelayRegisterer::NameOwnerChangedReceived,
                            weak_ptr_factory_.GetWeakPtr()));
  }
  SuspendDelayRegisterer(const SuspendDelayRegisterer&) = delete;
  SuspendDelayRegisterer& operator=(const SuspendDelayRegisterer&) = delete;

 private:
  // Announces that the process is ready for suspend attempt |suspend_id|.
  void SendSuspendReady(int suspend_id) {
    CHECK(delay_id_) << "Invalid suspend delay Id";
    LOG(INFO) << "Announcing readiness of delay " << delay_id_.value()
              << " for suspend attempt " << suspend_id;
    power_manager::SuspendReadinessInfo request;
    request.set_delay_id(delay_id_.value());
    request.set_suspend_id(suspend_id);
    CallMethod(powerd_proxy_, power_manager::kHandleSuspendReadinessMethod,
               request, nullptr);
  }

  // Handles the start of a suspend attempt. Posts a task to run
  // SendSuspendReady() after a delay.
  void HandleSuspendImminent(dbus::Signal* signal) {
    power_manager::SuspendImminent info;
    dbus::MessageReader reader(signal);
    CHECK(reader.PopArrayOfBytesAsProto(&info));
    int suspend_id = info.suspend_id();

    LOG(INFO) << "Got notification about suspend attempt " << suspend_id;
    LOG(INFO) << "Sleeping " << delay_ms_ << " ms before responding";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&SuspendDelayRegisterer::SendSuspendReady,
                       weak_ptr_factory_.GetWeakPtr(), suspend_id),
        base::Milliseconds(delay_ms_));
  }

  // Handles the completion of a suspend attempt.
  void HandleSuspendDone(dbus::Signal* signal) {
    power_manager::SuspendDone info;
    dbus::MessageReader reader(signal);
    CHECK(reader.PopArrayOfBytesAsProto(&info));
    const base::TimeDelta duration =
        base::Microseconds(info.suspend_duration());
    LOG(INFO) << "Suspend attempt " << info.suspend_id() << " is complete; "
              << "system was suspended for " << duration.InMilliseconds()
              << " ms";
  }

  // Handles the result of an attempt to connect to a D-Bus signal.
  void DBusSignalConnected(const std::string& interface,
                           const std::string& signal,
                           bool success) {
    CHECK(success) << "Unable to connect to " << interface << "." << signal;
  }

  // Registers a suspend delay and returns the corresponding ID.
  void RegisterSuspendDelay() {
    power_manager::RegisterSuspendDelayRequest request;
    request.set_timeout(base::Milliseconds(timeout_ms_).InMicroseconds());
    request.set_description(kSuspendDelayDescription);
    std::string method_name =
        dark_suspend_delay_ ? power_manager::kRegisterDarkSuspendDelayMethod
                            : power_manager::kRegisterSuspendDelayMethod;
    power_manager::RegisterSuspendDelayReply reply;
    CHECK(CallMethod(powerd_proxy_, method_name, request, &reply));
    LOG(INFO) << "Registered " << (dark_suspend_delay_ ? "dark " : "")
              << "suspend delay " << reply.delay_id();
    delay_id_ = reply.delay_id();

    powerd_proxy_->ConnectToSignal(
        power_manager::kPowerManagerInterface,
        power_manager::kSuspendImminentSignal,
        base::BindRepeating(&SuspendDelayRegisterer::HandleSuspendImminent,
                            weak_ptr_factory_.GetWeakPtr()),
        base::BindOnce(&SuspendDelayRegisterer::DBusSignalConnected,
                       weak_ptr_factory_.GetWeakPtr()));
    powerd_proxy_->ConnectToSignal(
        power_manager::kPowerManagerInterface,
        power_manager::kSuspendDoneSignal,
        base::BindRepeating(&SuspendDelayRegisterer::HandleSuspendDone,
                            weak_ptr_factory_.GetWeakPtr()),
        base::BindOnce(&SuspendDelayRegisterer::DBusSignalConnected,
                       weak_ptr_factory_.GetWeakPtr()));
  }

  void NameOwnerChangedReceived(const std::string& old_owner,
                                const std::string& new_owner) {
    //  Try to register suspend delay only if available.
    if (!new_owner.empty()) {
      LOG(INFO) << "Received NameOwnerChanged d-bus signal.";
      RegisterSuspendDelay();
    }
  }

  int delay_ms_;
  int timeout_ms_;
  // Id assigned by powerd to a suspend delay client.
  std::optional<int> delay_id_;
  // Whether to register dark/full suspend delay.
  bool dark_suspend_delay_ = false;
  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* powerd_proxy_ = nullptr;

  base::WeakPtrFactory<SuspendDelayRegisterer> weak_ptr_factory_;
};

int main(int argc, char* argv[]) {
  DEFINE_int32(delay_ms, 5000,
               "Milliseconds to wait before reporting suspend readiness");
  DEFINE_int32(timeout_ms, 7000, "Suspend timeout in milliseconds");
  DEFINE_bool(dark_suspend, false, "Register delay as a dark suspend");

  brillo::FlagHelper::Init(
      argc, argv,
      "Exercise powerd's functionality that permits other processes to\n"
      "perform last-minute work before the system suspends.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  SuspendDelayRegisterer suspend_delay_registerer(
      FLAGS_delay_ms, FLAGS_timeout_ms, FLAGS_dark_suspend);
  base::RunLoop().Run();

  // powerd will automatically unregister this process's suspend delay when the
  // process disconnects from D-Bus.
  return 0;
}
