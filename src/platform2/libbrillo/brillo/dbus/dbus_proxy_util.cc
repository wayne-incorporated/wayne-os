// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/dbus/dbus_proxy_util.h>

#include <string>
#include <utility>

namespace brillo {
namespace dbus_utils {

namespace {

std::unique_ptr<dbus::Response> CallDBusMethodInDbusThread(
    scoped_refptr<base::TaskRunner> task_runner,
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    int timeout_ms) {
  std::unique_ptr<dbus::Response> response;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](dbus::ObjectProxy* proxy, dbus::MethodCall* method_call,
             int timeout_ms, std::unique_ptr<dbus::Response>* response,
             base::WaitableEvent* event) {
            *response = proxy->CallMethodAndBlock(method_call, timeout_ms);
            event->Signal();
          },
          base::Unretained(proxy), base::Unretained(method_call), timeout_ms,
          base::Unretained(&response), base::Unretained(&event)));
  event.Wait();
  return response;
}

std::unique_ptr<dbus::Response> CallDBusMethodWithErrorResponseInDbusThread(
    scoped_refptr<base::TaskRunner> task_runner,
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    int timeout_ms,
    dbus::ScopedDBusError* error) {
  std::unique_ptr<dbus::Response> response;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](dbus::ObjectProxy* proxy, dbus::MethodCall* method_call,
             int timeout_ms, std::unique_ptr<dbus::Response>* response,
             dbus::ScopedDBusError* error, base::WaitableEvent* event) {
            *response = proxy->CallMethodAndBlockWithErrorDetails(
                method_call, timeout_ms, error);
            event->Signal();
          },
          base::Unretained(proxy), base::Unretained(method_call), timeout_ms,
          base::Unretained(&response), base::Unretained(error),
          base::Unretained(&event)));
  event.Wait();
  return response;
}

}  // namespace

std::unique_ptr<dbus::Response> CallDBusMethod(scoped_refptr<dbus::Bus> bus,
                                               dbus::ObjectProxy* proxy,
                                               dbus::MethodCall* method_call,
                                               int timeout_ms) {
  if (bus->HasDBusThread() &&
      !bus->GetDBusTaskRunner()->RunsTasksInCurrentSequence()) {
    return CallDBusMethodInDbusThread(bus->GetDBusTaskRunner(), proxy,
                                      method_call, timeout_ms);
  }
  return proxy->CallMethodAndBlock(method_call, timeout_ms);
}

std::unique_ptr<dbus::Response> CallDBusMethodWithErrorResponse(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    int timeout_ms,
    dbus::ScopedDBusError* error) {
  if (bus->HasDBusThread() &&
      !bus->GetDBusTaskRunner()->RunsTasksInCurrentSequence()) {
    return CallDBusMethodWithErrorResponseInDbusThread(
        bus->GetDBusTaskRunner(), proxy, method_call, timeout_ms, error);
  }
  return proxy->CallMethodAndBlockWithErrorDetails(method_call, timeout_ms,
                                                   error);
}

}  // namespace dbus_utils
}  // namespace brillo
