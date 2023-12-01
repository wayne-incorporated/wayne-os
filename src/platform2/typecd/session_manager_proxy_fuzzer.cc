// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/session_manager_proxy.h"

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <gmock/gmock.h>

#include "chromeos/dbus/service_constants.h"

using testing::_;
using testing::Invoke;

namespace {

// Matcher for D-Bus method names to be used in CallMethod*().
MATCHER_P(IsMethod, method_name, "") {
  return arg->GetMember() == method_name;
}

}  // namespace

namespace typecd {

// A small wrapper for the SessionManagerProxy object that allows us to call the
// private interfaces of SessionManagerProxy (we make this class a friend of
// SessionManagerProxy)
class SessionManagerProxyFuzzer {
 public:
  explicit SessionManagerProxyFuzzer(scoped_refptr<dbus::Bus> bus) {
    proxy_ = std::make_unique<SessionManagerProxy>(bus);
  }

  void CallOnSessionStateChanged(const std::string& state) {
    proxy_->OnSessionStateChanged(state);
  }

 private:
  std::unique_ptr<SessionManagerProxy> proxy_;
};

}  // namespace typecd

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  // Set up a fake debugd D-Bus proxy.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(options);
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy =
      new dbus::MockObjectProxy(
          bus.get(), login_manager::kSessionManagerServiceName,
          dbus::ObjectPath(login_manager::kSessionManagerServicePath));

  // Mock the GetObjectProxy for the |bus|.
  EXPECT_CALL(*bus,
              GetObjectProxy(
                  login_manager::kSessionManagerServiceName,
                  dbus::ObjectPath(login_manager::kSessionManagerServicePath)))
      .WillOnce(testing::Return(mock_object_proxy.get()));

  // Mock the method calls from the object proxy.
  EXPECT_CALL(*mock_object_proxy, CallMethodAndBlockWithErrorDetails(
                                      IsMethod("IsGuestSessionActive"), _, _))
      .WillOnce(Invoke([&](dbus::MethodCall* method_call, int timeout,
                           dbus::ScopedDBusError* error) {
        // We can set an arbitrary serial number.
        method_call->SetSerial(123);
        std::unique_ptr<dbus::Response> response =
            dbus::Response::FromMethodCall(method_call);
        dbus::MessageWriter writer(response.get());
        writer.AppendBool(data_provider.ConsumeBool());
        return response;
      }));

  auto fuzzer = typecd::SessionManagerProxyFuzzer(bus);
  fuzzer.CallOnSessionStateChanged(data_provider.ConsumeRandomLengthString(50));

  return 0;
}
