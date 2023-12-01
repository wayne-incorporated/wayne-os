// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cros_ec_util.h"

#include <base/logging.h>
#include <base/strings/string_util.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <gmock/gmock.h>

using testing::_;
using testing::Invoke;

namespace {

constexpr char kDebugdServiceName[] = "org.chromium.debugd";
constexpr char kDebugdServicePath[] = "/org/chromium/debugd";

// The following helper functions have been borrowed from:
// src/platform2/authpolicy/authpolicy_test.cc
//
// Creates a D-Bus response with the given |response_str| as message.
std::unique_ptr<dbus::Response> RespondWithString(
    dbus::MethodCall* method_call, const std::string& response_str) {
  // Set an arbitrary serial number.
  method_call->SetSerial(123);
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendString(response_str);
  return response;
}

// Matcher for D-Bus method names to be used in CallMethod*().
MATCHER_P(IsMethod, method_name, "") {
  return arg->GetMember() == method_name;
}

}  // namespace

class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_ERROR); }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  FuzzedDataProvider data_provider(data, size);

  // D-Bus Spec needs UTF-8 strings. Let's ensure that since we are not
  // testing D-Bus functionality here.
  auto resp_str = data_provider.ConsumeRemainingBytesAsString();
  if (!base::IsStringUTF8(resp_str))
    return 0;

  // Set up a fake debugd D-Bus proxy.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::MockBus> bus = new dbus::MockBus(options);
  scoped_refptr<dbus::MockObjectProxy> mock_object_proxy =
      new dbus::MockObjectProxy(bus.get(), kDebugdServiceName,
                                dbus::ObjectPath(kDebugdServicePath));

  // Mock the GetObjectProxy for the |bus|.
  EXPECT_CALL(*bus, GetObjectProxy(kDebugdServiceName,
                                   dbus::ObjectPath(kDebugdServicePath)))
      .WillOnce(testing::Return(mock_object_proxy.get()));

  // Mock the method calls from the object proxy.
  EXPECT_CALL(*mock_object_proxy, CallMethodAndBlockWithErrorDetails(
                                      IsMethod("EcGetInventory"), _, _))
      .WillOnce(Invoke([&](dbus::MethodCall* method_call, int timeout,
                           dbus::ScopedDBusError* error) {
        return RespondWithString(method_call, resp_str);
      }));

  auto util = std::make_unique<typecd::CrosECUtil>(bus);
  util->ModeEntrySupported();
  return 0;
}
