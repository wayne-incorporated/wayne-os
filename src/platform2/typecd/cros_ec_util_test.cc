// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/cros_ec_util.h"

#include <string>

#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using testing::_;
using testing::Invoke;

namespace {

constexpr char kDebugdServiceName[] = "org.chromium.debugd";
constexpr char kDebugdServicePath[] = "/org/chromium/debugd";

// Some sample inputs to feed into the mode entry checker.
const char kSampleInventoryInput1[] = "10  : Thermal management support";
const char kSampleInventoryInput2[] =
    "asdfas98790823845(*)*&$*)@*!@#&*_)$!$_)&!asdf`1`32`123--__&&@_@&_$\n"
    "90900-w3e0--0-z.xc,.x l\nsadflkjas;diojfapsodf0909sdad09f90sd0f9808093";
const char kSampleInventoryInput3[] =
    "33  : 64-bit host events support\n"
    "34  : Execute code in RAM support\n"
    "35  : Consumer Electronics Control support\n"
    "36  : Tight timestamp for sensors events support\n"
    "37  : Refined tablet mode hysteresis support\n"
    "38  : Early Firmware Selection v2 support\n"
    "41  : TCPMv2 Type-C commands support\n"
    "42  : Host-controlled Type-C mode entry\n"
    "43  : Unknown feature\n";
const char kSampleInventoryInput4[] = "";

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

namespace typecd {

class CrosECUtilTest : public ::testing::Test {};

// Test the mode entry parsing for various return strings of
// EcGetInventory.
TEST_F(CrosECUtilTest, ModeEntrySupported) {
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
      .WillOnce(Invoke([](dbus::MethodCall* method_call, int timeout,
                          dbus::ScopedDBusError* error) {
        return RespondWithString(method_call, kSampleInventoryInput1);
      }))
      .WillOnce(Invoke([](dbus::MethodCall* method_call, int timeout,
                          dbus::ScopedDBusError* error) {
        return RespondWithString(method_call, kSampleInventoryInput2);
      }))
      .WillOnce(Invoke([](dbus::MethodCall* method_call, int timeout,
                          dbus::ScopedDBusError* error) {
        return RespondWithString(method_call, kSampleInventoryInput3);
      }))
      .WillOnce(Invoke([](dbus::MethodCall* method_call, int timeout,
                          dbus::ScopedDBusError* error) {
        return RespondWithString(method_call, kSampleInventoryInput4);
      }));
  auto util = std::make_unique<CrosECUtil>(bus);
  EXPECT_FALSE(util->ModeEntrySupported());
  EXPECT_FALSE(util->ModeEntrySupported());
  EXPECT_TRUE(util->ModeEntrySupported());
  EXPECT_FALSE(util->ModeEntrySupported());
}

}  // namespace typecd
