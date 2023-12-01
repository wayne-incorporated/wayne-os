// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/dbus_wrapper.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>

namespace hammerd {

DBusWrapper::DBusWrapper() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(options);
  CHECK(bus_->Connect()) << "Failed to connect to system bus.";
  CHECK(bus_->RequestOwnershipAndBlock(kHammerdServiceName,
                                       dbus::Bus::REQUIRE_PRIMARY))
      << "Failed to request ownership.";
  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kHammerdServicePath));
}

void DBusWrapper::SendSignal(const std::string& signal_name) {
  SendSignalWithArg(signal_name, nullptr, 0);
}

void DBusWrapper::SendSignalWithArg(const std::string& signal_name,
                                    const uint8_t* values,
                                    size_t length) {
  LOG(INFO) << "Send the DBus signal: " << signal_name;
  dbus::Signal signal(kHammerdInterface, signal_name);
  if (length > 0) {
    dbus::MessageWriter writer(&signal);
    writer.AppendArrayOfBytes(values, length);
  }
  exported_object_->SendSignal(&signal);
}

}  // namespace hammerd
