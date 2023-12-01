// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/power_manager_client.h"

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <chromeos/dbus/service_constants.h>
#include <google/protobuf/message_lite.h>

#include "power_manager/proto_bindings/input_event.pb.h"

namespace {

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

namespace biod {

std::unique_ptr<PowerManagerClientInterface> PowerManagerClient::Create(
    const scoped_refptr<dbus::Bus>& bus) {
  return base::WrapUnique(new PowerManagerClient(bus));
}

PowerManagerClient::PowerManagerClient(const scoped_refptr<dbus::Bus>& bus) {
  proxy_ = std::make_unique<org::chromium::PowerManagerProxy>(bus);
  // Register Input Event signal Handler.
  proxy_->RegisterInputEventSignalHandler(
      base::BindRepeating(&PowerManagerClient::InputEvent,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerClient::OnSignalConnected,
                     weak_factory_.GetWeakPtr()));
}

void PowerManagerClient::AddObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

bool PowerManagerClient::HasObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  return observers_.HasObserver(observer);
}

void PowerManagerClient::RemoveObserver(PowerEventObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void PowerManagerClient::InputEvent(
    const std::vector<uint8_t>& serialized_proto) {
  power_manager::InputEvent proto;
  if (!DeserializeProtocolBuffer(serialized_proto, &proto)) {
    LOG(ERROR) << "Failed to parse InputEvent signal.";
    return;
  }
  base::TimeTicks timestamp =
      base::TimeTicks::FromInternalValue(proto.timestamp());
  if (proto.type() == power_manager::InputEvent_Type_POWER_BUTTON_DOWN ||
      proto.type() == power_manager::InputEvent_Type_POWER_BUTTON_UP) {
    const bool down =
        (proto.type() == power_manager::InputEvent_Type_POWER_BUTTON_DOWN);
    for (auto& observer : observers_)
      observer.PowerButtonEventReceived(down, timestamp);
  }
}

void PowerManagerClient::OnSignalConnected(const std::string& interface_name,
                                           const std::string& signal_name,
                                           bool success) {
  LOG(INFO) << __func__ << " interface: " << interface_name
            << " signal: " << signal_name << "success: " << success;
  if (!success) {
    LOG(ERROR) << "Failed to connect signal " << signal_name << " to interface "
               << interface_name;
  }
}

}  // namespace biod
