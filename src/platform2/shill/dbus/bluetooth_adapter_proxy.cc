// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/bluetooth_adapter_proxy.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/stringprintf.h>
#include <dbus/object_path.h>

#include "bluetooth/dbus-proxies.h"
#include "shill/bluetooth/bluetooth_manager_interface.h"
#include "shill/logging.h"
#include "shill/scope_logger.h"

namespace shill {

namespace {
// TOOD(b/262931830): Use constants defined in system_api once they've been
// added.
constexpr char kBTServiceName[] = "org.chromium.bluetooth";
constexpr char kBTObjectPathFormat[] = "/org/chromium/bluetooth/hci%d/adapter";

// UUIDs of the various profiles defined at
// https://android.googlesource.com/platform/packages/modules/Bluetooth/+/ac69da6c45771293530338709ee6e9599065ca5d/system/gd/rust/linux/stack/src/uuid.rs
const std::vector<uint8_t> kBTHFPUuid = {0x00, 0x00, 0x11, 0x1E, 0x00, 0x00,
                                         0x10, 0x00, 0x80, 0x00, 0x00, 0x80,
                                         0x5F, 0x9B, 0x34, 0xFB};
const std::vector<uint8_t> kBTA2DPSinkUuid = {
    0x00, 0x00, 0x11, 0x0B, 0x00, 0x00, 0x10, 0x00,
    0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB};

// Values defined at
// https://android.googlesource.com/platform/packages/modules/Bluetooth/+/ac69da6c45771293530338709ee6e9599065ca5d/system/gd/rust/topshim/src/profiles/mod.rs#7
constexpr uint32_t kBTStateDisconnected = 0;
constexpr uint32_t kBTStateDisconnecting = 1;
constexpr uint32_t kBTStateConnecting = 2;
constexpr uint32_t kBTStateConnected = 3;
constexpr uint32_t kBTStateActive = 4;
constexpr uint32_t kBTStateInvalid = 0x7FFFFFFE;

BluetoothManagerInterface::BTProfileConnectionState ConvertFromRawState(
    uint32_t state) {
  switch (state) {
    case kBTStateDisconnected:
      return BluetoothManagerInterface::BTProfileConnectionState::kDisconnected;
    case kBTStateDisconnecting:
      return BluetoothManagerInterface::BTProfileConnectionState::
          kDisconnecting;
    case kBTStateConnecting:
      return BluetoothManagerInterface::BTProfileConnectionState::kConnecting;
    case kBTStateConnected:
      return BluetoothManagerInterface::BTProfileConnectionState::kConnected;
    case kBTStateActive:
      return BluetoothManagerInterface::BTProfileConnectionState::kActive;
    case kBTStateInvalid:
      return BluetoothManagerInterface::BTProfileConnectionState::kInvalid;
  }
  LOG(ERROR) << "Received invalid BT state " << state;
  return BluetoothManagerInterface::BTProfileConnectionState::kInvalid;
}

const char* BTProfiletoString(BluetoothManagerInterface::BTProfile profile) {
  switch (profile) {
    case BluetoothManagerInterface::BTProfile::kHFP:
      return "HFP";
    case BluetoothManagerInterface::BTProfile::kA2DPSink:
      return "A2DP-Sink";
  }
}
}  // namespace

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kBluetooth;
}  // namespace Logging

BluetoothAdapterProxy::BluetoothAdapterProxy(
    const scoped_refptr<dbus::Bus>& bus, int32_t hci)
    : proxy_(new org::chromium::bluetooth::BluetoothProxy(
          bus,
          kBTServiceName,
          dbus::ObjectPath(base::StringPrintf(kBTObjectPathFormat, hci)))) {}

bool BluetoothAdapterProxy::GetProfileConnectionState(
    BluetoothManagerInterface::BTProfile profile,
    BluetoothManagerInterface::BTProfileConnectionState* state) const {
  brillo::ErrorPtr error;
  std::vector<uint8_t> profile_uuid;
  switch (profile) {
    case BluetoothManagerInterface::BTProfile::kHFP:
      profile_uuid = kBTHFPUuid;
      break;
    case BluetoothManagerInterface::BTProfile::kA2DPSink:
      profile_uuid = kBTA2DPSinkUuid;
      break;
  }
  uint32_t bt_state;
  if (!proxy_->GetProfileConnectionState(std::move(profile_uuid), &bt_state,
                                         &error)) {
    LOG(ERROR) << "Failed to query BT profile connection state: "
               << error->GetCode() << " " << error->GetMessage();
    return false;
  }
  SLOG(3) << __func__ << ": " << proxy_->GetObjectPath().value()
          << ": BT profile " << BTProfiletoString(profile) << " is in state "
          << bt_state;
  *state = ConvertFromRawState(bt_state);
  return true;
}

bool BluetoothAdapterProxy::IsDiscovering(bool* discovering) const {
  brillo::ErrorPtr error;
  if (!proxy_->IsDiscovering(discovering, &error)) {
    LOG(ERROR) << "Failed to query BT discovering state: " << error->GetCode()
               << " " << error->GetMessage();
    return false;
  }
  SLOG(3) << __func__ << ": " << proxy_->GetObjectPath().value()
          << ": BT is discovering: " << *discovering;
  return true;
}

}  // namespace shill
