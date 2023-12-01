// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_IPPUSB_DEVICE_H_
#define LORGNETTE_IPPUSB_DEVICE_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <libusb.h>

#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

namespace lorgnette {

// Convert an ippusb backend name to a real backend string, e.g.
// ippusb:escl:Device:1234_5678/eSCL/ to
// airscan:escl:Device:unix://1234-5678.sock/eSCL/.  In the process, checks for
// a matching ippusb_bridge socket in |socket_dir|, but does not make a
// connection to the bridge.  Return std::nullopt if the device can't be found
// or an error occurs waiting for the socket.
std::optional<std::string> BackendForDevice(const std::string& device_name,
                                            base::FilePath socket_dir);

// Get a list of potential eSCL-over-USB devices attached to the system.  Each
// returned device will be a printer that claims to support IPP-USB, but they
// are not probed for eSCL support.  The caller must double-check returned
// devices before using them to scan.
std::vector<ScannerInfo> FindIppUsbDevices(libusb_context* context);

// Loop through all altsettings for all interfaces in |config| and return true
// if any is a printer interface class that implements the IPP-USB protocol.
// Also sets |isPrinter| to true if any interface has the printer class
// regardless of whether it supports IPP-USB.
bool ContainsIppUsbInterface(const libusb_config_descriptor* config,
                             bool* isPrinter);
}  // namespace lorgnette

#endif  // LORGNETTE_IPPUSB_DEVICE_H_
