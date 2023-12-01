// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rgbkbd/internal_rgb_keyboard.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <libec/rgb_keyboard_command.h>

namespace rgbkbd {

namespace {

constexpr char kEcPath[] = "/dev/cros_ec";

std::string CreateRgbLogString(uint8_t r, uint8_t g, uint8_t b) {
  std::stringstream rgb_log;
  rgb_log << " R:" << static_cast<int>(r) << " G:" << static_cast<int>(g)
          << " B:" << static_cast<int>(b);
  return rgb_log.str();
}

void LogSupportType(RgbKeyboardCapabilities capabilities) {
  switch (capabilities) {
    case RgbKeyboardCapabilities::kNone:
      LOG(INFO) << "Device does not support an internal RGB keyboard";
      break;
    case RgbKeyboardCapabilities::kFourZoneFortyLed:
      LOG(INFO) << "Device supports four zone - fourty led keyboard";
      break;
    case RgbKeyboardCapabilities::kIndividualKey:
      LOG(INFO) << "Device supports per-key keyboard";
      break;
    case RgbKeyboardCapabilities::kFourZoneTwelveLed:
      LOG(INFO) << "Device supports four zone - twelve led keyboard";
      break;
    case RgbKeyboardCapabilities::kFourZoneFourLed:
      LOG(INFO) << "Device supports four zone - four led keyboard";
      break;
  }
}

std::unique_ptr<ec::EcUsbEndpointInterface> CreateEcUsbEndpoint() {
  auto endpoint = std::make_unique<ec::EcUsbEndpoint>();
  if (!endpoint->Init(ec::kUsbVidGoogle, ec::kUsbPidCrosEc)) {
    LOG(INFO) << "Failed to initialize EC USB Endpoint.";
    return nullptr;
  }

  return std::move(endpoint);
}

base::ScopedFD CreateFileDescriptorForEc() {
  auto raw_fd = open(kEcPath, O_RDWR | O_CLOEXEC);
  if (raw_fd == -1) {
    const int temp_errno = errno;
    LOG(ERROR) << "Failed to open FD for EC with errno=" << temp_errno;
    return base::ScopedFD();
  }

  return base::ScopedFD(raw_fd);
}

RgbKeyboardCapabilities ConvertEcCapabilitiesToRgbKeyboardCapabilities(
    uint8_t ec_capabilities) {
  switch (ec_capabilities) {
    case EC_RGBKBD_TYPE_UNKNOWN:
      return RgbKeyboardCapabilities::kNone;
    case EC_RGBKBD_TYPE_PER_KEY:
      return RgbKeyboardCapabilities::kIndividualKey;
    case EC_RGBKBD_TYPE_FOUR_ZONES_40_LEDS:
      return RgbKeyboardCapabilities::kFourZoneFortyLed;
    case EC_RGBKBD_TYPE_FOUR_ZONES_12_LEDS:
      return RgbKeyboardCapabilities::kFourZoneTwelveLed;
    case EC_RGBKBD_TYPE_FOUR_ZONES_4_LEDS:
      return RgbKeyboardCapabilities::kFourZoneFourLed;
    default:
      LOG(WARNING) << "Invalid EC Capability value: " << ec_capabilities
                   << ". Using default of None.";
      return RgbKeyboardCapabilities::kNone;
  }
}
}  // namespace

bool InternalRgbKeyboard::SetKeyColor(uint32_t key,
                                      uint8_t r,
                                      uint8_t g,
                                      uint8_t b) {
  struct rgb_s color = {r, g, b};
  ec::RgbkbdSetColorCommand command(key, std::vector<struct rgb_s>{color});
  const bool success = RunEcCommand(command);

  if (success) {
    LOG(INFO) << "Setting key color succeeded with key " << key
              << CreateRgbLogString(r, g, b);
  } else {
    LOG(ERROR) << "Setting key color failed with key " << key
               << CreateRgbLogString(r, g, b);
  }
  return success;
}

bool InternalRgbKeyboard::SetAllKeyColors(uint8_t r, uint8_t g, uint8_t b) {
  struct rgb_s color = {r, g, b};
  const bool success =
      RunEcCommand(*ec::RgbkbdCommand::Create(EC_RGBKBD_SUBCMD_CLEAR, color));

  if (success) {
    LOG(INFO) << "Setting all key colors to" << CreateRgbLogString(r, g, b)
              << " succeeded";
  } else {
    LOG(ERROR) << "Setting all key colors to" << CreateRgbLogString(r, g, b)
               << " failed";
  }
  return success;
}

RgbKeyboardCapabilities InternalRgbKeyboard::GetRgbKeyboardCapabilities() {
  RgbKeyboardCapabilities capabilities = RgbKeyboardCapabilities::kNone;

  LOG(INFO) << "Checking RgbKeyboardCapabilities.";
  auto command = ec::RgbkbdCommand::Create(EC_RGBKBD_SUBCMD_GET_CONFIG);

  if (SetCommunicationType(*command)) {
    const uint8_t ec_capabilities = command->GetConfig();
    LOG(INFO) << "EC GetConfig returned: " << ec_capabilities;
    capabilities =
        ConvertEcCapabilitiesToRgbKeyboardCapabilities(ec_capabilities);
  }

  LogSupportType(capabilities);
  return capabilities;
}

template <typename T, typename U>
bool InternalRgbKeyboard::SetCommunicationType(ec::EcCommand<T, U>& command) {
  LOG(INFO) << "Deducing Communication type";

  ec_fd_ = CreateFileDescriptorForEc();
  if (ec_fd_.is_valid() && command.Run(ec_fd_.get())) {
    LOG(INFO) << "Internal RGB Keyboard communicates over FD";
    communication_type_ = CommunicationType::kFileDescriptor;
    return true;
  }

  usb_endpoint_ = CreateEcUsbEndpoint();
  if (usb_endpoint_ && command.Run(*usb_endpoint_)) {
    LOG(INFO) << "Internal RGB Keyboard communicates over USB";
    communication_type_ = CommunicationType::kUsb;
    return true;
  }

  LOG(ERROR) << "Failed to deduce communication type for internal RGB Keyboard";
  return false;
}

void InternalRgbKeyboard::ResetUsbKeyboard() {
  LOG(INFO) << "Resetting USB Endpoint.";
  communication_type_.reset();
  usb_endpoint_.reset();
}

void InternalRgbKeyboard::InitializeUsbKeyboard() {
  if (!usb_endpoint_ || !communication_type_) {
    LOG(INFO) << "Initializing USB endpoint.";
    usb_endpoint_ = CreateEcUsbEndpoint();
    communication_type_ =
        usb_endpoint_ ? std::optional(CommunicationType::kUsb) : std::nullopt;
    if (communication_type_) {
      LOG(INFO) << "Successfully initialized USB endpoint.";
    } else {
      LOG(INFO) << "Failed to initialize USB endpoint.";
    }
  }
}

template <typename T, typename U>
bool InternalRgbKeyboard::RunEcCommand(ec::EcCommand<T, U>& command) {
  if (!communication_type_) {
    LOG(ERROR) << "Could not run EC command, Internal RGB Keyboard has no "
                  "communication type set";
    return false;
  }

  switch (communication_type_.value()) {
    case CommunicationType::kUsb:
      DCHECK(usb_endpoint_);
      return command.Run(*usb_endpoint_);
    case CommunicationType::kFileDescriptor:
      DCHECK(ec_fd_.is_valid());
      return command.Run(ec_fd_.get());
  }
}

}  // namespace rgbkbd
