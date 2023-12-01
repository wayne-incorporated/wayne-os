// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rgbkbd/rgb_keyboard_controller_impl.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "rgbkbd/constants.h"

namespace rgbkbd {

RgbKeyboardControllerImpl::RgbKeyboardControllerImpl(RgbKeyboard* keyboard)
    : keyboard_(keyboard), background_color_(kWhiteBackgroundColor) {}
RgbKeyboardControllerImpl::~RgbKeyboardControllerImpl() = default;

uint32_t RgbKeyboardControllerImpl::GetRgbKeyboardCapabilities() {
  if (!capabilities_.has_value()) {
    capabilities_ = keyboard_->GetRgbKeyboardCapabilities();
  }

  return static_cast<uint32_t>(capabilities_.value());
}

void RgbKeyboardControllerImpl::SetKeyColor(const KeyColor& key_color) {
  keyboard_->SetKeyColor(key_color.key, key_color.color.r, key_color.color.g,
                         key_color.color.b);
}

void RgbKeyboardControllerImpl::SetAllKeyColors(const Color& color) {
  keyboard_->SetAllKeyColors(color.r, color.g, color.b);
}

void RgbKeyboardControllerImpl::SetCapsLockState(bool enabled) {
  caps_lock_enabled_ = enabled;
  // Per zone keyboards can not independently set left/right shift RGB colors.
  // TODO(michaelcheco): Prevent this call from happening for per zone keyboards
  // higher up in the stack.
  if (IsZonedKeyboard()) {
    LOG(ERROR) << "Attempted to set caps lock color for a per zone keyboard";
    return;
  }

  SetKeyColor({kLeftShiftKey, GetCurrentCapsLockColor(kLeftShiftKey)});
  SetKeyColor({kRightShiftKey, GetCurrentCapsLockColor(kRightShiftKey)});
}

void RgbKeyboardControllerImpl::SetStaticBackgroundColor(uint8_t r,
                                                         uint8_t g,
                                                         uint8_t b) {
  background_type_ = BackgroundType::kStaticSingleColor;
  background_color_ = Color(r, g, b);
  SetAllKeyColors(background_color_);

  // If Capslock was enabled, re-color the highlight keys.
  if (caps_lock_enabled_) {
    SetCapsLockState(/*enabled=*/true);
  }
}

void RgbKeyboardControllerImpl::SetKeyboardClient(RgbKeyboard* keyboard) {
  DCHECK(keyboard);
  keyboard_ = keyboard;
}

void RgbKeyboardControllerImpl::SetKeyboardCapabilityForTesting(
    RgbKeyboardCapabilities capability) {
  capabilities_ = capability;
}

const std::vector<uint32_t>& RgbKeyboardControllerImpl::GetZone(
    int zone) const {
  DCHECK(capabilities_.has_value());
  DCHECK(zone >= 0 && zone < GetZoneCount());
  switch (capabilities_.value()) {
    case RgbKeyboardCapabilities::kNone:
      NOTREACHED();
      return kEmptyZone;
    case RgbKeyboardCapabilities::kIndividualKey:
      return GetIndividualKeyZones()[zone];
    case RgbKeyboardCapabilities::kFourZoneFortyLed:
      return GetFourtyLedZones()[zone];
    case RgbKeyboardCapabilities::kFourZoneTwelveLed:
      return GetTwelveLedZones()[zone];
    case RgbKeyboardCapabilities::kFourZoneFourLed:
      return GetFourLedZones()[zone];
  }
}

int RgbKeyboardControllerImpl::GetZoneCount() const {
  DCHECK(capabilities_.has_value());
  switch (capabilities_.value()) {
    case RgbKeyboardCapabilities::kNone:
      return 0;
    case RgbKeyboardCapabilities::kIndividualKey:
      return 5;
    case RgbKeyboardCapabilities::kFourZoneFortyLed:
    case RgbKeyboardCapabilities::kFourZoneTwelveLed:
    case RgbKeyboardCapabilities::kFourZoneFourLed:
      return 4;
  }
}

Color RgbKeyboardControllerImpl::GetRainbowZoneColor(int zone) const {
  DCHECK(capabilities_.has_value());
  DCHECK(zone >= 0 && zone < GetZoneCount());
  switch (capabilities_.value()) {
    case RgbKeyboardCapabilities::kNone:
      NOTREACHED();
      return kWhiteBackgroundColor;
    case RgbKeyboardCapabilities::kIndividualKey:
      return kIndividualKeyRainbowColors[zone];
    case RgbKeyboardCapabilities::kFourZoneFortyLed:
      return kFourZonesRainbowColors[zone];
    case RgbKeyboardCapabilities::kFourZoneTwelveLed:
      return kFourZonesRainbowColors[zone];
    case RgbKeyboardCapabilities::kFourZoneFourLed:
      return kFourZonesRainbowColors[zone];
  }
}

void RgbKeyboardControllerImpl::SetZoneColor(int zone,
                                             uint8_t r,
                                             uint8_t g,
                                             uint8_t b) {
  if (zone < 0 || zone >= GetZoneCount()) {
    LOG(ERROR) << "Attempted to set color for invalid zone: " << zone;
    return;
  }

  for (uint32_t led : GetZone(zone)) {
    if (capabilities_ == RgbKeyboardCapabilities::kIndividualKey) {
      individual_key_background_map_.insert_or_assign(led, Color(r, g, b));
    }
    // Check if caps lock is enabled to avoid overriding the caps lock
    // highlight keys.
    if (caps_lock_enabled_ && IsShiftKey(led)) {
      continue;
    }

    keyboard_->SetKeyColor(led, r, g, b);
  }
}

void RgbKeyboardControllerImpl::SetStaticZoneColor(int zone,
                                                   uint8_t r,
                                                   uint8_t g,
                                                   uint8_t b) {
  background_type_ = BackgroundType::kStaticZones;
  zone_colors_.insert_or_assign(zone, Color(r, g, b));
  SetZoneColor(zone, r, g, b);
}

void RgbKeyboardControllerImpl::SetRainbowMode() {
  DCHECK(capabilities_.has_value());

  background_type_ = BackgroundType::kStaticRainbow;

  int zone_count = GetZoneCount();
  for (int zone = 0; zone < zone_count; ++zone) {
    Color color = GetRainbowZoneColor(zone);
    SetZoneColor(zone, color.r, color.g, color.b);
  }
}

// TODO(jimmyxgong): Implement this stub.
void RgbKeyboardControllerImpl::SetAnimationMode(RgbAnimationMode mode) {
  NOTIMPLEMENTED();
}

std::vector<KeyColor> RgbKeyboardControllerImpl::
    GetRainbowModeColorsWithShiftKeysHighlightedForTesting() {
  DCHECK(capabilities_ == RgbKeyboardCapabilities::kIndividualKey);
  std::vector<KeyColor> vec;

  vec.emplace_back(kLeftShiftKey, kCapsLockHighlight);
  vec.emplace_back(kRightShiftKey, kCapsLockHighlight);

  for (const auto& entry : kRainbowModeIndividualKey) {
    if (entry.key == kLeftShiftKey || entry.key == kRightShiftKey) {
      continue;
    }
    vec.push_back(entry);
  }

  return vec;
}

Color RgbKeyboardControllerImpl::GetCurrentCapsLockColor(uint32_t key) const {
  if (caps_lock_enabled_) {
    return kCapsLockHighlight;
  }

  if (background_type_ == BackgroundType::kStaticRainbow ||
      background_type_ == BackgroundType::kStaticZones) {
    return GetBackgroundColorForKey(key);
  }

  return background_color_;
}

Color RgbKeyboardControllerImpl::GetBackgroundColorForKey(uint32_t key) const {
  DCHECK(capabilities_ == RgbKeyboardCapabilities::kIndividualKey);
  auto entry = individual_key_background_map_.find(key);
  if (entry == individual_key_background_map_.end()) {
    LOG(ERROR) << "The background color for key " << key << " wasn't set.";
    return kWhiteBackgroundColor;
  }

  return entry->second;
}

bool RgbKeyboardControllerImpl::IsZonedKeyboard() const {
  DCHECK(capabilities_.has_value());
  return capabilities_.value() != RgbKeyboardCapabilities::kIndividualKey;
}

void RgbKeyboardControllerImpl::ReinitializeOnDeviceReconnected() {
  if (background_type_ != BackgroundType::kNone) {
    SetKeyColor({kLeftShiftKey, GetCurrentCapsLockColor(kLeftShiftKey)});
    SetKeyColor({kRightShiftKey, GetCurrentCapsLockColor(kRightShiftKey)});
  }

  switch (background_type_) {
    case BackgroundType::kStaticSingleColor:
      SetStaticBackgroundColor(background_color_.r, background_color_.g,
                               background_color_.b);
      break;
    case BackgroundType::kStaticRainbow:
      SetRainbowMode();
      break;
    case BackgroundType::kStaticZones:
      for (auto const& [zone, color] : zone_colors_) {
        SetStaticZoneColor(zone, color.r, color.g, color.b);
      }
      break;
    case BackgroundType::kNone:
      break;
  }
}

void RgbKeyboardControllerImpl::SetKeyboardCapabilityAsIndividualKey() {
  capabilities_ = RgbKeyboardCapabilities::kIndividualKey;
}

void RgbKeyboardControllerImpl::OnUsbDeviceAdded(const std::string& sys_path,
                                                 uint8_t bus_number,
                                                 uint8_t device_address,
                                                 uint16_t vendor_id,
                                                 uint16_t product_id) {
  if (vendor_id == kPrismVendorId && product_id == kPrismProductId) {
    LOG(INFO) << "Detected the Prism device reconnecting to the system.";
    // Save prism usb sys_path to know when it disconnects.
    prism_usb_sys_path_ = sys_path;
    keyboard_->InitializeUsbKeyboard();
    ReinitializeOnDeviceReconnected();
  }
}

// Invoked when a USB device is removed from the system.
void RgbKeyboardControllerImpl::OnUsbDeviceRemoved(
    const std::string& sys_path) {
  if (sys_path == prism_usb_sys_path_) {
    LOG(INFO) << "Detected the Prism device being removed from the system.";
    prism_usb_sys_path_.clear();
    keyboard_->ResetUsbKeyboard();
  }
}

}  // namespace rgbkbd
