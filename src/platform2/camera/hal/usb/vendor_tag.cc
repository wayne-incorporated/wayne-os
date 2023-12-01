/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/vendor_tag.h"

namespace cros {

// static
const VendorTagManager& VendorTagOps::GetVendorTagManager() {
  static const auto manager = []() {
    VendorTagManager m;
    m.Add(kVendorTagVendorId, kVendorUsbSectionName, "vendorId", TYPE_BYTE);
    m.Add(kVendorTagProductId, kVendorUsbSectionName, "productId", TYPE_BYTE);
    m.Add(kVendorTagModelName, kVendorUsbSectionName, "modelName", TYPE_BYTE);
    m.Add(kVendorTagDevicePath, kVendorUsbSectionName, "devicePath", TYPE_BYTE);
    m.Add(kVendorTagTimestampSync, kVendorUsbSectionName, "timestampSync",
          TYPE_INT32);
    m.Add(kVendorTagControlBrightness, kVendorControlSectionName, "brightness",
          TYPE_INT32);
    m.Add(kVendorTagControlBrightnessRange, kVendorControlSectionName,
          "brightnessRange", TYPE_INT32);
    m.Add(kVendorTagControlBrightnessDefault, kVendorControlSectionName,
          "brightnessDefault", TYPE_INT32);
    m.Add(kVendorTagControlContrast, kVendorControlSectionName, "contrast",
          TYPE_INT32);
    m.Add(kVendorTagControlContrastRange, kVendorControlSectionName,
          "contrastRange", TYPE_INT32);
    m.Add(kVendorTagControlContrastDefault, kVendorControlSectionName,
          "contrastDefault", TYPE_INT32);
    m.Add(kVendorTagControlPan, kVendorControlSectionName, "pan", TYPE_INT32);
    m.Add(kVendorTagControlPanRange, kVendorControlSectionName, "panRange",
          TYPE_INT32);
    m.Add(kVendorTagControlPanDefault, kVendorControlSectionName, "panDefault",
          TYPE_INT32);
    m.Add(kVendorTagControlSaturation, kVendorControlSectionName, "saturation",
          TYPE_INT32);
    m.Add(kVendorTagControlSaturationRange, kVendorControlSectionName,
          "saturationRange", TYPE_INT32);
    m.Add(kVendorTagControlSaturationDefault, kVendorControlSectionName,
          "saturationDefault", TYPE_INT32);
    m.Add(kVendorTagControlSharpness, kVendorControlSectionName, "sharpness",
          TYPE_INT32);
    m.Add(kVendorTagControlSharpnessRange, kVendorControlSectionName,
          "sharpnessRange", TYPE_INT32);
    m.Add(kVendorTagControlSharpnessDefault, kVendorControlSectionName,
          "sharpnessDefault", TYPE_INT32);
    m.Add(kVendorTagControlTilt, kVendorControlSectionName, "tilt", TYPE_INT32);
    m.Add(kVendorTagControlTiltRange, kVendorControlSectionName, "tiltRange",
          TYPE_INT32);
    m.Add(kVendorTagControlTiltDefault, kVendorControlSectionName,
          "tiltDefault", TYPE_INT32);
    m.Add(kVendorTagControlZoom, kVendorControlSectionName, "zoom", TYPE_INT32);
    m.Add(kVendorTagControlZoomRange, kVendorControlSectionName, "zoomRange",
          TYPE_INT32);
    m.Add(kVendorTagControlZoomDefault, kVendorControlSectionName,
          "zoomDefault", TYPE_INT32);
    return m;
  }();
  return manager;
}

// static
int VendorTagOps::GetTagCount(const vendor_tag_ops_t*) {
  return GetVendorTagManager().GetTagCount();
}

// static
void VendorTagOps::GetAllTags(const vendor_tag_ops_t*, uint32_t* tag_array) {
  GetVendorTagManager().GetAllTags(tag_array);
}

// static
const char* VendorTagOps::GetSectionName(const vendor_tag_ops_t*,
                                         uint32_t tag) {
  return GetVendorTagManager().GetSectionName(tag);
}

// static
const char* VendorTagOps::GetTagName(const vendor_tag_ops_t*, uint32_t tag) {
  return GetVendorTagManager().GetTagName(tag);
}

// static
int VendorTagOps::GetTagType(const vendor_tag_ops_t*, uint32_t tag) {
  return GetVendorTagManager().GetTagType(tag);
}

}  // namespace cros
