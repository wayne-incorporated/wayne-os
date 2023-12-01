// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_CONSTANTS_H_

namespace diagnostics {

inline constexpr char kPropertieVendorFromDB[] = "ID_VENDOR_FROM_DATABASE";
inline constexpr char kPropertieModelFromDB[] = "ID_MODEL_FROM_DATABASE";
inline constexpr char kPropertieProduct[] = "PRODUCT";
inline constexpr char kFileUsbManufacturerName[] = "manufacturer";
inline constexpr char kFileUsbProductName[] = "product";
inline constexpr char kFileUsbDevClass[] = "bDeviceClass";
inline constexpr char kFileUsbDevSubclass[] = "bDeviceSubClass";
inline constexpr char kFileUsbDevProtocol[] = "bDeviceProtocol";
inline constexpr char kFileUsbIFNumber[] = "bInterfaceNumber";
inline constexpr char kFileUsbIFClass[] = "bInterfaceClass";
inline constexpr char kFileUsbIFSubclass[] = "bInterfaceSubClass";
inline constexpr char kFileUsbIFProtocol[] = "bInterfaceProtocol";
inline constexpr char kFileUsbVendor[] = "idVendor";
inline constexpr char kFileUsbProduct[] = "idProduct";
inline constexpr char kFileUsbSerial[] = "serial";
inline constexpr char kFileUsbSpeed[] = "speed";

inline constexpr char kLinuxFoundationVendorId[] = "1d6b";
inline constexpr uint16_t kLinuxFoundationUsb1ProductId = 1;
inline constexpr uint16_t kLinuxFoundationUsb2ProductId = 2;
inline constexpr uint16_t kLinuxFoundationUsb3ProductId = 3;

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_CONSTANTS_H_
