// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/test_util.h"

namespace lorgnette {

void PrintTo(const lorgnette::DocumentSource& ds, std::ostream* os) {
  *os << "DocumentSource(" << std::endl;
  *os << "  name = " << ds.name() << "," << std::endl;
  *os << "  type = " << SourceType_Name(ds.type()) << "," << std::endl;

  if (ds.has_area()) {
    *os << "  area.width = " << ds.area().width() << "," << std::endl;
    *os << "  area.height = " << ds.area().height() << "," << std::endl;
  }

  for (const auto resolution : ds.resolutions())
    *os << "  resolution = " << resolution << "," << std::endl;

  for (const auto color_mode : ds.color_modes())
    *os << "  color_mode = " << color_mode << "," << std::endl;

  *os << ")";
}

DocumentSource CreateDocumentSource(const std::string& name,
                                    SourceType type,
                                    double width,
                                    double height,
                                    const std::vector<uint32_t>& resolutions,
                                    const std::vector<ColorMode>& color_modes) {
  DocumentSource source;
  source.set_name(name);
  source.set_type(type);
  source.mutable_area()->set_width(width);
  source.mutable_area()->set_height(height);
  source.mutable_resolutions()->Add(resolutions.begin(), resolutions.end());
  source.mutable_color_modes()->Add(color_modes.begin(), color_modes.end());
  return source;
}

libusb_device_descriptor MakeMinimalDeviceDescriptor() {
  libusb_device_descriptor descriptor;
  memset(&descriptor, 0, sizeof(descriptor));
  descriptor.bLength = sizeof(descriptor);
  descriptor.bDescriptorType = LIBUSB_DT_DEVICE;
  descriptor.idVendor = 0x1234;
  descriptor.idProduct = 0x4321;
  return descriptor;
}

std::unique_ptr<libusb_interface_descriptor> MakeIppUsbInterfaceDescriptor() {
  auto descriptor = std::make_unique<libusb_interface_descriptor>();
  descriptor->bLength = sizeof(libusb_interface_descriptor);
  descriptor->bDescriptorType = LIBUSB_DT_INTERFACE;
  descriptor->bInterfaceNumber = 0;
  descriptor->bAlternateSetting = 1;
  descriptor->bInterfaceClass = LIBUSB_CLASS_PRINTER;
  descriptor->bInterfaceProtocol = 0x04;  // IPP-USB protocol.
  return descriptor;
}

}  // namespace lorgnette
