// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_TEST_UTIL_H_
#define LORGNETTE_TEST_UTIL_H_

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <libusb.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

using ::testing::ExplainMatchResult;
using ::testing::UnorderedElementsAreArray;

namespace lorgnette {

void PrintTo(const lorgnette::DocumentSource& ds, std::ostream* os);

DocumentSource CreateDocumentSource(const std::string& name,
                                    SourceType type,
                                    double width,
                                    double height,
                                    const std::vector<uint32_t>& resolutions,
                                    const std::vector<ColorMode>& color_modes);

MATCHER_P(EqualsDocumentSource, expected, "") {
  if (arg.type() != expected.type()) {
    *result_listener << "type " << SourceType_Name(arg.type())
                     << " does not match expected type "
                     << SourceType_Name(expected.type());
    return false;
  }

  if (arg.name() != expected.name()) {
    *result_listener << "name " << arg.name()
                     << " does not match expected name " << expected.name();
    return false;
  }

  if (arg.has_area() != expected.has_area()) {
    *result_listener << (arg.has_area() ? "has area" : "does not have area")
                     << " but expected to "
                     << (expected.has_area() ? "have area" : "not have area");
    return false;
  }

  if (arg.area().width() != expected.area().width()) {
    *result_listener << "width " << arg.area().width()
                     << " does not match expected width "
                     << expected.area().width();
    return false;
  }

  if (arg.area().height() != expected.area().height()) {
    *result_listener << "height " << arg.area().height()
                     << " does not match expected height "
                     << expected.area().height();
    return false;
  }

  if (!ExplainMatchResult(UnorderedElementsAreArray(expected.resolutions()),
                          arg.resolutions(), result_listener)) {
    return false;
  }

  return ExplainMatchResult(UnorderedElementsAreArray(expected.color_modes()),
                            arg.color_modes(), result_listener);
}

libusb_device_descriptor MakeMinimalDeviceDescriptor();
std::unique_ptr<libusb_interface_descriptor> MakeIppUsbInterfaceDescriptor();

}  // namespace lorgnette

#endif  // LORGNETTE_TEST_UTIL_H_
