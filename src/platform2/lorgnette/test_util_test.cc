// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/test_util.h"

#include <string>

#include <gtest/gtest.h>

using ::testing::HasSubstr;
using ::testing::Not;

namespace lorgnette {

TEST(TestUtils, PrintTo) {
  DocumentSource ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  std::stringstream ss;
  PrintTo(ds, &ss);
  std::string result = ss.str();
  EXPECT_THAT(result, HasSubstr("name = TestName"));
  EXPECT_THAT(result, HasSubstr("type = SOURCE_UNSPECIFIED"));
  EXPECT_THAT(result, HasSubstr("area.width = 1"));
  EXPECT_THAT(result, HasSubstr("area.height = 1"));
  EXPECT_THAT(result, HasSubstr("resolution = 120"));
  EXPECT_THAT(result, HasSubstr("color_mode = 0"));
}

TEST(TestUtils, EqualsDocumentSourceTrue) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, EqualsDocumentSource(expected_ds));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongName) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestNameWrong", SourceType::SOURCE_UNSPECIFIED, 1.0,
                           1.0, {120}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongType) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_PLATEN, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseAreaOnlyOnExpected) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  test_ds.clear_area();
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseAreaOnlyOnTest) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  expected_ds.clear_area();
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongWidth) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 2.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongHeight) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 2.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongResolutions) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {240}, {ColorMode::MODE_UNSPECIFIED});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, EqualsDocumentSourceFalseWrongColorModes) {
  DocumentSource expected_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_UNSPECIFIED});
  DocumentSource test_ds =
      CreateDocumentSource("TestName", SourceType::SOURCE_UNSPECIFIED, 1.0, 1.0,
                           {120}, {ColorMode::MODE_LINEART});
  EXPECT_THAT(test_ds, Not(EqualsDocumentSource(expected_ds)));
}

TEST(TestUtils, MakeMinimalDeviceDescriptor) {
  auto descriptor = MakeMinimalDeviceDescriptor();

  EXPECT_EQ(descriptor.bLength, sizeof(descriptor));
  EXPECT_EQ(descriptor.bDescriptorType, LIBUSB_DT_DEVICE);
  EXPECT_EQ(descriptor.idVendor, 0x1234);
  EXPECT_EQ(descriptor.idProduct, 0x4321);
}

TEST(TestUtils, MakeIppUsbInterfaceDescriptor) {
  auto descriptor = MakeIppUsbInterfaceDescriptor();

  EXPECT_EQ(descriptor->bLength, sizeof(libusb_interface_descriptor));
  EXPECT_EQ(descriptor->bDescriptorType, LIBUSB_DT_INTERFACE);
  EXPECT_EQ(descriptor->bInterfaceClass, LIBUSB_CLASS_PRINTER);
  EXPECT_EQ(descriptor->bInterfaceProtocol, 0x04);
}

}  // namespace lorgnette
