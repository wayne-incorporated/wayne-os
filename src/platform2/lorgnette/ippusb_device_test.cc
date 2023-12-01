// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/ippusb_device.h"

#include <optional>
#include <string>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace lorgnette {

TEST(IppUsbDeviceLookup, NoBackendForNonIppUsb) {
  std::optional<std::string> backend =
      BackendForDevice("notippusb:device_string", base::FilePath("/no/dir"));
  EXPECT_FALSE(backend.has_value());
}

TEST(IppUsbDeviceLookup, NoBackendForBadFormat) {
  std::optional<std::string> backend =
      BackendForDevice("ippusb:not_an_escl_string", base::FilePath("/no/dir"));
  EXPECT_FALSE(backend.has_value());
}

TEST(IppUsbDeviceLookup, NoBackendForMissingFile) {
  std::optional<std::string> backend = BackendForDevice(
      "ippusb:escl:Test:1234_5678/eSCL/", base::FilePath("/no/dir"));
  EXPECT_FALSE(backend.has_value());
}

TEST(IppUsbDeviceLookup, UpdatedBackend) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath socket_path = temp_dir.GetPath().Append("1234-5678.sock");
  base::File socket_file(socket_path,
                         base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  std::optional<std::string> backend =
      BackendForDevice("ippusb:escl:Test:1234_5678/eSCL/", temp_dir.GetPath());
  EXPECT_TRUE(backend.has_value());
  EXPECT_EQ(*backend, "airscan:escl:Test:unix://1234-5678.sock/eSCL/");
}

}  // namespace lorgnette
