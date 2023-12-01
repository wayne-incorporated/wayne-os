// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/videodev2.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include "runtime_probe/functions/usb_camera.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

constexpr char kDevPath[] = "/dev";
constexpr char kSysVideoPath[] = "/sys/class/video4linux";

class FakeUsbCameraFunction : public UsbCameraFunction {
  using UsbCameraFunction::UsbCameraFunction;

  std::optional<v4l2_capability> QueryV4l2Cap(int32_t fd) const override {
    return fake_cap_;
  }

 public:
  // The fake V4L2 capability used by fake function.
  std::optional<v4l2_capability> fake_cap_;
};

class UsbCameraFunctionTest : public BaseFunctionTest {
 protected:
  // Set up |camera_fields| for video device |id|.
  // For example:
  //   id = 0
  //   camera_fields = {
  //                     {"idProduct", "1234"},
  //                     {"idVendor", "5678"},
  //                   }
  // The function will set "1234" to file /sys/XXX/0/idVendor
  // and "5678" to file /sys/XXX/0/idProduct.
  void SetCameraDevice(
      int id, std::vector<std::pair<std::string, std::string>> camera_fields) {
    SetFile(base::FilePath(kDevPath).Append(base::StringPrintf("video%d", id)),
            "don't care");
    SetDirectory(base::StringPrintf("sys/XXX/%d/0:0", id));
    SetSymbolicLink(base::StringPrintf("/sys/XXX/%d/0:0", id),
                    base::FilePath(kSysVideoPath)
                        .Append(base::StringPrintf("video%d/device", id)));

    // Set up camera information that is going to be probed.
    for (const auto& [field, value] : camera_fields) {
      SetFile(base::StringPrintf("sys/XXX/%d/%s", id, field.c_str()), value);
    }
  }
};

TEST_F(UsbCameraFunctionTest, ProbeUsbCamera) {
  auto probe_function = CreateProbeFunction<FakeUsbCameraFunction>();

  SetCameraDevice(0, {{"idProduct", "1234"},
                      {"idVendor", "5678"},
                      {"manufacturer", "ABC"},
                      {"product", "ABC Camera"},
                      {"bcdDevice", "9876"},
                      {"removable", "fixed"}});
  SetCameraDevice(1, {{"idProduct", "4321"}, {"idVendor", "8765"}});

  probe_function->fake_cap_ = {.capabilities = V4L2_CAP_DEVICE_CAPS,
                               .device_caps = V4L2_CAP_VIDEO_CAPTURE};

  auto result = probe_function->Eval();

  auto ans = CreateProbeResultFromJson(
      base::StringPrintf(R"JSON(
    [
      {
        "bus_type": "usb",
        "usb_bcd_device": "9876",
        "usb_manufacturer": "ABC",
        "usb_product": "ABC Camera",
        "usb_product_id": "1234",
        "usb_removable": "FIXED",
        "usb_vendor_id": "5678",
        "path": "%s"
      },
      {
        "bus_type": "usb",
        "usb_product_id": "4321",
        "usb_vendor_id": "8765",
        "path": "%s"
      }
    ]
  )JSON",
                         GetPathUnderRoot({"dev/video0"}).value().c_str(),
                         GetPathUnderRoot({"dev/video1"}).value().c_str()));
  ExpectUnorderedListEqual(result, ans);
}

TEST_F(UsbCameraFunctionTest, NoRequiredFields) {
  auto probe_function = CreateProbeFunction<FakeUsbCameraFunction>();

  // No required field "idProduct".
  SetCameraDevice(0, {{"idVendor", "5678"},
                      {"manufacturer", "ABC"},
                      {"product", "ABC Camera"},
                      {"bcdDevice", "9876"},
                      {"removable", "FIXED"}});
  SetCameraDevice(1, {{"idProduct", "4321"}, {"idVendor", "8765"}});

  probe_function->fake_cap_ = {.capabilities = V4L2_CAP_DEVICE_CAPS,
                               .device_caps = V4L2_CAP_VIDEO_CAPTURE};

  auto result = probe_function->Eval();
  // Only contain results that meet the required fields.
  auto ans = CreateProbeResultFromJson(
      base::StringPrintf(R"JSON(
    [
      {
        "bus_type": "usb",
        "usb_product_id": "4321",
        "usb_vendor_id": "8765",
        "path": "%s"
      }
    ]
  )JSON",
                         GetPathUnderRoot({"dev/video1"}).value().c_str()));
  EXPECT_EQ(result, ans);
}

TEST_F(UsbCameraFunctionTest, QueryCapFailed) {
  auto probe_function = CreateProbeFunction<FakeUsbCameraFunction>();

  SetCameraDevice(0, {{"idProduct", "1234"}, {"idVendor", "5678"}});

  probe_function->fake_cap_ = std::nullopt;

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(UsbCameraFunctionTest, InvalidCap) {
  auto probe_function = CreateProbeFunction<FakeUsbCameraFunction>();

  SetCameraDevice(0, {{"idProduct", "1234"}, {"idVendor", "5678"}});

  // Cameras should have CAPTURE capability but no OUTPUT capability.
  probe_function->fake_cap_ = {
      .capabilities = V4L2_CAP_DEVICE_CAPS,
      .device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_OUTPUT};

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

TEST_F(UsbCameraFunctionTest, NoSysfsData) {
  auto probe_function = CreateProbeFunction<FakeUsbCameraFunction>();

  SetFile({kDevPath, "video0"}, "don't care");

  probe_function->fake_cap_ = {.capabilities = V4L2_CAP_DEVICE_CAPS,
                               .device_caps = V4L2_CAP_VIDEO_CAPTURE};

  auto result = probe_function->Eval();
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
