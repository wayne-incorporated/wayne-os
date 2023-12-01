// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/fake_video_capture_service_client.h"

namespace mri {

bool FakeVideoCaptureServiceClient::Connect() {
  connected_ = true;
  return connected_;
}

bool FakeVideoCaptureServiceClient::IsConnected() {
  return connected_;
}

void FakeVideoCaptureServiceClient::SetDevicesForGetDevices(
    std::vector<SerializedVideoDevice> devices) {
  devices_ = devices;
}

void FakeVideoCaptureServiceClient::GetDevices(
    const GetDevicesCallback& callback) {
  callback(devices_);
}

void FakeVideoCaptureServiceClient::OpenDevice(
    const std::string& device_id,
    bool force_reopen_with_settings,
    const SerializedVideoStreamParams& capture_format,
    const OpenDeviceCallback& callback) {}

bool FakeVideoCaptureServiceClient::IsVideoCaptureStartedForDevice(
    const std::string& device_id, SerializedVideoStreamParams* capture_format) {
  return false;
}

int FakeVideoCaptureServiceClient::AddFrameHandler(const std::string& device_id,
                                                   FrameHandler frame_handler) {
  return 0;
}

void FakeVideoCaptureServiceClient::CreateVirtualDevice(
    const SerializedVideoDevice& video_device,
    const VirtualDeviceCallback& callback) {}

void FakeVideoCaptureServiceClient::PushFrameToVirtualDevice(
    const std::string& device_id,
    uint64_t timestamp_in_microseconds,
    std::unique_ptr<const uint8_t[]> data,
    int data_size,
    RawPixelFormat pixel_format,
    int frame_width,
    int frame_height) {}

void FakeVideoCaptureServiceClient::CloseVirtualDevice(
    const std::string& device_id) {}

bool FakeVideoCaptureServiceClient::RemoveFrameHandler(
    const std::string& device_id, int frame_handler_id) {
  return false;
}

}  // namespace mri
