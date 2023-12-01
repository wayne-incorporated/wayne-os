// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/mojo_connector.h"

#include <algorithm>
#include <map>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/invitation.h>

#include "media_perception/mojom/video_capture_types.mojom.h"
#include "media_perception/serialized_proto.h"

namespace mri {

namespace {

CreatePushSubscriptionResultCode GetCreatePushSubscriptionResultCode(
    video_capture::mojom::CreatePushSubscriptionResultCodePtr code) {
  if (!code->is_success_code()) {
    return CreatePushSubscriptionResultCode::FAILED;
  }
  switch (code->get_success_code()) {
    case video_capture::mojom::CreatePushSubscriptionSuccessCode::
        kCreatedWithDifferentSettings:
      return CreatePushSubscriptionResultCode::CREATED_WITH_DIFFERENT_SETTINGS;
    case video_capture::mojom::CreatePushSubscriptionSuccessCode::
        kCreatedWithRequestedSettings:
      return CreatePushSubscriptionResultCode::CREATED_WITH_REQUESTED_SETTINGS;
  }
  return CreatePushSubscriptionResultCode::RESULT_UNKNOWN;
}

PixelFormat GetPixelFormatFromVideoCapturePixelFormat(
    media::mojom::VideoCapturePixelFormat format) {
  switch (format) {
    case media::mojom::VideoCapturePixelFormat::I420:
      return PixelFormat::I420;
    case media::mojom::VideoCapturePixelFormat::MJPEG:
      return PixelFormat::MJPEG;
    case media::mojom::VideoCapturePixelFormat::NV12:
      return PixelFormat::NV12;
    default:
      return PixelFormat::FORMAT_UNKNOWN;
  }
}

media::mojom::VideoCapturePixelFormat GetVideoCapturePixelFormatFromPixelFormat(
    PixelFormat pixel_format) {
  switch (pixel_format) {
    case PixelFormat::I420:
      return media::mojom::VideoCapturePixelFormat::I420;
    case PixelFormat::MJPEG:
      return media::mojom::VideoCapturePixelFormat::MJPEG;
    case PixelFormat::NV12:
      return media::mojom::VideoCapturePixelFormat::NV12;
    default:
      return media::mojom::VideoCapturePixelFormat::UNKNOWN;
  }
}

bool DeviceIdIsOverviewStreamIpAddress(const std::string& device_id) {
  // Check for the existence of four "." characters.
  return std::count(device_id.begin(), device_id.end(), '.') == 4;
}

constexpr char kConnectorPipe[] = "mpp-connector-pipe";

}  // namespace

MojoConnector::MojoConnector() : ipc_thread_("IpcThread") {
  mojo::core::Init();
  LOG(INFO) << "Starting IPC thread.";
  if (!ipc_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOG(ERROR) << "Failed to start IPC Thread";
  }
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  unique_device_counter_ = 1;
}

void MojoConnector::SetVideoCaptureServiceClient(
    std::shared_ptr<VideoCaptureServiceClient> video_capture_service_client) {
  video_capture_service_client_ = video_capture_service_client;
}

void MojoConnector::SetChromeAudioServiceClient(
    std::shared_ptr<ChromeAudioServiceClient> chrome_audio_service_client) {
  chrome_audio_service_client_ = chrome_audio_service_client;
}

void MojoConnector::SetRtanalytics(std::shared_ptr<Rtanalytics> rtanalytics) {
  rtanalytics_ = rtanalytics;
}

void MojoConnector::ReceiveMojoInvitationFileDescriptor(int fd_int) {
  base::ScopedFD fd(fd_int);
  if (!fd.is_valid()) {
    LOG(ERROR) << "FD is not valid.";
    return;
  }
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&MojoConnector::AcceptConnectionOnIpcThread,
                                base::Unretained(this), std::move(fd)));
}

void MojoConnector::OnConnectionErrorOrClosed() {
  LOG(ERROR) << "Connection error/closed received";
}

void MojoConnector::OnVideoSourceProviderConnectionErrorOrClosed() {
  std::lock_guard<std::mutex> lock(vcs_connection_state_mutex_);
  is_connected_to_vcs_ = false;
}

void MojoConnector::AcceptConnectionOnIpcThread(base::ScopedFD fd) {
  CHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  mojo::IncomingInvitation invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(fd))));
  mojo::ScopedMessagePipeHandle child_pipe =
      invitation.ExtractMessagePipe(kConnectorPipe);
  if (!child_pipe.is_valid()) {
    LOG(ERROR) << "child_pipe is not valid";
  }
  media_perception_service_impl_ = std::make_unique<MediaPerceptionServiceImpl>(
      std::move(child_pipe),
      base::BindRepeating(&MojoConnector::OnConnectionErrorOrClosed,
                          base::Unretained(this)),
      video_capture_service_client_, chrome_audio_service_client_,
      rtanalytics_);
}

void MojoConnector::ConnectToVideoCaptureService() {
  std::lock_guard<std::mutex> lock(vcs_connection_state_mutex_);
  if (!is_connected_to_vcs_) {
    ipc_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&MojoConnector::ConnectToVideoCaptureServiceOnIpcThread,
                       base::Unretained(this)));
    is_connected_to_vcs_ = true;
  }
}

void MojoConnector::ConnectToVideoCaptureServiceOnIpcThread() {
  unique_device_counter_ = 1;

  media_perception_service_impl_->ConnectToVideoCaptureService(
      video_source_provider_.BindNewPipeAndPassReceiver());
  video_source_provider_.set_disconnect_handler(base::BindRepeating(
      &MojoConnector::OnVideoSourceProviderConnectionErrorOrClosed,
      base::Unretained(this)));
}

bool MojoConnector::IsConnectedToVideoCaptureService() {
  std::lock_guard<std::mutex> lock(vcs_connection_state_mutex_);
  return is_connected_to_vcs_;
}

void MojoConnector::GetDevices(
    const VideoCaptureServiceClient::GetDevicesCallback& callback) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&MojoConnector::GetDevicesOnIpcThread,
                                base::Unretained(this), callback));
}

void MojoConnector::GetDevicesOnIpcThread(
    const VideoCaptureServiceClient::GetDevicesCallback& callback) {
  video_source_provider_->GetSourceInfos(base::BindOnce(
      &MojoConnector::OnDeviceInfosReceived, base::Unretained(this), callback));
}

std::string MojoConnector::GetObfuscatedDeviceId(
    const std::string& device_id, const std::string& display_name) {
  const std::string unique_id = device_id + display_name;
  std::map<std::string, std::string>::iterator it =
      unique_id_map_.find(unique_id);
  if (it == unique_id_map_.end()) {
    // If the device ID is an IP address there is no need to obfuscate it
    // and we need it to send PTZ commands via the IP peripheral service.
    std::string obfuscated_id = DeviceIdIsOverviewStreamIpAddress(device_id)
                                    ? device_id
                                    : std::to_string(unique_device_counter_);
    unique_id_map_.insert(std::make_pair(unique_id, obfuscated_id));
    // Increment the counter so the next obfuscated id is different.
    unique_device_counter_++;
    return obfuscated_id;
  }

  // Obfuscated id already created for this device.
  return it->second;
}

void MojoConnector::OnDeviceInfosReceived(
    const VideoCaptureServiceClient::GetDevicesCallback& callback,
    std::vector<media::mojom::VideoCaptureDeviceInfoPtr> infos) {
  LOG(INFO) << "Got callback for device infos.";
  std::vector<SerializedVideoDevice> devices;
  for (const auto& capture_device : infos) {
    VideoDevice device;
    const std::string device_id = capture_device->descriptor->device_id;
    const std::string obfuscated_device_id = GetObfuscatedDeviceId(
        device_id, capture_device->descriptor->display_name);
    obfuscated_device_id_map_.insert(
        std::make_pair(obfuscated_device_id, device_id));
    device.set_id(obfuscated_device_id);
    device.set_display_name(capture_device->descriptor->display_name);
    device.set_model_id(capture_device->descriptor->model_id);
    LOG(INFO) << "Device: " << device.display_name();
    for (const auto& capture_format : capture_device->supported_formats) {
      VideoStreamParams supported_format;
      supported_format.set_width_in_pixels(capture_format->frame_size->width);
      supported_format.set_height_in_pixels(capture_format->frame_size->height);
      supported_format.set_frame_rate_in_frames_per_second(
          capture_format->frame_rate);
      supported_format.set_pixel_format(
          GetPixelFormatFromVideoCapturePixelFormat(
              capture_format->pixel_format));
      *device.add_supported_configurations() = supported_format;
    }
    devices.push_back(Serialized<VideoDevice>(device).GetBytes());
  }
  callback(devices);
}

void MojoConnector::OpenDevice(
    const std::string& device_id,
    bool force_reopen_with_settings,
    std::shared_ptr<VideoFrameHandlerImpl> video_frame_handler_impl,
    const VideoStreamParams& capture_format,
    const VideoCaptureServiceClient::OpenDeviceCallback& callback) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&MojoConnector::OpenDeviceOnIpcThread,
                     base::Unretained(this), device_id,
                     force_reopen_with_settings, video_frame_handler_impl,
                     capture_format, callback));
}

void MojoConnector::OpenDeviceOnIpcThread(
    const std::string& device_id,
    bool force_reopen_with_settings,
    std::shared_ptr<VideoFrameHandlerImpl> video_frame_handler_impl,
    const VideoStreamParams& capture_format,
    const VideoCaptureServiceClient::OpenDeviceCallback& callback) {
  std::map<std::string, std::string>::iterator it =
      obfuscated_device_id_map_.find(device_id);
  if (it == obfuscated_device_id_map_.end()) {
    LOG(ERROR) << "Device id not found in obfuscated_device_id map.";
    callback(device_id, CreatePushSubscriptionResultCode::FAILED,
             Serialized<VideoStreamParams>(capture_format).GetBytes());
  }

  std::map<std::string, VideoSourceAndPushSubscription>::iterator device_it =
      device_id_to_active_device_map_.find(device_id);
  // Check to see if the device is already opened.
  if (device_it != device_id_to_active_device_map_.end()) {
    callback(device_id, CreatePushSubscriptionResultCode::ALREADY_OPEN,
             Serialized<VideoStreamParams>(
                 video_frame_handler_impl->GetCaptureFormat())
                 .GetBytes());
    return;
  }

  // Create a new struct and move it into the member variable map.
  VideoSourceAndPushSubscription new_device;
  device_id_to_active_device_map_.insert(
      std::make_pair(device_id, std::move(new_device)));
  device_it = device_id_to_active_device_map_.find(device_id);

  video_source_provider_->GetVideoSource(
      it->second, device_it->second.video_source.BindNewPipeAndPassReceiver());

  auto requested_settings = media::mojom::VideoCaptureParams::New();
  requested_settings->requested_format =
      media::mojom::VideoCaptureFormat::New();

  requested_settings->requested_format->frame_rate =
      capture_format.frame_rate_in_frames_per_second();

  requested_settings->requested_format->pixel_format =
      GetVideoCapturePixelFormatFromPixelFormat(capture_format.pixel_format());

  requested_settings->requested_format->frame_size = gfx::mojom::Size::New();
  requested_settings->requested_format->frame_size->width =
      capture_format.width_in_pixels();
  requested_settings->requested_format->frame_size->height =
      capture_format.height_in_pixels();

  requested_settings->buffer_type =
      media::mojom::VideoCaptureBufferType::kSharedMemoryViaRawFileDescriptor;

  device_it->second.video_source->CreatePushSubscription(
      video_frame_handler_impl->CreateInterfacePendingRemote(),
      std::move(requested_settings), force_reopen_with_settings,
      device_it->second.push_video_stream_subscription
          .BindNewPipeAndPassReceiver(),
      base::BindOnce(&MojoConnector::OnCreatePushSubscriptionCallback,
                     base::Unretained(this), device_id, callback));
}

void MojoConnector::OnCreatePushSubscriptionCallback(
    const std::string& device_id,
    const VideoCaptureServiceClient::OpenDeviceCallback& callback,
    video_capture::mojom::CreatePushSubscriptionResultCodePtr code,
    media::mojom::VideoCaptureParamsPtr settings_opened_with) {
  VideoStreamParams params;
  params.set_frame_rate_in_frames_per_second(
      settings_opened_with->requested_format->frame_rate);
  params.set_pixel_format(GetPixelFormatFromVideoCapturePixelFormat(
      settings_opened_with->requested_format->pixel_format));
  params.set_width_in_pixels(
      settings_opened_with->requested_format->frame_size->width);
  params.set_height_in_pixels(
      settings_opened_with->requested_format->frame_size->height);
  callback(device_id, GetCreatePushSubscriptionResultCode(std::move(code)),
           Serialized<VideoStreamParams>(params).GetBytes());
}

bool MojoConnector::ActivateDevice(const std::string& device_id) {
  std::map<std::string, VideoSourceAndPushSubscription>::iterator it =
      device_id_to_active_device_map_.find(device_id);
  if (it == device_id_to_active_device_map_.end()) {
    LOG(ERROR) << "Device id not found in active device map.";
    return false;
  }
  it->second.push_video_stream_subscription->Activate();
  return true;
}

void MojoConnector::StopVideoCapture(const std::string& device_id) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&MojoConnector::StopVideoCaptureOnIpcThread,
                                base::Unretained(this), device_id));
}

void MojoConnector::StopVideoCaptureOnIpcThread(const std::string& device_id) {
  device_id_to_active_device_map_.erase(device_id);
}

void MojoConnector::CreateVirtualDevice(
    const VideoDevice& video_device,
    std::shared_ptr<ProducerImpl> producer_impl,
    const VideoCaptureServiceClient::VirtualDeviceCallback& callback) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&MojoConnector::CreateVirtualDeviceOnIpcThread,
                                base::Unretained(this), video_device,
                                producer_impl, callback));
}

void MojoConnector::CreateVirtualDeviceOnIpcThread(
    const VideoDevice& video_device,
    std::shared_ptr<ProducerImpl> producer_impl,
    const VideoCaptureServiceClient::VirtualDeviceCallback& callback) {
  media::mojom::VideoCaptureDeviceInfoPtr info =
      media::mojom::VideoCaptureDeviceInfo::New();
  // TODO(b/3743548): After libchrome uprev, assigning to std::vector<> is
  // just redundant, so should be removed.
  info->supported_formats = std::vector<media::mojom::VideoCaptureFormatPtr>();
  info->descriptor = media::mojom::VideoCaptureDeviceDescriptor::New();
  info->descriptor->model_id = video_device.model_id();
  info->descriptor->device_id = video_device.id();
  info->descriptor->display_name = video_device.display_name();
  info->descriptor->capture_api = media::mojom::VideoCaptureApi::VIRTUAL_DEVICE;
  // No PTZ controls supported.
  info->descriptor->control_support =
      media::mojom::VideoCaptureControlSupport::New();
  info->descriptor->control_support->pan = false;
  info->descriptor->control_support->tilt = false;
  info->descriptor->control_support->zoom = false;
  producer_impl->RegisterVirtualDevice(&video_source_provider_,
                                       std::move(info));

  callback(Serialized<VideoDevice>(video_device).GetBytes());
}

void MojoConnector::PushFrameToVirtualDevice(
    std::shared_ptr<ProducerImpl> producer_impl,
    base::TimeDelta timestamp,
    std::unique_ptr<const uint8_t[]> data,
    int data_size,
    PixelFormat pixel_format,
    int frame_width,
    int frame_height) {
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&MojoConnector::PushFrameToVirtualDeviceOnIpcThread,
                     base::Unretained(this), producer_impl, timestamp,
                     std::move(data), data_size, pixel_format, frame_width,
                     frame_height));
}

void MojoConnector::PushFrameToVirtualDeviceOnIpcThread(
    std::shared_ptr<ProducerImpl> producer_impl,
    base::TimeDelta timestamp,
    std::unique_ptr<const uint8_t[]> data,
    int data_size,
    PixelFormat pixel_format,
    int frame_width,
    int frame_height) {
  producer_impl->PushNextFrame(
      producer_impl, timestamp, std::move(data), data_size,
      GetVideoCapturePixelFormatFromPixelFormat(pixel_format), frame_width,
      frame_height);
}

}  // namespace mri
