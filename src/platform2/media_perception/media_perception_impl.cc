// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/media_perception_impl.h"

#include <utility>
#include <vector>

#include "base/check.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "media_perception/media_perception_mojom.pb.h"
#include "media_perception/perception_interface.pb.h"
#include "media_perception/proto_mojom_conversion.h"
#include "media_perception/serialized_proto.h"


namespace mri {

MediaPerceptionImpl::MediaPerceptionImpl(
    mojo::PendingReceiver<chromeos::media_perception::mojom::MediaPerception>
        receiver,
    std::shared_ptr<VideoCaptureServiceClient> vidcap_client,
    std::shared_ptr<ChromeAudioServiceClient> cras_client,
    std::shared_ptr<Rtanalytics> rtanalytics)
    : receiver_(this, std::move(receiver)),
      vidcap_client_(vidcap_client),
      cras_client_(cras_client),
      rtanalytics_(rtanalytics) {
  if (!vidcap_client_->IsConnected()) {
    vidcap_client_->Connect();
  }

  if (!cras_client_->IsConnected()) {
    cras_client_->Connect();
  }

  CHECK(rtanalytics_.get())
      << "Rtanalytics is a nullptr: " << rtanalytics_.get();
}

void MediaPerceptionImpl::set_connection_error_handler(
    base::RepeatingClosure connection_error_handler) {
  receiver_.set_disconnect_handler(std::move(connection_error_handler));
}

void MediaPerceptionImpl::SetupConfiguration(
    const std::string& configuration_name,
    SetupConfigurationCallback callback) {
  SerializedSuccessStatus serialized_status;
  SerializedPerceptionInterfaces serialized_perception_interfaces =
      rtanalytics_->SetupConfiguration(configuration_name, &serialized_status);
  PerceptionInterfaces perception_interfaces =
      Serialized<PerceptionInterfaces>(serialized_perception_interfaces)
          .Deserialize();

  SuccessStatus status =
      Serialized<SuccessStatus>(serialized_status).Deserialize();
  chromeos::media_perception::mojom::PerceptionInterfacesPtr interfaces_ptr =
      chromeos::media_perception::mojom::PerceptionInterfaces::New();

  // Sets up perception interfaces and assigns output handlers.
  configuration_name_to_output_manager_map_[configuration_name] =
      std::make_unique<OutputManager>(configuration_name, rtanalytics_,
                                      perception_interfaces, &interfaces_ptr);
  std::move(callback).Run(chromeos::media_perception::mojom::ToMojom(status),
                          std::move(interfaces_ptr));
}

void MediaPerceptionImpl::SetTemplateArguments(
    const std::string& configuration_name,
    const std::vector<uint8_t>& serialized_arguments_proto,
    SetTemplateArgumentsCallback callback) {
  SerializedSuccessStatus serialized_status =
      rtanalytics_->SetTemplateArguments(configuration_name,
                                         serialized_arguments_proto);
  std::move(callback).Run(chromeos::media_perception::mojom::ToMojom(
      Serialized<SuccessStatus>(serialized_status).Deserialize()));
}

void MediaPerceptionImpl::GetVideoDevices(GetVideoDevicesCallback callback) {
  // Get the list of video devices from the VideoCaptureServiceClient and
  // convert them to mojom objects.
  auto repeating_callback =
      base::AdaptCallbackForRepeating(std::move(callback));
  vidcap_client_->GetDevices([repeating_callback](
                                 std::vector<SerializedVideoDevice> devices) {
    std::vector<chromeos::media_perception::mojom::VideoDevicePtr>
        mojom_devices;
    for (const SerializedVideoDevice& device : devices) {
      VideoDevice video_device = Serialized<VideoDevice>(device).Deserialize();
      mojom_devices.push_back(
          chromeos::media_perception::mojom::ToMojom(video_device));
    }
    repeating_callback.Run(std::move(mojom_devices));
  });
}

void MediaPerceptionImpl::GetAudioDevices(GetAudioDevicesCallback callback) {
  // Get the list of audio devices from the ChromeAudioServiceClient and convert
  // them to mojom objects.
  std::vector<SerializedAudioDevice> devices = cras_client_->GetInputDevices();
  std::vector<chromeos::media_perception::mojom::AudioDevicePtr> mojom_devices;
  for (const SerializedAudioDevice& device : devices) {
    AudioDevice audio_device = Serialized<AudioDevice>(device).Deserialize();
    mojom_devices.push_back(
        chromeos::media_perception::mojom::ToMojom(audio_device));
  }
  std::move(callback).Run(std::move(mojom_devices));
}

void MediaPerceptionImpl::GetTemplateDevices(
    const std::string& configuration_name,
    GetTemplateDevicesCallback callback) {
  std::vector<SerializedDeviceTemplate> device_templates =
      rtanalytics_->GetTemplateDevices(configuration_name);
  std::vector<chromeos::media_perception::mojom::DeviceTemplatePtr>
      template_ptrs;
  for (const auto& serialized_device_template : device_templates) {
    DeviceTemplate device_template =
        Serialized<DeviceTemplate>(serialized_device_template).Deserialize();
    template_ptrs.push_back(
        chromeos::media_perception::mojom::ToMojom(device_template));
  }
  std::move(callback).Run(std::move(template_ptrs));
}

void MediaPerceptionImpl::SetVideoDeviceForTemplateName(
    const std::string& configuration_name,
    const std::string& template_name,
    chromeos::media_perception::mojom::VideoDevicePtr device,
    SetVideoDeviceForTemplateNameCallback callback) {
  SerializedVideoDevice serialized_video_device =
      Serialized<VideoDevice>(ToProto(device)).GetBytes();
  SerializedSuccessStatus status = rtanalytics_->SetVideoDeviceForTemplateName(
      configuration_name, template_name, serialized_video_device);

  SuccessStatus success_status =
      Serialized<SuccessStatus>(status).Deserialize();
  std::move(callback).Run(
      chromeos::media_perception::mojom::ToMojom(success_status));
}

void MediaPerceptionImpl::SetAudioDeviceForTemplateName(
    const std::string& configuration_name,
    const std::string& template_name,
    chromeos::media_perception::mojom::AudioDevicePtr device,
    SetAudioDeviceForTemplateNameCallback callback) {
  SerializedAudioDevice serialized_audio_device =
      Serialized<AudioDevice>(ToProto(device)).GetBytes();
  SerializedSuccessStatus status = rtanalytics_->SetAudioDeviceForTemplateName(
      configuration_name, template_name, serialized_audio_device);

  SuccessStatus success_status =
      Serialized<SuccessStatus>(status).Deserialize();
  std::move(callback).Run(
      chromeos::media_perception::mojom::ToMojom(success_status));
}

void MediaPerceptionImpl::SetVirtualVideoDeviceForTemplateName(
    const std::string& configuration_name,
    const std::string& template_name,
    chromeos::media_perception::mojom::VirtualVideoDevicePtr device,
    SetVirtualVideoDeviceForTemplateNameCallback callback) {
  SerializedVirtualVideoDevice serialized_virtual_video_device =
      Serialized<VirtualVideoDevice>(ToProto(device)).GetBytes();
  SerializedSuccessStatus status =
      rtanalytics_->SetVirtualVideoDeviceForTemplateName(
          configuration_name, template_name, serialized_virtual_video_device);

  SuccessStatus success_status =
      Serialized<SuccessStatus>(status).Deserialize();
  std::move(callback).Run(
      chromeos::media_perception::mojom::ToMojom(success_status));
}

void MediaPerceptionImpl::GetPipelineState(
    const std::string& configuration_name, GetPipelineStateCallback callback) {
  SerializedPipelineState serialized_pipeline_state =
      rtanalytics_->GetPipelineState(configuration_name);

  PipelineState pipeline_state =
      Serialized<PipelineState>(serialized_pipeline_state).Deserialize();
  std::move(callback).Run(
      chromeos::media_perception::mojom::ToMojom(pipeline_state));
}

void MediaPerceptionImpl::SetPipelineState(
    const std::string& configuration_name,
    chromeos::media_perception::mojom::PipelineStatePtr desired_state,
    SetPipelineStateCallback callback) {
  SerializedPipelineState serialized_desired_state =
      Serialized<PipelineState>(ToProto(desired_state)).GetBytes();
  SerializedPipelineState serialized_pipeline_state =
      rtanalytics_->SetPipelineState(configuration_name,
                                     serialized_desired_state);

  PipelineState pipeline_state =
      Serialized<PipelineState>(serialized_pipeline_state).Deserialize();
  std::move(callback).Run(
      chromeos::media_perception::mojom::ToMojom(pipeline_state));
}

void MediaPerceptionImpl::GetGlobalPipelineState(
    GetGlobalPipelineStateCallback callback) {
  SerializedGlobalPipelineState serialized_state =
      rtanalytics_->GetGlobalPipelineState();

  GlobalPipelineState state =
      Serialized<GlobalPipelineState>(serialized_state).Deserialize();
  std::move(callback).Run(chromeos::media_perception::mojom::ToMojom(state));
}

}  // namespace mri
