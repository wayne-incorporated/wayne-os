// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/proto_mojom_conversion.h"

#include <gtest/gtest.h>
#include <string>
#include <utility>

const char kMockConfigurationName[] = "fake_configuration";
const char kMockErrorSource[] = "Mock Error Source";
const char kMockErrorString[] = "Mock Error String";

namespace {

constexpr int kNumSupportedConfigurations = 3;

}  // namespace

namespace chromeos {
namespace media_perception {
namespace mojom {

namespace {

mri::VideoStreamParams CreateVideoStreamParamsProto(
    int width_in_pixels,
    int height_in_pixels,
    float frame_rate_in_frames_per_second) {
  mri::VideoStreamParams params;
  params.set_width_in_pixels(width_in_pixels);
  params.set_height_in_pixels(height_in_pixels);
  params.set_frame_rate_in_frames_per_second(frame_rate_in_frames_per_second);
  params.set_pixel_format(mri::PixelFormat::I420);
  return params;
}

mri::VideoDevice CreateVideoDeviceProto(std::string id,
                                        std::string display_name,
                                        std::string model_id,
                                        bool in_use) {
  mri::VideoDevice device;
  device.set_id(id);
  device.set_display_name(display_name);
  device.set_model_id(model_id);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    int j = i * kNumSupportedConfigurations;
    mri::VideoStreamParams* params = device.add_supported_configurations();
    *params = CreateVideoStreamParamsProto(j, j + 1, j + 2);
  }
  device.set_in_use(in_use);
  if (in_use) {
    mri::VideoStreamParams* params = device.mutable_configuration();
    *params = CreateVideoStreamParamsProto(1, 2, 3);
  }
  return device;
}

mri::AudioStreamParams CreateAudioStreamParamsProto(
    float frequency_in_hz,
    int num_channels,
    int frame_size,
    mri::SampleFormat sample_format) {
  mri::AudioStreamParams params;
  params.set_frequency_in_hz(frequency_in_hz);
  params.set_num_channels(num_channels);
  params.set_frame_size(frame_size);
  params.set_sample_format(sample_format);
  return params;
}

mri::AudioDevice CreateAudioDeviceProto(std::string id,
                                        std::string display_name) {
  mri::AudioDevice device;
  device.set_id(id);
  device.set_display_name(display_name);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    int j = i * kNumSupportedConfigurations;
    mri::AudioStreamParams* params = device.add_supported_configurations();
    *params = CreateAudioStreamParamsProto(
        j, j + 1, j + 2, mri::SampleFormat::SND_PCM_FORMAT_S32_LE);
  }
  mri::AudioStreamParams* params = device.mutable_configuration();
  *params = CreateAudioStreamParamsProto(
      1, 2, 3, mri::SampleFormat::SND_PCM_FORMAT_S16_LE);
  return device;
}

TEST(ProtoMojomConversionTest, SuccessStatusToMojom) {
  mri::SuccessStatus status;
  status.set_success(false);
  status.set_failure_reason("failed");

  SuccessStatusPtr status_ptr = ToMojom(status);
  EXPECT_EQ(status_ptr->success, false);
  EXPECT_EQ(*status_ptr->failure_reason, "failed");
}

TEST(ProtoMojomConversionTest, VideoStreamParamsToMojom) {
  mri::VideoStreamParams params = CreateVideoStreamParamsProto(1, 2, 3);

  VideoStreamParamsPtr params_ptr = ToMojom(params);
  EXPECT_EQ(params_ptr->width_in_pixels, 1);
  EXPECT_EQ(params_ptr->height_in_pixels, 2);
  EXPECT_EQ(params_ptr->frame_rate_in_frames_per_second, 3);
  EXPECT_EQ(params_ptr->pixel_format, PixelFormat::I420);
}

TEST(ProtoMojomConversionTest, VideoDeviceToMojom) {
  mri::VideoDevice device =
      CreateVideoDeviceProto("id", "display_name", "model_id", true);

  VideoDevicePtr device_ptr = ToMojom(device);
  EXPECT_EQ(device_ptr->id, "id");
  EXPECT_EQ(*device_ptr->display_name, "display_name");
  EXPECT_EQ(*device_ptr->model_id, "model_id");
  EXPECT_EQ(device_ptr->in_use, true);
  EXPECT_EQ(device_ptr->configuration->width_in_pixels, 1);
  EXPECT_EQ(device_ptr->configuration->height_in_pixels, 2);
  EXPECT_EQ(device_ptr->configuration->frame_rate_in_frames_per_second, 3);
  EXPECT_EQ(device_ptr->configuration->pixel_format, PixelFormat::I420);
  EXPECT_EQ(device_ptr->supported_configurations.size(),
            kNumSupportedConfigurations);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    EXPECT_EQ(device_ptr->supported_configurations[i]->width_in_pixels,
              i * kNumSupportedConfigurations);
  }
}

TEST(ProtoMojomConversionTest, VirtualVideoDeviceToMojom) {
  mri::VirtualVideoDevice device;
  mri::VideoDevice* video_device = device.mutable_video_device();
  *video_device =
      CreateVideoDeviceProto("id", "display_name", "model_id", true);
  VirtualVideoDevicePtr device_ptr = ToMojom(device);
  EXPECT_EQ(device_ptr->video_device->id, "id");
}

TEST(ProtoMojomConversionTest, AudioStreamParamsToMojom) {
  mri::AudioStreamParams params = CreateAudioStreamParamsProto(
      1, 2, 3, mri::SampleFormat::SND_PCM_FORMAT_S32_LE);
  AudioStreamParamsPtr params_ptr = ToMojom(params);
  EXPECT_EQ(params_ptr->frequency_in_hz, 1);
  EXPECT_EQ(params_ptr->num_channels, 2);
  EXPECT_EQ(params_ptr->frame_size, 3);
  EXPECT_EQ(params_ptr->sample_format, SampleFormat::SND_PCM_FORMAT_S32_LE);

  params = CreateAudioStreamParamsProto(
      1, 2, 3, mri::SampleFormat::SND_PCM_FORMAT_S16_LE);
  params_ptr = ToMojom(params);
  EXPECT_EQ(params_ptr->sample_format, SampleFormat::SND_PCM_FORMAT_S16_LE);
}

TEST(ProtoMojomConversionTest, AudioDeviceToMojom) {
  mri::AudioDevice device = CreateAudioDeviceProto("id", "display_name");
  AudioDevicePtr device_ptr = ToMojom(device);
  EXPECT_EQ(device_ptr->id, "id");
  EXPECT_EQ(*device_ptr->display_name, "display_name");
  EXPECT_EQ(device_ptr->configuration->frequency_in_hz, 1);
  EXPECT_EQ(device_ptr->configuration->num_channels, 2);
  EXPECT_EQ(device_ptr->supported_configurations.size(),
            kNumSupportedConfigurations);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    EXPECT_EQ(device_ptr->supported_configurations[i]->frequency_in_hz,
              i * kNumSupportedConfigurations);
  }
}

TEST(ProtoMojomConversionTest, DeviceTemplateToMojom) {
  mri::DeviceTemplate device_template;
  device_template.set_template_name("template_name");
  device_template.set_device_type(mri::DeviceType::VIRTUAL_VIDEO);
  DeviceTemplatePtr template_ptr = ToMojom(device_template);
  EXPECT_EQ(template_ptr->template_name, "template_name");
  EXPECT_EQ(template_ptr->device_type, DeviceType::VIRTUAL_VIDEO);
}

TEST(ProtoMojomConversionTest, NormalizedBoundingBoxToMojom) {
  mri::NormalizedBoundingBox bbox;
  bbox.set_x_min(0.1);
  bbox.set_y_min(0.2);
  bbox.set_x_max(0.7);
  bbox.set_y_max(0.8);
  bbox.set_normalization_width(10);
  bbox.set_normalization_height(20);

  NormalizedBoundingBoxPtr bbox_ptr = ToMojom(bbox);
  EXPECT_FLOAT_EQ(bbox_ptr->x_min, 0.1);
  EXPECT_FLOAT_EQ(bbox_ptr->y_min, 0.2);
  EXPECT_FLOAT_EQ(bbox_ptr->x_max, 0.7);
  EXPECT_FLOAT_EQ(bbox_ptr->y_max, 0.8);
  EXPECT_EQ(bbox_ptr->normalization_width, 10);
  EXPECT_EQ(bbox_ptr->normalization_height, 20);
}

TEST(ProtoMojomConversionTest, DistanceToMojom) {
  mri::Distance distance;
  distance.set_units(mri::DistanceUnits::METERS);
  distance.set_magnitude(1.5);

  DistancePtr distance_ptr = ToMojom(distance);
  EXPECT_EQ(distance_ptr->units, DistanceUnits::METERS);
  EXPECT_FLOAT_EQ(distance_ptr->magnitude, 1.5);
}

TEST(ProtoMojomConversionTest, HotwordDetectionToMojom) {
  mri::HotwordDetection hotword_detection;

  mri::Hotword* hotword1 = hotword_detection.add_hotwords();
  hotword1->set_type(mri::HotwordType::OK_GOOGLE);
  hotword1->set_start_timestamp_ms(100);
  hotword1->set_end_timestamp_ms(250);

  mri::Hotword* hotword2 = hotword_detection.add_hotwords();
  hotword2->set_start_timestamp_ms(560);
  hotword2->set_end_timestamp_ms(700);

  HotwordDetectionPtr hotword_detection_ptr = ToMojom(hotword_detection);
  EXPECT_EQ(hotword_detection_ptr->hotwords.size(), 2);

  EXPECT_EQ(hotword_detection_ptr->hotwords[0]->type, HotwordType::OK_GOOGLE);
  EXPECT_EQ(hotword_detection_ptr->hotwords[0]->start_timestamp_ms, 100);
  EXPECT_EQ(hotword_detection_ptr->hotwords[0]->end_timestamp_ms, 250);

  EXPECT_EQ(hotword_detection_ptr->hotwords[1]->type,
            HotwordType::HOTWORD_TYPE_UNKNOWN);
  EXPECT_EQ(hotword_detection_ptr->hotwords[1]->start_timestamp_ms, 560);
  EXPECT_EQ(hotword_detection_ptr->hotwords[1]->end_timestamp_ms, 700);
}

TEST(ProtoMojomConversionTest, EntityToMojom) {
  mri::Entity entity;
  entity.set_type(mri::EntityType::FACE);
  entity.set_label("face 0");
  entity.set_confidence(0.1);
  entity.mutable_depth()->set_units(mri::DistanceUnits::METERS);
  entity.mutable_bounding_box()->set_x_min(0.2);

  EntityPtr entity_ptr = ToMojom(entity);
  EXPECT_EQ(entity_ptr->type, EntityType::FACE);
  EXPECT_EQ(*entity_ptr->label, "face 0");
  EXPECT_FLOAT_EQ(entity_ptr->confidence, 0.1);
  EXPECT_EQ(entity_ptr->depth->units, DistanceUnits::METERS);
  EXPECT_FLOAT_EQ(entity_ptr->bounding_box->x_min, 0.2);
}

TEST(ProtoMojomConversionTest, FramePerceptionToMojom) {
  mri::FramePerception perception;
  perception.set_frame_id(1);
  perception.set_timestamp_us(157);
  perception.add_perception_types(mri::FramePerceptionType::FACE_DETECTION);
  perception.add_perception_types(mri::FramePerceptionType::PERSON_DETECTION);
  perception.add_perception_types(mri::FramePerceptionType::MOTION_DETECTION);
  perception.add_entities()->set_type(mri::EntityType::FACE);
  perception.add_entities()->set_type(mri::EntityType::PERSON);
  perception.add_entities()->set_type(mri::EntityType::MOTION_REGION);
  perception.add_entities()->set_type(mri::EntityType::LABELED_REGION);

  FramePerceptionPtr perception_ptr = ToMojom(perception);
  EXPECT_EQ(perception_ptr->frame_id, 1);
  EXPECT_EQ(perception_ptr->timestamp_us, 157);
  EXPECT_EQ(perception_ptr->perception_types.size(), 3);
  EXPECT_EQ(perception_ptr->perception_types[0],
            FramePerceptionType::FACE_DETECTION);
  EXPECT_EQ(perception_ptr->perception_types[1],
            FramePerceptionType::PERSON_DETECTION);
  EXPECT_EQ(perception_ptr->perception_types[2],
            FramePerceptionType::MOTION_DETECTION);
  EXPECT_EQ(perception_ptr->entities.size(), 4);
  EXPECT_EQ(perception_ptr->entities[0]->type, EntityType::FACE);
  EXPECT_EQ(perception_ptr->entities[1]->type, EntityType::PERSON);
  EXPECT_EQ(perception_ptr->entities[2]->type, EntityType::MOTION_REGION);
  EXPECT_EQ(perception_ptr->entities[3]->type, EntityType::LABELED_REGION);
}

TEST(ProtoMojomConversionTest, PipelineErrorToMojom) {
  mri::PipelineError error;
  error.set_error_type(mri::PipelineErrorType::CONFIGURATION);
  error.set_error_source(kMockErrorSource);
  error.set_error_string(kMockErrorString);

  PipelineErrorPtr error_ptr = ToMojom(error);
  EXPECT_EQ(error_ptr->error_type, PipelineErrorType::CONFIGURATION);
  EXPECT_EQ(*error_ptr->error_source, kMockErrorSource);
  EXPECT_EQ(*error_ptr->error_string, kMockErrorString);
}

TEST(ProtoMojomConversionTest, PipelineStateToMojom) {
  mri::PipelineState state;
  state.set_configuration_name(kMockConfigurationName);
  state.set_status(mri::PipelineStatus::RUNNING);

  mri::PipelineError& error = *state.mutable_error();
  error.set_error_type(mri::PipelineErrorType::CONFIGURATION);
  error.set_error_source(kMockErrorSource);
  error.set_error_string(kMockErrorString);

  PipelineStatePtr state_ptr = ToMojom(state);
  EXPECT_EQ(state_ptr->status, PipelineStatus::RUNNING);
  EXPECT_EQ(*state_ptr->configuration_name, kMockConfigurationName);

  PipelineErrorPtr& error_ptr = state_ptr->error;
  EXPECT_EQ(error_ptr->error_type, PipelineErrorType::CONFIGURATION);
  EXPECT_EQ(*error_ptr->error_source, kMockErrorSource);
  EXPECT_EQ(*error_ptr->error_string, kMockErrorString);
}

TEST(ProtoMojomConversionTest, GlobalPipelineStateToMojom) {
  mri::GlobalPipelineState state;
  state.add_states()->set_configuration_name("0");
  state.add_states()->set_configuration_name("1");

  GlobalPipelineStatePtr state_ptr = ToMojom(state);
  EXPECT_EQ(*state_ptr->states[0]->configuration_name, "0");
  EXPECT_EQ(*state_ptr->states[1]->configuration_name, "1");
}

TEST(ProtoMojomConversionTest, PresencePerceptionToMojom) {
  mri::PresencePerception perception;
  perception.set_timestamp_us(100);
  perception.set_presence_confidence(0.5);

  PresencePerceptionPtr perception_ptr = ToMojom(perception);
  EXPECT_EQ(perception_ptr->timestamp_us, 100);
  EXPECT_FLOAT_EQ(perception_ptr->presence_confidence, 0.5);
}

TEST(ProtoMojomConversionTest, OccupancyTriggerToMojom) {
  mri::OccupancyTrigger occupancy_trigger;
  occupancy_trigger.set_trigger(true);
  occupancy_trigger.set_timestamp_ms(100);

  OccupancyTriggerPtr occupancy_ptr = ToMojom(occupancy_trigger);
  EXPECT_EQ(occupancy_ptr->trigger, true);
  EXPECT_EQ(occupancy_ptr->timestamp_ms, 100);
}

}  // namespace
}  // namespace mojom
}  // namespace media_perception
}  // namespace chromeos

namespace mri {
namespace {

chromeos::media_perception::mojom::VideoStreamParamsPtr
CreateVideoStreamParamsPtr(int width_in_pixels,
                           int height_in_pixels,
                           float frame_rate_in_frames_per_second) {
  chromeos::media_perception::mojom::VideoStreamParamsPtr params_ptr =
      chromeos::media_perception::mojom::VideoStreamParams::New();
  params_ptr->width_in_pixels = width_in_pixels;
  params_ptr->height_in_pixels = height_in_pixels;
  params_ptr->frame_rate_in_frames_per_second = frame_rate_in_frames_per_second;
  params_ptr->pixel_format =
      chromeos::media_perception::mojom::PixelFormat::I420;
  return params_ptr;
}

chromeos::media_perception::mojom::VideoDevicePtr CreateVideoDevicePtr(
    std::string id,
    std::string display_name,
    std::string model_id,
    bool in_use) {
  chromeos::media_perception::mojom::VideoDevicePtr device_ptr =
      chromeos::media_perception::mojom::VideoDevice::New();
  device_ptr->id = id;
  device_ptr->display_name = display_name;
  device_ptr->model_id = model_id;
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    int j = i * kNumSupportedConfigurations;
    device_ptr->supported_configurations.push_back(
        CreateVideoStreamParamsPtr(j, j + 1, j + 2));
  }
  device_ptr->in_use = in_use;
  if (in_use) {
    device_ptr->configuration = CreateVideoStreamParamsPtr(1, 2, 3);
  }
  return device_ptr;
}

chromeos::media_perception::mojom::AudioStreamParamsPtr
CreateAudioStreamParamsPtr(float frequency_in_hz,
                           int num_channels,
                           int frame_size) {
  chromeos::media_perception::mojom::AudioStreamParamsPtr params_ptr =
      chromeos::media_perception::mojom::AudioStreamParams::New();
  params_ptr->frequency_in_hz = frequency_in_hz;
  params_ptr->num_channels = num_channels;
  params_ptr->frame_size = frame_size;
  params_ptr->sample_format =
      chromeos::media_perception::mojom::SampleFormat::SND_PCM_FORMAT_S16_LE;
  return params_ptr;
}

chromeos::media_perception::mojom::AudioDevicePtr CreateAudioDevicePtr(
    std::string id, std::string display_name) {
  chromeos::media_perception::mojom::AudioDevicePtr device_ptr =
      chromeos::media_perception::mojom::AudioDevice::New();
  device_ptr->id = id;
  device_ptr->display_name = display_name;
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    int j = i * kNumSupportedConfigurations;
    device_ptr->supported_configurations.push_back(
        CreateAudioStreamParamsPtr(j, j + 1, j + 2));
  }
  device_ptr->configuration = CreateAudioStreamParamsPtr(1, 2, 3);
  return device_ptr;
}

TEST(ProtoMojomConversionTest, SuccessStatusToProto) {
  chromeos::media_perception::mojom::SuccessStatusPtr status_ptr =
      chromeos::media_perception::mojom::SuccessStatus::New();
  status_ptr->success = true;
  *status_ptr->failure_reason = "failed";

  SuccessStatus status = ToProto(status_ptr);
  EXPECT_EQ(status.success(), true);
  EXPECT_EQ(status.failure_reason(), "failed");
}

TEST(ProtoMojomConversionTest, VideoStreamParamsToProto) {
  chromeos::media_perception::mojom::VideoStreamParamsPtr params_ptr;
  VideoStreamParams params = ToProto(params_ptr);
  EXPECT_EQ(params.width_in_pixels(), 0);

  params = ToProto(CreateVideoStreamParamsPtr(1, 2, 3));
  EXPECT_EQ(params.width_in_pixels(), 1);
  EXPECT_EQ(params.height_in_pixels(), 2);
  EXPECT_EQ(params.frame_rate_in_frames_per_second(), 3);
  EXPECT_EQ(params.pixel_format(), PixelFormat::I420);
}

TEST(ProtoMojomConversionTest, VideoDeviceToProto) {
  chromeos::media_perception::mojom::VideoDevicePtr device_ptr =
      CreateVideoDevicePtr("id", "display_name", "model_id", true);

  VideoDevice device = ToProto(device_ptr);
  EXPECT_EQ(device.id(), "id");
  EXPECT_EQ(device.display_name(), "display_name");
  EXPECT_EQ(device.model_id(), "model_id");
  EXPECT_EQ(device.in_use(), true);
  EXPECT_EQ(device.configuration().width_in_pixels(), 1);
  EXPECT_EQ(device.configuration().height_in_pixels(), 2);
  EXPECT_EQ(device.configuration().frame_rate_in_frames_per_second(), 3);
  EXPECT_EQ(device.configuration().pixel_format(), PixelFormat::I420);
  EXPECT_EQ(device.supported_configurations().size(),
            kNumSupportedConfigurations);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    EXPECT_EQ(device.supported_configurations(i).width_in_pixels(),
              i * kNumSupportedConfigurations);
  }
}

TEST(ProtoMojomConversionTest, VirtualVideoDeviceToProto) {
  chromeos::media_perception::mojom::VirtualVideoDevicePtr device_ptr =
      chromeos::media_perception::mojom::VirtualVideoDevice::New();
  device_ptr->video_device =
      CreateVideoDevicePtr("id", "display_name", "model_id", true);
  VirtualVideoDevice device = ToProto(device_ptr);
  EXPECT_EQ(device.video_device().id(), "id");
}

TEST(ProtoMojomConversionTest, AudioStreamParamsToProto) {
  chromeos::media_perception::mojom::AudioStreamParamsPtr params_ptr;
  AudioStreamParams params = ToProto(params_ptr);
  EXPECT_EQ(params.frequency_in_hz(), 0);

  params = ToProto(CreateAudioStreamParamsPtr(1, 2, 3));
  EXPECT_EQ(params.frequency_in_hz(), 1);
  EXPECT_EQ(params.num_channels(), 2);
  EXPECT_EQ(params.frame_size(), 3);
  EXPECT_EQ(params.sample_format(), SampleFormat::SND_PCM_FORMAT_S16_LE);
}

TEST(ProtoMojomConversionTest, AudioDeviceToProto) {
  chromeos::media_perception::mojom::AudioDevicePtr device_ptr =
      CreateAudioDevicePtr("id", "display_name");

  AudioDevice device = ToProto(device_ptr);
  EXPECT_EQ(device.id(), "id");
  EXPECT_EQ(device.display_name(), "display_name");
  EXPECT_EQ(device.configuration().frequency_in_hz(), 1);
  EXPECT_EQ(device.configuration().num_channels(), 2);
  EXPECT_EQ(device.supported_configurations().size(),
            kNumSupportedConfigurations);
  for (int i = 0; i < kNumSupportedConfigurations; i++) {
    EXPECT_EQ(device.supported_configurations(i).frequency_in_hz(),
              i * kNumSupportedConfigurations);
  }
}

TEST(ProtoMojomConversionTest, DeviceTemplateToProto) {
  chromeos::media_perception::mojom::DeviceTemplatePtr template_ptr =
      chromeos::media_perception::mojom::DeviceTemplate::New();
  template_ptr->template_name = "template_name";
  template_ptr->device_type =
      chromeos::media_perception::mojom::DeviceType::VIRTUAL_VIDEO;
  DeviceTemplate device_template = ToProto(template_ptr);
  EXPECT_EQ(device_template.template_name(), "template_name");
  EXPECT_EQ(device_template.device_type(), DeviceType::VIRTUAL_VIDEO);
}

TEST(ProtoMojomConversionTest, NormalizedBoundingBoxToProto) {
  chromeos::media_perception::mojom::NormalizedBoundingBoxPtr bbox_ptr =
      chromeos::media_perception::mojom::NormalizedBoundingBox::New();
  bbox_ptr->x_min = 0.1;
  bbox_ptr->y_min = 0.2;
  bbox_ptr->x_max = 0.7;
  bbox_ptr->y_max = 0.8;
  bbox_ptr->normalization_width = 10;
  bbox_ptr->normalization_height = 20;

  NormalizedBoundingBox bbox = ToProto(bbox_ptr);
  EXPECT_FLOAT_EQ(bbox.x_min(), 0.1);
  EXPECT_FLOAT_EQ(bbox.y_min(), 0.2);
  EXPECT_FLOAT_EQ(bbox.x_max(), 0.7);
  EXPECT_FLOAT_EQ(bbox.y_max(), 0.8);
  EXPECT_FLOAT_EQ(bbox.normalization_width(), 10);
  EXPECT_FLOAT_EQ(bbox.normalization_height(), 20);
}

TEST(ProtoMojomConversionTest, DistanceToProto) {
  chromeos::media_perception::mojom::DistancePtr distance_ptr =
      chromeos::media_perception::mojom::Distance::New();
  distance_ptr->units =
      chromeos::media_perception::mojom::DistanceUnits::METERS;
  distance_ptr->magnitude = 1.5;

  Distance distance = ToProto(distance_ptr);
  EXPECT_EQ(distance.units(), DistanceUnits::METERS);
  EXPECT_FLOAT_EQ(distance.magnitude(), 1.5);
}

TEST(ProtoMojomConversionTest, HotwordDetectionToProto) {
  chromeos::media_perception::mojom::HotwordDetectionPtr hotword_detection_ptr =
      chromeos::media_perception::mojom::HotwordDetection::New();
  hotword_detection_ptr->hotwords.resize(2);

  hotword_detection_ptr->hotwords[0] =
      chromeos::media_perception::mojom::Hotword::New();
  hotword_detection_ptr->hotwords[0]->type =
      chromeos::media_perception::mojom::HotwordType::HOTWORD_TYPE_UNKNOWN;
  hotword_detection_ptr->hotwords[0]->start_timestamp_ms = 100;
  hotword_detection_ptr->hotwords[0]->end_timestamp_ms = 250;

  hotword_detection_ptr->hotwords[1] =
      chromeos::media_perception::mojom::Hotword::New();
  hotword_detection_ptr->hotwords[1]->type =
      chromeos::media_perception::mojom::HotwordType::OK_GOOGLE;
  hotword_detection_ptr->hotwords[1]->start_timestamp_ms = 560;
  hotword_detection_ptr->hotwords[1]->end_timestamp_ms = 700;

  HotwordDetection hotword_detection = ToProto(hotword_detection_ptr);
  EXPECT_EQ(hotword_detection.hotwords_size(), 2);

  EXPECT_EQ(hotword_detection.hotwords(0).type(),
            HotwordType::HOTWORD_TYPE_UNKNOWN);
  EXPECT_EQ(hotword_detection.hotwords(0).start_timestamp_ms(), 100);
  EXPECT_EQ(hotword_detection.hotwords(0).end_timestamp_ms(), 250);

  EXPECT_EQ(hotword_detection.hotwords(1).type(), HotwordType::OK_GOOGLE);
  EXPECT_EQ(hotword_detection.hotwords(1).start_timestamp_ms(), 560);
  EXPECT_EQ(hotword_detection.hotwords(1).end_timestamp_ms(), 700);
}

TEST(ProtoMojomConversionTest, EntityToProto) {
  chromeos::media_perception::mojom::EntityPtr entity_ptr =
      chromeos::media_perception::mojom::Entity::New();
  entity_ptr->type = chromeos::media_perception::mojom::EntityType::FACE;
  *entity_ptr->label = "face 0";
  entity_ptr->confidence = 0.1;
  entity_ptr->depth = chromeos::media_perception::mojom::Distance::New();
  entity_ptr->depth->magnitude = 2.5;
  entity_ptr->bounding_box =
      chromeos::media_perception::mojom::NormalizedBoundingBox::New();
  entity_ptr->bounding_box->x_min = 0.6;

  Entity entity = ToProto(entity_ptr);
  EXPECT_EQ(entity.type(), EntityType::FACE);
  EXPECT_EQ(entity.label(), "face 0");
  EXPECT_FLOAT_EQ(entity.confidence(), 0.1);
  EXPECT_FLOAT_EQ(entity.depth().magnitude(), 2.5);
  EXPECT_FLOAT_EQ(entity.bounding_box().x_min(), 0.6);
}

TEST(ProtoMojomConversionTest, FramePerceptionToProto) {
  chromeos::media_perception::mojom::FramePerceptionPtr perception_ptr =
      chromeos::media_perception::mojom::FramePerception::New();
  perception_ptr->frame_id = 1;
  perception_ptr->timestamp_us = 157;
  perception_ptr->perception_types.push_back(
      chromeos::media_perception::mojom::FramePerceptionType::FACE_DETECTION);
  perception_ptr->perception_types.push_back(
      chromeos::media_perception::mojom::FramePerceptionType::PERSON_DETECTION);
  perception_ptr->perception_types.push_back(
      chromeos::media_perception::mojom::FramePerceptionType::MOTION_DETECTION);
  perception_ptr->entities.resize(4);
  perception_ptr->entities[0] =
      chromeos::media_perception::mojom::Entity::New();
  perception_ptr->entities[1] =
      chromeos::media_perception::mojom::Entity::New();
  perception_ptr->entities[2] =
      chromeos::media_perception::mojom::Entity::New();
  perception_ptr->entities[3] =
      chromeos::media_perception::mojom::Entity::New();
  perception_ptr->entities[0]->type =
      chromeos::media_perception::mojom::EntityType::FACE;
  perception_ptr->entities[1]->type =
      chromeos::media_perception::mojom::EntityType::PERSON;
  perception_ptr->entities[2]->type =
      chromeos::media_perception::mojom::EntityType::MOTION_REGION;
  perception_ptr->entities[3]->type =
      chromeos::media_perception::mojom::EntityType::LABELED_REGION;

  FramePerception perception = ToProto(perception_ptr);
  EXPECT_EQ(perception.frame_id(), 1);
  EXPECT_EQ(perception.timestamp_us(), 157);
  EXPECT_EQ(perception.perception_types_size(), 3);
  EXPECT_EQ(perception.perception_types(0),
            FramePerceptionType::FACE_DETECTION);
  EXPECT_EQ(perception.perception_types(1),
            FramePerceptionType::PERSON_DETECTION);
  EXPECT_EQ(perception.perception_types(2),
            FramePerceptionType::MOTION_DETECTION);
  EXPECT_EQ(perception.entities_size(), 4);
  EXPECT_EQ(perception.entities(0).type(), EntityType::FACE);
  EXPECT_EQ(perception.entities(1).type(), EntityType::PERSON);
  EXPECT_EQ(perception.entities(2).type(), EntityType::MOTION_REGION);
  EXPECT_EQ(perception.entities(3).type(), EntityType::LABELED_REGION);
}

TEST(ProtoMojomConversionTest, PipelineErrorToProto) {
  // Construct mojom ptr for PipelineError.
  chromeos::media_perception::mojom::PipelineErrorPtr error_ptr =
      chromeos::media_perception::mojom::PipelineError::New();
  error_ptr->error_type =
      chromeos::media_perception::mojom::PipelineErrorType::CONFIGURATION;
  *error_ptr->error_source = kMockErrorSource;
  *error_ptr->error_string = kMockErrorString;

  PipelineError error = ToProto(error_ptr);
  EXPECT_EQ(error.error_type(), PipelineErrorType::CONFIGURATION);
  EXPECT_EQ(error.error_source(), kMockErrorSource);
  EXPECT_EQ(error.error_string(), kMockErrorString);
}

TEST(ProtoMojomConversionTest, PipelineStateToProto) {
  chromeos::media_perception::mojom::PipelineStatePtr state_ptr =
      chromeos::media_perception::mojom::PipelineState::New();
  state_ptr->status =
      chromeos::media_perception::mojom::PipelineStatus::RUNNING;

  state_ptr->error = chromeos::media_perception::mojom::PipelineError::New();

  state_ptr->error->error_type =
      chromeos::media_perception::mojom::PipelineErrorType::CONFIGURATION;
  *state_ptr->error->error_source = kMockErrorSource;
  *state_ptr->error->error_string = kMockErrorString;

  *state_ptr->configuration_name = kMockConfigurationName;

  PipelineState state = ToProto(state_ptr);
  EXPECT_EQ(state.status(), PipelineStatus::RUNNING);
  EXPECT_EQ(state.configuration_name(), kMockConfigurationName);
  EXPECT_EQ(state.error().error_type(), PipelineErrorType::CONFIGURATION);
  EXPECT_EQ(state.error().error_source(), kMockErrorSource);
  EXPECT_EQ(state.error().error_string(), kMockErrorString);
}

TEST(ProtoMojomConversionTest, PresencePerceptionToProto) {
  chromeos::media_perception::mojom::PresencePerceptionPtr perception_ptr =
      chromeos::media_perception::mojom::PresencePerception::New();
  perception_ptr->timestamp_us = 100;
  perception_ptr->presence_confidence = 0.5;

  PresencePerception perception = ToProto(perception_ptr);
  EXPECT_EQ(perception.timestamp_us(), 100);
  EXPECT_FLOAT_EQ(perception.presence_confidence(), 0.5);
}

TEST(ProtoMojomConversionTest, OccupancyTriggerToProto) {
  chromeos::media_perception::mojom::OccupancyTriggerPtr occupancy_ptr =
      chromeos::media_perception::mojom::OccupancyTrigger::New();
  occupancy_ptr->trigger = true;
  occupancy_ptr->timestamp_ms = 100;

  OccupancyTrigger occupancy_trigger = ToProto(occupancy_ptr);
  EXPECT_EQ(occupancy_trigger.trigger(), true);
  EXPECT_EQ(occupancy_trigger.timestamp_ms(), 100);
}

}  // namespace
}  // namespace mri
