// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_perception/proto_mojom_conversion.h"

#include <utility>
#include <vector>

namespace chromeos {
namespace media_perception {
namespace mojom {

SuccessStatusPtr ToMojom(const mri::SuccessStatus& status) {
  SuccessStatusPtr status_ptr = SuccessStatus::New();
  status_ptr->success = status.success();
  status_ptr->failure_reason = status.failure_reason();
  return status_ptr;
}

PixelFormat ToMojom(mri::PixelFormat format) {
  switch (format) {
    case mri::PixelFormat::I420:
      return PixelFormat::I420;
    case mri::PixelFormat::MJPEG:
      return PixelFormat::MJPEG;
    case mri::PixelFormat::NV12:
      return PixelFormat::NV12;
    case mri::PixelFormat::FORMAT_UNKNOWN:
      return PixelFormat::FORMAT_UNKNOWN;
  }
  return PixelFormat::FORMAT_UNKNOWN;
}

VideoStreamParamsPtr ToMojom(const mri::VideoStreamParams& params) {
  VideoStreamParamsPtr params_ptr = VideoStreamParams::New();
  params_ptr->width_in_pixels = params.width_in_pixels();
  params_ptr->height_in_pixels = params.height_in_pixels();
  params_ptr->frame_rate_in_frames_per_second =
      params.frame_rate_in_frames_per_second();
  params_ptr->pixel_format = ToMojom(params.pixel_format());
  return params_ptr;
}

VideoDevicePtr ToMojom(const mri::VideoDevice& device) {
  VideoDevicePtr device_ptr = VideoDevice::New();
  device_ptr->id = device.id();
  device_ptr->display_name = device.display_name();
  device_ptr->model_id = device.model_id();
  std::vector<VideoStreamParamsPtr> supported_configurations;
  for (const mri::VideoStreamParams& params :
       device.supported_configurations()) {
    supported_configurations.push_back(ToMojom(params));
  }
  device_ptr->supported_configurations = std::move(supported_configurations);
  if (device.has_configuration()) {
    device_ptr->configuration = ToMojom(device.configuration());
  }
  device_ptr->in_use = device.in_use();
  return device_ptr;
}

VirtualVideoDevicePtr ToMojom(const mri::VirtualVideoDevice& device) {
  VirtualVideoDevicePtr device_ptr = VirtualVideoDevice::New();
  if (device.has_video_device())
    device_ptr->video_device = ToMojom(device.video_device());
  return device_ptr;
}

SampleFormat ToMojom(mri::SampleFormat format) {
  switch (format) {
    case mri::SampleFormat::SND_PCM_FORMAT_S32_LE:
      return SampleFormat::SND_PCM_FORMAT_S32_LE;
    case mri::SampleFormat::SND_PCM_FORMAT_S16_LE:
      return SampleFormat::SND_PCM_FORMAT_S16_LE;
    case mri::SampleFormat::SND_PCM_UNKNOWN_FORMAT:
      return SampleFormat::SND_PCM_UNKNOWN_FORMAT;
  }
  return SampleFormat::SND_PCM_UNKNOWN_FORMAT;
}

AudioStreamParamsPtr ToMojom(const mri::AudioStreamParams& params) {
  AudioStreamParamsPtr params_ptr = AudioStreamParams::New();
  params_ptr->frequency_in_hz = params.frequency_in_hz();
  params_ptr->num_channels = params.num_channels();
  params_ptr->frame_size = params.frame_size();
  params_ptr->sample_format = ToMojom(params.sample_format());
  return params_ptr;
}

AudioDevicePtr ToMojom(const mri::AudioDevice& device) {
  AudioDevicePtr device_ptr = AudioDevice::New();
  device_ptr->id = device.id();
  device_ptr->display_name = device.display_name();
  std::vector<AudioStreamParamsPtr> supported_configurations;
  for (const mri::AudioStreamParams& params :
       device.supported_configurations()) {
    supported_configurations.push_back(ToMojom(params));
  }
  device_ptr->supported_configurations = std::move(supported_configurations);
  if (device.has_configuration()) {
    device_ptr->configuration = ToMojom(device.configuration());
  }
  return device_ptr;
}

DeviceType ToMojom(mri::DeviceType type) {
  switch (type) {
    case mri::DeviceType::VIDEO:
      return DeviceType::VIDEO;
    case mri::DeviceType::AUDIO:
      return DeviceType::AUDIO;
    case mri::DeviceType::VIRTUAL_VIDEO:
      return DeviceType::VIRTUAL_VIDEO;
    case mri::DeviceType::DEVICE_TYPE_UNKNOWN:
      return DeviceType::TYPE_UNKNOWN;
  }
  return DeviceType::TYPE_UNKNOWN;
}

DeviceTemplatePtr ToMojom(const mri::DeviceTemplate& device_template) {
  DeviceTemplatePtr template_ptr = DeviceTemplate::New();
  template_ptr->template_name = device_template.template_name();
  template_ptr->device_type = ToMojom(device_template.device_type());
  return template_ptr;
}

DistanceUnits ToMojom(mri::DistanceUnits units) {
  switch (units) {
    case mri::DistanceUnits::METERS:
      return DistanceUnits::METERS;
    case mri::DistanceUnits::PIXELS:
      return DistanceUnits::PIXELS;
    case mri::DistanceUnits::UNITS_UNKNOWN:
      return DistanceUnits::UNITS_UNKNOWN;
  }
  return DistanceUnits::UNITS_UNKNOWN;
}

NormalizedBoundingBoxPtr ToMojom(const mri::NormalizedBoundingBox& bbox) {
  NormalizedBoundingBoxPtr bbox_ptr = NormalizedBoundingBox::New();
  bbox_ptr->x_min = bbox.x_min();
  bbox_ptr->y_min = bbox.y_min();
  bbox_ptr->x_max = bbox.x_max();
  bbox_ptr->y_max = bbox.y_max();
  bbox_ptr->normalization_width = bbox.normalization_width();
  bbox_ptr->normalization_height = bbox.normalization_height();
  return bbox_ptr;
}

DistancePtr ToMojom(const mri::Distance& distance) {
  DistancePtr distance_ptr = Distance::New();
  distance_ptr->units = ToMojom(distance.units());
  distance_ptr->magnitude = distance.magnitude();
  return distance_ptr;
}

HotwordType ToMojom(mri::HotwordType type) {
  switch (type) {
    case mri::HotwordType::OK_GOOGLE:
      return HotwordType::OK_GOOGLE;
    case mri::HotwordType::HOTWORD_TYPE_UNKNOWN:
      return HotwordType::HOTWORD_TYPE_UNKNOWN;
  }
  return HotwordType::HOTWORD_TYPE_UNKNOWN;
}

HotwordPtr ToMojom(const mri::Hotword& hotword) {
  HotwordPtr hotword_ptr = Hotword::New();
  hotword_ptr->type = ToMojom(hotword.type());
  hotword_ptr->start_timestamp_ms = hotword.start_timestamp_ms();
  hotword_ptr->end_timestamp_ms = hotword.end_timestamp_ms();
  return hotword_ptr;
}

HotwordDetectionPtr ToMojom(const mri::HotwordDetection& hotword_detection) {
  HotwordDetectionPtr hotword_detection_ptr = HotwordDetection::New();
  for (int i = 0; i < hotword_detection.hotwords_size(); ++i) {
    hotword_detection_ptr->hotwords.push_back(
        ToMojom(hotword_detection.hotwords(i)));
  }
  return hotword_detection_ptr;
}

EntityType ToMojom(mri::EntityType type) {
  switch (type) {
    case mri::EntityType::FACE:
      return EntityType::FACE;
    case mri::EntityType::PERSON:
      return EntityType::PERSON;
    case mri::EntityType::MOTION_REGION:
      return EntityType::MOTION_REGION;
    case mri::EntityType::LABELED_REGION:
      return EntityType::LABELED_REGION;
    case mri::EntityType::ENTITY_TYPE_UNKNOWN:
      return EntityType::ENTITY_TYPE_UNKNOWN;
  }
  return EntityType::ENTITY_TYPE_UNKNOWN;
}

FramePerceptionType ToMojom(mri::FramePerceptionType type) {
  switch (type) {
    case mri::FramePerceptionType::FACE_DETECTION:
      return FramePerceptionType::FACE_DETECTION;
    case mri::FramePerceptionType::PERSON_DETECTION:
      return FramePerceptionType::PERSON_DETECTION;
    case mri::FramePerceptionType::MOTION_DETECTION:
      return FramePerceptionType::MOTION_DETECTION;
    case mri::FramePerceptionType::FRAME_PERCEPTION_TYPE_UNKNOWN:
      return FramePerceptionType::FRAME_PERCEPTION_TYPE_UNKNOWN;
  }
  return FramePerceptionType::FRAME_PERCEPTION_TYPE_UNKNOWN;
}

EntityPtr ToMojom(const mri::Entity& entity) {
  EntityPtr entity_ptr = Entity::New();
  entity_ptr->type = ToMojom(entity.type());
  entity_ptr->label = entity.label();
  entity_ptr->bounding_box = ToMojom(entity.bounding_box());
  entity_ptr->confidence = entity.confidence();
  entity_ptr->depth = ToMojom(entity.depth());
  return entity_ptr;
}

FramePerceptionPtr ToMojom(const mri::FramePerception& perception) {
  FramePerceptionPtr perception_ptr = FramePerception::New();
  perception_ptr->frame_id = perception.frame_id();
  perception_ptr->timestamp_us = perception.timestamp_us();

  for (int i = 0; i < perception.entities_size(); ++i) {
    perception_ptr->entities.push_back(ToMojom(perception.entities(i)));
  }

  for (int i = 0; i < perception.perception_types_size(); ++i) {
    perception_ptr->perception_types.push_back(
        ToMojom(perception.perception_types(i)));
  }

  return perception_ptr;
}

PipelineStatus ToMojom(mri::PipelineStatus status) {
  switch (status) {
    case mri::PipelineStatus::STARTED:
      return PipelineStatus::STARTED;
    case mri::PipelineStatus::RUNNING:
      return PipelineStatus::RUNNING;
    case mri::PipelineStatus::SUSPENDED:
      return PipelineStatus::SUSPENDED;
    case mri::PipelineStatus::ERROR:
      return PipelineStatus::ERROR;
    case mri::PIPELINE_STATUS_UNKNOWN:
      return PipelineStatus::UNKNOWN;
  }
  return PipelineStatus::UNKNOWN;
}

PipelineErrorType ToMojom(mri::PipelineErrorType error_type) {
  switch (error_type) {
    case mri::PipelineErrorType::CONFIGURATION:
      return PipelineErrorType::CONFIGURATION;
    case mri::PipelineErrorType::STARTUP:
      return PipelineErrorType::STARTUP;
    case mri::PipelineErrorType::RUNTIME:
      return PipelineErrorType::RUNTIME;
    case mri::PipelineErrorType::CONTENT:
      return PipelineErrorType::CONTENT;
    case mri::PIPELINE_ERROR_TYPE_UNKNOWN:
      return PipelineErrorType::UNKNOWN;
  }
  return PipelineErrorType::UNKNOWN;
}

PipelineErrorPtr ToMojom(const mri::PipelineError& error) {
  PipelineErrorPtr error_ptr = PipelineError::New();
  error_ptr->error_type = ToMojom(error.error_type());
  error_ptr->error_source = error.error_source();
  error_ptr->error_string = error.error_string();
  return error_ptr;
}

PipelineStatePtr ToMojom(const mri::PipelineState& state) {
  PipelineStatePtr state_ptr = PipelineState::New();
  state_ptr->status = ToMojom(state.status());
  state_ptr->error = ToMojom(state.error());
  state_ptr->configuration_name = state.configuration_name();
  return state_ptr;
}

GlobalPipelineStatePtr ToMojom(const mri::GlobalPipelineState& state) {
  GlobalPipelineStatePtr state_ptr = GlobalPipelineState::New();
  std::vector<PipelineStatePtr> states;
  for (const mri::PipelineState& pipeline_state : state.states()) {
    states.push_back(ToMojom(pipeline_state));
  }
  state_ptr->states = std::move(states);
  return state_ptr;
}

PresencePerceptionPtr ToMojom(const mri::PresencePerception& perception) {
  PresencePerceptionPtr perception_ptr = PresencePerception::New();
  perception_ptr->timestamp_us = perception.timestamp_us();
  perception_ptr->presence_confidence = perception.presence_confidence();
  return perception_ptr;
}

OccupancyTriggerPtr ToMojom(const mri::OccupancyTrigger& occupancy_trigger) {
  OccupancyTriggerPtr occupancy_ptr = OccupancyTrigger::New();
  occupancy_ptr->trigger = occupancy_trigger.trigger();
  occupancy_ptr->timestamp_ms = occupancy_trigger.timestamp_ms();
  return occupancy_ptr;
}

}  // namespace mojom
}  // namespace media_perception
}  // namespace chromeos

namespace mri {

SuccessStatus ToProto(
    const chromeos::media_perception::mojom::SuccessStatusPtr& status_ptr) {
  SuccessStatus status;
  if (status_ptr.is_null())
    return status;
  status.set_success(status_ptr->success);
  if (status_ptr->failure_reason.has_value()) {
    status.set_failure_reason(*status_ptr->failure_reason);
  }
  return status;
}

PixelFormat ToProto(chromeos::media_perception::mojom::PixelFormat format) {
  switch (format) {
    case chromeos::media_perception::mojom::PixelFormat::I420:
      return PixelFormat::I420;
    case chromeos::media_perception::mojom::PixelFormat::MJPEG:
      return PixelFormat::MJPEG;
    case chromeos::media_perception::mojom::PixelFormat::NV12:
      return PixelFormat::NV12;
    case chromeos::media_perception::mojom::PixelFormat::FORMAT_UNKNOWN:
      return PixelFormat::FORMAT_UNKNOWN;
  }
  return PixelFormat::FORMAT_UNKNOWN;
}

VideoStreamParams ToProto(
    const chromeos::media_perception::mojom::VideoStreamParamsPtr& params_ptr) {
  VideoStreamParams params;
  if (params_ptr.is_null())
    return params;
  params.set_width_in_pixels(params_ptr->width_in_pixels);
  params.set_height_in_pixels(params_ptr->height_in_pixels);
  params.set_frame_rate_in_frames_per_second(
      params_ptr->frame_rate_in_frames_per_second);
  params.set_pixel_format(ToProto(params_ptr->pixel_format));
  return params;
}

VideoDevice ToProto(
    const chromeos::media_perception::mojom::VideoDevicePtr& device_ptr) {
  VideoDevice device;
  if (device_ptr.is_null())
    return device;
  device.set_id(device_ptr->id);
  if (device_ptr->display_name.has_value()) {
    device.set_display_name(*device_ptr->display_name);
  }
  if (device_ptr->model_id.has_value()) {
    device.set_model_id(*device_ptr->model_id);
  }
  for (int i = 0; i < device_ptr->supported_configurations.size(); i++) {
    mri::VideoStreamParams* params = device.add_supported_configurations();
    *params = ToProto(device_ptr->supported_configurations[i]);
  }
  if (!device_ptr->configuration.is_null()) {
    mri::VideoStreamParams* params = device.mutable_configuration();
    *params = ToProto(device_ptr->configuration);
  }
  device.set_in_use(device_ptr->in_use);
  return device;
}

VirtualVideoDevice ToProto(
    const chromeos::media_perception::mojom::VirtualVideoDevicePtr&
        device_ptr) {
  VirtualVideoDevice device;
  if (device_ptr.is_null())
    return device;

  VideoDevice* video_device = device.mutable_video_device();
  *video_device = ToProto(device_ptr->video_device);
  return device;
}

SampleFormat ToProto(chromeos::media_perception::mojom::SampleFormat format) {
  switch (format) {
    case chromeos::media_perception::mojom::SampleFormat::SND_PCM_FORMAT_S32_LE:
      return SampleFormat::SND_PCM_FORMAT_S32_LE;
    case chromeos::media_perception::mojom::SampleFormat::SND_PCM_FORMAT_S16_LE:
      return SampleFormat::SND_PCM_FORMAT_S16_LE;
    case chromeos::media_perception::mojom::SampleFormat ::
        SND_PCM_UNKNOWN_FORMAT:
      return SampleFormat::SND_PCM_UNKNOWN_FORMAT;
  }
  return SampleFormat::SND_PCM_UNKNOWN_FORMAT;
}

AudioStreamParams ToProto(
    const chromeos::media_perception::mojom::AudioStreamParamsPtr& params_ptr) {
  AudioStreamParams params;
  if (params_ptr.is_null())
    return params;

  params.set_frequency_in_hz(params_ptr->frequency_in_hz);
  params.set_num_channels(params_ptr->num_channels);
  params.set_frame_size(params_ptr->frame_size);
  params.set_sample_format(ToProto(params_ptr->sample_format));
  return params;
}

AudioDevice ToProto(
    const chromeos::media_perception::mojom::AudioDevicePtr& device_ptr) {
  AudioDevice device;
  if (device_ptr.is_null())
    return device;

  device.set_id(device_ptr->id);
  if (device_ptr->display_name.has_value()) {
    device.set_display_name(*device_ptr->display_name);
  }
  for (int i = 0; i < device_ptr->supported_configurations.size(); i++) {
    mri::AudioStreamParams* params = device.add_supported_configurations();
    *params = ToProto(device_ptr->supported_configurations[i]);
  }
  if (!device_ptr->configuration.is_null()) {
    mri::AudioStreamParams* params = device.mutable_configuration();
    *params = ToProto(device_ptr->configuration);
  }
  return device;
}

DeviceType ToProto(const chromeos::media_perception::mojom::DeviceType type) {
  switch (type) {
    case chromeos::media_perception::mojom::DeviceType::VIDEO:
      return DeviceType::VIDEO;
    case chromeos::media_perception::mojom::DeviceType::AUDIO:
      return DeviceType::AUDIO;
    case chromeos::media_perception::mojom::DeviceType::VIRTUAL_VIDEO:
      return DeviceType::VIRTUAL_VIDEO;
    case chromeos::media_perception::mojom::DeviceType::TYPE_UNKNOWN:
      return DeviceType::DEVICE_TYPE_UNKNOWN;
  }
  return DeviceType::DEVICE_TYPE_UNKNOWN;
}

DeviceTemplate ToProto(
    const chromeos::media_perception::mojom::DeviceTemplatePtr& template_ptr) {
  DeviceTemplate device_template;
  if (template_ptr.is_null())
    return device_template;

  device_template.set_template_name(template_ptr->template_name);
  device_template.set_device_type(ToProto(template_ptr->device_type));
  return device_template;
}

DistanceUnits ToProto(chromeos::media_perception::mojom::DistanceUnits units) {
  switch (units) {
    case chromeos::media_perception::mojom::DistanceUnits::METERS:
      return DistanceUnits::METERS;
    case chromeos::media_perception::mojom::DistanceUnits::PIXELS:
      return DistanceUnits::PIXELS;
    case chromeos::media_perception::mojom::DistanceUnits::UNITS_UNKNOWN:
      return DistanceUnits::UNITS_UNKNOWN;
  }
  return DistanceUnits::UNITS_UNKNOWN;
}

NormalizedBoundingBox ToProto(
    const chromeos::media_perception::mojom::NormalizedBoundingBoxPtr&
        bbox_ptr) {
  NormalizedBoundingBox bbox;
  if (bbox_ptr.is_null())
    return bbox;

  bbox.set_x_min(bbox_ptr->x_min);
  bbox.set_y_min(bbox_ptr->y_min);
  bbox.set_x_max(bbox_ptr->x_max);
  bbox.set_y_max(bbox_ptr->y_max);
  bbox.set_normalization_width(bbox_ptr->normalization_width);
  bbox.set_normalization_height(bbox_ptr->normalization_height);
  return bbox;
}

Distance ToProto(
    const chromeos::media_perception::mojom::DistancePtr& distance_ptr) {
  Distance distance;
  if (distance_ptr.is_null())
    return distance;

  distance.set_units(ToProto(distance_ptr->units));
  distance.set_magnitude(distance_ptr->magnitude);
  return distance;
}

HotwordType ToProto(chromeos::media_perception::mojom::HotwordType type) {
  switch (type) {
    case chromeos::media_perception::mojom::HotwordType::OK_GOOGLE:
      return HotwordType::OK_GOOGLE;
    case chromeos::media_perception::mojom::HotwordType::HOTWORD_TYPE_UNKNOWN:
      return HotwordType::HOTWORD_TYPE_UNKNOWN;
  }
  return HotwordType::HOTWORD_TYPE_UNKNOWN;
}

Hotword ToProto(
    const chromeos::media_perception::mojom::HotwordPtr& hotword_ptr) {
  Hotword hotword;
  if (hotword_ptr.is_null())
    return hotword;

  hotword.set_type(ToProto(hotword_ptr->type));
  hotword.set_start_timestamp_ms(hotword_ptr->start_timestamp_ms);
  hotword.set_end_timestamp_ms(hotword_ptr->end_timestamp_ms);
  return hotword;
}

HotwordDetection ToProto(
    const chromeos::media_perception::mojom::HotwordDetectionPtr&
        hotword_detection_ptr) {
  HotwordDetection hotword_detection;
  if (hotword_detection_ptr.is_null())
    return hotword_detection;

  for (const auto& hotword : hotword_detection_ptr->hotwords)
    *hotword_detection.add_hotwords() = ToProto(hotword);

  return hotword_detection;
}

EntityType ToProto(chromeos::media_perception::mojom::EntityType type) {
  switch (type) {
    case chromeos::media_perception::mojom::EntityType::FACE:
      return EntityType::FACE;
    case chromeos::media_perception::mojom::EntityType::PERSON:
      return EntityType::PERSON;
    case chromeos::media_perception::mojom::EntityType::MOTION_REGION:
      return EntityType::MOTION_REGION;
    case chromeos::media_perception::mojom::EntityType::LABELED_REGION:
      return EntityType::LABELED_REGION;
    case chromeos::media_perception::mojom::EntityType::ENTITY_TYPE_UNKNOWN:
      return EntityType::ENTITY_TYPE_UNKNOWN;
  }
  return EntityType::ENTITY_TYPE_UNKNOWN;
}

FramePerceptionType ToProto(
    chromeos::media_perception::mojom::FramePerceptionType type) {
  switch (type) {
    case chromeos::media_perception::mojom::FramePerceptionType::FACE_DETECTION:
      return FramePerceptionType::FACE_DETECTION;
    case chromeos::media_perception::mojom::FramePerceptionType ::
        PERSON_DETECTION:
      return FramePerceptionType::PERSON_DETECTION;
    case chromeos::media_perception::mojom::FramePerceptionType ::
        MOTION_DETECTION:
      return FramePerceptionType::MOTION_DETECTION;
    case chromeos::media_perception::mojom::FramePerceptionType ::
        FRAME_PERCEPTION_TYPE_UNKNOWN:
      return FramePerceptionType::FRAME_PERCEPTION_TYPE_UNKNOWN;
  }
  return FramePerceptionType::FRAME_PERCEPTION_TYPE_UNKNOWN;
}

Entity ToProto(const chromeos::media_perception::mojom::EntityPtr& entity_ptr) {
  Entity entity;
  if (entity_ptr.is_null())
    return entity;

  entity.set_type(ToProto(entity_ptr->type));
  if (entity_ptr->label.has_value()) {
    entity.set_label(*entity_ptr->label);
  }
  *entity.mutable_bounding_box() = ToProto(entity_ptr->bounding_box);
  entity.set_confidence(entity_ptr->confidence);
  *entity.mutable_depth() = ToProto(entity_ptr->depth);
  return entity;
}

FramePerception ToProto(
    const chromeos::media_perception::mojom::FramePerceptionPtr&
        perception_ptr) {
  FramePerception perception;
  if (perception_ptr.is_null())
    return perception;

  perception.set_frame_id(perception_ptr->frame_id);
  perception.set_timestamp_us(perception_ptr->timestamp_us);

  for (const auto& entity : perception_ptr->entities)
    *perception.add_entities() = ToProto(entity);

  for (const auto& perception_type : perception_ptr->perception_types)
    perception.add_perception_types(ToProto(perception_type));

  return perception;
}

PipelineStatus ToProto(
    chromeos::media_perception::mojom::PipelineStatus status) {
  switch (status) {
    case chromeos::media_perception::mojom::PipelineStatus::STARTED:
      return PipelineStatus::STARTED;
    case chromeos::media_perception::mojom::PipelineStatus::RUNNING:
      return PipelineStatus::RUNNING;
    case chromeos::media_perception::mojom::PipelineStatus::SUSPENDED:
      return PipelineStatus::SUSPENDED;
    case chromeos::media_perception::mojom::PipelineStatus::ERROR:
      return PipelineStatus::ERROR;
    case chromeos::media_perception::mojom::PipelineStatus::UNKNOWN:
      return PipelineStatus::PIPELINE_STATUS_UNKNOWN;
  }
  return PipelineStatus::PIPELINE_STATUS_UNKNOWN;
}

PipelineErrorType ToProto(
    chromeos::media_perception::mojom::PipelineErrorType error_type) {
  switch (error_type) {
    case chromeos::media_perception::mojom::PipelineErrorType::CONFIGURATION:
      return PipelineErrorType::CONFIGURATION;
    case chromeos::media_perception::mojom::PipelineErrorType::STARTUP:
      return PipelineErrorType::STARTUP;
    case chromeos::media_perception::mojom::PipelineErrorType::RUNTIME:
      return PipelineErrorType::RUNTIME;
    case chromeos::media_perception::mojom::PipelineErrorType::CONTENT:
      return PipelineErrorType::CONTENT;
    case chromeos::media_perception::mojom::PipelineErrorType::UNKNOWN:
      return PipelineErrorType::PIPELINE_ERROR_TYPE_UNKNOWN;
  }
  return PipelineErrorType::PIPELINE_ERROR_TYPE_UNKNOWN;
}

PipelineError ToProto(
    const chromeos::media_perception::mojom::PipelineErrorPtr& error_ptr) {
  PipelineError error;
  if (error_ptr.is_null())
    return error;
  error.set_error_type(ToProto(error_ptr->error_type));
  if (error_ptr->error_source.has_value()) {
    error.set_error_source(*error_ptr->error_source);
  }
  if (error_ptr->error_string.has_value()) {
    error.set_error_string(*error_ptr->error_string);
  }
  return error;
}

PipelineState ToProto(
    const chromeos::media_perception::mojom::PipelineStatePtr& state_ptr) {
  PipelineState state;
  if (state_ptr.is_null())
    return state;
  state.set_status(ToProto(state_ptr->status));

  *state.mutable_error() = ToProto(state_ptr->error);
  if (state_ptr->configuration_name.has_value()) {
    state.set_configuration_name(*state_ptr->configuration_name);
  }
  return state;
}

PresencePerception ToProto(
    const chromeos::media_perception::mojom::PresencePerceptionPtr&
        perception_ptr) {
  PresencePerception perception;
  if (perception_ptr.is_null())
    return perception;

  perception.set_timestamp_us(perception_ptr->timestamp_us);
  perception.set_presence_confidence(perception_ptr->presence_confidence);
  return perception;
}

OccupancyTrigger ToProto(
    const chromeos::media_perception::mojom::OccupancyTriggerPtr&
        occupancy_ptr) {
  OccupancyTrigger occupancy_trigger;
  if (occupancy_ptr.is_null())
    return occupancy_trigger;

  occupancy_trigger.set_trigger(occupancy_ptr->trigger);
  occupancy_trigger.set_timestamp_ms(occupancy_ptr->timestamp_ms);
  return occupancy_trigger;
}

}  // namespace mri
