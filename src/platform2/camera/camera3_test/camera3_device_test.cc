// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_device_fixture.h"

#include "camera3_test/camera3_device_impl.h"

#include <base/check.h>

namespace camera3_test {

Camera3Device::Camera3Device(int cam_id)
    : impl_(new Camera3DeviceImpl(cam_id)) {}

Camera3Device::~Camera3Device() {}

int Camera3Device::Initialize(Camera3Module* cam_module) {
  DCHECK(impl_);
  return impl_->Initialize(cam_module);
}

void Camera3Device::Destroy() {
  DCHECK(impl_);
  impl_->Destroy();
}

void Camera3Device::RegisterProcessCaptureResultCallback(
    Camera3Device::ProcessCaptureResultCallback cb) {
  DCHECK(impl_);
  impl_->RegisterProcessCaptureResultCallback(cb);
}

void Camera3Device::RegisterNotifyCallback(Camera3Device::NotifyCallback cb) {
  DCHECK(impl_);
  impl_->RegisterNotifyCallback(cb);
}

void Camera3Device::RegisterResultMetadataOutputBufferCallback(
    Camera3Device::ProcessResultMetadataOutputBuffersCallback cb) {
  DCHECK(impl_);
  impl_->RegisterResultMetadataOutputBufferCallback(cb);
}

void Camera3Device::RegisterPartialMetadataCallback(
    Camera3Device::ProcessPartialMetadataCallback cb) {
  DCHECK(impl_);
  impl_->RegisterPartialMetadataCallback(cb);
}

bool Camera3Device::IsTemplateSupported(int32_t type) {
  DCHECK(impl_);
  return impl_->IsTemplateSupported(type);
}

const camera_metadata_t* Camera3Device::ConstructDefaultRequestSettings(
    int type) {
  DCHECK(impl_);
  return impl_->ConstructDefaultRequestSettings(type);
}

void Camera3Device::AddOutputStream(
    int format,
    int width,
    int height,
    camera3_stream_rotation_t crop_rotate_scale_degrees) {
  DCHECK(impl_);
  impl_->AddStream(format, width, height,
                   static_cast<int>(crop_rotate_scale_degrees),
                   CAMERA3_STREAM_OUTPUT);
}

void Camera3Device::AddInputStream(int format, int width, int height) {
  DCHECK(impl_);
  impl_->AddStream(format, width, height, 0, CAMERA3_STREAM_INPUT);
}

void Camera3Device::AddBidirectionalStream(int format, int width, int height) {
  DCHECK(impl_);
  impl_->AddStream(format, width, height, 0, CAMERA3_STREAM_BIDIRECTIONAL);
}

void Camera3Device::AddOutputStreamWithRawDegrees(
    int format, int width, int height, int crop_rotate_scale_degrees) {
  DCHECK(impl_);
  impl_->AddStream(format, width, height, crop_rotate_scale_degrees,
                   CAMERA3_STREAM_OUTPUT);
}

int Camera3Device::ConfigureStreams(
    std::vector<const camera3_stream_t*>* streams) {
  DCHECK(impl_);
  return impl_->ConfigureStreams(streams);
}

int Camera3Device::AllocateOutputStreamBuffers(
    std::vector<camera3_stream_buffer_t>* output_buffers) {
  DCHECK(impl_);
  return impl_->AllocateOutputStreamBuffers(output_buffers);
}

int Camera3Device::AllocateOutputBuffersByStreams(
    const std::vector<const camera3_stream_t*>& streams,
    std::vector<camera3_stream_buffer_t>* output_buffers) {
  DCHECK(impl_);
  return impl_->AllocateOutputBuffersByStreams(streams, output_buffers);
}

int Camera3Device::RegisterOutputBuffer(
    const camera3_stream_t& stream, cros::ScopedBufferHandle unique_buffer) {
  DCHECK(impl_);
  return impl_->RegisterOutputBuffer(stream, std::move(unique_buffer));
}

int Camera3Device::ProcessCaptureRequest(
    camera3_capture_request_t* capture_request) {
  DCHECK(impl_);
  return impl_->ProcessCaptureRequest(capture_request);
}

int Camera3Device::WaitShutter(const struct timespec& timeout) {
  DCHECK(impl_);
  return impl_->WaitShutter(timeout);
}

int Camera3Device::WaitCaptureResult(const struct timespec& timeout) {
  DCHECK(impl_);
  return impl_->WaitCaptureResult(timeout);
}

int Camera3Device::Flush() {
  DCHECK(impl_);
  return impl_->Flush();
}

const Camera3Device::StaticInfo* Camera3Device::GetStaticInfo() const {
  DCHECK(impl_);
  return impl_->GetStaticInfo();
}

Camera3Device::StaticInfo::StaticInfo(const camera_info& cam_info)
    : characteristics_(const_cast<camera_metadata_t*>(
          cam_info.static_camera_characteristics)) {}

bool Camera3Device::StaticInfo::IsKeyAvailable(uint32_t tag) const {
  return AreKeysAvailable(std::vector<uint32_t>(1, tag));
}

bool Camera3Device::StaticInfo::AreKeysAvailable(
    std::vector<uint32_t> tags) const {
  for (const auto& tag : tags) {
    camera_metadata_ro_entry_t entry;
    if (find_camera_metadata_ro_entry(characteristics_, tag, &entry)) {
      return false;
    }
  }
  return true;
}

uint8_t Camera3Device::StaticInfo::GetHardwareLevel() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
                                    &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL";
    return -EINVAL;
  }
  return entry.data.u8[0];
}

bool Camera3Device::StaticInfo::IsHardwareLevelAtLeast(uint8_t level) const {
  return isHardwareLevelSupported(GetHardwareLevel(), level);
}

bool Camera3Device::StaticInfo::IsHardwareLevelAtLeastFull() const {
  return IsHardwareLevelAtLeast(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_FULL);
}

bool Camera3Device::StaticInfo::IsHardwareLevelAtLeastExternal() const {
  return IsHardwareLevelAtLeast(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL);
}

bool Camera3Device::StaticInfo::IsCapabilitySupported(
    uint8_t capability) const {
  EXPECT_GE(capability, 0) << "Capability must be non-negative";

  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
                                    &entry) == 0) {
    return std::find(entry.data.u8, entry.data.u8 + entry.count, capability) !=
           entry.data.u8 + entry.count;
  }
  return false;
}

bool Camera3Device::StaticInfo::IsDepthOutputSupported() const {
  return IsCapabilitySupported(
      ANDROID_REQUEST_AVAILABLE_CAPABILITIES_DEPTH_OUTPUT);
}

bool Camera3Device::StaticInfo::IsColorOutputSupported() const {
  return IsCapabilitySupported(
      ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
}

bool Camera3Device::StaticInfo::HasAvailableRequestKey(int32_t key) const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                    &entry) == 0) {
    return std::find(entry.data.i32, entry.data.i32 + entry.count, key) !=
           entry.data.i32 + entry.count;
  }
  return false;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableModes(
    int32_t key, int32_t min_value, int32_t max_value) const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_, key, &entry) != 0) {
    ADD_FAILURE() << "Cannot find the metadata "
                  << get_camera_metadata_tag_name(key);
    return std::set<uint8_t>();
  }
  std::set<uint8_t> modes;
  for (size_t i = 0; i < entry.count; i++) {
    uint8_t mode = entry.data.u8[i];
    // Each element must be distinct
    EXPECT_TRUE(modes.find(mode) == modes.end())
        << "Duplicate modes " << mode << " for the metadata "
        << get_camera_metadata_tag_name(key);
    EXPECT_TRUE(mode >= min_value && mode <= max_value)
        << "Mode " << mode << " is outside of [" << min_value << ","
        << max_value << "] for the metadata "
        << get_camera_metadata_tag_name(key);
    modes.insert(mode);
  }
  return modes;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableEdgeModes() const {
  std::set<uint8_t> modes = GetAvailableModes(
      ANDROID_EDGE_AVAILABLE_EDGE_MODES, ANDROID_EDGE_MODE_OFF,
      ANDROID_EDGE_MODE_ZERO_SHUTTER_LAG);

  // Full device should always include OFF and FAST
  if (IsHardwareLevelAtLeastFull()) {
    EXPECT_TRUE((modes.find(ANDROID_EDGE_MODE_OFF) != modes.end()) &&
                (modes.find(ANDROID_EDGE_MODE_FAST) != modes.end()))
        << "Full device must contain OFF and FAST edge modes";
  }

  // FAST and HIGH_QUALITY mode must be both present or both not present
  EXPECT_TRUE((modes.find(ANDROID_EDGE_MODE_FAST) != modes.end()) ==
              (modes.find(ANDROID_EDGE_MODE_HIGH_QUALITY) != modes.end()))
      << "FAST and HIGH_QUALITY mode must both present or both not present";

  return modes;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableNoiseReductionModes()
    const {
  std::set<uint8_t> modes =
      GetAvailableModes(ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES,
                        ANDROID_NOISE_REDUCTION_MODE_OFF,
                        ANDROID_NOISE_REDUCTION_MODE_ZERO_SHUTTER_LAG);

  // Full device should always include OFF and FAST
  if (IsHardwareLevelAtLeastFull()) {
    EXPECT_TRUE((modes.find(ANDROID_NOISE_REDUCTION_MODE_OFF) != modes.end()) &&
                (modes.find(ANDROID_NOISE_REDUCTION_MODE_FAST) != modes.end()))
        << "Full device must contain OFF and FAST noise reduction modes";
  }

  // FAST and HIGH_QUALITY mode must be both present or both not present
  EXPECT_TRUE(
      (modes.find(ANDROID_NOISE_REDUCTION_MODE_FAST) != modes.end()) ==
      (modes.find(ANDROID_NOISE_REDUCTION_MODE_HIGH_QUALITY) != modes.end()))
      << "FAST and HIGH_QUALITY mode must both present or both not present";

  return modes;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableColorAberrationModes()
    const {
  std::set<uint8_t> modes =
      GetAvailableModes(ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
                        ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF,
                        ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY);

  EXPECT_TRUE((modes.find(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF) !=
               modes.end()) ||
              (modes.find(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST) !=
               modes.end()))
      << "Camera devices must always support either OFF or FAST mode";

  // FAST and HIGH_QUALITY mode must be both present or both not present
  EXPECT_TRUE(
      (modes.find(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST) !=
       modes.end()) ==
      (modes.find(ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY) !=
       modes.end()))
      << "FAST and HIGH_QUALITY mode must both present or both not present";

  return modes;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableToneMapModes() const {
  std::set<uint8_t> modes = GetAvailableModes(
      ANDROID_TONEMAP_AVAILABLE_TONE_MAP_MODES,
      ANDROID_TONEMAP_MODE_CONTRAST_CURVE, ANDROID_TONEMAP_MODE_PRESET_CURVE);

  EXPECT_TRUE(modes.find(ANDROID_TONEMAP_MODE_FAST) != modes.end())
      << "Camera devices must always support FAST mode";

  // FAST and HIGH_QUALITY mode must be both present
  EXPECT_TRUE(modes.find(ANDROID_TONEMAP_MODE_HIGH_QUALITY) != modes.end())
      << "FAST and HIGH_QUALITY mode must both present";

  return modes;
}

std::set<std::pair<int32_t, int32_t>>
Camera3Device::StaticInfo::GetAvailableFpsRanges() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
          &entry) != 0) {
    ADD_FAILURE() << "Cannot find the metadata "
                     "ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES";
    return {};
  }
  if (entry.count % 2 != 0) {
    ADD_FAILURE() << "Unexpected amount of entries of "
                     "ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES";
    return {};
  }
  std::set<std::pair<int32_t, int32_t>> available_fps_ranges;
  for (size_t i = 0; i < entry.count; i += 2) {
    int32_t min_fps = entry.data.i32[i];
    int32_t max_fps = entry.data.i32[i + 1];
    available_fps_ranges.insert({min_fps, max_fps});
  }
  return available_fps_ranges;
}

void Camera3Device::StaticInfo::GetStreamConfigEntry(
    camera_metadata_ro_entry_t* entry) const {
  entry->count = 0;

  camera_metadata_ro_entry_t local_entry = {};
  ASSERT_EQ(
      0, find_camera_metadata_ro_entry(
             characteristics_, ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
             &local_entry))
      << "Fail to find metadata key "
         "ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS";
  ASSERT_NE(0u, local_entry.count) << "Camera stream configuration is empty";
  ASSERT_EQ(0u, local_entry.count % kNumOfElementsInStreamConfigEntry)
      << "Camera stream configuration parsing error";
  *entry = local_entry;
}

std::set<int32_t> Camera3Device::StaticInfo::GetAvailableFormats(
    int32_t direction) const {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(&available_config);
  std::set<int32_t> formats;
  for (size_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    int32_t format = available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX];
    int32_t in_or_out =
        available_config.data.i32[i + STREAM_CONFIG_DIRECTION_INDEX];
    if (in_or_out == direction) {
      formats.insert(format);
    }
  }
  return formats;
}

bool Camera3Device::StaticInfo::IsFormatAvailable(int format) const {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(&available_config);
  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    if (available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX] == format) {
      return true;
    }
  }
  return false;
}

std::vector<ResolutionInfo>
Camera3Device::StaticInfo::GetSortedOutputResolutions(int32_t format) const {
  return GetSortedResolutions(format, true);
}

std::vector<ResolutionInfo>
Camera3Device::StaticInfo::GetSortedInputResolutions(int32_t format) const {
  return GetSortedResolutions(format, false);
}

std::vector<ResolutionInfo> Camera3Device::StaticInfo::GetSortedResolutions(
    int32_t format, bool is_output) const {
  camera_metadata_ro_entry_t available_config = {};
  GetStreamConfigEntry(&available_config);
  std::vector<ResolutionInfo> available_resolutions;
  const int32_t direction =
      is_output ? ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT
                : ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_INPUT;
  for (uint32_t i = 0; i < available_config.count;
       i += kNumOfElementsInStreamConfigEntry) {
    int32_t fmt = available_config.data.i32[i + STREAM_CONFIG_FORMAT_INDEX];
    int32_t width = available_config.data.i32[i + STREAM_CONFIG_WIDTH_INDEX];
    int32_t height = available_config.data.i32[i + STREAM_CONFIG_HEIGHT_INDEX];
    int32_t in_or_out =
        available_config.data.i32[i + STREAM_CONFIG_DIRECTION_INDEX];
    if (fmt == format && in_or_out == direction) {
      available_resolutions.emplace_back(width, height);
    }
  }
  std::sort(available_resolutions.begin(), available_resolutions.end());
  return available_resolutions;
}

bool Camera3Device::StaticInfo::GetInputOutputConfigurationMap(
    std::map<int32_t, std::vector<int32_t>>* config_map) const {
  camera_metadata_ro_entry_t entry = {};
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_SCALER_AVAILABLE_INPUT_OUTPUT_FORMATS_MAP,
          &entry)) {
    ADD_FAILURE() << "Cannot find the metadata "
                     "ANDROID_SCALER_AVAILABLE_INPUT_OUTPUT_FORMATS_MAP";
    return false;
  }

  /* format of the map is : input format, num_output_formats,
   * outputFormat1,..,outputFormatN */
  uint32_t num_out;
  const int32_t* p = entry.data.i32;
  for (const int32_t* end = p + entry.count; p < end; p += num_out) {
    int32_t in_format = *(p++);
    num_out = *(p++);
    config_map->emplace(std::piecewise_construct,
                        std::forward_as_tuple(in_format),
                        std::forward_as_tuple(p, p + num_out));
  }
  return true;
}

bool Camera3Device::StaticInfo::IsAELockSupported() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_CONTROL_AE_LOCK_AVAILABLE, &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_CONTROL_AE_LOCK_AVAILABLE";
    return false;
  }
  return entry.data.u8[0] == ANDROID_CONTROL_AE_LOCK_AVAILABLE_TRUE;
}

bool Camera3Device::StaticInfo::IsAWBLockSupported() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_CONTROL_AWB_LOCK_AVAILABLE, &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_CONTROL_AWB_LOCK_AVAILABLE";
    return false;
  }
  return entry.data.u8[0] == ANDROID_CONTROL_AWB_LOCK_AVAILABLE_TRUE;
}

int32_t Camera3Device::StaticInfo::GetPartialResultCount() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_REQUEST_PARTIAL_RESULT_COUNT,
                                    &entry) != 0) {
    // Optional key. Default value is 1 if key is missing.
    return 1;
  }
  return entry.data.i32[0];
}

uint8_t Camera3Device::StaticInfo::GetRequestPipelineMaxDepth() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_REQUEST_PIPELINE_MAX_DEPTH, &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_REQUEST_PIPELINE_MAX_DEPTH";
    return -EINVAL;
  }
  return entry.data.u8[0];
}

int32_t Camera3Device::StaticInfo::GetJpegMaxSize() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_, ANDROID_JPEG_MAX_SIZE,
                                    &entry) != 0) {
    ADD_FAILURE() << "Cannot find the metadata ANDROID_JPEG_MAX_SIZE";
    return -EINVAL;
  }
  return entry.data.i32[0];
}

int32_t Camera3Device::StaticInfo::GetSensorOrientation() const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_SENSOR_ORIENTATION, &entry) != 0) {
    ADD_FAILURE() << "Cannot find the metadata ANDROID_SENSOR_ORIENTATION";
    return -EINVAL;
  }
  return entry.data.i32[0];
}

int32_t Camera3Device::StaticInfo::GetAvailableThumbnailSizes(
    std::vector<ResolutionInfo>* resolutions) const {
  const size_t kNumOfEntriesForSize = 2;
  enum { WIDTH_ENTRY_INDEX, HEIGHT_ENTRY_INDEX };
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
                                    &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES";
    return -EINVAL;
  }
  if (entry.count % kNumOfEntriesForSize) {
    ADD_FAILURE() << "Camera JPEG available thumbnail sizes parsing error";
    return -EINVAL;
  }
  for (size_t i = 0; i < entry.count; i += kNumOfEntriesForSize) {
    resolutions->emplace_back(entry.data.i32[i + WIDTH_ENTRY_INDEX],
                              entry.data.i32[i + HEIGHT_ENTRY_INDEX]);
  }
  return 0;
}

int32_t Camera3Device::StaticInfo::GetAvailableFocalLengths(
    std::vector<float>* focal_lengths) const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
                                    &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS";
    return -EINVAL;
  }
  if (entry.count == 0) {
    ADD_FAILURE() << "There should be at least one available focal length";
    return -EINVAL;
  }
  for (size_t i = 0; i < entry.count; i++) {
    EXPECT_LT(0.0f, entry.data.f[i])
        << "Available focal length " << entry.data.f[i]
        << " should be positive";
    focal_lengths->push_back(entry.data.f[i]);
  }
  EXPECT_EQ(
      focal_lengths->size(),
      std::set<float>(focal_lengths->begin(), focal_lengths->end()).size())
      << "Avaliable focal lengths should be distinct";
  return 0;
}

int32_t Camera3Device::StaticInfo::GetAvailableApertures(
    std::vector<float>* apertures) const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(characteristics_,
                                    ANDROID_LENS_INFO_AVAILABLE_APERTURES,
                                    &entry) != 0) {
    ADD_FAILURE()
        << "Cannot find the metadata ANDROID_LENS_INFO_AVAILABLE_APERTURES";
    return -EINVAL;
  }
  if (entry.count == 0) {
    ADD_FAILURE() << "There should be at least one available apertures";
    return -EINVAL;
  }
  for (size_t i = 0; i < entry.count; i++) {
    EXPECT_LT(0.0f, entry.data.f[i])
        << "Available apertures " << entry.data.f[i] << " should be positive";
    apertures->push_back(entry.data.f[i]);
  }
  EXPECT_EQ(apertures->size(),
            std::set<float>(apertures->begin(), apertures->end()).size())
      << "Avaliable apertures should be distinct";
  return 0;
}

int32_t Camera3Device::StaticInfo::GetAvailableAFModes(
    std::vector<uint8_t>* af_modes) const {
  camera_metadata_ro_entry_t entry;
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_CONTROL_AF_AVAILABLE_MODES, &entry) == 0) {
    for (size_t i = 0; i < entry.count; i++) {
      af_modes->push_back(entry.data.u8[i]);
    }
  }
  return 0;
}

int32_t Camera3Device::StaticInfo::GetAvailableTestPatternModes(
    std::vector<int32_t>* test_pattern_modes) const {
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_SENSOR_AVAILABLE_TEST_PATTERN_MODES, &entry);
  if (result == 0) {
    for (size_t i = 0; i < entry.count; i++) {
      test_pattern_modes->push_back(entry.data.i32[i]);
    }
  }
  return result;
}

int32_t Camera3Device::StaticInfo::GetAvailableFaceDetectModes(
    std::set<uint8_t>* face_detect_modes) const {
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
      &entry);
  if (result == 0) {
    for (size_t i = 0; i < entry.count; i++) {
      face_detect_modes->insert(entry.data.u8[i]);
    }
  }
  return result;
}

int32_t Camera3Device::StaticInfo::GetAeMaxRegions() const {
  constexpr size_t kMaxRegionsAeIdx = 0;
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_CONTROL_MAX_REGIONS, &entry);
  return (result == 0 && entry.count > kMaxRegionsAeIdx)
             ? entry.data.i32[kMaxRegionsAeIdx]
             : 0;
}

int32_t Camera3Device::StaticInfo::GetAwbMaxRegions() const {
  constexpr size_t kMaxRegionsAwbIdx = 1;
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_CONTROL_MAX_REGIONS, &entry);
  return (result == 0 && entry.count > kMaxRegionsAwbIdx)
             ? entry.data.i32[kMaxRegionsAwbIdx]
             : 0;
}

int32_t Camera3Device::StaticInfo::GetAfMaxRegions() const {
  constexpr size_t kMaxRegionsAfIdx = 2;
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_CONTROL_MAX_REGIONS, &entry);
  return (result == 0 && entry.count > kMaxRegionsAfIdx)
             ? entry.data.i32[kMaxRegionsAfIdx]
             : 0;
}

int32_t Camera3Device::StaticInfo::GetSensorPixelArraySize(
    uint32_t* width, uint32_t* height) const {
  if (!width || !height) {
    return -EINVAL;
  }
  camera_metadata_ro_entry_t entry;
  int32_t result = find_camera_metadata_ro_entry(
      characteristics_, ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE, &entry);
  if (result == 0 && entry.count == 2) {
    *width = entry.data.i32[0];
    *height = entry.data.i32[1];
  } else if (result == 0) {
    return -ENOENT;
  }
  return result;
}

std::set<uint8_t> Camera3Device::StaticInfo::GetAvailableRotateAndCropModes()
    const {
  camera_metadata_ro_entry_t entry = {};
  if (find_camera_metadata_ro_entry(
          characteristics_, ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES,
          &entry) != 0 ||
      entry.count == 0) {
    return {};
  }
  return std::set<uint8_t>(entry.data.u8, entry.data.u8 + entry.count);
}

// Test fixture

void Camera3DeviceFixture::SetUp() {
  ASSERT_EQ(0, cam_device_.Initialize(&cam_module_))
      << "Camera device initialization fails";
  cam_device_.RegisterResultMetadataOutputBufferCallback(base::BindRepeating(
      &Camera3DeviceFixture::ProcessResultMetadataOutputBuffers,
      base::Unretained(this)));
  cam_device_.RegisterPartialMetadataCallback(base::BindRepeating(
      &Camera3DeviceFixture::ProcessPartialMetadata, base::Unretained(this)));
}

void Camera3DeviceFixture::TearDown() {
  cam_device_.Destroy();
}

// Test cases

// Test spec:
// - Camera ID
class Camera3DeviceSimpleTest : public Camera3DeviceFixture,
                                public ::testing::WithParamInterface<int> {
 public:
  Camera3DeviceSimpleTest() : Camera3DeviceFixture(GetParam()) {}
};

TEST_P(Camera3DeviceSimpleTest, SensorOrientationTest) {
  // Chromebook has a hardware requirement that the top of the camera should
  // match the top of the display in tablet mode.
  ASSERT_EQ(0, cam_device_.GetStaticInfo()->GetSensorOrientation())
      << "Invalid camera sensor orientation";
}

// Test spec:
// - Camera ID
// - Capture type
class Camera3DeviceDefaultSettings
    : public Camera3DeviceFixture,
      public ::testing::WithParamInterface<std::tuple<int, int>> {
 public:
  Camera3DeviceDefaultSettings()
      : Camera3DeviceFixture(std::get<0>(GetParam())) {}
};

static bool IsMetadataKeyAvailable(const camera_metadata_t* settings,
                                   int32_t key) {
  camera_metadata_ro_entry_t entry;
  return find_camera_metadata_ro_entry(settings, key, &entry) == 0;
}

static void ExpectKeyValue(const camera_metadata_t* settings,
                           int32_t key,
                           const char* key_name,
                           int32_t value,
                           int32_t compare_type) {
  camera_metadata_ro_entry_t entry;
  ASSERT_EQ(0, find_camera_metadata_ro_entry(settings, key, &entry))
      << "Cannot find the metadata " << key_name;
  if (compare_type == 0) {
    ASSERT_EQ(value, entry.data.i32[0])
        << "Wrong value of metadata " << key_name;
  } else {
    ASSERT_NE(value, entry.data.i32[0])
        << "Wrong value of metadata " << key_name;
  }
}
#define EXPECT_KEY_VALUE_EQ(settings, key, value) \
  ExpectKeyValue(settings, key, #key, value, 0)
#define EXPECT_KEY_VALUE_NE(settings, key, value) \
  ExpectKeyValue(settings, key, #key, value, 1)

static void ExpectKeyValueNotEqualsI64(const camera_metadata_t* settings,
                                       int32_t key,
                                       const char* key_name,
                                       int64_t value) {
  camera_metadata_ro_entry_t entry;
  ASSERT_EQ(0, find_camera_metadata_ro_entry(settings, key, &entry))
      << "Cannot find the metadata " << key_name;
  ASSERT_NE(value, entry.data.i64[0]) << "Wrong value of metadata " << key_name;
}
#define EXPECT_KEY_VALUE_NE_I64(settings, key, value) \
  ExpectKeyValueNotEqualsI64(settings, key, #key, value)

TEST_P(Camera3DeviceDefaultSettings, ConstructDefaultSettings) {
  int type = std::get<1>(GetParam());
  auto static_info = cam_device_.GetStaticInfo();

  const camera_metadata_t* default_settings;
  default_settings = cam_device_.ConstructDefaultRequestSettings(type);
  if (!default_settings) {
    if (type == CAMERA3_TEMPLATE_MANUAL &&
        !static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_MANUAL_SENSOR)) {
      return;
    } else if (
        type == CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG &&
        !static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING)) {
      return;
    }
  }
  ASSERT_NE(nullptr, default_settings) << "Camera default settings are NULL";

  // Reference: camera2/cts/CameraDeviceTest.java#captureTemplateTestByCamera
  if (!cam_device_.IsTemplateSupported(type)) {
    return;
  } else if (type != CAMERA3_TEMPLATE_PREVIEW &&
             static_info->IsDepthOutputSupported() &&
             !static_info->IsColorOutputSupported()) {
    // Depth-only devices need only support PREVIEW template
    return;
  }

  // Reference: camera2/cts/CameraDeviceTest.java#checkRequestForTemplate
  // 3A settings--control mode
  if (type == CAMERA3_TEMPLATE_MANUAL) {
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_MODE,
                        ANDROID_CONTROL_MODE_OFF);
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AE_MODE,
                        ANDROID_CONTROL_AE_MODE_OFF);
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AWB_MODE,
                        ANDROID_CONTROL_AWB_MODE_OFF);
  } else {
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AE_MODE,
                        ANDROID_CONTROL_AE_MODE_ON);

    EXPECT_KEY_VALUE_EQ(default_settings,
                        ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION, 0);

    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
                        ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER_IDLE);

    // if AE lock is not supported, expect the control key to be non-existent or
    // false
    if (static_info->IsAELockSupported() ||
        IsMetadataKeyAvailable(default_settings, ANDROID_CONTROL_AE_LOCK)) {
      EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AE_LOCK,
                          ANDROID_CONTROL_AE_LOCK_OFF);
    }

    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AF_TRIGGER,
                        ANDROID_CONTROL_AF_TRIGGER_IDLE);

    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AWB_MODE,
                        ANDROID_CONTROL_AWB_MODE_AUTO);

    // if AWB lock is not supported, expect the control key to be non-existent
    // or false
    if (static_info->IsAWBLockSupported() ||
        IsMetadataKeyAvailable(default_settings, ANDROID_CONTROL_AWB_LOCK)) {
      EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_AWB_LOCK,
                          ANDROID_CONTROL_AWB_LOCK_OFF);
    }

    // Check 3A regions
    // TODO(hywu): CONTROL_AE_REGIONS, CONTROL_AWB_REGIONS, CONTROL_AF_REGIONS?
  }

  // Sensor settings
  // TODO(hywu): LENS_APERTURE, LENS_FILTER_DENSITY, LENS_FOCAL_LENGTH,
  //       LENS_OPTICAL_STABILIZATION_MODE?
  //       BLACK_LEVEL_LOCK?

  if (static_info->IsKeyAvailable(ANDROID_BLACK_LEVEL_LOCK)) {
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_BLACK_LEVEL_LOCK,
                        ANDROID_BLACK_LEVEL_LOCK_OFF);
  }

  if (static_info->IsKeyAvailable(ANDROID_SENSOR_FRAME_DURATION)) {
    EXPECT_KEY_VALUE_NE_I64(default_settings, ANDROID_SENSOR_FRAME_DURATION, 0);
  }

  if (static_info->IsKeyAvailable(ANDROID_SENSOR_EXPOSURE_TIME)) {
    EXPECT_KEY_VALUE_NE_I64(default_settings, ANDROID_SENSOR_EXPOSURE_TIME, 0);
  }

  if (static_info->IsKeyAvailable(ANDROID_SENSOR_SENSITIVITY)) {
    EXPECT_KEY_VALUE_NE(default_settings, ANDROID_SENSOR_SENSITIVITY, 0);
  }

  // ISP-processing settings

  // CTS expects the default mode is OFF.
  EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_STATISTICS_FACE_DETECT_MODE,
                      ANDROID_STATISTICS_FACE_DETECT_MODE_OFF);

  EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_FLASH_MODE,
                      ANDROID_FLASH_MODE_OFF);

  if (static_info->IsKeyAvailable(ANDROID_STATISTICS_LENS_SHADING_MAP_MODE)) {
    // If the device doesn't support RAW, all template should have OFF as
    // default
    if (!static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW)) {
      EXPECT_KEY_VALUE_EQ(default_settings,
                          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
                          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF);
    }
  }

  bool support_reprocessing =
      static_info->IsCapabilitySupported(
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING) ||
      static_info->IsCapabilitySupported(
          ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING);

  if (type == CAMERA3_TEMPLATE_STILL_CAPTURE) {
    // Not enforce high quality here, as some devices may not effectively have
    // high quality mode
    if (static_info->IsKeyAvailable(ANDROID_COLOR_CORRECTION_MODE)) {
      EXPECT_KEY_VALUE_NE(default_settings, ANDROID_COLOR_CORRECTION_MODE,
                          ANDROID_COLOR_CORRECTION_MODE_TRANSFORM_MATRIX);
    }

    // Edge enhancement, noise reduction and aberration correction modes.
    EXPECT_EQ(IsMetadataKeyAvailable(default_settings, ANDROID_EDGE_MODE),
              static_info->IsKeyAvailable(ANDROID_EDGE_AVAILABLE_EDGE_MODES))
        << "Edge mode must be present in request if available edge modes are "
           "present in metadata, and vice-versa";
    if (static_info->IsKeyAvailable(ANDROID_EDGE_MODE)) {
      std::set<uint8_t> edge_modes = static_info->GetAvailableEdgeModes();
      // Don't need check fast as fast or high quality must be both present or
      // both not.
      if (edge_modes.find(ANDROID_EDGE_MODE_HIGH_QUALITY) != edge_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_EDGE_MODE,
                            ANDROID_EDGE_MODE_HIGH_QUALITY);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_EDGE_MODE,
                            ANDROID_EDGE_MODE_OFF);
      }
    }

    EXPECT_EQ(
        IsMetadataKeyAvailable(default_settings, ANDROID_NOISE_REDUCTION_MODE),
        static_info->IsKeyAvailable(
            ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES))
        << "Noise reduction mode must be present in request if available noise "
           "reductions are present in metadata, and vice-versa";
    if (static_info->IsKeyAvailable(
            ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES)) {
      std::set<uint8_t> nr_modes =
          static_info->GetAvailableNoiseReductionModes();
      // Don't need check fast as fast or high quality must be both present or
      // both not
      if (nr_modes.find(ANDROID_NOISE_REDUCTION_MODE_HIGH_QUALITY) !=
          nr_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_NOISE_REDUCTION_MODE,
                            ANDROID_NOISE_REDUCTION_MODE_HIGH_QUALITY);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_NOISE_REDUCTION_MODE,
                            ANDROID_NOISE_REDUCTION_MODE_OFF);
      }
    }

    EXPECT_EQ(IsMetadataKeyAvailable(default_settings,
                                     ANDROID_COLOR_CORRECTION_ABERRATION_MODE),
              static_info->IsKeyAvailable(
                  ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES))
        << "Aberration correction mode must be present in request if available "
           "aberration correction reductions are present in metadata, and "
           "vice-versa";
    if (static_info->IsKeyAvailable(ANDROID_COLOR_CORRECTION_ABERRATION_MODE)) {
      std::set<uint8_t> aberration_modes =
          static_info->GetAvailableColorAberrationModes();
      // Don't need check fast as fast or high quality must be both present or
      // both not
      if (aberration_modes.find(
              ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY) !=
          aberration_modes.end()) {
        EXPECT_KEY_VALUE_EQ(
            default_settings, ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
            ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF);
      }
    }
  } else if (type == CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG &&
             support_reprocessing) {
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_EDGE_MODE,
                        ANDROID_EDGE_MODE_ZERO_SHUTTER_LAG);
    EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_NOISE_REDUCTION_MODE,
                        ANDROID_NOISE_REDUCTION_MODE_ZERO_SHUTTER_LAG);
  } else if (type == CAMERA3_TEMPLATE_PREVIEW ||
             type == CAMERA3_TEMPLATE_VIDEO_RECORD) {
    if (static_info->IsKeyAvailable(ANDROID_EDGE_MODE)) {
      std::set<uint8_t> edge_modes = static_info->GetAvailableEdgeModes();
      if (edge_modes.find(ANDROID_EDGE_MODE_FAST) != edge_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_EDGE_MODE,
                            ANDROID_EDGE_MODE_FAST);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_EDGE_MODE,
                            ANDROID_EDGE_MODE_OFF);
      }
    }

    if (static_info->IsKeyAvailable(ANDROID_NOISE_REDUCTION_MODE)) {
      std::set<uint8_t> nr_modes =
          static_info->GetAvailableNoiseReductionModes();
      if (nr_modes.find(ANDROID_NOISE_REDUCTION_MODE_FAST) != nr_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_NOISE_REDUCTION_MODE,
                            ANDROID_NOISE_REDUCTION_MODE_FAST);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_NOISE_REDUCTION_MODE,
                            ANDROID_NOISE_REDUCTION_MODE_OFF);
      }
    }

    if (static_info->IsKeyAvailable(ANDROID_COLOR_CORRECTION_ABERRATION_MODE)) {
      std::set<uint8_t> aberration_modes =
          static_info->GetAvailableColorAberrationModes();
      if (aberration_modes.find(
              ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST) !=
          aberration_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                            ANDROID_COLOR_CORRECTION_ABERRATION_MODE_OFF);
      }
    }
  } else {
    if (static_info->IsKeyAvailable(ANDROID_EDGE_MODE)) {
      ASSERT_TRUE(IsMetadataKeyAvailable(default_settings, ANDROID_EDGE_MODE));
    }

    if (static_info->IsKeyAvailable(ANDROID_NOISE_REDUCTION_MODE)) {
      ASSERT_TRUE(IsMetadataKeyAvailable(default_settings,
                                         ANDROID_NOISE_REDUCTION_MODE));
    }

    if (static_info->IsKeyAvailable(ANDROID_COLOR_CORRECTION_ABERRATION_MODE)) {
      ASSERT_TRUE(IsMetadataKeyAvailable(
          default_settings, ANDROID_COLOR_CORRECTION_ABERRATION_MODE));
    }
  }

  // Tone map and lens shading modes.
  if (type == CAMERA3_TEMPLATE_STILL_CAPTURE) {
    EXPECT_EQ(
        IsMetadataKeyAvailable(default_settings, ANDROID_TONEMAP_MODE),
        static_info->IsKeyAvailable(ANDROID_TONEMAP_AVAILABLE_TONE_MAP_MODES))
        << "Tonemap mode must be present in request if available tonemap modes "
           "are present in metadata, and vice-versa";
    if (static_info->IsKeyAvailable(ANDROID_TONEMAP_AVAILABLE_TONE_MAP_MODES)) {
      std::set<uint8_t> tone_map_modes =
          static_info->GetAvailableToneMapModes();
      if (tone_map_modes.find(ANDROID_TONEMAP_MODE_HIGH_QUALITY) !=
          tone_map_modes.end()) {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_TONEMAP_MODE,
                            ANDROID_TONEMAP_MODE_HIGH_QUALITY);
      } else {
        EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_TONEMAP_MODE,
                            ANDROID_TONEMAP_MODE_FAST);
      }
    }

    // Still capture template should have android.statistics.lensShadingMapMode
    // ON when RAW capability is supported.
    if (static_info->IsKeyAvailable(ANDROID_STATISTICS_LENS_SHADING_MAP_MODE) &&
        static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_RAW)) {
      EXPECT_KEY_VALUE_EQ(default_settings,
                          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
                          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_ON);
    }
  } else {
    if (static_info->IsKeyAvailable(ANDROID_TONEMAP_MODE)) {
      EXPECT_KEY_VALUE_NE(default_settings, ANDROID_TONEMAP_MODE,
                          ANDROID_TONEMAP_MODE_CONTRAST_CURVE);
      EXPECT_KEY_VALUE_NE(default_settings, ANDROID_TONEMAP_MODE,
                          ANDROID_TONEMAP_MODE_GAMMA_VALUE);
      EXPECT_KEY_VALUE_NE(default_settings, ANDROID_TONEMAP_MODE,
                          ANDROID_TONEMAP_MODE_PRESET_CURVE);
    }
    if (static_info->IsKeyAvailable(ANDROID_STATISTICS_LENS_SHADING_MAP_MODE)) {
      EXPECT_KEY_VALUE_NE(default_settings,
                          ANDROID_STATISTICS_LENS_SHADING_MAP_MODE, 0);
    }
  }

  EXPECT_KEY_VALUE_EQ(default_settings, ANDROID_CONTROL_CAPTURE_INTENT, type);
}

// Test spec:
// - Camera ID
// - Capture type
class CreateInvalidTemplate
    : public Camera3DeviceFixture,
      public ::testing::WithParamInterface<std::tuple<int, int>> {
 public:
  CreateInvalidTemplate() : Camera3DeviceFixture(std::get<0>(GetParam())) {}
};

TEST_P(CreateInvalidTemplate, ConstructDefaultSettings) {
  // Reference:
  // camera2/cts/CameraDeviceTest.java#testCameraDeviceCreateCaptureBuilder
  int type = std::get<1>(GetParam());
  ASSERT_EQ(nullptr, cam_device_.ConstructDefaultRequestSettings(type))
      << "Should get error due to an invalid template ID";
}

// Test spec:
// - Camera ID
class Camera3AlgoSandboxIPCErrorTest
    : public Camera3DeviceFixture,
      public ::testing::WithParamInterface<int> {
 public:
  const uint32_t kDefaultTimeoutMs = 1000;

  Camera3AlgoSandboxIPCErrorTest()
      : Camera3DeviceFixture(GetParam()), cam_id_(GetParam()) {}

  void SetUp() override;

 protected:
  void Notify(const camera3_notify_msg* msg);

  int cam_id_;

  sem_t ipc_error_sem_;
};

void Camera3AlgoSandboxIPCErrorTest::SetUp() {
  Camera3DeviceFixture::SetUp();
  cam_device_.RegisterNotifyCallback(base::BindRepeating(
      &Camera3AlgoSandboxIPCErrorTest::Notify, base::Unretained(this)));
  sem_init(&ipc_error_sem_, 0, 0);
}

void Camera3AlgoSandboxIPCErrorTest::Notify(const camera3_notify_msg* msg) {
  EXPECT_EQ(CAMERA3_MSG_ERROR, msg->type)
      << "Unexpected message type " << msg->type << " is notified";
  EXPECT_EQ(CAMERA3_MSG_ERROR_DEVICE, msg->message.error.error_code)
      << "Unexpected error code " << msg->message.error.error_code
      << " is notified";
  sem_post(&ipc_error_sem_);
}

TEST_P(Camera3AlgoSandboxIPCErrorTest, IPCErrorBeforeOpen) {
  cam_device_.Destroy();
  (void)system("stop cros-camera-algo");
  ASSERT_EQ(nullptr, cam_module_.OpenDevice(cam_id_))
      << "Camera device should not be opened successfully";

  (void)system("start cros-camera-algo");
  ASSERT_EQ(0, cam_device_.Initialize(&cam_module_))
      << "Camera device initialization fails";
}

TEST_P(Camera3AlgoSandboxIPCErrorTest, IPCErrorAfterOpen) {
  (void)system("stop cros-camera-algo");
  struct timespec timeout;
  memset(&timeout, 0, sizeof(timeout));
  if (clock_gettime(CLOCK_REALTIME, &timeout)) {
    LOG(ERROR) << "Failed to get clock time";
  }
  timeout.tv_sec += kDefaultTimeoutMs / 1000;
  timeout.tv_nsec += (kDefaultTimeoutMs % 1000) * 1000;
  ASSERT_EQ(0, sem_timedwait(&ipc_error_sem_, &timeout));

  (void)system("start cros-camera-algo");
  cam_device_.Destroy();
  ASSERT_EQ(0, cam_device_.Initialize(&cam_module_))
      << "Camera device initialization fails";
}

INSTANTIATE_TEST_SUITE_P(Camera3DeviceTest,
                         Camera3DeviceSimpleTest,
                         ::testing::ValuesIn(Camera3Module().GetCameraIds()));

INSTANTIATE_TEST_SUITE_P(
    Camera3DeviceTest,
    Camera3DeviceDefaultSettings,
    ::testing::Combine(::testing::ValuesIn(Camera3Module().GetCameraIds()),
                       ::testing::Values(CAMERA3_TEMPLATE_PREVIEW,
                                         CAMERA3_TEMPLATE_STILL_CAPTURE,
                                         CAMERA3_TEMPLATE_VIDEO_RECORD,
                                         CAMERA3_TEMPLATE_VIDEO_SNAPSHOT,
                                         CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG,
                                         CAMERA3_TEMPLATE_MANUAL)));

INSTANTIATE_TEST_SUITE_P(
    Camera3DeviceTest,
    CreateInvalidTemplate,
    ::testing::Combine(::testing::ValuesIn(Camera3Module().GetCameraIds()),
                       ::testing::Values(CAMERA3_TEMPLATE_PREVIEW - 1,
                                         CAMERA3_TEMPLATE_MANUAL + 1)));

INSTANTIATE_TEST_SUITE_P(Camera3DeviceTest,
                         Camera3AlgoSandboxIPCErrorTest,
                         ::testing::ValuesIn(Camera3Module().GetCameraIds()));

}  // namespace camera3_test
