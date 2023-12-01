/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_hal3_helpers.h"

#include <utility>

#include <base/at_exit.h>
#include <base/json/json_reader.h>
#include <camera/camera_metadata.h>
#include <gtest/gtest.h>
#include <optional>

#include "cros-camera/common.h"
#include "cros-camera/tracing.h"

namespace cros {

TEST(Camera3StreamConfiguration, BasicCorrectnessTest) {
  std::vector<camera3_stream_t> raw_streams = {
      camera3_stream_t{
          .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
      },
      camera3_stream_t{
          .format = HAL_PIXEL_FORMAT_BLOB,
      },
  };
  std::vector<camera3_stream_t*> raw_streams_ptr;
  for (auto& s : raw_streams) {
    raw_streams_ptr.push_back(&s);
  }
  constexpr uint32_t kTestOperationMode =
      CAMERA3_STREAM_CONFIGURATION_CONSTRAINED_HIGH_SPEED_MODE;
  camera3_stream_configuration_t stream_list = {
      .num_streams = static_cast<uint32_t>(raw_streams_ptr.size()),
      .streams = raw_streams_ptr.data(),
      .operation_mode = kTestOperationMode,
      .session_parameters = nullptr,
  };

  Camera3StreamConfiguration stream_config(stream_list);

  // stream_config should have the same data content as the raw stream_list.
  EXPECT_TRUE(stream_config.is_valid());
  EXPECT_EQ(stream_config.operation_mode(), kTestOperationMode);
  EXPECT_EQ(stream_config.num_streams(), raw_streams_ptr.size());
  base::span<camera3_stream_t* const> streams = stream_config.GetStreams();
  for (size_t i = 0; i < streams.size(); ++i) {
    EXPECT_EQ(streams[i], raw_streams_ptr[i]);
  }

  // Test that we can update the streams.
  camera3_stream_t p010_stream = {.format = HAL_PIXEL_FORMAT_YCBCR_P010};
  std::vector<camera3_stream_t*> new_streams_ptr(streams.begin(),
                                                 streams.end());
  new_streams_ptr.push_back(&p010_stream);
  stream_config.SetStreams(new_streams_ptr);
  EXPECT_EQ(stream_config.num_streams(), 3);
  EXPECT_EQ(stream_config.GetStreams()[2]->format, HAL_PIXEL_FORMAT_YCBCR_P010);

  // Test that Lock works.
  camera3_stream_configuration_t* raw_config = stream_config.Lock();
  EXPECT_EQ(raw_config->num_streams, new_streams_ptr.size());
  for (size_t i = 0; i < raw_config->num_streams; ++i) {
    EXPECT_EQ(raw_config->streams[i], new_streams_ptr[i]);
  }
  EXPECT_EQ(raw_config->operation_mode, kTestOperationMode);
  EXPECT_EQ(raw_config->session_parameters, nullptr);
}

TEST(Camera3StreamConfiguration, ToJsonStringTest) {
  std::vector<camera3_stream_t> raw_streams = {
      camera3_stream_t{
          .stream_type = CAMERA3_STREAM_BIDIRECTIONAL,
          .width = 1280,
          .height = 720,
          .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
          .usage = GRALLOC_USAGE_HW_CAMERA_WRITE | GRALLOC_USAGE_SW_READ_OFTEN,
          .max_buffers = 6,
          .data_space = HAL_DATASPACE_V0_SRGB,
          .rotation = 0,
          .physical_camera_id = "camera0",
      },
      camera3_stream_t{
          .stream_type = CAMERA3_STREAM_OUTPUT,
          .width = 1920,
          .height = 1080,
          .format = HAL_PIXEL_FORMAT_BLOB,
          .usage = GRALLOC_USAGE_HW_CAMERA_WRITE | GRALLOC_USAGE_SW_READ_OFTEN,
          .max_buffers = 6,
          .data_space = HAL_DATASPACE_JFIF,
          .rotation = 0,
          .physical_camera_id = "camera0",
      },
  };
  std::vector<camera3_stream_t*> raw_streams_ptr;
  for (auto& s : raw_streams) {
    raw_streams_ptr.push_back(&s);
  }
  constexpr uint32_t kTestOperationMode =
      CAMERA3_STREAM_CONFIGURATION_CONSTRAINED_HIGH_SPEED_MODE;
  camera3_stream_configuration_t stream_list = {
      .num_streams = static_cast<uint32_t>(raw_streams_ptr.size()),
      .streams = raw_streams_ptr.data(),
      .operation_mode = kTestOperationMode,
      .session_parameters = nullptr,
  };

  Camera3StreamConfiguration stream_config(stream_list);

  std::string json_string = stream_config.ToJsonString();

  auto vals =
      base::JSONReader::Read(json_string, base::JSON_PARSE_CHROMIUM_EXTENSIONS);

  // The unmarshaled JSON object should be a list of dicts with the same size as
  // |raw_streams_ptr|.
  EXPECT_TRUE(vals.has_value());
  EXPECT_NE(nullptr, vals->GetIfList());
  const auto& list_view = vals->GetList();
  EXPECT_EQ(raw_streams_ptr.size(), list_view.size());

  // Validate the unmarshaled YUV stream.
  EXPECT_EQ(raw_streams[0].stream_type,
            list_view[0].GetDict().FindInt("stream_type").value());
  EXPECT_EQ(raw_streams[0].width,
            list_view[0].GetDict().FindInt("width").value());
  EXPECT_EQ(raw_streams[0].height,
            list_view[0].GetDict().FindInt("height").value());
  EXPECT_EQ(raw_streams[0].format,
            list_view[0].GetDict().FindInt("format").value());
  EXPECT_EQ(raw_streams[0].usage,
            list_view[0].GetDict().FindInt("usage").value());
  EXPECT_EQ(raw_streams[0].max_buffers,
            list_view[0].GetDict().FindInt("max_buffers").value());
  EXPECT_EQ(raw_streams[0].data_space,
            list_view[0].GetDict().FindInt("data_space").value());
  EXPECT_EQ(raw_streams[0].rotation,
            list_view[0].GetDict().FindInt("rotation").value());
  EXPECT_EQ(raw_streams[0].physical_camera_id,
            *list_view[0].GetDict().FindString("physical_camera_id"));

  // Validate the unmarshaled BLOB stream.
  EXPECT_EQ(raw_streams[1].stream_type,
            list_view[1].GetDict().FindInt("stream_type").value());
  EXPECT_EQ(raw_streams[1].width,
            list_view[1].GetDict().FindInt("width").value());
  EXPECT_EQ(raw_streams[1].height,
            list_view[1].GetDict().FindInt("height").value());
  EXPECT_EQ(raw_streams[1].format,
            list_view[1].GetDict().FindInt("format").value());
  EXPECT_EQ(raw_streams[1].usage,
            list_view[1].GetDict().FindInt("usage").value());
  EXPECT_EQ(raw_streams[1].max_buffers,
            list_view[1].GetDict().FindInt("max_buffers").value());
  EXPECT_EQ(raw_streams[1].data_space,
            list_view[1].GetDict().FindInt("data_space").value());
  EXPECT_EQ(raw_streams[1].rotation,
            list_view[1].GetDict().FindInt("rotation").value());
  EXPECT_EQ(raw_streams[1].physical_camera_id,
            *list_view[1].GetDict().FindString("physical_camera_id"));
}

TEST(Camera3CaptureDescriptor, BasicCaptureRequestCorrectnessTest) {
  android::CameraMetadata request_settings(10);
  std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_ON};
  request_settings.update(ANDROID_CONTROL_AE_MODE, ae_mode.data(),
                          ae_mode.size());
  std::array<camera_metadata_rational_t, 1> ae_comp_step{
      camera_metadata_rational_t{1, 3}};
  request_settings.update(ANDROID_CONTROL_AE_COMPENSATION_STEP,
                          ae_comp_step.data(), ae_comp_step.size());
  std::array<int32_t, 0> faces = {};
  request_settings.update(ANDROID_STATISTICS_FACE_RECTANGLES, faces.data(),
                          faces.size());
  std::vector<camera3_stream_buffer_t> output_buffers(2);

  constexpr uint32_t kTestFrameNumber = 15;
  camera3_capture_request_t request = {
      .frame_number = kTestFrameNumber,
      .settings = request_settings.getAndLock(),
      .input_buffer = nullptr,
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .num_physcam_settings = 0,
      .physcam_id = nullptr,
      .physcam_settings = nullptr,
  };

  Camera3CaptureDescriptor desc(request);

  // We should be able to get the AE_MODE and AE_COMPENSATION_STEP metadata and
  // their values should be ON and 1/3.
  {
    base::span<const uint8_t> ae_mode =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode.size(), 1);
    EXPECT_EQ(ae_mode[0], ANDROID_CONTROL_AE_MODE_ON);
    base::span<const camera_metadata_rational_t> ae_comp_step =
        desc.GetMetadata<camera_metadata_rational_t>(
            ANDROID_CONTROL_AE_COMPENSATION_STEP);
    EXPECT_EQ(ae_comp_step.size(), 1);
    EXPECT_EQ(ae_comp_step[0].numerator, 1);
    EXPECT_EQ(ae_comp_step[0].denominator, 3);
  }

  // We should be able to modify the AE_MODE metadata to OFF, and add a new
  // AE_EXPOSURE_COMPENSATION metadata.
  {
    std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_OFF};
    desc.UpdateMetadata(ANDROID_CONTROL_AE_MODE,
                        base::span<const uint8_t>(ae_mode));
    std::array<int32_t, 1> ae_compensation{1};
    desc.UpdateMetadata(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
                        base::span<const int32_t>(ae_compensation));
    base::span<const uint8_t> ae_mode_entry =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode_entry.size(), 1);
    EXPECT_EQ(ae_mode_entry[0], ANDROID_CONTROL_AE_MODE_OFF);
    base::span<const int32_t> ae_comp_entry =
        desc.GetMetadata<int32_t>(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION);
    EXPECT_EQ(ae_comp_entry.size(), 1);
    EXPECT_EQ(ae_comp_entry[0], 1);
  }

  // The input buffer should be nullptr initially, and we should be able to add
  // an input buffer.
  {
    EXPECT_EQ(desc.GetInputBuffer(), nullptr);
    // Use a fake stream pointer as cookie for test.
    camera3_stream_t* kFakeStreamPtr =
        reinterpret_cast<camera3_stream_t*>(0xbeef);
    desc.SetInputBuffer(
        Camera3StreamBuffer::MakeRequestInput({.stream = kFakeStreamPtr}));
    EXPECT_EQ(desc.GetInputBuffer()->stream(), kFakeStreamPtr);
  }

  // There should be two output buffers initially, and we should be able to add
  // a new output buffer.
  {
    std::vector<Camera3StreamBuffer> output_buffers =
        desc.AcquireOutputBuffers();
    EXPECT_EQ(output_buffers.size(), 2);
    output_buffers.emplace_back();
    desc.SetOutputBuffers(std::move(output_buffers));
    EXPECT_EQ(desc.GetOutputBuffers().size(), 3);
  }

  // There should exists faces array, but with zero size, and no landmarks are
  // available.
  {
    EXPECT_EQ(
        desc.GetMetadata<int32_t>(ANDROID_STATISTICS_FACE_RECTANGLES).size(),
        0);
    EXPECT_EQ(desc.HasMetadata(ANDROID_STATISTICS_FACE_RECTANGLES), true);
    EXPECT_EQ(
        desc.GetMetadata<int32_t>(ANDROID_STATISTICS_FACE_LANDMARKS).size(), 0);
    EXPECT_EQ(desc.HasMetadata(ANDROID_STATISTICS_FACE_LANDMARKS), false);
  }

  // Finally the locked camera3_capture_request_t should reflect all the changes
  // we made above.
  {
    const camera3_capture_request_t* locked_request = desc.LockForRequest();
    EXPECT_EQ(locked_request->frame_number, kTestFrameNumber);
    EXPECT_EQ(get_camera_metadata_entry_count(locked_request->settings), 4);
    EXPECT_NE(locked_request->input_buffer, nullptr);
    EXPECT_EQ(locked_request->num_output_buffers, 3);
  }

  // The metadata shouldn't be modified when the descriptor is locked.
  {
    std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_ON};
    EXPECT_FALSE(desc.UpdateMetadata(ANDROID_CONTROL_AE_MODE,
                                     base::span<const uint8_t>(ae_mode)));
    base::span<const uint8_t> ae_mode_entry =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode_entry.size(), 1);
    EXPECT_EQ(ae_mode_entry[0], ANDROID_CONTROL_AE_MODE_OFF);
  }
}

TEST(Camera3CaptureDescriptor, BasicCaptureResultCorrectnessTest) {
  android::CameraMetadata result_metadata(10);
  std::array<uint8_t, 1> ae_mode{ANDROID_CONTROL_AE_MODE_ON};
  result_metadata.update(ANDROID_CONTROL_AE_MODE, ae_mode.data(),
                         ae_mode.size());
  std::array<camera_metadata_rational_t, 1> ae_comp_step{
      camera_metadata_rational_t{1, 3}};
  result_metadata.update(ANDROID_CONTROL_AE_COMPENSATION_STEP,
                         ae_comp_step.data(), ae_comp_step.size());
  std::vector<camera3_stream_buffer_t> output_buffers(2);

  constexpr uint32_t kTestFrameNumber = 15;
  camera3_capture_result_t result = {
      .frame_number = kTestFrameNumber,
      .result = result_metadata.getAndLock(),
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .input_buffer = nullptr,
      .partial_result = 1,
      .num_physcam_metadata = 0,
      .physcam_ids = nullptr,
      .physcam_metadata = nullptr,
  };

  Camera3CaptureDescriptor desc(result);

  // We should be able to get the AE_MODE and AE_COMPENSATION_STEP metadata and
  // their values should be ON and 1/3.
  {
    base::span<const uint8_t> ae_mode =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode.size(), 1);
    EXPECT_EQ(ae_mode[0], ANDROID_CONTROL_AE_MODE_ON);
    base::span<const camera_metadata_rational_t> ae_comp_step =
        desc.GetMetadata<camera_metadata_rational_t>(
            ANDROID_CONTROL_AE_COMPENSATION_STEP);
    EXPECT_EQ(ae_comp_step.size(), 1);
    EXPECT_EQ(ae_comp_step[0].numerator, 1);
    EXPECT_EQ(ae_comp_step[0].denominator, 3);
  }

  // We should be able to modify the AE_MODE metadata to OFF, and add a new
  // AE_EXPOSURE_COMPENSATION metadata.
  {
    std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_OFF};
    desc.UpdateMetadata(ANDROID_CONTROL_AE_MODE,
                        base::span<const uint8_t>(ae_mode));
    std::array<int32_t, 1> ae_compensation{1};
    desc.UpdateMetadata(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
                        base::span<const int32_t>(ae_compensation));
    base::span<const uint8_t> ae_mode_entry =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode_entry.size(), 1);
    EXPECT_EQ(ae_mode_entry[0], ANDROID_CONTROL_AE_MODE_OFF);
    base::span<const int32_t> ae_comp_entry =
        desc.GetMetadata<int32_t>(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION);
    EXPECT_EQ(ae_comp_entry.size(), 1);
    EXPECT_EQ(ae_comp_entry[0], 1);
  }

  // The input buffer should be nullptr initially, and we should be able to add
  // an input buffer.
  {
    EXPECT_EQ(desc.GetInputBuffer(), nullptr);
    desc.SetInputBuffer(
        Camera3StreamBuffer::MakeResultInput(camera3_stream_buffer_t()));
    EXPECT_NE(desc.GetInputBuffer(), nullptr);
  }

  // There should be two output buffers initially, and we should be able to add
  // a new output buffer.
  {
    std::vector<Camera3StreamBuffer> output_buffers =
        desc.AcquireOutputBuffers();
    EXPECT_EQ(output_buffers.size(), 2);
    output_buffers.emplace_back();
    desc.SetOutputBuffers(std::move(output_buffers));
    EXPECT_EQ(desc.GetOutputBuffers().size(), 3);
  }

  // Finally the locked camera3_capture_result_t should reflect all the changes
  // we made above.
  {
    const camera3_capture_result_t* locked_result = desc.LockForResult();
    EXPECT_EQ(locked_result->frame_number, kTestFrameNumber);
    EXPECT_EQ(get_camera_metadata_entry_count(locked_result->result), 3);
    EXPECT_NE(locked_result->input_buffer, nullptr);
    EXPECT_EQ(locked_result->num_output_buffers, 3);
    EXPECT_EQ(locked_result->partial_result, 1);
  }

  // The metadata shouldn't be modified when the descriptor is locked.
  {
    std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_ON};
    EXPECT_FALSE(desc.UpdateMetadata(ANDROID_CONTROL_AE_MODE,
                                     base::span<const uint8_t>(ae_mode)));
    base::span<const uint8_t> ae_mode_entry =
        desc.GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(ae_mode_entry.size(), 1);
    EXPECT_EQ(ae_mode_entry[0], ANDROID_CONTROL_AE_MODE_OFF);
  }
}

TEST(Camera3CaptureDescriptor, ToJsonStringTest) {
  android::CameraMetadata result_metadata(10);
  std::array<uint8_t, 1> ae_mode{ANDROID_CONTROL_AE_MODE_ON};
  result_metadata.update(ANDROID_CONTROL_AE_MODE, ae_mode.data(),
                         ae_mode.size());
  std::array<camera_metadata_rational_t, 1> ae_comp_step{
      camera_metadata_rational_t{1, 3}};
  result_metadata.update(ANDROID_CONTROL_AE_COMPENSATION_STEP,
                         ae_comp_step.data(), ae_comp_step.size());
  std::vector<camera3_stream_buffer_t> output_buffers;
  output_buffers.emplace_back();
  output_buffers.emplace_back();

  constexpr uint32_t kTestFrameNumber = 15;
  camera3_capture_result_t result = {
      .frame_number = kTestFrameNumber,
      .result = result_metadata.getAndLock(),
      .num_output_buffers = static_cast<uint32_t>(output_buffers.size()),
      .output_buffers = output_buffers.data(),
      .input_buffer = nullptr,
      .partial_result = 1,
      .num_physcam_metadata = 0,
      .physcam_ids = nullptr,
      .physcam_metadata = nullptr,
  };

  Camera3CaptureDescriptor desc(result);

  std::string json_string = desc.ToJsonString();

  auto vals =
      base::JSONReader::Read(json_string, base::JSON_PARSE_CHROMIUM_EXTENSIONS);

  // The unmarshaled JSON object should be a dict.
  EXPECT_TRUE(vals.has_value());
  EXPECT_NE(nullptr, vals->GetIfDict());
  const auto& dict_view = vals->GetDict();
  EXPECT_STREQ("Result", dict_view.FindString("capture_type")->c_str());
  EXPECT_EQ(result.frame_number, dict_view.FindInt("frame_number").value());
  EXPECT_EQ(result.num_output_buffers,
            dict_view.FindList("output_buffers")->size());
  EXPECT_EQ(dict_view.FindDict("input_buffer"), nullptr);
  EXPECT_EQ(result.partial_result, dict_view.FindInt("partial_result"));
}

TEST(Camera3CaptureDescriptor, AddListItemToMetadataTag) {
  android::CameraMetadata metadata;
  const android::CameraMetadata& const_metadata = metadata;
  // Update to null tag.
  EXPECT_TRUE(AddListItemToMetadataTag(&metadata,
                                       ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                       ANDROID_CONTROL_AE_MODE));
  {
    camera_metadata_ro_entry entry =
        const_metadata.find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    EXPECT_EQ(entry.count, 1);
    EXPECT_EQ(entry.data.i32[0], ANDROID_CONTROL_AE_MODE);
  }
  // Update more items.
  EXPECT_TRUE(AddListItemToMetadataTag(&metadata,
                                       ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                       ANDROID_CONTROL_AF_MODE));
  EXPECT_TRUE(AddListItemToMetadataTag(&metadata,
                                       ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                       ANDROID_CONTROL_AWB_MODE));
  {
    camera_metadata_ro_entry entry =
        const_metadata.find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    EXPECT_EQ(entry.count, 3);
    EXPECT_EQ(entry.data.i32[0], ANDROID_CONTROL_AE_MODE);
    EXPECT_EQ(entry.data.i32[1], ANDROID_CONTROL_AF_MODE);
    EXPECT_EQ(entry.data.i32[2], ANDROID_CONTROL_AWB_MODE);
  }
  // Update with an existing item.
  EXPECT_TRUE(AddListItemToMetadataTag(&metadata,
                                       ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS,
                                       ANDROID_CONTROL_AF_MODE));
  {
    camera_metadata_ro_entry entry =
        const_metadata.find(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS);
    EXPECT_EQ(entry.count, 3);
  }
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
