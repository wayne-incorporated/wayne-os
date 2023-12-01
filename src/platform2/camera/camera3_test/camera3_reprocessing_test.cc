// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iterator>
#include <set>
#include <sstream>
#include <vector>

#include <libyuv.h>
#include "camera3_test/camera3_exif_validator.h"
#include "camera3_test/camera3_frame_fixture.h"

namespace camera3_test {

// Test parameters:
// - Camera ID
class Camera3ReprocessingTest : public Camera3FrameFixture,
                                public ::testing::WithParamInterface<int32_t> {
 public:
  Camera3ReprocessingTest() : Camera3FrameFixture(GetParam()) {}

 protected:
  using ExifTestData = Camera3ExifValidator::ExifTestData;
  using ScopedImage = std::unique_ptr<struct Image>;

  const int kNumOfReprocessCaptures = 3;
  const double kReprocessingTestSsimThreshold = 0.75;

  // Crop the input image with the output aspect ratio if necessary and then
  // scale it to the designated width and height
  ScopedImage CropAndScale(const ScopedImage& in_buffer,
                           uint32_t to_width,
                           uint32_t to_height);

  // |exif_test_data| is used only when |reprocessing_format| is
  // HAL_PIXEL_FORMAT_BLOB
  void TestReprocessing(const ResolutionInfo& input_size,
                        int32_t input_format,
                        const ResolutionInfo& reprocessing_size,
                        int32_t reprocessing_format,
                        const ExifTestData& exif_test_data,
                        int num_reprocessing_captures);

  // Configure all IO streams at once. Return configured input stream with
  // size=|in_size|, format=|in_format| and vector of configured output streams
  // in which size/format of each stream matches size/format in |out_configs|.
  // If it fails, return pair of nullptr and empty output stream vector.
  std::pair<const camera3_stream_t*, std::vector<const camera3_stream_t*>>
  PrepareStreams(
      const ResolutionInfo& in_size,
      int32_t in_format,
      const std::vector<std::pair<ResolutionInfo, int32_t>>& out_configs);

  // Configure all IO streams at once. Similar to PrepareStreams, this function
  // returns configured input and output streams, but the input stream and the
  // first output stream will be the same bidirectional stream.
  std::pair<const camera3_stream_t*, std::vector<const camera3_stream_t*>>
  PrepareBidirectionalStreams(const ResolutionInfo& bi_size,
                              int32_t bi_format,
                              const ResolutionInfo& out_size,
                              int32_t out_format);

  virtual void AddPrepareStreams(
      const ResolutionInfo& in_size,
      int32_t in_format,
      const std::vector<std::pair<ResolutionInfo, int32_t>>& out_configs);

  void DoTemplateCapture(int32_t template_type,
                         const camera3_stream_t* output_stream,
                         ScopedCameraMetadata* output_metadata,
                         cros::ScopedBufferHandle* output_buffer,
                         const uint32_t timeout);

  void DoReprocessingCapture(ScopedCameraMetadata* in_metadata,
                             const camera3_stream_t* in_stream,
                             const cros::ScopedBufferHandle& in_buffer,
                             const camera3_stream_t* out_stream,
                             const ExifTestData& exif_test_data,
                             ScopedCameraMetadata* out_metadata,
                             cros::ScopedBufferHandle* out_buffer,
                             const uint32_t timeout);

 private:
  cros::ScopedBufferHandle buffer_handle_;
  ScopedCameraMetadata result_metadata_;

  void ProcessResultMetadataOutputBuffers(
      uint32_t frame_number,
      ScopedCameraMetadata metadata,
      std::vector<cros::ScopedBufferHandle> buffers) override;
};

Camera3ReprocessingTest::ScopedImage Camera3ReprocessingTest::CropAndScale(
    const ScopedImage& image, uint32_t to_width, uint32_t to_height) {
  if (ImageFormat::IMAGE_FORMAT_I420 != image->format) {
    ADD_FAILURE() << "Cannot scale non-I420 format";
    return nullptr;
  }

  const struct Image* crop_image;
  ScopedImage crop_buffer;
  if (image->width * to_height == image->height * to_width) {
    crop_image = image.get();
  } else {
    uint32_t crop_w, crop_h;
    if (image->width * to_height < image->height * to_width) {
      crop_w = image->width;
      crop_h = image->width * to_height / to_width;
    } else {
      crop_w = image->height * to_width / to_height;
      crop_h = image->height;
    }

    crop_buffer =
        std::make_unique<Image>(crop_w, crop_h, ImageFormat::IMAGE_FORMAT_I420);
    int ret = libyuv::ConvertToI420(
        image->data.data(), image->data.size(), crop_buffer->planes[0].addr,
        crop_buffer->planes[0].stride, crop_buffer->planes[1].addr,
        crop_buffer->planes[1].stride, crop_buffer->planes[2].addr,
        crop_buffer->planes[2].stride, (image->width - crop_w) / 2,
        (image->height - crop_h) / 2, image->width, image->height, crop_w,
        crop_h, libyuv::RotationMode::kRotate0, libyuv::FourCC::FOURCC_I420);
    if (ret != 0) {
      ADD_FAILURE() << "libyuv I420 crop failed";
      return nullptr;
    }

    crop_image = crop_buffer.get();
  }

  auto out_buffer = std::make_unique<Image>(to_width, to_height,
                                            ImageFormat::IMAGE_FORMAT_I420);
  libyuv::I420Scale(crop_image->planes[0].addr, crop_image->planes[0].stride,
                    crop_image->planes[1].addr, crop_image->planes[1].stride,
                    crop_image->planes[2].addr, crop_image->planes[2].stride,
                    crop_image->width, crop_image->height,
                    out_buffer->planes[0].addr, out_buffer->planes[0].stride,
                    out_buffer->planes[1].addr, out_buffer->planes[1].stride,
                    out_buffer->planes[2].addr, out_buffer->planes[2].stride,
                    out_buffer->width, out_buffer->height,
                    libyuv::kFilterBilinear);
  return out_buffer;
}

void Camera3ReprocessingTest::TestReprocessing(
    const ResolutionInfo& input_size,
    int32_t input_format,
    const ResolutionInfo& reprocessing_size,
    int32_t reprocessing_format,
    const ExifTestData& exif_test_data,
    int num_reprocessing_captures) {
  // Prepare all streams
  const camera3_stream_t* input_stream;
  std::vector<const camera3_stream_t*> output_streams;
  if (input_format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) {
    std::tie(input_stream, output_streams) = PrepareBidirectionalStreams(
        input_size, input_format, reprocessing_size, reprocessing_format);
  } else {
    std::tie(input_stream, output_streams) = PrepareStreams(
        input_size, input_format,
        {{input_size, input_format}, {reprocessing_size, reprocessing_format}});
  }
  ASSERT_TRUE(input_stream != nullptr && !output_streams.empty())
      << "PrepareStreams failed";

  for (int i = 0; i < num_reprocessing_captures; i++) {
    // Capture first image
    ScopedCameraMetadata result_metadata;
    cros::ScopedBufferHandle result_buffer;
    DoTemplateCapture(CAMERA3_TEMPLATE_STILL_CAPTURE, output_streams[0],
                      &result_metadata, &result_buffer, kDefaultTimeoutMs);
    time_t capture_time;
    time(&capture_time);

    // Reprocessing first image
    ScopedCameraMetadata reprocess_result_metadata;
    cros::ScopedBufferHandle reprocess_result_buffer;
    DoReprocessingCapture(&result_metadata, input_stream, result_buffer,
                          output_streams[1], exif_test_data,
                          &reprocess_result_metadata, &reprocess_result_buffer,
                          kDefaultTimeoutMs);

    int32_t exif_orientation = 0;
    if (reprocessing_format == HAL_PIXEL_FORMAT_BLOB) {
      // Verify exif
      size_t jpeg_max_size = cam_device_.GetStaticInfo()->GetJpegMaxSize();

      Camera3ExifValidator exif_validator(*cam_device_.GetStaticInfo());
      exif_validator.ValidateExifKeys(
          reprocessing_size, exif_test_data, reprocess_result_buffer,
          jpeg_max_size, *reprocess_result_metadata.get(), capture_time);
      exif_orientation = exif_validator.getExifOrientation(
          reprocess_result_buffer, jpeg_max_size);
    }

    // Check similarity
    if (input_format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED ||
        input_format == HAL_PIXEL_FORMAT_RAW_OPAQUE) {
      // Skip similarity check if we cannot identify the real format
      continue;
    }
    ScopedImage input_image =
        ConvertToImage(std::move(result_buffer), input_size.Width(),
                       input_size.Height(), ImageFormat::IMAGE_FORMAT_I420);
    ASSERT_TRUE(input_image != nullptr) << "Failed to convert input image";
    input_image = CropAndScale(input_image, reprocessing_size.Width(),
                               reprocessing_size.Height());
    ASSERT_TRUE(input_image != nullptr) << "Failed to scale input image";

    ScopedImage repr_image;
    if (exif_orientation == 0 && exif_test_data.orientation != 0) {
      // Rotate the reprocessed image back if HAL auto correct the orientation
      int correct_rotation = (360 - exif_test_data.orientation) % 360;
      int cur_width = reprocessing_size.Width();
      int cur_height = reprocessing_size.Height();
      if (correct_rotation % 180 == 90) {
        std::swap(cur_width, cur_height);
      }
      repr_image = ConvertToImageAndRotate(
          std::move(reprocess_result_buffer), cur_width, cur_height,
          ImageFormat::IMAGE_FORMAT_I420, correct_rotation);
    } else {
      repr_image = ConvertToImage(
          std::move(reprocess_result_buffer), reprocessing_size.Width(),
          reprocessing_size.Height(), ImageFormat::IMAGE_FORMAT_I420);
    }
    ASSERT_TRUE(repr_image != nullptr)
        << "Failed to convert reprocessing image";

    ASSERT_GT(ComputeSsim(*input_image, *repr_image),
              kReprocessingTestSsimThreshold)
        << "SSIM value is lower than threshold";
  }
}

std::pair<const camera3_stream_t*, std::vector<const camera3_stream_t*>>
Camera3ReprocessingTest::PrepareBidirectionalStreams(
    const ResolutionInfo& bi_size,
    int32_t bi_format,
    const ResolutionInfo& out_size,
    int32_t out_format) {
  // Add and configure streams
  cam_device_.AddBidirectionalStream(bi_format, bi_size.Width(),
                                     bi_size.Height());
  cam_device_.AddOutputStream(out_format, out_size.Width(), out_size.Height(),
                              CAMERA3_STREAM_ROTATION_0);
  std::vector<const camera3_stream_t*> streams;
  if (cam_device_.ConfigureStreams(&streams) != 0) {
    ADD_FAILURE() << "Configure stream failed";
    return {};
  }

  auto GetStream = [&streams](const ResolutionInfo& size, int32_t format,
                              bool is_output) {
    auto dir = is_output ? CAMERA3_STREAM_OUTPUT : CAMERA3_STREAM_BIDIRECTIONAL;
    auto it = std::find_if(
        streams.begin(), streams.end(), [&](const camera3_stream_t* stream) {
          return stream->format == format && stream->stream_type == dir &&
                 stream->width == size.Width() &&
                 stream->height == size.Height();
        });
    return it == streams.end() ? nullptr : *it;
  };

  auto bi_stream = GetStream(bi_size, bi_format, false);
  if (bi_stream == nullptr) {
    ADD_FAILURE() << "Connot find configured bidirectional stream Format 0x"
                  << std::hex << bi_format << " Resolution " << std::dec
                  << bi_size;
    return {};
  }
  std::vector<const camera3_stream_t*> out_streams{bi_stream};
  auto stream = GetStream(out_size, out_format, true);
  if (stream == nullptr) {
    ADD_FAILURE() << "Connot find configured output stream Format 0x"
                  << std::hex << out_format << " Resolution " << std::dec
                  << out_size;
    return {};
  }
  out_streams.push_back(stream);
  return {bi_stream, out_streams};
}

std::pair<const camera3_stream_t*, std::vector<const camera3_stream_t*>>
Camera3ReprocessingTest::PrepareStreams(
    const ResolutionInfo& in_size,
    int32_t in_format,
    const std::vector<std::pair<ResolutionInfo, int32_t>>& out_configs) {
  // Find unique out_configs
  std::set<std::pair<ResolutionInfo, int32_t>> uniq_configs(out_configs.begin(),
                                                            out_configs.end());
  AddPrepareStreams(in_size, in_format,
                    std::vector<std::pair<ResolutionInfo, int32_t>>(
                        uniq_configs.begin(), uniq_configs.end()));
  std::vector<const camera3_stream_t*> streams;
  if (cam_device_.ConfigureStreams(&streams) != 0) {
    ADD_FAILURE() << "Configure stream failed";
    return {};
  }

  auto GetStream = [&streams](const ResolutionInfo& size, int32_t format,
                              bool is_output) {
    auto dir = is_output ? CAMERA3_STREAM_OUTPUT : CAMERA3_STREAM_INPUT;
    auto it = std::find_if(
        streams.begin(), streams.end(), [&](const camera3_stream_t* stream) {
          return stream->format == format && stream->stream_type == dir &&
                 stream->width == size.Width() &&
                 stream->height == size.Height();
        });
    return it == streams.end() ? nullptr : *it;
  };

  auto in_stream = GetStream(in_size, in_format, false);
  if (in_stream == nullptr) {
    ADD_FAILURE() << "Connot find configured input stream Format 0x" << std::hex
                  << in_format << " Resolution " << std::dec << in_size;
    return {};
  }
  std::vector<const camera3_stream_t*> out_streams;
  for (const auto& it : out_configs) {
    auto stream = GetStream(it.first, it.second, true);
    if (stream == nullptr) {
      ADD_FAILURE() << "Connot find configured output stream Format 0x"
                    << std::hex << it.second << " Resolution " << std::dec
                    << it.first;
      return {};
    }
    out_streams.push_back(stream);
  }
  return {in_stream, out_streams};
}

void Camera3ReprocessingTest::AddPrepareStreams(
    const ResolutionInfo& in_size,
    int32_t in_format,
    const std::vector<std::pair<ResolutionInfo, int32_t>>& out_configs) {
  // Add in stream
  cam_device_.AddInputStream(in_format, in_size.Width(), in_size.Height());

  // Add unique out streams
  for (const auto& config : out_configs) {
    const auto& size = config.first;
    int32_t format = config.second;
    cam_device_.AddOutputStream(format, size.Width(), size.Height(),
                                CAMERA3_STREAM_ROTATION_0);
  }
}

void Camera3ReprocessingTest::DoTemplateCapture(
    int32_t template_type,
    const camera3_stream_t* output_stream,
    ScopedCameraMetadata* output_metadata,
    cros::ScopedBufferHandle* output_buffer,
    const uint32_t timeout) {
  const camera_metadata_t* metadata =
      cam_device_.ConstructDefaultRequestSettings(template_type);
  ASSERT_TRUE(metadata != nullptr) << "Camera default settings are NULL";

  std::vector<camera3_stream_buffer_t> buffers;
  ASSERT_EQ(
      0, cam_device_.AllocateOutputBuffersByStreams({output_stream}, &buffers));
  camera3_capture_request_t capture_request = {.frame_number = UINT32_MAX,
                                               .settings = metadata,
                                               .input_buffer = NULL,
                                               .num_output_buffers = 1,
                                               .output_buffers = buffers.data(),
                                               .num_physcam_settings = 0};

  ASSERT_EQ(0, cam_device_.ProcessCaptureRequest(&capture_request))
      << "Reprocessing capture failed";
  struct timespec timeout_ts;
  GetTimeOfTimeout(timeout, &timeout_ts);
  ASSERT_EQ(0, cam_device_.WaitCaptureResult(timeout_ts))
      << "Timeout waiting for capture result callback";
  *output_metadata = std::move(result_metadata_);
  *output_buffer = std::move(buffer_handle_);
}

void Camera3ReprocessingTest::DoReprocessingCapture(
    ScopedCameraMetadata* in_metadata,
    const camera3_stream_t* in_stream,
    const cros::ScopedBufferHandle& in_buffer,
    const camera3_stream_t* out_stream,
    const ExifTestData& exif_test_data,
    ScopedCameraMetadata* out_metadata,
    cros::ScopedBufferHandle* out_buffer,
    const uint32_t timeout) {
  if (out_stream->format == HAL_PIXEL_FORMAT_BLOB) {
    int32_t thumbnail_resolution[] = {
        exif_test_data.thumbnail_resolution.Width(),
        exif_test_data.thumbnail_resolution.Height()};
    EXPECT_EQ(0,
              UpdateMetadata(ANDROID_JPEG_THUMBNAIL_SIZE, thumbnail_resolution,
                             std::size(thumbnail_resolution), in_metadata));
    EXPECT_EQ(0, UpdateMetadata(ANDROID_JPEG_ORIENTATION,
                                &exif_test_data.orientation, 1, in_metadata));
    EXPECT_EQ(0, UpdateMetadata(ANDROID_JPEG_QUALITY,
                                &exif_test_data.jpeg_quality, 1, in_metadata));
    EXPECT_EQ(
        0, UpdateMetadata(ANDROID_JPEG_THUMBNAIL_QUALITY,
                          &exif_test_data.thumbnail_quality, 1, in_metadata));
  }

  // prepare input_buffer
  camera3_stream_buffer_t input_buffer = {
      .stream = const_cast<camera3_stream_t*>(in_stream),
      .buffer = in_buffer.get(),
      .status = CAMERA3_BUFFER_STATUS_OK,
      .acquire_fence = -1,
      .release_fence = -1};

  // prepare output_stream_buffer
  std::vector<camera3_stream_buffer_t> output_buffers;
  ASSERT_EQ(0, cam_device_.AllocateOutputBuffersByStreams({out_stream},
                                                          &output_buffers));

  camera3_capture_request_t capture_request = {
      .frame_number = UINT32_MAX,
      .settings = in_metadata->get(),
      .input_buffer = &input_buffer,
      .num_output_buffers = 1,
      .output_buffers = output_buffers.data(),
      .num_physcam_settings = 0};

  ASSERT_EQ(0, cam_device_.ProcessCaptureRequest(&capture_request))
      << "Reprocessing capture failed";
  struct timespec timeout_ts;
  GetTimeOfTimeout(timeout, &timeout_ts);
  ASSERT_EQ(0, cam_device_.WaitCaptureResult(timeout_ts))
      << "Timeout waiting for capture result callback";
  *out_metadata = std::move(result_metadata_);
  *out_buffer = std::move(buffer_handle_);
}

void Camera3ReprocessingTest::ProcessResultMetadataOutputBuffers(
    uint32_t frame_number,
    ScopedCameraMetadata metadata,
    std::vector<cros::ScopedBufferHandle> buffers) {
  ASSERT_EQ(1, buffers.size()) << "Should return one output image only";
  buffer_handle_ = std::move(buffers[0]);
  result_metadata_ = std::move(metadata);
}

TEST_P(Camera3ReprocessingTest, ConfigureMultipleInputStreams) {
  std::map<int32_t, std::vector<int32_t>> config_map;
  // Find all available size/format of input streams
  ASSERT_TRUE(
      cam_device_.GetStaticInfo()->GetInputOutputConfigurationMap(&config_map));
  std::set<std::pair<int32_t, ResolutionInfo>> in_configs;
  for (const auto& kv : config_map) {
    auto in_format = kv.first;
    for (const auto& size :
         cam_device_.GetStaticInfo()->GetSortedInputResolutions(in_format)) {
      in_configs.insert({in_format, size});
    }
  }

  // Configure any of 2 size/format input streams
  for (const auto& it : in_configs) {
    for (const auto& it2 : in_configs) {
      cam_device_.AddInputStream(it.first, it.second.Width(),
                                 it.second.Height());
      cam_device_.AddInputStream(it2.first, it2.second.Width(),
                                 it2.second.Height());
      ASSERT_NE(0, cam_device_.ConfigureStreams(nullptr))
          << "HAL should fail to configure multiple input streams";
    }
  }
}

TEST_P(Camera3ReprocessingTest, SizeFormatCombination) {
  // Reference:
  // camera2/cts/ReprocessCaptureTest.java#testReprocessingSizeFormat
  auto static_info = cam_device_.GetStaticInfo();

  // Test with max size thumbnail
  std::vector<ResolutionInfo> thumbnail_resolutions;
  EXPECT_TRUE(static_info->GetAvailableThumbnailSizes(&thumbnail_resolutions) ==
                  0 &&
              !thumbnail_resolutions.empty())
      << "JPEG thumbnail sizes are not available";
  ResolutionInfo max_thumbnail_size = thumbnail_resolutions.back();

  std::map<int32_t, std::vector<int32_t>> config_map;
  ASSERT_TRUE(static_info->GetInputOutputConfigurationMap(&config_map));
  for (const auto& kv : config_map) {
    auto in_format = kv.first;
    std::vector<ResolutionInfo> input_sizes =
        static_info->GetSortedInputResolutions(in_format);
    ASSERT_FALSE(input_sizes.empty())
        << "No supported input resolution for reprocessing input format 0x"
        << std::hex << in_format;
    for (int32_t out_format : kv.second) {
      std::vector<ResolutionInfo> output_sizes =
          static_info->GetSortedOutputResolutions(out_format);
      ASSERT_FALSE(output_sizes.empty())
          << "No supported output resolution for reprocessing output format 0x"
          << std::hex << out_format;
      for (const auto& input_size : input_sizes) {
        for (const auto& output_size : output_sizes) {
          LOG(INFO) << "Device " << cam_id_;
          LOG(INFO) << "Input Format 0x" << std::hex << in_format
                    << " Resolution " << std::dec << input_size;
          LOG(INFO) << "Output Format 0x" << std::hex << out_format
                    << " Resolution " << std::dec << output_size;
          TestReprocessing(input_size, in_format, output_size, out_format,
                           {max_thumbnail_size, 0, 90, 85},
                           kNumOfReprocessCaptures);
        }
      }
    }
  }
}

TEST_P(Camera3ReprocessingTest, JpegExif) {
  // Reference:
  // camera2/cts/ReprocessCaptureTest.java#testReprocessJpegExif
  auto static_info = cam_device_.GetStaticInfo();

  std::map<int32_t, std::vector<int32_t>> config_map;
  ASSERT_TRUE(static_info->GetInputOutputConfigurationMap(&config_map));

  std::vector<ResolutionInfo> thumbnail_resolutions;
  EXPECT_TRUE(static_info->GetAvailableThumbnailSizes(&thumbnail_resolutions) ==
                  0 &&
              !thumbnail_resolutions.empty())
      << "JPEG thumbnail sizes are not available";
  ExifTestData exif_test_data[] = {
      {thumbnail_resolutions.front(), 90, 80, 75},
      {thumbnail_resolutions.front(), 180, 90, 85},
      {thumbnail_resolutions.back(), 270, 100, 100},
  };

  ResolutionInfo input_size(0, 0), output_size(0, 0);
  for (const auto& kv : config_map) {
    auto in_format = kv.first;
    ASSERT_EQ(0, GetMaxResolution(in_format, &input_size, false))
        << "Failed to get max input resolution for format " << in_format;
    for (int32_t out_format : kv.second) {
      if (out_format == HAL_PIXEL_FORMAT_BLOB) {
        ASSERT_EQ(0, GetMaxResolution(out_format, &output_size, true))
            << "Failed to get max output resolution for format " << out_format;
        for (const auto& it : exif_test_data) {
          TestReprocessing(input_size, in_format, output_size, out_format, it,
                           kNumOfReprocessCaptures);
        }
      }
    }
  }
}

// Similar to |Camera3ReprocessingTest|, but configure streams in all different
// possible order.
// Test parameters:
// - Camera ID
class Camera3ReprocessingReorderTest : public Camera3ReprocessingTest {
 public:
  Camera3ReprocessingReorderTest() : Camera3ReprocessingTest() {}

 protected:
  // |stream_num|: number of unique stream
  void ResetOrder(int stream_num) {
    order_.clear();
    for (int i = 0; i < stream_num; i++) {
      order_.push_back(i);
    }
  }

  // Return if has next iteration
  bool NextOrder() {
    return std::next_permutation(order_.begin(), order_.end());
  }

 private:
  std::vector<size_t> order_;

  void AddPrepareStreams(const ResolutionInfo& in_size,
                         int32_t in_format,
                         const std::vector<std::pair<ResolutionInfo, int32_t>>&
                             out_configs) override {
    LOG(INFO) << "Add streams in order:";
    for (auto i : order_) {
      if (i == 0) {
        LOG(INFO) << "Input format=0x" << std::hex << in_format
                  << " size=" << std::dec << in_size;
        cam_device_.AddInputStream(in_format, in_size.Width(),
                                   in_size.Height());
      } else {
        const auto& size = out_configs[i - 1].first;
        int32_t format = out_configs[i - 1].second;
        LOG(INFO) << "Output format=0x" << std::hex << format
                  << " size=" << std::dec << size;
        cam_device_.AddOutputStream(format, size.Width(), size.Height(),
                                    CAMERA3_STREAM_ROTATION_0);
      }
    }
  }
};

TEST_P(Camera3ReprocessingReorderTest, ReorderStream) {
  auto static_info = cam_device_.GetStaticInfo();

  // Test with max size thumbnail
  std::vector<ResolutionInfo> thumbnail_resolutions;
  EXPECT_TRUE(static_info->GetAvailableThumbnailSizes(&thumbnail_resolutions) ==
                  0 &&
              !thumbnail_resolutions.empty())
      << "JPEG thumbnail sizes are not available";
  ResolutionInfo max_thumbnail_size = thumbnail_resolutions.back();

  std::map<int32_t, std::vector<int32_t>> config_map;
  ASSERT_TRUE(static_info->GetInputOutputConfigurationMap(&config_map));

  ResolutionInfo input_size(0, 0), output_size(0, 0);
  for (const auto& kv : config_map) {
    auto in_format = kv.first;
    ASSERT_EQ(0, GetMaxResolution(in_format, &input_size, false))
        << "Failed to get max input resolution for format " << in_format;
    for (int32_t out_format : kv.second) {
      ASSERT_EQ(0, GetMaxResolution(out_format, &output_size, true))
          << "Failed to get max output resolution for format " << out_format;
      ResetOrder((in_format == out_format && input_size == output_size) ? 2
                                                                        : 3);
      do {
        TestReprocessing(input_size, in_format, output_size, out_format,
                         {max_thumbnail_size, 0, 90, 85},
                         kNumOfReprocessCaptures);
        // We only configure a bidirectional stream and an output_stream when
        // input format is implementation-defined. Therefore there is no need
        // run this test multiple times by reordering the streams.
      } while (NextOrder() &&
               in_format != HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED);
    }
  }
}

// Return ids of test cameras which has reprocessing capability
static std::vector<int> EnumerateReprocessingTestCameras() {
  std::vector<int> ret_ids;
  std::ostringstream ss;
  Camera3Module m;
  for (auto cam_id : m.GetTestCameraIds()) {
    camera_info info;
    m.GetCameraInfo(cam_id, &info);
    auto static_info = std::make_unique<Camera3Device::StaticInfo>(info);
    if (static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_YUV_REPROCESSING) ||
        static_info->IsCapabilitySupported(
            ANDROID_REQUEST_AVAILABLE_CAPABILITIES_PRIVATE_REPROCESSING)) {
      ret_ids.push_back(cam_id);
      ss << ' ' << cam_id;
    }
  }
  LOG(INFO) << "Test camera with reprocessing capability:" << ss.str();
  return ret_ids;
}

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3ReprocessingTest,
    ::testing::ValuesIn(EnumerateReprocessingTestCameras()));

INSTANTIATE_TEST_SUITE_P(
    Camera3FrameTest,
    Camera3ReprocessingReorderTest,
    ::testing::ValuesIn(EnumerateReprocessingTestCameras()));

}  // namespace camera3_test
