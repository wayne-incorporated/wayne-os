/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/hdrnet_stream_manipulator.h"

#include <algorithm>
#include <utility>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/test/task_environment.h>
#include <base/test/test_timeouts.h>
#pragma push_macro("None")
#pragma push_macro("Bool")
#undef None
#undef Bool

// gtest's internal typedef of None and Bool conflicts with the None and Bool
// macros in X11/X.h (https://github.com/google/googletest/issues/371).
// X11/X.h is pulled in by the GL headers we include.
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#pragma pop_macro("None")
#pragma pop_macro("Bool")
#include <hardware/camera3.h>

#include "common/camera_hal3_helpers.h"
#include "common/test_support/fake_still_capture_processor.h"
#include "features/hdrnet/hdrnet_config.h"
#include "features/hdrnet/hdrnet_processor.h"
#include "gpu/gpu_resources.h"

using ::testing::Test;

namespace cros {

namespace {

constexpr uint32_t kImpl720pStreamWidth = 1280;
constexpr uint32_t kImpl720pStreamHeight = 720;
constexpr uint32_t kImpl720pStreamFormat =
    HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED;
constexpr uint32_t kImpl720pStreamUsage = GRALLOC_USAGE_SW_READ_OFTEN |
                                          GRALLOC_USAGE_HW_CAMERA_WRITE |
                                          GRALLOC_USAGE_HW_TEXTURE;

constexpr uint32_t kYuv480pStreamWidth = 640;
constexpr uint32_t kYuv480pStreamHeight = 480;
constexpr uint32_t kYuv480pStreamFormat = HAL_PIXEL_FORMAT_YCbCr_420_888;
constexpr uint32_t kYuv480pStreamUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_CAMERA_WRITE |
    GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_HW_VIDEO_ENCODER;

constexpr uint32_t kYuv1080pStreamWidth = 1920;
constexpr uint32_t kYuv1080pStreamHeight = 1080;
constexpr uint32_t kYuv1080pStreamFormat = HAL_PIXEL_FORMAT_YCbCr_420_888;
constexpr uint32_t kYuv1080pStreamUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_CAMERA_WRITE |
    GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_HW_VIDEO_ENCODER;

constexpr uint32_t kBlobStreamWidth = 2560;
constexpr uint32_t kBlobStreamHeight = 1920;
constexpr uint32_t kBlobStreamFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr uint32_t kBlobStreamUsage =
    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_CAMERA_WRITE;

constexpr uint32_t kFakePriv = 0xdeadbeef;

}  // namespace

class Camera3Stream {
 public:
  Camera3Stream(uint32_t width,
                uint32_t height,
                int format,
                uint32_t usage,
                int stream_type = CAMERA3_STREAM_OUTPUT) {
    stream_.stream_type = stream_type;
    stream_.width = width;
    stream_.height = height;
    stream_.format = format;
    stream_.usage = usage;
  }

  bool HasSameSize(const camera3_stream_t& raw_stream) {
    return (stream_.width == raw_stream.width &&
            stream_.height == raw_stream.height);
  }

  camera3_stream_buffer_t CreateBuffer() {
    return camera3_stream_buffer_t{
        .stream = &stream_,
        .buffer = &buffer_,
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    };
  }

  camera3_stream_t* get() { return &stream_; }

  uint32_t width() const { return stream_.width; }
  uint32_t height() const { return stream_.height; }
  int format() const { return stream_.format; }
  uint32_t usage() const { return stream_.usage; }

 private:
  camera3_stream_t stream_ = {};
  buffer_handle_t buffer_ = nullptr;
};

class MockHdrNetProcessor : public HdrNetProcessor {
 public:
  MockHdrNetProcessor(const camera_metadata_t* static_info,
                      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : task_runner_(task_runner) {}

  ~MockHdrNetProcessor() override = default;

  MOCK_METHOD(bool,
              Initialize,
              (GpuResources * gpu_resources,
               Size input_size,
               const std::vector<Size>& output_sizes),
              (override));
  MOCK_METHOD(void, TearDown, (), (override));
  MOCK_METHOD(void, SetOptions, (const Options& options), (override));
  MOCK_METHOD(bool,
              WriteRequestParameters,
              (Camera3CaptureDescriptor * request),
              (override));
  MOCK_METHOD(void,
              ProcessResultMetadata,
              (Camera3CaptureDescriptor * result),
              (override));
  MOCK_METHOD(base::ScopedFD,
              Run,
              (int frame_number,
               const HdrNetConfig::Options& options,
               const SharedImage& input_external_yuv,
               base::ScopedFD input_release_fence,
               const std::vector<buffer_handle_t>& output_nv12_buffers,
               HdrnetMetrics* hdrnet_metrics),
              (override));

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

std::unique_ptr<HdrNetProcessor> CreateMockHdrNetProcessorInstance(
    const camera_metadata_t* static_info,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return std::make_unique<::testing::NiceMock<MockHdrNetProcessor>>(
      static_info, task_runner);
}

class HdrNetStreamManipulatorTest : public Test {
 protected:
  HdrNetStreamManipulatorTest()
      : impl_720p_stream_(kImpl720pStreamWidth,
                          kImpl720pStreamHeight,
                          kImpl720pStreamFormat,
                          kImpl720pStreamUsage),
        yuv_480p_stream_(kYuv480pStreamWidth,
                         kYuv480pStreamHeight,
                         kYuv480pStreamFormat,
                         kYuv480pStreamUsage),
        yuv_1080p_stream_(kYuv1080pStreamWidth,
                          kYuv1080pStreamHeight,
                          kYuv1080pStreamFormat,
                          kYuv1080pStreamUsage),
        blob_stream_(kBlobStreamWidth,
                     kBlobStreamHeight,
                     kBlobStreamFormat,
                     kBlobStreamUsage) {}

  void SetUp() override {
    CHECK(gpu_resources_.Initialize());
    HdrNetConfig::Options test_options = {.hdrnet_enable = true};
    stream_manipulator_ = std::make_unique<HdrNetStreamManipulator>(
        &gpu_resources_, base::FilePath(),
        std::make_unique<tests::FakeStillCaptureProcessor>(),
        base::BindRepeating(CreateMockHdrNetProcessorInstance), &test_options);
    stream_manipulator_->Initialize(
        nullptr, StreamManipulator::Callbacks{
                     .result_callback = base::BindRepeating(
                         &HdrNetStreamManipulatorTest::ProcessCaptureResult,
                         base::Unretained(this)),
                     .notify_callback = base::DoNothing()});
  }

  void SetImpl720pStreamInConfig() {
    stream_config_.AppendStream(impl_720p_stream_.get());
  }

  void SetYuv480pStreamInConfig() {
    stream_config_.AppendStream(yuv_480p_stream_.get());
  }

  void SetYuv1080pStreamInConfig() {
    stream_config_.AppendStream(yuv_1080p_stream_.get());
  }

  void SetBlobStreamInConfig() {
    stream_config_.AppendStream(blob_stream_.get());
  }

  // Set up all three streams for test: one IMPL 720p, one YUV 1080p, and one
  // BLOB.
  void SetUpStreamsForTest(uint32_t max_buffers) {
    SetImpl720pStreamInConfig();
    SetYuv1080pStreamInConfig();
    SetBlobStreamInConfig();
    ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                      &stream_effects_map_));
    std::vector<camera3_stream_t*> modified_streams;
    for (auto* stream : stream_config_.GetStreams()) {
      stream->max_buffers = max_buffers;
      stream->priv = reinterpret_cast<void*>(kFakePriv);
      modified_streams.push_back(stream);
    }
    ASSERT_TRUE(stream_manipulator_->OnConfiguredStreams(&stream_config_));
  }

  // Set up three streams, including two YUV/IMPL streams with different aspect
  // ratios, for test: one IMPL 720p, one YUV 480p, and one BLOB.
  void SetUpStreamsWithDifferentAspectRatiosForTest(uint32_t max_buffers) {
    SetImpl720pStreamInConfig();
    SetYuv480pStreamInConfig();
    SetBlobStreamInConfig();
    ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                      &stream_effects_map_));
    std::vector<camera3_stream_t*> modified_streams;
    for (auto* stream : stream_config_.GetStreams()) {
      stream->max_buffers = max_buffers;
      stream->priv = reinterpret_cast<void*>(kFakePriv);
      modified_streams.push_back(stream);
    }
    ASSERT_TRUE(stream_manipulator_->OnConfiguredStreams(&stream_config_));
  }

  // Construct a capture request with three buffers: one IMPL 720p, one YUV
  // 1080p and one BLOB.
  Camera3CaptureDescriptor ConstructCaptureRequestForTest(
      uint32_t frame_number, bool with_blob_buffer = true) {
    std::vector<Camera3StreamBuffer> output_buffers;
    output_buffers.emplace_back(Camera3StreamBuffer::MakeRequestOutput(
        impl_720p_stream_.CreateBuffer()));
    output_buffers.emplace_back(Camera3StreamBuffer::MakeRequestOutput(
        yuv_1080p_stream_.CreateBuffer()));
    if (with_blob_buffer) {
      output_buffers.emplace_back(
          Camera3StreamBuffer::MakeRequestOutput(blob_stream_.CreateBuffer()));
    }
    Camera3CaptureDescriptor desc(
        camera3_capture_request_t{.frame_number = frame_number});
    desc.SetOutputBuffers(std::move(output_buffers));
    return desc;
  }

  // Construct a capture request with three buffers: one IMPL 720p, one YUV
  // 480p and one BLOB.
  Camera3CaptureDescriptor
  ConstructCaptureRequestWithDifferentAspectRatiosForTest(
      uint32_t frame_number, bool with_blob_buffer = true) {
    std::vector<Camera3StreamBuffer> output_buffers;
    output_buffers.emplace_back(Camera3StreamBuffer::MakeRequestOutput(
        impl_720p_stream_.CreateBuffer()));
    output_buffers.emplace_back(Camera3StreamBuffer::MakeRequestOutput(
        yuv_480p_stream_.CreateBuffer()));
    if (with_blob_buffer) {
      output_buffers.emplace_back(
          Camera3StreamBuffer::MakeRequestOutput(blob_stream_.CreateBuffer()));
    }
    Camera3CaptureDescriptor desc(
        camera3_capture_request_t{.frame_number = frame_number});
    desc.SetOutputBuffers(std::move(output_buffers));
    return desc;
  }

  void ProcessCaptureResult(Camera3CaptureDescriptor result) {
    callback_received_.insert(result.frame_number());
    returned_result_ = std::move(result);
  }

  base::test::SingleThreadTaskEnvironment task_environment_;
  GpuResources gpu_resources_;
  StreamManipulator::RuntimeOptions runtime_options_;
  std::unique_ptr<HdrNetStreamManipulator> stream_manipulator_;
  Camera3CaptureDescriptor returned_result_;
  Camera3Stream impl_720p_stream_;
  Camera3Stream yuv_480p_stream_;
  Camera3Stream yuv_1080p_stream_;
  Camera3Stream blob_stream_;
  Camera3StreamConfiguration stream_config_;
  StreamEffectMap stream_effects_map_;
  std::set<uint32_t> callback_received_;
};

// Test that HdrNetStreamManipulator can handle stream configuration with a
// single YUV stream.
TEST_F(HdrNetStreamManipulatorTest, ConfigureSingleYuvStreamTest) {
  // Prepare a configuration with single IMPL 720p stream.
  SetImpl720pStreamInConfig();

  ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                    &stream_effects_map_));

  // The stream operation mode should remain unchanged.
  EXPECT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  // The modified stream config should have one stream.
  EXPECT_EQ(stream_config_.num_streams(), 1);
  camera3_stream_t* stream = stream_config_.GetStreams()[0];
  // The modified stream config should replace the original stream with another
  // replacement stream that has the same width and height.
  EXPECT_NE(stream, impl_720p_stream_.get());
  EXPECT_TRUE(impl_720p_stream_.HasSameSize(*stream));
}

// Test that HdrNetStreamManipulator can handle stream configuration with
// multiple YUV streams. The HdrNetStreamManipulator should replace each of the
// YUV streams with a HDRnet stream it controls.
TEST_F(HdrNetStreamManipulatorTest, ConfigureMultipleYuvStreamsTest) {
  // Prepare a configuration with multiple YUV streams and a BLOB stream with
  // different resolutions.
  SetImpl720pStreamInConfig();
  SetYuv1080pStreamInConfig();
  SetBlobStreamInConfig();

  ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                    &stream_effects_map_));

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  // The modified streams should have four streams: three HDRnet streams plus
  // the original BLOB stream.
  ASSERT_EQ(stream_config_.num_streams(), 4);
  bool impl_720p_configured = false, yuv_1080p_configured = false;
  for (auto* stream : stream_config_.GetStreams()) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB stream should be left untouched.
      EXPECT_EQ(stream, blob_stream_.get());
    } else {
      // The modified stream config should have two streams in replace of the
      // 720p and 1080p streams with the same size.
      EXPECT_NE(stream, impl_720p_stream_.get());
      EXPECT_NE(stream, yuv_1080p_stream_.get());
      if (impl_720p_stream_.HasSameSize(*stream)) {
        impl_720p_configured = true;
      } else if (yuv_1080p_stream_.HasSameSize(*stream)) {
        yuv_1080p_configured = true;
      }
    }
  }
  EXPECT_TRUE(impl_720p_configured);
  EXPECT_TRUE(yuv_1080p_configured);
}

// Test that HdrNetStreamManipulator correctly restores the stream configuration
// with the set of streams requested by the client.
TEST_F(HdrNetStreamManipulatorTest, OnConfiguredMultipleYuvStreamsTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsForTest(kMaxBuffers);

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  ASSERT_EQ(stream_config_.num_streams(), 3);
  bool impl_720p_restored = false, yuv_1080p_restored = false;
  for (auto* stream : stream_config_.GetStreams()) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB stream should be left untouched.
      EXPECT_EQ(stream, blob_stream_.get());
    } else {
      // The two original YUV streams should be restored, with |max_buffers| and
      // |priv| updated.
      if (stream == impl_720p_stream_.get()) {
        impl_720p_restored = true;
      } else if (stream == yuv_1080p_stream_.get()) {
        yuv_1080p_restored = true;
      }
      EXPECT_EQ(stream->max_buffers, kMaxBuffers);
      EXPECT_EQ(stream->priv, reinterpret_cast<void*>(kFakePriv));
    }
  }
  EXPECT_TRUE(impl_720p_restored);
  EXPECT_TRUE(yuv_1080p_restored);
}

// Test that HdrNetStreamManipulator can handle stream configuration with
// multiple YUV streams of different aspect ratios. The HdrNetStreamManipulator
// should replace each of the YUV streams with a HDRnet stream it controls.
TEST_F(HdrNetStreamManipulatorTest,
       ConfigureMultipleYuvStreamsOfDifferentAspectRatiosTest) {
  // Prepare a configuration with multiple YUV streams and a BLOB stream with
  // different resolutions.
  SetImpl720pStreamInConfig();
  SetYuv480pStreamInConfig();
  SetBlobStreamInConfig();

  ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                    &stream_effects_map_));

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  // The modified streams should have four streams: three HDRnet streams plus
  // the original BLOB stream.
  ASSERT_EQ(stream_config_.num_streams(), 4);
  bool impl_720p_replaced = false, yuv_480p_replaced = false;
  for (auto* stream : stream_config_.GetStreams()) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB stream should be left untouched.
      EXPECT_EQ(stream, blob_stream_.get());
    } else {
      // The modified stream config should have two streams in replace of the
      // 720p and 480p streams with the same size.
      EXPECT_NE(stream, impl_720p_stream_.get());
      EXPECT_NE(stream, yuv_480p_stream_.get());
      if (impl_720p_stream_.HasSameSize(*stream)) {
        impl_720p_replaced = true;
      } else if (yuv_480p_stream_.HasSameSize(*stream)) {
        yuv_480p_replaced = true;
      }
    }
  }
  EXPECT_TRUE(impl_720p_replaced);
  EXPECT_TRUE(yuv_480p_replaced);
}

// Test that HdrNetStreamManipulator correctly restores the stream configuration
// with the set of streams of different aspect ratios requested by the client.
TEST_F(HdrNetStreamManipulatorTest,
       OnConfiguredMultipleYuvStreamsOfDifferentAspectRatiosTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsWithDifferentAspectRatiosForTest(kMaxBuffers);

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  ASSERT_EQ(stream_config_.num_streams(), 3);
  bool impl_720p_restored = false, yuv_480p_restored = false;
  for (auto* stream : stream_config_.GetStreams()) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB stream should be left untouched.
      EXPECT_EQ(stream, blob_stream_.get());
    } else {
      // The two original YUV streams should be restored, with |max_buffers| and
      // |priv| updated.
      if (stream == impl_720p_stream_.get()) {
        impl_720p_restored = true;
      } else if (stream == yuv_480p_stream_.get()) {
        yuv_480p_restored = true;
      }
      EXPECT_EQ(stream->max_buffers, kMaxBuffers);
      EXPECT_EQ(stream->priv, reinterpret_cast<void*>(kFakePriv));
    }
  }
  EXPECT_TRUE(impl_720p_restored);
  EXPECT_TRUE(yuv_480p_restored);
}

// Test that HdrNetStreamManipulator handles multiple configure_streams() calls
// correctly.
TEST_F(HdrNetStreamManipulatorTest, MultipleConfigureStreamsTest) {
  // First configure a single IMPL 720p stream.
  SetImpl720pStreamInConfig();
  ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                    &stream_effects_map_));

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  // The modified stream config should have one stream.
  ASSERT_EQ(stream_config_.num_streams(), 1);
  camera3_stream_t* stream = stream_config_.GetStreams()[0];
  // The modified stream config should replace the original stream with another
  // replacement stream that has the same width and height.
  ASSERT_NE(stream, impl_720p_stream_.get());
  ASSERT_TRUE(impl_720p_stream_.HasSameSize(*stream));

  // Call ConfigureStreams the second time with different stream configurations.
  stream_config_.SetStreams({});
  SetImpl720pStreamInConfig();
  SetYuv1080pStreamInConfig();
  SetBlobStreamInConfig();
  ASSERT_TRUE(stream_manipulator_->ConfigureStreams(&stream_config_,
                                                    &stream_effects_map_));

  // The stream operation mode should remain unchanged.
  ASSERT_EQ(stream_config_.operation_mode(),
            CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE);
  // The modified streams should be returned.
  ASSERT_EQ(stream_config_.num_streams(), 4);
  bool impl_720p_configured = false, yuv_1080p_configured = false;
  for (auto* stream : stream_config_.GetStreams()) {
    if (stream->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB stream should be left untouched.
      EXPECT_EQ(stream, blob_stream_.get());
    } else {
      // The modified stream config should have two streams in replace of the
      // 720p and 1080p streams with the same size.
      EXPECT_NE(stream, impl_720p_stream_.get());
      EXPECT_NE(stream, yuv_1080p_stream_.get());
      if (impl_720p_stream_.HasSameSize(*stream)) {
        impl_720p_configured = true;
      } else if (yuv_1080p_stream_.HasSameSize(*stream)) {
        yuv_1080p_configured = true;
      }
    }
  }
  EXPECT_TRUE(impl_720p_configured);
  EXPECT_TRUE(yuv_1080p_configured);
}

// Test that HdrNetStreamManipulator handles capture request correctly.
// HdrNetStreamManipulator should replace the YUV buffers with the HDRnet buffer
// it controls.
TEST_F(HdrNetStreamManipulatorTest, ProcessCaptureRequestTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsForTest(kMaxBuffers);

  constexpr int kFrameNumber = 0;
  Camera3CaptureDescriptor request =
      ConstructCaptureRequestForTest(kFrameNumber);

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureRequest(&request));

  // The modified request should have three output buffers: two HDRnet buffers
  // and the original BLOB buffer.
  EXPECT_EQ(request.num_output_buffers(), 3);
  bool blob_buffer_found = false;
  bool hdrnet_buffer_for_yuv_found = false;
  bool hdrnet_buffer_for_blob_found = false;
  for (const auto& buffer : request.GetOutputBuffers()) {
    if (buffer.stream()->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB buffer should be unchanged.
      EXPECT_EQ(blob_stream_.get(), buffer.stream());
      blob_buffer_found = true;
    } else {
      // The HDRnet buffer should come from the HdrNetStreamManipulator.
      EXPECT_NE(impl_720p_stream_.get(), buffer.stream());
      EXPECT_NE(yuv_1080p_stream_.get(), buffer.stream());
      if (yuv_1080p_stream_.HasSameSize(*buffer.stream())) {
        hdrnet_buffer_for_yuv_found = true;
      } else if (blob_stream_.HasSameSize(*buffer.stream())) {
        hdrnet_buffer_for_blob_found = true;
      }
    }
  }
  EXPECT_TRUE(blob_buffer_found);
  EXPECT_TRUE(hdrnet_buffer_for_yuv_found);
  EXPECT_TRUE(hdrnet_buffer_for_blob_found);
}

// Test that HdrNetStreamManipulator handles process result correctly.
// HdrNetStreamManipulator should produce HDRnet output and fill the client NV12
// buffers.
TEST_F(HdrNetStreamManipulatorTest, ProcessCaptureResultTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsForTest(kMaxBuffers);

  constexpr int kFrameNumber = 0;
  Camera3CaptureDescriptor request =
      ConstructCaptureRequestForTest(kFrameNumber);
  // Don't count the BLOB buffer.
  int num_yuv_buffers_in_original_request = request.num_output_buffers() - 1;

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureRequest(&request));

  // Construct a capture result with the same set of buffers as in the modified
  // request.
  Camera3CaptureDescriptor result(
      camera3_capture_result_t{.frame_number = kFrameNumber});
  result.SetOutputBuffers(request.AcquireOutputBuffers());

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureResult(std::move(result)));

  // The result should have all the YUV output buffers as requested.
  EXPECT_EQ(returned_result_.num_output_buffers(),
            num_yuv_buffers_in_original_request);
  // The buffers should be restored to the ones that was provided by the capture
  // request.
  for (const auto& buffer : returned_result_.GetOutputBuffers()) {
    if (impl_720p_stream_.HasSameSize(*buffer.stream())) {
      EXPECT_EQ(impl_720p_stream_.get(), buffer.stream());
    } else if (yuv_1080p_stream_.HasSameSize(*buffer.stream())) {
      EXPECT_EQ(yuv_1080p_stream_.get(), buffer.stream());
    } else {
      FAIL() << "Unexpected result buffer";
    }
  }
  // We should get the result callback for the BLOB buffer.
  EXPECT_EQ(callback_received_.count(kFrameNumber), 1);
}

// Test that HdrNetStreamManipulator handles capture request with request
// buffers of different aspect ratios correctly. HdrNetStreamManipulator should
// replace the YUV buffers with the HDRnet buffer it controls.
TEST_F(HdrNetStreamManipulatorTest,
       ProcessCaptureRequestWithDifferentAspectRatiosTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsWithDifferentAspectRatiosForTest(kMaxBuffers);

  constexpr int kFrameNumber = 0;
  Camera3CaptureDescriptor request =
      ConstructCaptureRequestWithDifferentAspectRatiosForTest(kFrameNumber);

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureRequest(&request));

  // The modified request should have four output buffers: one HDRnet 720p
  // buffer, one HDRnet 480p buffer, the original BLOB buffer and one HDRnet
  // buffer for the BLOB buffer.
  EXPECT_EQ(request.num_output_buffers(), 4);
  bool blob_buffer_found = false;
  bool hdrnet_720p_buffer_found = false;
  bool hdrnet_480p_buffer_found = false;
  for (const auto& buffer : request.GetOutputBuffers()) {
    if (buffer.stream()->format == HAL_PIXEL_FORMAT_BLOB) {
      // The BLOB buffer should be unchanged.
      EXPECT_EQ(blob_stream_.get(), buffer.stream());
      blob_buffer_found = true;
    } else {
      // The HDRnet buffer should come from the HdrNetStreamManipulator.
      EXPECT_NE(impl_720p_stream_.get(), buffer.stream());
      EXPECT_NE(yuv_480p_stream_.get(), buffer.stream());
      if (impl_720p_stream_.HasSameSize(*buffer.stream())) {
        hdrnet_720p_buffer_found = true;
      } else if (yuv_480p_stream_.HasSameSize(*buffer.stream())) {
        hdrnet_480p_buffer_found = true;
      }
    }
  }
  EXPECT_TRUE(blob_buffer_found);
  EXPECT_TRUE(hdrnet_720p_buffer_found);
  EXPECT_TRUE(hdrnet_480p_buffer_found);
}

// Test that HdrNetStreamManipulator handles process result with buffers of
// different aspect ratios correctly. HdrNetStreamManipulator should produce
// HDRnet output and fill the client NV12 buffers.
TEST_F(HdrNetStreamManipulatorTest,
       ProcessCaptureResultWithDifferentAspectRatiosTest) {
  constexpr uint32_t kMaxBuffers = 6;
  SetUpStreamsWithDifferentAspectRatiosForTest(kMaxBuffers);

  constexpr int kFrameNumber = 0;
  Camera3CaptureDescriptor request =
      ConstructCaptureRequestWithDifferentAspectRatiosForTest(kFrameNumber);
  // Don't count the BLOB buffer.
  int num_yuv_buffers_in_original_request = request.num_output_buffers() - 1;

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureRequest(&request));

  // Construct a capture result with the same set of buffers as in the modified
  // request.
  Camera3CaptureDescriptor result(
      camera3_capture_result_t{.frame_number = kFrameNumber});
  result.SetOutputBuffers(request.AcquireOutputBuffers());

  ASSERT_TRUE(stream_manipulator_->ProcessCaptureResult(std::move(result)));

  // The result should have the same number of YUV output buffers as requested.
  // BLOB output should be handled by still capture processor.
  EXPECT_EQ(returned_result_.num_output_buffers(),
            num_yuv_buffers_in_original_request);
  // The buffers should be restored to the ones that was provided by the capture
  // request.
  for (const auto& buffer : returned_result_.GetOutputBuffers()) {
    if (impl_720p_stream_.HasSameSize(*buffer.stream())) {
      EXPECT_EQ(impl_720p_stream_.get(), buffer.stream());
    } else if (yuv_480p_stream_.HasSameSize(*buffer.stream())) {
      EXPECT_EQ(yuv_480p_stream_.get(), buffer.stream());
    } else {
      FAIL() << "Unexpected result buffer";
    }
  }
  // We should get the result callback for the BLOB buffer.
  EXPECT_EQ(callback_received_.count(kFrameNumber), 1);
}

// Test that HdrNetStreamManipulator handles error notify messages correctly.
// HdrNetStreamManipulator should release the error buffer for future capture
// requests.
TEST_F(HdrNetStreamManipulatorTest, NotifyBufferErrorTest) {
  constexpr uint32_t kMaxBuffers = 1;
  SetUpStreamsForTest(kMaxBuffers);

  // Deplete the internal buffers of the HdrNetStreamManipulator.
  uint32_t frame_number = 0;
  Camera3CaptureDescriptor last_successful_request;
  do {
    std::vector<camera3_stream_buffer_t> request_output_buffers;
    Camera3CaptureDescriptor request = ConstructCaptureRequestForTest(
        frame_number, /*with_blob_buffer=*/false);
    if (!stream_manipulator_->ProcessCaptureRequest(&request)) {
      break;
    }
    last_successful_request = std::move(request);
    frame_number++;
  } while (true);

  // Mark the last request with buffer error.
  EXPECT_EQ(last_successful_request.num_output_buffers(), 1);
  camera3_stream_t* hdrnet_stream = const_cast<camera3_stream_t*>(
      last_successful_request.GetOutputBuffers()[0].stream());
  EXPECT_TRUE(yuv_1080p_stream_.HasSameSize(*hdrnet_stream));
  camera3_error_msg_t error_msg = {
      .frame_number = last_successful_request.frame_number(),
      .error_stream = hdrnet_stream,
      .error_code = CAMERA3_MSG_ERROR_BUFFER,
  };
  camera3_notify_msg_t notify_msg = {
      .type = CAMERA3_MSG_ERROR,
      .message = {error_msg},
  };

  stream_manipulator_->Notify(std::move(notify_msg));

  // The buffer error notification should free up one HDRnet internal buffer, so
  // we should be able to submit one more request.
  Camera3CaptureDescriptor request =
      ConstructCaptureRequestForTest(frame_number, /*with_blob_buffer=*/false);
  EXPECT_TRUE(stream_manipulator_->ProcessCaptureRequest(&request));
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
