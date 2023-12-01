/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/cached_frame.h"

#include <errno.h>

#include <limits>
#include <string>

#include <base/check_op.h>
#include <base/timer/elapsed_timer.h>
#include <hardware/camera3.h>

#include "cros-camera/common.h"
#include "cros-camera/exif_utils.h"
#include "cros-camera/utils/camera_config.h"
#include "hal/usb/camera_hal.h"
#include "hal/usb/common_types.h"
#include "hal/usb/tracing.h"

namespace cros {

// How precise the float-to-rational conversion for EXIF tags would be.
static const int kRationalPrecision = 10000;

// Since the structure of the App1 segment is like:
//   0xFF [1 byte marker] [2 bytes size] [data]
// And it should not be larger than 64K.
static const int kApp1MaxDataSize = 65532;

static bool SetExifTags(const android::CameraMetadata& static_metadata,
                        const android::CameraMetadata& request_metadata,
                        const FrameBuffer& in_frame,
                        ExifUtils* utils);

static bool InsertJpegBlob(FrameBuffer& out_frame, uint32_t jpeg_data_size);

static Size CalculateCropSize(const Size& in_size, const Size& out_size) {
  // Crop the input image to the same ratio as the output image.
  // We want to compare w1/h1 and w2/h2. To avoid floating point precision loss
  // we compare w1*h2 and w2*h1 instead, with w1 and h1 being the width and
  // height of the input; w2 and h2 those of the output.
  uint32_t in_aspect_ratio = in_size.width * out_size.height;
  uint32_t out_aspect_ratio = out_size.width * in_size.height;

  // Same Ratio.
  Size crop_size(0u, 0u);
  if (in_aspect_ratio == out_aspect_ratio) {
    crop_size.width = in_size.width;
    crop_size.height = in_size.height;
  } else if (in_aspect_ratio > out_aspect_ratio) {
    // Need to crop width.
    crop_size.width = out_aspect_ratio / out_size.height;
    crop_size.height = in_size.height;
  } else {
    // Need to crop height.
    crop_size.width = in_size.width;
    crop_size.height = in_aspect_ratio / out_size.width;
  }
  // Make sure crop size is even.
  crop_size.width = (crop_size.width + 1) & (~1);
  crop_size.height = (crop_size.height + 1) & (~1);

  return crop_size;
}

static bool ValidateThumbnailSize(
    const android::CameraMetadata& static_metadata, int width, int height) {
  auto entry = static_metadata.find(ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES);
  DCHECK_GT(entry.count, 0);
  DCHECK_EQ(entry.count % 2, 0);
  for (size_t i = 0; i < entry.count; i += 2) {
    if (width == entry.data.i32[i] && height == entry.data.i32[i + 1]) {
      return true;
    }
  }
  return false;
}

CachedFrame::CachedFrame(const android::CameraMetadata& static_metadata)
    : image_processor_(new ImageProcessor()),
      camera_metrics_(CameraMetrics::New()),
      jda_available_(false),
      jda_resolution_cap_(std::numeric_limits<int>::max(),
                          std::numeric_limits<int>::max()),
      force_jpeg_hw_decode_(false) {
  auto* mojo_manager_token = CameraHal::GetInstance().GetMojoManagerToken();

  jda_ = JpegDecodeAccelerator::CreateInstance(mojo_manager_token);
  jda_available_ = jda_->Start();
  if (!jda_available_) {
    LOGF(INFO) << "No JDA available";
  } else {
    std::unique_ptr<CameraConfig> camera_config =
        CameraConfig::Create(constants::kCrosCameraConfigPathString);
    jda_resolution_cap_ =
        Size(camera_config->GetInteger(constants::kCrosUsbJDACapWidth,
                                       std::numeric_limits<int>::max()),
             camera_config->GetInteger(constants::kCrosUsbJDACapHeight,
                                       std::numeric_limits<int>::max()));
    if (jda_resolution_cap_.width != std::numeric_limits<int>::max() ||
        jda_resolution_cap_.height != std::numeric_limits<int>::max()) {
      LOGF(INFO) << "Cap JDA resolution:" << jda_resolution_cap_.width << "x"
                 << jda_resolution_cap_.height;
    }
  }

  jpeg_compressor_ = JpegCompressor::GetInstance(mojo_manager_token);

  // Read force_jpeg_hw_dec configs
  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraTestConfigPathString);
  force_jpeg_hw_decode_ = camera_config->GetBoolean(
      constants::kCrosForceJpegHardwareDecodeOption, false);
  if (force_jpeg_hw_decode_) {
    LOGF(INFO) << "Force JPEG hardware decode";
  }

  camera_metadata_ro_entry entry =
      static_metadata.find(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);
  DCHECK_EQ(entry.count, 4);
  active_array_size_.width = entry.data.i32[2];
  active_array_size_.height = entry.data.i32[3];

  face_detector_ = FaceDetector::Create();
}

int CachedFrame::Convert(
    const android::CameraMetadata& static_metadata,
    const android::CameraMetadata& request_metadata,
    int rotate_degree,
    FrameBuffer& in_frame,
    const std::vector<std::unique_ptr<FrameBuffer>>& out_frames,
    std::vector<int>& out_frame_status,
    std::vector<human_sensing::CrosFace>* faces) {
  //
  // Overview of the conversion graph.
  //
  // 1. Convert input (MJPEG or YUYV) into a temp NV12 buffer, which is taken
  //    from output buffers if a suitable size/format is found, or is allocated
  //    and cached in this class.
  //
  //   1a. Input format is MJPEG. Try HW JDA decoding or fallback to SW
  //       decoding:
  //
  //             HW JDA or SW Decode
  //      MJPEG ---------------------> NV12
  //
  //   1b. Input format is YUYV:
  //
  //             Convert
  //      YUYV ----------> NV12
  //
  // 2. If source frame needs to be rotated for portrait view, the temp NV12
  //    buffer will be cropped, rotated, and scaled back into it:
  //
  //             Crop + Rotate          Scale           Convert
  //      NV12 ----------------> I420 --------> I420' ----------> NV12
  //
  // 3. Convert the temp NV12 frame into each output frame.
  //
  //   3a. Output size is the same as input size:
  //
  //               HW/SW JEA
  //      NV12 ( ------------> JPEG )
  //                Convert
  //           ( ------------> other )
  //
  //   3b. Input size needs to be cropped and scaled into output size:
  //
  //            Crop        Scale           Convert         HW/SW JEA
  //      NV12 -----> I420 ------> I420' ( --------> NV12' ----------> JPEG )
  //                                        Convert
  //                                     ( --------> other )
  //
  // TODO(kamesan): optimize the SW paths to reduce I420 <-> NV12 copies, by
  // refactoring of the graph or libyuv support.
  //
  VLOGF(1) << "Input frame: " << in_frame.GetWidth() << "x"
           << in_frame.GetHeight() << " "
           << FormatToString(in_frame.GetFourcc()) << ", rotate "
           << rotate_degree;

  if (in_frame.GetHeight() % 2 != 0 || in_frame.GetWidth() % 2 != 0) {
    LOGF(ERROR) << "Source image has odd dimension: " << in_frame.GetWidth()
                << "x" << in_frame.GetHeight();
    return -EINVAL;
  }

  // Try to find a temp NV12 buffer in |out_frames| that has the same size as
  // |in_frame|. If found, |in_frame| will be converted directly into it to save
  // a copy.
  size_t nv12_frame_index = out_frames.size();
  for (size_t i = 0; i < out_frames.size(); i++) {
    FrameBuffer* out_frame = out_frames[i].get();
    VLOGF(1) << "Output frame " << i << ": " << out_frame->GetWidth() << "x"
             << out_frame->GetHeight() << " "
             << FormatToString(out_frame->GetFourcc());
    if (in_frame.GetWidth() == out_frame->GetWidth() &&
        in_frame.GetHeight() == out_frame->GetHeight() &&
        (out_frame->GetFourcc() == V4L2_PIX_FMT_NV12 ||
         out_frame->GetFourcc() == V4L2_PIX_FMT_NV12M)) {
      nv12_frame_index = i;
      break;
    }
  }

  FrameBuffer* nv12_frame;
  if (nv12_frame_index < out_frames.size()) {
    nv12_frame = out_frames[nv12_frame_index].get();
  } else {
    if (!GrallocFrameBuffer::Reallocate(in_frame.GetWidth(),
                                        in_frame.GetHeight(), V4L2_PIX_FMT_NV12,
                                        &temp_nv12_frame_)) {
      return -EINVAL;
    }
    nv12_frame = temp_nv12_frame_.get();
  }

  // Convert |in_frame| into |nv12_frame|.
  if (in_frame.GetFourcc() == V4L2_PIX_FMT_MJPEG) {
    int ret = DecodeToNV12(in_frame, *nv12_frame);
    if (ret)
      return ret;
  } else {
    int ret = image_processor_->ConvertFormat(in_frame, *nv12_frame);
    if (ret)
      return ret;
  }

  if (rotate_degree > 0) {
    int ret = CropRotateScale(rotate_degree, *nv12_frame);
    if (ret)
      return ret;
  }

  if (faces && request_metadata.exists(ANDROID_STATISTICS_FACE_DETECT_MODE)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_STATISTICS_FACE_DETECT_MODE);
    if (entry.data.u8[0] == ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE) {
      DetectFaces(*nv12_frame, faces);
    } else {
      faces->clear();
    }
  }

  // Convert |nv12_frame| into the output frames. At this time, this
  // function will always return 0 and record the per-output-frame conversion
  // status in |out_frame_status|.
  out_frame_status.resize(out_frames.size());
  for (size_t i = 0; i < out_frames.size(); i++) {
    if (i == nv12_frame_index) {
      out_frame_status[i] = 0;
      continue;
    }
    out_frame_status[i] = ConvertFromNV12(static_metadata, request_metadata,
                                          *nv12_frame, *out_frames[i]);
  }
  return 0;
}

int CachedFrame::ConvertFromNV12(
    const android::CameraMetadata& static_metadata,
    const android::CameraMetadata& request_metadata,
    FrameBuffer& in_frame,
    FrameBuffer& out_frame) {
  const Size in_size(in_frame.GetWidth(), in_frame.GetHeight());
  const Size out_size(out_frame.GetWidth(), out_frame.GetHeight());
  const Size crop_size = CalculateCropSize(in_size, out_size);

  FrameBuffer* src_frame = &in_frame;
  if (!(in_size == out_size)) {
    // Crop to the same aspect ratio of output size. Also converts format to
    // I420 since libyuv doesn't support NV12 scaling.
    if (!SharedFrameBuffer::Reallocate(crop_size.width, crop_size.height,
                                       V4L2_PIX_FMT_YUV420,
                                       &temp_i420_frame_)) {
      return -EINVAL;
    }
    int ret = image_processor_->Crop(in_frame, *temp_i420_frame_);
    if (ret)
      return ret;
    // Scale to the output size.
    if (!SharedFrameBuffer::Reallocate(
            out_frame.GetWidth(), out_frame.GetHeight(), V4L2_PIX_FMT_YUV420,
            &temp_i420_frame2_)) {
      return -EINVAL;
    }
    ret = image_processor_->Scale(*temp_i420_frame_, *temp_i420_frame2_);
    if (ret)
      return ret;
    src_frame = temp_i420_frame2_.get();
  }

  // Output JPEG.
  if (out_frame.GetFourcc() == V4L2_PIX_FMT_JPEG) {
    if (src_frame->GetFourcc() != V4L2_PIX_FMT_NV12 &&
        src_frame->GetFourcc() != V4L2_PIX_FMT_NV12M) {
      if (!GrallocFrameBuffer::Reallocate(
              out_frame.GetWidth(), out_frame.GetHeight(), V4L2_PIX_FMT_NV12,
              &temp_nv12_frame2_)) {
        return -EINVAL;
      }
      int ret = image_processor_->ConvertFormat(*src_frame, *temp_nv12_frame2_);
      if (ret)
        return ret;
      src_frame = temp_nv12_frame2_.get();
    }
    return CompressNV12(static_metadata, request_metadata, *src_frame,
                        out_frame);
  }
  // Output other formats.
  return image_processor_->ConvertFormat(*src_frame, out_frame);
}

int CachedFrame::DecodeToNV12(FrameBuffer& in_frame, FrameBuffer& out_frame) {
  TRACE_USB_HAL();

  // Try HW decoding.
  base::ElapsedTimer hw_timer;
  int ret = DecodeByJDA(in_frame, out_frame);
  if (ret == 0) {
    camera_metrics_->SendJpegProcessLatency(JpegProcessType::kDecode,
                                            JpegProcessMethod::kHardware,
                                            hw_timer.Elapsed());
    camera_metrics_->SendJpegResolution(
        JpegProcessType::kDecode, JpegProcessMethod::kHardware,
        in_frame.GetWidth(), in_frame.GetHeight());
    return ret;
  }
  if (ret == -EAGAIN) {
    return ret;
  }

  // JDA error, fallback to SW decoding if not forcing HW decoding.
  if (force_jpeg_hw_decode_) {
    return -EINVAL;
  }

  // SW decoding.
  base::ElapsedTimer sw_timer;
  ret = image_processor_->ConvertFormat(in_frame, out_frame);
  if (ret) {
    return -EAGAIN;
  }
  camera_metrics_->SendJpegProcessLatency(JpegProcessType::kDecode,
                                          JpegProcessMethod::kSoftware,
                                          sw_timer.Elapsed());
  camera_metrics_->SendJpegResolution(
      JpegProcessType::kDecode, JpegProcessMethod::kSoftware,
      in_frame.GetWidth(), in_frame.GetHeight());
  return 0;
}

int CachedFrame::DecodeByJDA(FrameBuffer& in_frame, FrameBuffer& out_frame) {
  if (!jda_available_)
    return -EINVAL;

  // For test case, don't need to cap the resolution.
  if (!force_jpeg_hw_decode_) {
    if (in_frame.GetWidth() > jda_resolution_cap_.width ||
        in_frame.GetHeight() > jda_resolution_cap_.height) {
      return -EINVAL;
    }
  }
  // The output frame needs to be mapped after HW JDA processing otherwise the
  // mapped addresses won't sync the content correctly. If the frame is already
  // mapped, unmap it first.
  // TODO(kamesan): simplify the map/unmap logics when we figure out a proper
  // way to sync mapped addresses (probably inside JDA implementation).
  if (out_frame.Unmap()) {
    LOGF(ERROR) << "Failed to unmap frame";
    return -EINVAL;
  }
  // TODO(kamesan): pass the buffer offset from V4L2 to here.
  JpegDecodeAccelerator::Error error = jda_->DecodeSync(
      in_frame.GetFd(), in_frame.GetDataSize(), 0 /* input_buffer_offset */,
      out_frame.GetBufferHandle());
  switch (error) {
    case JpegDecodeAccelerator::Error::NO_ERRORS:
      return 0;
    case JpegDecodeAccelerator::Error::PARSE_JPEG_FAILED:
    case JpegDecodeAccelerator::Error::UNSUPPORTED_JPEG:
      // Camera device may temporarily output invalid MJPEG stream. HAL should
      // skip this frame and get the next frame.
      return -EAGAIN;
    case JpegDecodeAccelerator::Error::TRY_START_AGAIN:
      // Possibly Mojo communication error. Try restart JDA and return error
      // this time.
      jda_available_ = jda_->Start();
      LOGF(WARNING) << "Restart JDA: " << jda_available_;
      return -EINVAL;
    default:
      // Other JDA errors.
      return -EINVAL;
  }
}

int CachedFrame::CropRotateScale(int rotate_degree, FrameBuffer& frame) {
  if (frame.GetHeight() > frame.GetWidth()) {
    LOGF(ERROR) << "frame is tall frame already: " << frame.GetWidth() << "x"
                << frame.GetHeight();
    return -EINVAL;
  }

  // Step 1: Crop and rotate
  //
  //   Original frame                  Cropped frame              Rotated frame
  // --------------------               --------
  // |     |      |     |               |      |                 ---------------
  // |     |      |     |               |      |                 |             |
  // |     |      |     |   =======>>   |      |     =======>>   |             |
  // |     |      |     |               |      |                 ---------------
  // |     |      |     |               |      |
  // --------------------               --------
  //
  uint32_t cropped_width =
      frame.GetHeight() * frame.GetHeight() / frame.GetWidth();
  if (cropped_width % 2 == 1) {
    // Make cropped_width to the closest even number.
    cropped_width++;
  }
  int cropped_height = frame.GetHeight();
  if (!SharedFrameBuffer::Reallocate(cropped_height, cropped_width,
                                     V4L2_PIX_FMT_YUV420, &temp_i420_frame2_)) {
    return -EINVAL;
  }

  int ret = image_processor_->ProcessForInsetPortraitMode(
      frame, *temp_i420_frame2_, rotate_degree);
  if (ret) {
    LOGF(ERROR) << "Crop and Rotate " << rotate_degree << " degree fails.";
    return ret;
  }

  // Step 2: Scale
  //
  //                               Final frame
  //  Rotated frame            ---------------------
  // --------------            |                   |
  // |            |  =====>>   |                   |
  // |            |            |                   |
  // --------------            |                   |
  //                           |                   |
  //                           ---------------------
  //
  if (!SharedFrameBuffer::Reallocate(frame.GetWidth(), frame.GetHeight(),
                                     V4L2_PIX_FMT_YUV420, &temp_i420_frame_)) {
    return -EINVAL;
  }
  ret = image_processor_->Scale(*temp_i420_frame2_, *temp_i420_frame_);
  LOGF_IF(ERROR, ret) << "Scale failed: " << ret;

  return image_processor_->ConvertFormat(*temp_i420_frame_, frame);
}

int CachedFrame::CompressNV12(const android::CameraMetadata& static_metadata,
                              const android::CameraMetadata& request_metadata,
                              FrameBuffer& in_frame,
                              FrameBuffer& out_frame) {
  ExifUtils utils;
  if (!utils.Initialize()) {
    LOGF(ERROR) << "ExifUtils initialization failed.";
    return -ENODEV;
  }

  if (!SetExifTags(static_metadata, request_metadata, in_frame, &utils)) {
    LOGF(ERROR) << "Setting Exif tags failed.";
    return -EINVAL;
  }

  int jpeg_quality, thumbnail_jpeg_quality;
  camera_metadata_ro_entry entry = request_metadata.find(ANDROID_JPEG_QUALITY);
  if (entry.count) {
    jpeg_quality = entry.data.u8[0];
  } else {
    LOGF(ERROR) << "Cannot find jpeg quality in metadata.";
    return -EINVAL;
  }
  if (request_metadata.exists(ANDROID_JPEG_THUMBNAIL_QUALITY)) {
    entry = request_metadata.find(ANDROID_JPEG_THUMBNAIL_QUALITY);
    thumbnail_jpeg_quality = entry.data.u8[0];
  } else {
    thumbnail_jpeg_quality = jpeg_quality;
  }

  // Generate thumbnail
  std::vector<uint8_t> thumbnail;
  if (request_metadata.exists(ANDROID_JPEG_THUMBNAIL_SIZE)) {
    entry = request_metadata.find(ANDROID_JPEG_THUMBNAIL_SIZE);
    if (entry.count < 2) {
      LOGF(ERROR) << "Thumbnail size in metadata is not complete.";
      return -EINVAL;
    }
    int thumbnail_width = entry.data.i32[0];
    int thumbnail_height = entry.data.i32[1];
    if (thumbnail_width == 0 && thumbnail_height == 0) {
      VLOGF(1) << "Thumbnail size = (0, 0), nothing will be generated";
    } else if (!ValidateThumbnailSize(static_metadata, thumbnail_width,
                                      thumbnail_height)) {
      LOGF(ERROR) << "Invalid thumbnail size " << thumbnail_width << "x"
                  << thumbnail_height;
      return -EINVAL;
    } else {
      const uint8_t* i420_data;
      if (in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420) {
        i420_data = in_frame.GetData();
      } else {
        if (!SharedFrameBuffer::Reallocate(
                in_frame.GetWidth(), in_frame.GetHeight(), V4L2_PIX_FMT_YUV420,
                &temp_i420_frame_)) {
          LOGF(ERROR) << "Failed to allocate shared memory buffer";
          return -EINVAL;
        }
        int ret = image_processor_->ConvertFormat(in_frame, *temp_i420_frame_);
        if (ret) {
          LOGF(ERROR) << "Failed to convert frame to I420";
          return ret;
        }
        i420_data = temp_i420_frame_->GetData();
      }
      uint32_t thumbnail_data_size = 0;
      thumbnail.resize(kApp1MaxDataSize);
      if (jpeg_compressor_->GenerateThumbnail(
              i420_data, in_frame.GetWidth(), in_frame.GetHeight(),
              thumbnail_width, thumbnail_height, thumbnail_jpeg_quality,
              thumbnail.size(), thumbnail.data(), &thumbnail_data_size)) {
        thumbnail.resize(thumbnail_data_size);
      } else {
        LOGF(WARNING) << "Generate JPEG thumbnail failed";
        thumbnail.clear();
      }
    }
  }

  // TODO(shik): Regenerate if thumbnail is too large.
  if (!utils.GenerateApp1(thumbnail.data(), thumbnail.size())) {
    LOGF(ERROR) << "Generating APP1 segment failed.";
    return -EINVAL;
  }

  // TODO(okuji): Without this Map(),
  // Camera3FrameTest/Camera3PortraitRotationTest.GetFrame/* does not pass.
  // Figure out why this is required although CompressImageFromHandle() maps
  // |out_frame| when it falls back to software encoding.
  if (out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return -EINVAL;
  }
  uint32_t jpeg_data_size = 0;
  if (!jpeg_compressor_->CompressImageFromHandle(
          in_frame.GetBufferHandle(), out_frame.GetBufferHandle(),
          in_frame.GetWidth(), in_frame.GetHeight(), jpeg_quality,
          utils.GetApp1Buffer(), utils.GetApp1Length(), &jpeg_data_size)) {
    LOGF(ERROR) << "JPEG image compression failed";
    return -EINVAL;
  }
  if (!InsertJpegBlob(out_frame, jpeg_data_size)) {
    LOGF(ERROR) << "Inserting JPEG blob failed";
    return -EINVAL;
  }
  return 0;
}

void CachedFrame::DetectFaces(const FrameBuffer& input_nv12_frame,
                              std::vector<human_sensing::CrosFace>* faces) {
  // Number of frames to detect faces once.
  const int kFaceDetectFrameInterval = 10;
  DCHECK(faces);

  if (!face_detector_) {
    faces->clear();
    return;
  }

  frame_count_ = (frame_count_ + 1) % kFaceDetectFrameInterval;
  if (frame_count_ != 1) {
    *faces = faces_;
    return;
  }

  FaceDetectResult ret = face_detector_->Detect(
      input_nv12_frame.GetBufferHandle(), &faces_, active_array_size_);
  if (ret != FaceDetectResult::kDetectOk) {
    faces_.clear();
  }
  *faces = faces_;
}

static bool InsertJpegBlob(FrameBuffer& out_frame, uint32_t jpeg_data_size) {
  if (out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return false;
  }
  camera3_jpeg_blob_t blob;
  blob.jpeg_blob_id = CAMERA3_JPEG_BLOB_ID;
  blob.jpeg_size = jpeg_data_size;
  memcpy(out_frame.GetData() + out_frame.GetBufferSize() - sizeof(blob), &blob,
         sizeof(blob));
  return true;
}

static bool SetExifTags(const android::CameraMetadata& static_metadata,
                        const android::CameraMetadata& request_metadata,
                        const FrameBuffer& in_frame,
                        ExifUtils* utils) {
  if (!utils->SetImageWidth(in_frame.GetWidth()) ||
      !utils->SetImageLength(in_frame.GetHeight())) {
    LOGF(ERROR) << "Setting image resolution failed.";
    return false;
  }

  struct timespec tp;
  struct tm time_info;
  bool time_available = clock_gettime(CLOCK_REALTIME, &tp) != -1;
  tzset();
  localtime_r(&tp.tv_sec, &time_info);
  if (!utils->SetDateTime(time_info)) {
    LOGF(ERROR) << "Setting data time failed.";
    return false;
  }

  if (request_metadata.exists(ANDROID_LENS_FOCAL_LENGTH)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_LENS_FOCAL_LENGTH);
    float focal_length = entry.data.f[0];
    if (!utils->SetFocalLength(
            static_cast<uint32_t>(focal_length * kRationalPrecision),
            kRationalPrecision)) {
      LOGF(ERROR) << "Setting focal length failed.";
      return false;
    }
  } else {
    if (static_metadata.exists(ANDROID_LENS_FACING)) {
      camera_metadata_ro_entry entry =
          static_metadata.find(ANDROID_LENS_FACING);
      if (entry.data.u8[0] != ANDROID_LENS_FACING_EXTERNAL) {
        LOGF(ERROR)
            << "Cannot find focal length in metadata from a built-in camera.";
        return false;
      }
    } else {
      LOGF(WARNING) << "Cannot find focal length in metadata.";
    }
  }

  if (request_metadata.exists(ANDROID_JPEG_GPS_COORDINATES)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_JPEG_GPS_COORDINATES);
    if (entry.count < 3) {
      LOGF(ERROR) << "Gps coordinates in metadata is not complete.";
      return false;
    }
    if (!utils->SetGpsLatitude(entry.data.d[0])) {
      LOGF(ERROR) << "Setting gps latitude failed.";
      return false;
    }
    if (!utils->SetGpsLongitude(entry.data.d[1])) {
      LOGF(ERROR) << "Setting gps longitude failed.";
      return false;
    }
    if (!utils->SetGpsAltitude(entry.data.d[2])) {
      LOGF(ERROR) << "Setting gps altitude failed.";
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_JPEG_GPS_PROCESSING_METHOD)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_JPEG_GPS_PROCESSING_METHOD);
    std::string method_str(reinterpret_cast<const char*>(entry.data.u8));
    if (!utils->SetGpsProcessingMethod(method_str)) {
      LOGF(ERROR) << "Setting gps processing method failed.";
      return false;
    }
  }

  if (time_available && request_metadata.exists(ANDROID_JPEG_GPS_TIMESTAMP)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_JPEG_GPS_TIMESTAMP);
    time_t timestamp = static_cast<time_t>(entry.data.i64[0]);
    if (gmtime_r(&timestamp, &time_info)) {
      if (!utils->SetGpsTimestamp(time_info)) {
        LOGF(ERROR) << "Setting gps timestamp failed.";
        return false;
      }
    } else {
      LOGF(ERROR) << "Time tranformation failed.";
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_JPEG_ORIENTATION)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_JPEG_ORIENTATION);
    if (!utils->SetOrientation(entry.data.i32[0])) {
      LOGF(ERROR) << "Setting orientation failed.";
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_LENS_APERTURE)) {
    const int kAperturePrecision = 10000;
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_LENS_APERTURE);
    if (!utils->SetFNumber(entry.data.f[0] * kAperturePrecision,
                           kAperturePrecision)) {
      LOGF(ERROR) << "Setting F number failed.";
      return false;
    }
  }

  if (static_metadata.exists(ANDROID_FLASH_INFO_AVAILABLE)) {
    camera_metadata_ro_entry entry =
        static_metadata.find(ANDROID_FLASH_INFO_AVAILABLE);
    if (entry.data.u8[0] == ANDROID_FLASH_INFO_AVAILABLE_FALSE) {
      const uint32_t kNoFlashFunction = 0x20;
      if (!utils->SetFlash(kNoFlashFunction)) {
        LOGF(ERROR) << "Setting flash failed.";
        return false;
      }
    } else {
      LOGF(ERROR) << "Unsupported flash info: " << entry.data.u8[0];
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_CONTROL_AWB_MODE)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_CONTROL_AWB_MODE);
    if (entry.data.u8[0] == ANDROID_CONTROL_AWB_MODE_AUTO) {
      const uint16_t kAutoWhiteBalance = 0;
      if (!utils->SetWhiteBalance(kAutoWhiteBalance)) {
        LOGF(ERROR) << "Setting white balance failed.";
        return false;
      }
    } else {
      LOGF(ERROR) << "Unsupported awb mode: " << entry.data.u8[0];
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_CONTROL_AE_MODE)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_CONTROL_AE_MODE);
    const uint16_t kExposureMode =
        (entry.data.u8[0] == ANDROID_CONTROL_AE_MODE_OFF) ? 1 : 0;
    if (!utils->SetExposureMode(kExposureMode)) {
      LOGF(ERROR) << "Setting exposure mode failed.";
      return false;
    }
  }

  if (request_metadata.exists(ANDROID_SENSOR_EXPOSURE_TIME)) {
    camera_metadata_ro_entry entry =
        request_metadata.find(ANDROID_SENSOR_EXPOSURE_TIME);
    if (!utils->SetExposureTime(entry.data.i64[0], 1'000'000'000)) {
      LOGF(ERROR) << "Setting exposure time failed.";
      return false;
    }
  }

  if (time_available) {
    char str[4];
    if (snprintf(str, sizeof(str), "%03ld", tp.tv_nsec / 1000000) < 0) {
      LOGF(ERROR) << "Subsec is invalid: " << tp.tv_nsec;
      return false;
    }
    if (!utils->SetSubsecTime(std::string(str))) {
      LOGF(ERROR) << "Setting subsec time failed.";
      return false;
    }
  }

  return true;
}

}  // namespace cros
