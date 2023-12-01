/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/frame_annotator/libs/frame_annotator_stream_manipulator.h"

#include <cinttypes>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/strings/string_piece.h>
#include <libyuv.h>
#include <skia/core/SkCanvas.h>
#include <skia/core/SkColorSpace.h>
#include <skia/core/SkSurface.h>
#include <skia/gpu/gl/GrGLInterface.h>
#include <skia/gpu/GrYUVABackendTextures.h>
#include <sync/sync.h>

#include "common/camera_hal3_helpers.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "features/frame_annotator/libs/face_rectangles_frame_annotator.h"
#include "features/frame_annotator/libs/metadata_previewer_frame_annotator.h"
#include "features/frame_annotator/tracing.h"
#include "gpu/gles/texture_2d.h"
#include "gpu/shared_image.h"

namespace cros {

namespace {

// Options for 'frame_annotator_config.json'
constexpr char kFlipTypeKey[] = "flip_type";
constexpr char kFaceRectanglesFrameAnnotatorKey[] =
    "face_rectangles_frame_annotator";
constexpr char kMetadataPreviewerFrameAnnotatorKey[] =
    "metadata_previewer_frame_annotator";
constexpr char kFaceRectanglesKey[] = "face_rectangles";
constexpr char kFaceRectanglesConfidenceKey[] = "face_rectangles_confidence";
constexpr char kFaceLandmarksKey[] = "face_landmarks";
constexpr char kFaceLandmarksConfidenceKey[] = "face_landmarks_confidence";

constexpr int kSyncWaitTimeoutMs = 300;

GrBackendTexture ConvertToGrBackendTexture(const Texture2D& texture) {
  GrGLTextureInfo gl_info = {.fTarget = texture.target(),
                             .fID = texture.handle(),
                             .fFormat = texture.internal_format()};
  return GrBackendTexture(texture.width(), texture.height(), GrMipmapped::kNo,
                          gl_info);
}

GrYUVABackendTextures ConvertToGrTextures(const SharedImage& image) {
  auto image_size =
      SkISize::Make(image.y_texture().width(), image.y_texture().height());
  // Assumes downstream is using kJPEG_FULL_SkYUVColorSpace.
  SkYUVAInfo info{image_size, SkYUVAInfo::PlaneConfig::kY_UV,
                  SkYUVAInfo::Subsampling::k420, kJPEG_Full_SkYUVColorSpace};
  GrBackendTexture textures[2] = {
      ConvertToGrBackendTexture(image.y_texture()),
      ConvertToGrBackendTexture(image.uv_texture())};
  return GrYUVABackendTextures(info, textures,
                               GrSurfaceOrigin::kTopLeft_GrSurfaceOrigin);
}

}  // namespace

//
// FrameAnnotatorStreamManipulator implementations.
//

FrameAnnotatorStreamManipulator::FrameAnnotatorStreamManipulator()
    : config_(ReloadableConfigFile::Options{
          base::FilePath(FrameAnnotator::kFrameAnnotatorConfigFile),
          base::FilePath(FrameAnnotator::kOverrideFrameAnnotatorConfigFile)}),
      gpu_thread_("FrameAnnotatorThread") {
  CHECK(gpu_thread_.Start());

  config_.SetCallback(
      base::BindRepeating(&FrameAnnotatorStreamManipulator::OnOptionsUpdated,
                          base::Unretained(this)));

  if (options_.face_rectangles_frame_annotator) {
    frame_annotators_.emplace_back(
        std::make_unique<FaceRectanglesFrameAnnotator>());
    LOGF(INFO) << "FaceRectanglesFrameAnnotator enabled";
  }
  if (options_.metadata_previewer_frame_annotator) {
    frame_annotators_.emplace_back(
        std::make_unique<MetadataPreviewerFrameAnnotator>());
    LOGF(INFO) << "MetadataPreviewerFrameAnnotator enabled";
  }
}

FrameAnnotatorStreamManipulator::~FrameAnnotatorStreamManipulator() {
  gpu_thread_.Stop();
}

bool FrameAnnotatorStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  callbacks_ = std::move(callbacks);
  base::span<const int32_t> active_array_size = GetRoMetadataAsSpan<int32_t>(
      static_info, ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);
  DCHECK_EQ(active_array_size.size(), 4);
  active_array_dimension_ = Size(active_array_size[2], active_array_size[3]);

  for (const auto& frame_annotator : frame_annotators_) {
    bool res = frame_annotator->Initialize(static_info);
    if (!res) {
      LOGF(ERROR)
          << "Failed to initialize one of the enabled frame annotators.";
      return false;
    }
  }

  bool ret;
  gpu_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&FrameAnnotatorStreamManipulator::SetUpContextsOnGpuThread,
                     base::Unretained(this)),
      &ret);
  return ret;
}

bool FrameAnnotatorStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  yuv_stream_ = nullptr;

  for (const auto* s : stream_config->GetStreams()) {
    // Pick output stream.
    if (s->stream_type != CAMERA3_STREAM_OUTPUT) {
      continue;
    }
    // Pick preview stream.
    if ((GRALLOC_USAGE_HW_COMPOSER & s->usage) != GRALLOC_USAGE_HW_COMPOSER) {
      continue;
    }
    // Pick YUV stream.
    if (HAL_PIXEL_FORMAT_YCbCr_420_888 == s->format ||
        HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED == s->format) {
      // Pick the buffer with the largest width. This is heuristic and shouldn't
      // matter for the majority of the time, as for most cases the requested
      // streams would have the same aspect ratio.
      if (!yuv_stream_ || s->width > yuv_stream_->width) {
        yuv_stream_ = s;
      }
    }
  }

  if (yuv_stream_) {
    VLOGF(1) << "YUV stream for CrOS Frame Annotator processing: "
             << GetDebugString(yuv_stream_);
  } else {
    LOGF(WARNING)
        << "No YUV stream suitable for CrOS Frame Annotator processing";
  }
  return true;
}

bool FrameAnnotatorStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  return true;
}

bool FrameAnnotatorStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool FrameAnnotatorStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  return true;
}

bool FrameAnnotatorStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  base::ScopedClosureRunner result_callback_task =
      StreamManipulator::MakeScopedCaptureResultCallbackRunner(
          callbacks_.result_callback, result);

  if (frame_annotators_.empty()) {
    return true;
  }

  bool ret;
  gpu_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(
          &FrameAnnotatorStreamManipulator::ProcessCaptureResultOnGpuThread,
          base::Unretained(this), &result),
      &ret);
  return ret;
}

void FrameAnnotatorStreamManipulator::Notify(camera3_notify_msg_t msg) {
  TRACE_FRAME_ANNOTATOR();

  callbacks_.notify_callback.Run(std::move(msg));
}

bool FrameAnnotatorStreamManipulator::Flush() {
  return true;
}

bool FrameAnnotatorStreamManipulator::ProcessCaptureResultOnGpuThread(
    Camera3CaptureDescriptor* result) {
  DCHECK(gpu_thread_.IsCurrentThread());

  for (const auto& frame_annotator : frame_annotators_) {
    bool res = frame_annotator->ProcessCaptureResult(result);
    if (!res) {
      LOGF(ERROR) << "One of the enabled frame annotators failed to process "
                     "capture result.";
      return false;
    }
  }

  for (auto& b : result->GetMutableOutputBuffers()) {
    if (b.stream() != yuv_stream_) {
      continue;
    }
    if (b.status() == CAMERA3_BUFFER_STATUS_ERROR) {
      continue;
    }
    bool res = PlotOnGpuThread(b);
    if (!res) {
      return false;
    }
  }

  return true;
}

bool FrameAnnotatorStreamManipulator::SetUpContextsOnGpuThread() {
  DCHECK(gpu_thread_.IsCurrentThread());

  if (!egl_context_) {
    egl_context_ = EglContext::GetSurfacelessContext();
    if (!egl_context_->IsValid()) {
      LOGF(ERROR) << "Failed to create EGL context";
      return false;
    }
  }
  if (!egl_context_->MakeCurrent()) {
    LOGF(ERROR) << "Failed to make EGL context current";
    return false;
  }

  gr_context_ = GrDirectContext::MakeGL();
  if (!gr_context_) {
    LOGF(ERROR) << "Failed to make Skia's GL context";
    return false;
  }

  return true;
}

bool FrameAnnotatorStreamManipulator::PlotOnGpuThread(
    Camera3StreamBuffer& buffer) {
  DCHECK(gpu_thread_.IsCurrentThread());

  if (!buffer.WaitOnAndClearReleaseFence(kSyncWaitTimeoutMs)) {
    LOGF(ERROR) << "Timed out waiting for input buffer";
    return false;
  }

  // Convert SharedImage to SkImage and create a SkCanvas.
  auto image = SharedImage::CreateFromBuffer(
      *buffer.buffer(), Texture2D::Target::kTarget2D, true);
  auto sk_image = SkImage::MakeFromYUVATextures(gr_context_.get(),
                                                ConvertToGrTextures(image));
  auto surface = SkSurface::MakeRenderTarget(
      gr_context_.get(), SkBudgeted::kYes, sk_image->imageInfo());
  auto canvas = surface->getCanvas();
  canvas->drawImage(sk_image, 0, 0);

  bool surface_need_flush = false;
  for (auto& frame_annotator : frame_annotators_) {
    if (frame_annotator->IsPlotNeeded()) {
      frame_annotator->Plot(canvas);
      surface_need_flush = true;
    }
  }
  if (surface_need_flush) {
    FlushSkSurfaceToBuffer(surface.get(), *buffer.buffer());
  }

  DCHECK_EQ(buffer.acquire_fence(), -1);
  buffer.mutable_raw_buffer().status = CAMERA3_BUFFER_STATUS_OK;
  return true;
}

void FrameAnnotatorStreamManipulator::FlushSkSurfaceToBuffer(
    SkSurface* surface, buffer_handle_t yuv_buf) {
  DCHECK(gpu_thread_.IsCurrentThread());

  struct Context {
    buffer_handle_t buf;
    size_t width, height;
    Context(buffer_handle_t b, size_t w, size_t h)
        : buf(b), width(w), height(h) {}
  } context(yuv_buf, surface->width(), surface->height());

  surface->asyncRescaleAndReadPixelsYUV420(
      kJPEG_Full_SkYUVColorSpace, SkColorSpace::MakeSRGB(),
      SkIRect::MakeWH(surface->width(), surface->height()),
      SkISize::Make(surface->width(), surface->height()),
      SkSurface::RescaleGamma::kSrc, SkSurface::RescaleMode::kNearest,
      [](void* ctx_ptr,
         std::unique_ptr<const SkSurface::AsyncReadResult> result) {
        Context* ctx = reinterpret_cast<Context*>(ctx_ptr);
        ScopedMapping mapping(ctx->buf);

        CHECK_EQ(mapping.num_planes(), 2);

        const auto y_plane = mapping.plane(0);
        const auto uv_plane = mapping.plane(1);

        DCHECK_EQ(ctx->width % 2, 0);

        libyuv::I420ToNV12(
            reinterpret_cast<const uint8_t*>(result->data(0)), ctx->width,
            reinterpret_cast<const uint8_t*>(result->data(1)), ctx->width / 2,
            reinterpret_cast<const uint8_t*>(result->data(2)), ctx->width / 2,
            y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
            ctx->width, ctx->height);
      },
      &context);

  // Force the result to be written back to the buffer before returning from
  // the function. Therefore, it's safe to pass local variables here as the
  // lifetime is being guaranteed.
  surface->flushAndSubmit(/*syncCpu=*/true);
}

void FrameAnnotatorStreamManipulator::OnOptionsUpdated(
    const base::Value::Dict& json_values) {
  if (auto flip_type = json_values.FindString(kFlipTypeKey)) {
    base::StringPiece name = *flip_type;
    if (name == "default") {
      options_.flip_type = FrameAnnotator::FlipType::kDefault;
    } else if (name == "none") {
      options_.flip_type = FrameAnnotator::FlipType::kNone;
    } else if (name == "horizontal") {
      options_.flip_type = FrameAnnotator::FlipType::kHorizontal;
    } else if (name == "vertical") {
      options_.flip_type = FrameAnnotator::FlipType::kVertical;
    } else if (name == "rotate180") {
      options_.flip_type = FrameAnnotator::FlipType::kRotate180;
    } else {
      LOGF(WARNING) << "Invalid flip_type value: " << name;
    }
  }

  auto update_bool_option = [&](bool& result, const char key_name[]) {
    result = json_values.FindBool(key_name).value_or(result);
  };
  update_bool_option(options_.face_rectangles_frame_annotator,
                     kFaceRectanglesFrameAnnotatorKey);
  update_bool_option(options_.metadata_previewer_frame_annotator,
                     kMetadataPreviewerFrameAnnotatorKey);
  update_bool_option(options_.face_rectangles, kFaceRectanglesKey);
  update_bool_option(options_.face_rectangles_confidence,
                     kFaceRectanglesConfidenceKey);
  update_bool_option(options_.face_landmarks, kFaceLandmarksKey);
  update_bool_option(options_.face_landmarks_confidence,
                     kFaceLandmarksConfidenceKey);

  for (auto& frame_annotator : frame_annotators_) {
    frame_annotator->UpdateOptions(options_);
  }
}

}  // namespace cros
