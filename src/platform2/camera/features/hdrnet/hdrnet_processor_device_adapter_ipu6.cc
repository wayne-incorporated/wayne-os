/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/hdrnet_processor_device_adapter_ipu6.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/strings/stringprintf.h>
#include <base/timer/elapsed_timer.h>

#include "common/embed_file_toc.h"
#include "cros-camera/camera_buffer_utils.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "features/gcam_ae/ae_info.h"
#include "features/hdrnet/embedded_hdrnet_processor_shaders_ipu6_toc.h"
#include "features/hdrnet/hdrnet_metrics.h"
#include "features/hdrnet/ipu6_gamma.h"
#include "features/hdrnet/tracing.h"
#include "features/third_party/intel/intel_vendor_metadata_tags.h"
#include "gpu/embedded_gpu_shaders_toc.h"
#include "gpu/gles/framebuffer.h"
#include "gpu/gles/state_guard.h"
#include "gpu/gles/transform.h"

namespace cros {

namespace {

constexpr const char kVertexShaderFilename[] =
    "fullscreen_rect_highp_310_es.vert";
constexpr const char kPreprocessorFilename[] = "preprocess_ipu6.frag";
constexpr const char kModelDir[] = "/usr/share/cros-camera/ml_models/hdrnet";

constexpr int kCoeffInputWidth = 256;
constexpr int kCoeffInputHeight = 192;

}  // namespace

HdrNetProcessorDeviceAdapterIpu6::HdrNetProcessorDeviceAdapterIpu6(
    const camera_metadata_t* static_info,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(task_runner) {
  std::optional<int32_t> max_curve_points =
      GetRoMetadata<int32_t>(static_info, ANDROID_TONEMAP_MAX_CURVE_POINTS);
  CHECK(max_curve_points) << ": ANDROID_TONEMAP_MAX_CURVE_POINTS not set";
  num_curve_points_ = *max_curve_points;
}

bool HdrNetProcessorDeviceAdapterIpu6::Initialize(
    GpuResources* gpu_resources,
    Size input_size,
    const std::vector<Size>& output_sizes) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET_DEBUG();

  CHECK(gpu_resources);
  gpu_resources_ = gpu_resources;
  // In the current implementation |task_runner_| should always be the GPU
  // resource task runner.
  // TODO(jcliang): Consolidate and clean up the task runner and GPU threads.
  DCHECK(gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());

  VLOGF(1) << "Create HDRnet pipeline with: input_width=" << input_size.width
           << " input_height=" << input_size.height
           << " output_width=" << input_size.width
           << " output_height=" << input_size.height;
  HdrNetLinearRgbPipelineCrOS::CreateOptions options{
      .input_width = static_cast<int>(input_size.width),
      .input_height = static_cast<int>(input_size.height),
      .output_width = static_cast<int>(input_size.width),
      .output_height = static_cast<int>(input_size.height),
      .intermediate_format = GL_RGBA16F,
      .min_hdr_ratio = 1.0f,
      .max_hdr_ratio = 15.0f,
  };
  std::string model_dir = "";
  if (base::PathExists(base::FilePath(kModelDir))) {
    model_dir = kModelDir;
  }
  hdrnet_pipeline_ =
      HdrNetLinearRgbPipelineCrOS::CreatePipeline(options, model_dir);
  if (!hdrnet_pipeline_) {
    LOGF(ERROR) << "Failed to create HDRnet pipeline";
    return false;
  }

  rect_ = std::make_unique<ScreenSpaceRect>();
  nearest_clamp_to_edge_ = Sampler(NearestClampToEdge());
  linear_clamp_to_edge_ = Sampler(LinearClampToEdge());

  EmbeddedFileToc hdrnet_processor_shaders =
      GetEmbeddedHdrnetProcessorShadersIpu6Toc();
  EmbeddedFileToc gpu_shaders = GetEmbeddedGpuShadersToc();
  // Create the vextex shader.
  base::span<const char> src = gpu_shaders.Get(kVertexShaderFilename);
  Shader vertex_shader(GL_VERTEX_SHADER, std::string(src.data(), src.size()));
  if (!vertex_shader.IsValid()) {
    LOGF(ERROR) << "Failed to load vertex shader";
    return false;
  }

  {
    base::span<const char> src =
        hdrnet_processor_shaders.Get(kPreprocessorFilename);
    Shader fragment_shader(GL_FRAGMENT_SHADER,
                           std::string(src.data(), src.size()));
    if (!fragment_shader.IsValid()) {
      LOGF(ERROR) << "Failed to load preprocess shader";
      return false;
    }
    preprocessor_program_ = ShaderProgram({&vertex_shader, &fragment_shader});
  }

  gamma_lut_ = intel_ipu6::CreateGammaLutTexture();
  inverse_gamma_lut_ = intel_ipu6::CreateInverseGammaLutTexture();

  coeff_prediction_rgb_ = SharedImage::CreateFromGpuTexture(
      GL_RGBA16F, kCoeffInputWidth, kCoeffInputHeight);

  output_uv_intermediate_ = SharedImage::CreateFromGpuTexture(
      GL_RG16F, input_size.width, input_size.height);

  VLOGF(1) << "Created IPU6 HDRnet device processor";
  initialized_ = true;
  return true;
}

void HdrNetProcessorDeviceAdapterIpu6::TearDown() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET_DEBUG();
}

bool HdrNetProcessorDeviceAdapterIpu6::WriteRequestParameters(
    Camera3CaptureDescriptor* request, MetadataLogger* metadata_logger) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET_DEBUG();

  std::array<uint8_t, 1> tonemap_curve_enable = {
      INTEL_VENDOR_CAMERA_CALLBACK_TM_CURVE_TRUE};
  if (!request->UpdateMetadata<uint8_t>(INTEL_VENDOR_CAMERA_CALLBACK_TM_CURVE,
                                        tonemap_curve_enable)) {
    LOGF(ERROR) << "Cannot enable INTEL_VENDOR_CAMERA_CALLBACK_TM_CURVE in "
                   "request metadta";
    return false;
  }
  return true;
}

void HdrNetProcessorDeviceAdapterIpu6::ProcessResultMetadata(
    Camera3CaptureDescriptor* result, MetadataLogger* metadata_logger) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET_DEBUG();

  // TODO(jcliang): Theoretically metadata can come after the buffer as well.
  // Currently the pipeline would break if the metadata come after the buffers.
  if (!initialized_) {
    LOGF(ERROR) << "HDRnet processor hadn't been initialized";
    return;
  }

  base::span<const float> tonemap_curve =
      result->GetMetadata<float>(INTEL_VENDOR_CAMERA_TONE_MAP_CURVE);
  if (!tonemap_curve.empty()) {
    VLOGF(1) << "Update GTM curve";
    CHECK_EQ(tonemap_curve.size(), num_curve_points_ * 2);
    gtm_lut_ = CreateGainLutTexture(tonemap_curve, false);
    inverse_gtm_lut_ = CreateGainLutTexture(tonemap_curve, true);

    if (metadata_logger) {
      metadata_logger->Log(result->frame_number(), kTagToneMapCurve,
                           tonemap_curve);
    }
  }
}

bool HdrNetProcessorDeviceAdapterIpu6::Run(int frame_number,
                                           const HdrNetConfig::Options& options,
                                           const SharedImage& input,
                                           const SharedImage& output,
                                           HdrnetMetrics* hdrnet_metrics) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  CHECK(gpu_resources_);

  TRACE_HDRNET();

  bool success = false;
  {
    TRACE_HDRNET_EVENT(kEventPreprocess, "frame_number", frame_number);
    base::ElapsedTimer t;
    // Run the HDRnet pipeline.
    success = CreateCoeffPredictionImage(input, coeff_prediction_rgb_);
    hdrnet_metrics->accumulated_preprocessing_latency_us +=
        t.Elapsed().InMicroseconds();
  }
  if (options.dump_buffer) {
    gpu_resources_->DumpSharedImage(
        coeff_prediction_rgb_,
        base::FilePath(base::StringPrintf(
            "preprocess_out_rgba_%dx%d_result#%d.rgba",
            coeff_prediction_rgb_.texture().width(),
            coeff_prediction_rgb_.texture().height(), frame_number)));
  }
  if (!success) {
    LOGF(ERROR) << "Cannot produce coefficient prediction input";
    return false;
  }

  // Run the HDRnet linear RGB pipeline
  HdrNetLinearRgbPipelineCrOS::RunOptions run_options = {
      .hdr_ratio = options.hdr_ratio,
      .min_gain = 1.0f,
      .max_gain = options.hdr_ratio,
      .max_gain_blend_threshold = options.max_gain_blend_threshold,
      .spatial_filter_sigma = options.spatial_filter_sigma,
      .range_filter_sigma = options.range_filter_sigma,
      .iir_filter_strength = options.iir_filter_strength,
  };

  // Pipeline inputs.
  Texture2DDescriptor input_y = {
      .id = base::checked_cast<GLint>(input.y_texture().handle()),
      .internal_format = GL_R16F,
      .width = input.y_texture().width(),
      .height = input.y_texture().height()};
  Texture2DDescriptor input_uv = {
      .id = base::checked_cast<GLint>(input.uv_texture().handle()),
      .internal_format = GL_RG16F,
      .width = input.uv_texture().width(),
      .height = input.uv_texture().height()};
  Texture2DDescriptor coeff_prediction_rgb = {
      .id = base::checked_cast<GLint>(coeff_prediction_rgb_.texture().handle()),
      .internal_format = GL_RGBA16F,
      .width = coeff_prediction_rgb_.texture().width(),
      .height = coeff_prediction_rgb_.texture().height()};

  // Pre-/post-process curves.
  Texture2DDescriptor inverse_gamma_curve = {
      .id = base::checked_cast<GLint>(inverse_gamma_lut_.handle()),
      .internal_format = GL_R16F,
      .width = inverse_gamma_lut_.width(),
      .height = inverse_gamma_lut_.height(),
  };
  Texture2DDescriptor inverse_adtm_curve = {
      .id = base::checked_cast<GLint>(inverse_gtm_lut_.handle()),
      .internal_format = GL_R16F,
      .width = inverse_gtm_lut_.width(),
      .height = inverse_gtm_lut_.height(),
  };
  Texture2DDescriptor gamma_curve = {
      .id = base::checked_cast<GLint>(gamma_lut_.handle()),
      .internal_format = GL_R16F,
      .width = gamma_lut_.width(),
      .height = gamma_lut_.height(),
  };
  Texture2DDescriptor adtm_curve = {
      .id = base::checked_cast<GLint>(gtm_lut_.handle()),
      .internal_format = GL_R16F,
      .width = gtm_lut_.width(),
      .height = gtm_lut_.height(),
  };

  // Pipeline output.
  Texture2DDescriptor output_y = {
      .id = base::checked_cast<GLint>(output.y_texture().handle()),
      .internal_format = GL_R16F,
      .width = output.y_texture().width(),
      .height = output.y_texture().height()};
  Texture2DDescriptor output_uv_intermediate = {
      .id =
          base::checked_cast<GLint>(output_uv_intermediate_.texture().handle()),
      .internal_format = GL_RG16F,
      .width = output_uv_intermediate_.texture().width(),
      .height = output_uv_intermediate_.texture().height()};

  bool result = hdrnet_pipeline_->RunIntelIpu6Pipeline(
      std::move(input_y), std::move(input_uv), std::move(inverse_gamma_curve),
      std::move(inverse_adtm_curve), std::move(gamma_curve),
      std::move(adtm_curve), std::move(coeff_prediction_rgb),
      std::move(output_y), std::move(output_uv_intermediate), run_options);
  if (!result) {
    LOGF(WARNING) << "Failed to run HDRnet pipeline";
    return false;
  }

  // Downsample to produce the UV plane for the output NV12 buffer.
  gpu_resources_->image_processor()->SubsampleChroma(
      output_uv_intermediate_.texture(), output.uv_texture());

  return true;
}

Texture2D HdrNetProcessorDeviceAdapterIpu6::CreateGainLutTexture(
    base::span<const float> tonemap_curve, bool inverse) {
  TRACE_HDRNET_DEBUG();

  auto interpolate = [](float i, float x0, float y0, float x1,
                        float y1) -> float {
    float kEpsilon = 1e-8;
    if (std::abs(x1 - x0) < kEpsilon) {
      return y0;
    }
    float slope = (y1 - y0) / (x1 - x0);
    return y0 + (i - x0) * slope;
  };

  if (gtm_lut_buffer_.size() < num_curve_points_) {
    gtm_lut_buffer_.resize(num_curve_points_);
  }

  // |tonemap_curve| is an array of |num_curve_points_| (v, g) pairs of floats,
  // with v in [0, 1] and g > 0. Each (v, g) pair specifies the gain `g` to
  // apply when the pixel value is `v`. Note that the Intel IPU6 GTM LUT is
  // "gain-based" and is different from the plain LUT as defined in [1]. It is
  // assumed that v * g is non-decreasing otherwise the LUT cannot be reasonably
  // inversed.
  //
  // For the forward LUT, we build a table with |num_curve_points_| (v, g)
  // entries, where `g` is the gain to apply for pre-gain pixel value `v`. This
  // is similar to the input |tonemap_curve|.
  //
  // For the inverse LUT, we build a table with |num_curve_points_| (u, g)
  // entries, where `g` is the estimated gain applied on post-gain pixel value
  // `u`. The shader would divide `u` by `g` to transform the pixel value back
  // to pseudo-linear domain.
  //
  // [1]:
  // https://developer.android.com/reference/android/hardware/camera2/CaptureRequest#TONEMAP_CURVE
  {
    TRACE_HDRNET_DEBUG_EVENT("Interpolate");
    int lut_index = 0;
    float x0 = 0.0, y0 = 1.0;
    for (int i = 0; i < num_curve_points_; ++i) {
      int idx = i * 2;
      float x1 = tonemap_curve[idx], y1 = tonemap_curve[idx + 1];
      if (inverse) {
        x1 = x1 * y1;  // x-axis is the value with gain applied.
      }
      const int scaled_x1 = x1 * static_cast<float>(num_curve_points_);
      for (; lut_index <= scaled_x1 && lut_index < num_curve_points_;
           ++lut_index) {
        gtm_lut_buffer_[lut_index] =
            interpolate(static_cast<float>(lut_index) /
                            static_cast<float>(num_curve_points_),
                        x0, y0, x1, y1);
        DVLOGF(3) << base::StringPrintf("(%5d, %1.10f, %d)", lut_index,
                                        gtm_lut_buffer_[lut_index], inverse);
      }
      x0 = x1;
      y0 = y1;
    }
    for (; lut_index < num_curve_points_; ++lut_index) {
      gtm_lut_buffer_[lut_index] = interpolate(
          static_cast<float>(lut_index) / static_cast<float>(num_curve_points_),
          x0, y0, 1.0, 1.0);
      DVLOGF(3) << base::StringPrintf("(%5d, %1.10f, %d)", lut_index,
                                      gtm_lut_buffer_[lut_index], inverse);
    }
  }

  {
    TRACE_HDRNET_DEBUG_EVENT("UploadTexture");
    Texture2D lut_texture(GL_R16F, num_curve_points_, 1);
    CHECK(lut_texture.IsValid());
    lut_texture.Bind();
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, num_curve_points_, 1, GL_RED,
                    GL_FLOAT, gtm_lut_buffer_.data());
    return lut_texture;
  }
}

bool HdrNetProcessorDeviceAdapterIpu6::CreateCoeffPredictionImage(
    const SharedImage& input_yuv, const SharedImage& output_rgba) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET_DEBUG();

  if (!inverse_gtm_lut_.IsValid()) {
    LOGF(ERROR) << "Invalid GTM curve textures";
    return false;
  }
  // Intel's GLES implementation always samples the YUV image with narrow range
  // color space and it's crushing the shadow areas on the images. Before we
  // have a fix in mesa, sample and covert the YUV image to RGB ourselves.
  if (!input_yuv.y_texture().IsValid() || !input_yuv.uv_texture().IsValid() ||
      !output_rgba.texture().IsValid()) {
    LOGF(ERROR) << "Invalid input or output textures";
    return false;
  }
  if ((input_yuv.y_texture().width() / 2 != input_yuv.uv_texture().width()) ||
      (input_yuv.y_texture().height() / 2 != input_yuv.uv_texture().height())) {
    LOG(ERROR) << "Invalid Y (" << input_yuv.y_texture().width() << ", "
               << input_yuv.y_texture().height() << ") and UV ("
               << input_yuv.uv_texture().width() << ", "
               << input_yuv.uv_texture().height() << ") output dimension";
    return false;
  }

  FramebufferGuard fb_guard;
  ViewportGuard viewport_guard;
  ProgramGuard program_guard;
  VertexArrayGuard va_guard;

  rect_->SetAsVertexInput();

  constexpr int kYInputBinding = 0;
  constexpr int kUvInputBinding = 1;
  constexpr int kInverseGammaLutBinding = 2;
  constexpr int kInverseGtmLutBinding = 3;

  glActiveTexture(GL_TEXTURE0 + kYInputBinding);
  input_yuv.y_texture().Bind();
  nearest_clamp_to_edge_.Bind(kYInputBinding);
  glActiveTexture(GL_TEXTURE0 + kUvInputBinding);
  input_yuv.uv_texture().Bind();
  nearest_clamp_to_edge_.Bind(kUvInputBinding);
  glActiveTexture(GL_TEXTURE0 + kInverseGammaLutBinding);
  inverse_gamma_lut_.Bind();
  linear_clamp_to_edge_.Bind(kInverseGammaLutBinding);
  glActiveTexture(GL_TEXTURE0 + kInverseGtmLutBinding);
  inverse_gtm_lut_.Bind();
  linear_clamp_to_edge_.Bind(kInverseGtmLutBinding);

  preprocessor_program_.UseProgram();

  // Set shader uniforms.
  std::vector<float> texture_matrix = TextureSpaceFromNdc();
  GLint uTextureMatrix =
      preprocessor_program_.GetUniformLocation("uTextureMatrix");
  glUniformMatrix4fv(uTextureMatrix, 1, false, texture_matrix.data());

  Framebuffer fb;
  fb.Bind();
  glViewport(0, 0, output_rgba.texture().width(),
             output_rgba.texture().height());
  fb.Attach(GL_COLOR_ATTACHMENT0, output_rgba.texture());
  rect_->Draw();

  // Clean up.
  glActiveTexture(GL_TEXTURE0 + kYInputBinding);
  input_yuv.y_texture().Unbind();
  Sampler::Unbind(kYInputBinding);
  glActiveTexture(GL_TEXTURE0 + kUvInputBinding);
  input_yuv.uv_texture().Unbind();
  Sampler::Unbind(kUvInputBinding);
  glActiveTexture(GL_TEXTURE0 + kInverseGammaLutBinding);
  inverse_gamma_lut_.Unbind();
  Sampler::Unbind(kInverseGammaLutBinding);
  glActiveTexture(GL_TEXTURE0 + kInverseGtmLutBinding);
  inverse_gtm_lut_.Unbind();
  Sampler::Unbind(kInverseGtmLutBinding);

  return true;
}

}  // namespace cros
