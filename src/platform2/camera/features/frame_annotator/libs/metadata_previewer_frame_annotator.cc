/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/frame_annotator/libs/metadata_previewer_frame_annotator.h"

#include <cinttypes>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_piece.h>
#include <skia/core/SkFont.h>

#include "common/camera_metadata_string_utils.h"
#include "cros-camera/camera_metadata_utils.h"

namespace cros {

//
// MetadataPreviewerFrameAnnotator implementations.
//

bool MetadataPreviewerFrameAnnotator::Initialize(
    const camera_metadata_t* static_info) {
  auto facing = GetRoMetadata<uint8_t>(static_info, ANDROID_LENS_FACING);
  DCHECK(facing.has_value());
  facing_ = static_cast<camera_metadata_enum_android_lens_facing_t>(*facing);
  return true;
}

bool MetadataPreviewerFrameAnnotator::ProcessCaptureResult(
    const Camera3CaptureDescriptor* result) {
  if (result->HasMetadata(ANDROID_STATISTICS_FACE_DETECT_MODE)) {
    auto face_detect_mode =
        result->GetMetadata<uint8_t>(ANDROID_STATISTICS_FACE_DETECT_MODE);
    face_detect_mode_ =
        static_cast<camera_metadata_enum_android_statistics_face_detect_mode_t>(
            face_detect_mode[0]);
  }
  if (result->HasMetadata(ANDROID_STATISTICS_FACE_RECTANGLES)) {
    num_faces_ =
        result->GetMetadata<int32_t>(ANDROID_STATISTICS_FACE_RECTANGLES).size();
  }

  if (result->HasMetadata(ANDROID_CONTROL_AF_MODE)) {
    auto af_mode = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AF_MODE);
    af_enabled_ = af_mode[0] != ANDROID_CONTROL_AF_MODE_OFF;
  }
  if (result->HasMetadata(ANDROID_LENS_FOCUS_DISTANCE)) {
    auto focus_distance =
        result->GetMetadata<float>(ANDROID_LENS_FOCUS_DISTANCE);
    focus_distance_ = focus_distance[0];
  }
  if (result->HasMetadata(ANDROID_CONTROL_AF_STATE)) {
    auto af_state = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AF_STATE);
    af_state_ = static_cast<camera_metadata_enum_android_control_af_state_t>(
        af_state[0]);
  }

  if (result->HasMetadata(ANDROID_CONTROL_AE_MODE)) {
    auto ae_mode = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
    ae_enabled_ = ae_mode[0] != ANDROID_CONTROL_AE_MODE_OFF;
  }
  if (result->HasMetadata(ANDROID_SENSOR_SENSITIVITY)) {
    auto sensor_sensitivity =
        result->GetMetadata<int32_t>(ANDROID_SENSOR_SENSITIVITY);
    sensor_sensitivity_ = sensor_sensitivity[0];
  }
  if (result->HasMetadata(ANDROID_CONTROL_POST_RAW_SENSITIVITY_BOOST)) {
    auto sensor_sensitivity_boost = result->GetMetadata<int32_t>(
        ANDROID_CONTROL_POST_RAW_SENSITIVITY_BOOST);
    sensor_sensitivity_boost_ = sensor_sensitivity_boost[0];
  }
  if (result->HasMetadata(ANDROID_SENSOR_EXPOSURE_TIME)) {
    auto exposure_time =
        result->GetMetadata<int64_t>(ANDROID_SENSOR_EXPOSURE_TIME);
    exposure_time_ = exposure_time[0];
  }
  if (result->HasMetadata(ANDROID_SENSOR_FRAME_DURATION)) {
    auto frame_duration =
        result->GetMetadata<int64_t>(ANDROID_SENSOR_FRAME_DURATION);
    frame_duration_ = frame_duration[0];
  }
  if (result->HasMetadata(ANDROID_CONTROL_AE_ANTIBANDING_MODE)) {
    auto ae_antibanding_mode =
        result->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_ANTIBANDING_MODE);
    ae_antibanding_mode_ =
        static_cast<camera_metadata_enum_android_control_ae_antibanding_mode_t>(
            ae_antibanding_mode[0]);
  }
  if (result->HasMetadata(ANDROID_CONTROL_AE_STATE)) {
    auto ae_state = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_STATE);
    ae_state_ = static_cast<camera_metadata_enum_android_control_ae_state_t>(
        ae_state[0]);
  }

  if (result->HasMetadata(ANDROID_CONTROL_AWB_MODE)) {
    auto awb_state = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AWB_MODE);
    awb_enabled_ = awb_state[0] != ANDROID_CONTROL_AWB_MODE_OFF;
  }
  if (result->HasMetadata(ANDROID_COLOR_CORRECTION_GAINS)) {
    auto color_gains =
        result->GetMetadata<float>(ANDROID_COLOR_CORRECTION_GAINS);
    DCHECK_EQ(color_gains.size(), 4);
    wb_gain_red_ = color_gains[0];
    wb_gain_blue_ = color_gains[3];
  }
  if (result->HasMetadata(ANDROID_CONTROL_AWB_STATE)) {
    auto awb_state = result->GetMetadata<uint8_t>(ANDROID_CONTROL_AWB_STATE);
    awb_state_ = static_cast<camera_metadata_enum_android_control_awb_state_t>(
        awb_state[0]);
  }

  hdr_ratio_ = result->feature_metadata().hdr_ratio;

  return true;
}

bool MetadataPreviewerFrameAnnotator::IsPlotNeeded() const {
  return true;
}

bool MetadataPreviewerFrameAnnotator::Plot(SkCanvas* canvas) {
  timestamps_.emplace(base::TimeTicks::Now());
  while (timestamps_.size() > kFpsMeasureFrames) {
    timestamps_.pop();
  }

  const auto canvas_info = canvas->imageInfo();
  canvas->save();

  if (options_.flip_type == FrameAnnotator::FlipType::kHorizontal ||
      options_.flip_type == FrameAnnotator::FlipType::kRotate180 ||
      (options_.flip_type == FrameAnnotator::FlipType::kDefault &&
       facing_ == ANDROID_LENS_FACING_FRONT)) {
    // Flip horizontally.
    canvas->scale(-1, 1);
    canvas->translate(-static_cast<float>(canvas_info.width()), 0);
  }
  if (options_.flip_type == FrameAnnotator::FlipType::kVertical ||
      options_.flip_type == FrameAnnotator::FlipType::kRotate180) {
    // Flip vertically.
    canvas->scale(1, -1);
    canvas->translate(0, -static_cast<float>(canvas_info.height()));
  }

  const auto scale_ratio = static_cast<float>(canvas_info.height()) / 480;
  canvas->scale(scale_ratio, scale_ratio);

  constexpr SkScalar font_size = 16;
  const auto normal_typeface =
      SkTypeface::MakeFromName(nullptr, SkFontStyle::Normal());
  const auto bold_typeface =
      SkTypeface::MakeFromName(nullptr, SkFontStyle::Bold());
  SkFont font(normal_typeface, font_size);
  font.setEdging(SkFont::Edging::kAntiAlias);

  SkPaint paint;

  using ColorPair = std::pair<SkColor, SkColor>;
  auto draw_text_box = [&](base::StringPiece text, ColorPair color,
                           SkScalar left, SkScalar top,
                           std::optional<SkScalar> height = {}) {
    paint.setColor(color.second);
    SkRect bg_box;
    font.measureText(text.data(), text.size(), SkTextEncoding::kUTF8, &bg_box,
                     &paint);
    bg_box.setXYWH(left - 3, top - font_size, bg_box.width() + 7,
                   height.value_or(bg_box.height() + 8));
    canvas->drawRoundRect(bg_box, 2, 2, paint);

    paint.setColor(color.first);
    canvas->drawString(text.data(), left, top, font, paint);
    return bg_box;
  };
  auto draw_metadata =
      [&](SkScalar left, SkScalar top, base::StringPiece title,
          ColorPair title_color,
          std::vector<std::pair<base::StringPiece, ColorPair>> info) {
        font.setTypeface(bold_typeface);
        const auto title_box = draw_text_box(title, title_color, left, top);
        font.setTypeface(normal_typeface);

        left = 6 + title_box.right();
        for (const auto& [info_str, info_color] : info) {
          if (info_str.empty()) {
            continue;
          }
          left = 6 + draw_text_box(info_str, info_color, left, top,
                                   title_box.height())
                         .right();
        }
        return title_box.bottom();
      };

  constexpr ColorPair title_colors[] = {/* mode off */ {0xff666666, 0xa0ffffff},
                                        /* mode on */ {0xffffffff, 0xe0007900}};
  constexpr ColorPair info_color{0xe0000000, 0x60ffffff};
  constexpr ColorPair red_info_color{0xe0ff0000, 0x60ffffff};
  constexpr ColorPair blue_info_color{0xe00000ff, 0x60ffffff};

  constexpr SkScalar left = 60;
  SkScalar top = 30;
  top = draw_metadata(left, top, "Info", title_colors[1],
                      {{base::StringPrintf("%dx%d", canvas_info.width(),
                                           canvas_info.height()),
                        info_color}}) +
        font_size + 5;
  top = draw_metadata(left, top, "Stat", title_colors[1],
                      {{TimestampsToFPSString(timestamps_), info_color},
                       {face_detect_mode_
                            ? FaceInfoToString(*face_detect_mode_, num_faces_)
                            : "",
                        info_color}}) +
        font_size + 5;
  top = draw_metadata(
            left, top, "AF", title_colors[af_enabled_],
            {{focus_distance_ ? FocusDistanceToString(*focus_distance_) : "",
              info_color},
             {af_state_ ? AFStateToString(*af_state_) : "", info_color}}) +
        font_size + 5;
  top = draw_metadata(
            left, top, "AE", title_colors[ae_enabled_],
            {{[&]() -> std::string {
                if (!sensor_sensitivity_ && !sensor_sensitivity_boost_) {
                  return "";
                }
                if (!sensor_sensitivity_) {
                  return "N/A";
                }
                return SensitivityToString(
                    *sensor_sensitivity_,
                    sensor_sensitivity_boost_.value_or(100));
              }(),
              info_color},
             {exposure_time_ ? ExposureTimeToString(*exposure_time_) : "",
              info_color},
             {frame_duration_ ? FrameDurationToString(*frame_duration_) : "",
              info_color},
             {ae_antibanding_mode_ ? AEModeToString(*ae_antibanding_mode_) : "",
              info_color},
             {ae_state_ ? AEStateToString(*ae_state_) : "", info_color}}) +
        font_size + 5;
  top = draw_metadata(
            left, top, "AWB", title_colors[awb_enabled_],
            {{wb_gain_red_ ? ColorGainToString(*wb_gain_red_) : "",
              red_info_color},
             {wb_gain_blue_ ? ColorGainToString(*wb_gain_blue_) : "",
              blue_info_color},
             {awb_state_ ? AWBStateToString(*awb_state_) : "", info_color}}) +
        font_size + 5;
  top =
      draw_metadata(
          left, top, "HDR Ratio", title_colors[1],
          {{hdr_ratio_ ? HdrRatioToString(*hdr_ratio_) : "N/A", info_color}}) +
      font_size + 5;

  canvas->restore();

  return true;
}

void MetadataPreviewerFrameAnnotator::UpdateOptions(
    const FrameAnnotator::Options& options) {
  options_ = options;
}

}  // namespace cros
