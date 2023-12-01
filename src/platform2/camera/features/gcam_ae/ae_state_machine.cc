/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/gcam_ae/ae_state_machine.h"

#include <algorithm>
#include <cmath>
#include <string>

#include "common/reloadable_config_file.h"
#include "cros-camera/common.h"
#include "cros-camera/tracing.h"
#include "features/gcam_ae/tracing.h"

namespace cros {

namespace {

constexpr char kSmallStepLog2[] = "small_step_log2";
constexpr char kLargeStepLog2[] = "large_step_log2";
constexpr char kLogSceneBrightnessThreshold[] =
    "log_scene_brightness_threshold";
constexpr char kTetConvergeStabilizeDurationMs[] =
    "tet_converge_stabilize_duration_ms";
constexpr char kTetConvergeThresholdLog2[] = "tet_converge_threshold_log2";
constexpr char kTetRescanThresholdLog2[] = "tet_rescan_threshold_log2";
constexpr char kTetRetentionDurationMsDefault[] =
    "tet_retention_duration_ms_default";
constexpr char kTetRetentionDurationMsWithFace[] =
    "tet_retention_duration_ms_with_face";
constexpr char kTetTargetThresholdLog2[] = "tet_target_threshold_log2";
constexpr char kHdrRatioStep[] = "hdr_ratio_step";

// The log2 IIR filter strength for the long/short TET computed by Gcam AE.
constexpr float kFilterStrength = 0.85f;

constexpr float kTetEpsilon = 1.0e-8f;

// IIR filter on log2 space:
//   exp2(|strength| * log2(current_value) + (1 - |strength|) * log2(new_value))
float IirFilterLog2(float current_value, float new_value, float strength) {
  if (current_value > kTetEpsilon && new_value > kTetEpsilon) {
    const float curr_log = std::log2f(current_value);
    const float new_log = std::log2f(new_value);
    const float next_log = strength * curr_log + (1 - strength) * new_log;
    return std::max(std::exp2f(next_log), kTetEpsilon);
  }
  return current_value;
}

// Gets a smoothed TET value moving from |previous| to |target| with no more
// than |step_log2| difference in the log2 space.
float SmoothTetTransition(const float target,
                          const float previous,
                          const float step_log2) {
  if (target > kTetEpsilon && previous > kTetEpsilon) {
    const float prev_log = std::log2f(previous);
    if (target > previous) {
      return std::min(target, std::exp2f(prev_log + step_log2));
    } else {
      return std::max(target, std::exp2f(prev_log - step_log2));
    }
  }
  return target;
}

// Gets a smoothed HDR ratio value moving from |previous| to |target| with no
// more than |step| difference.
float SmoothHdrRatioTransition(const float target,
                               const float previous,
                               const float step) {
  if (target > previous) {
    return std::min(target, previous + step);
  } else {
    return std::max(target, previous - step);
  }
}

int ElapsedTimeMs(base::TimeTicks since) {
  return (base::TimeTicks::Now() - since).InMilliseconds();
}

perfetto::StaticString GetAeStateString(AeStateMachine::State state) {
  switch (state) {
    case AeStateMachine::State::kInactive:
      return kAeStateInactive;
    case AeStateMachine::State::kSearching:
      return kAeStateSearching;
    case AeStateMachine::State::kConverging:
      return kAeStateConverging;
    case AeStateMachine::State::kConverged:
      return kAeStateConverged;
    case AeStateMachine::State::kLocked:
      return kAeStateLocked;
  }
}

}  // namespace

std::string AeStateMachine::ExposureDescriptor::ToString() const {
  return base::StringPrintf("{tet=%f, hdr_ratio=%f, log_scene_brightness=%f}",
                            tet, hdr_ratio, log_scene_brightness);
}

AeStateMachine::AeStateMachine()
    : tet_step_log2_(tuning_parameters_.large_step_log2),
      camera_metrics_(CameraMetrics::New()) {
  perfetto::Track ae_state_track(kAeStateTrack);
  auto desc = ae_state_track.Serialize();
  desc.set_name("AE state");
  cros_camera::TrackEvent::SetTrackDescriptor(ae_state_track, desc);
}

AeStateMachine::~AeStateMachine() {
  UploadMetrics();
  TRACE_GCAM_AE_TRACK_END(perfetto::Track(kAeStateTrack));
}

void AeStateMachine::OnNewAeParameters(InputParameters inputs,
                                       MetadataLogger* metadata_logger) {
  base::AutoLock lock(lock_);
  const AeFrameInfo& frame_info = inputs.ae_frame_info;
  const AeParameters& raw_ae_parameters = inputs.ae_parameters;

  VLOGFID(1, frame_info.frame_number)
      << "Raw AE parameters:"
      << " short_tet=" << raw_ae_parameters.short_tet
      << " long_tet=" << raw_ae_parameters.long_tet
      << " log_scene_brightness=" << raw_ae_parameters.log_scene_brightness;

  // Filter the TET transition to avoid AE fluctuations or hunting.
  float prev_short_tet = current_ae_parameters_.short_tet;
  float prev_long_tet = current_ae_parameters_.long_tet;
  if (!current_ae_parameters_.IsValid()) {
    // This is the first set of AE parameters we get.
    prev_short_tet = tuning_parameters_.initial_tet;
    prev_long_tet =
        tuning_parameters_.initial_tet * tuning_parameters_.initial_hdr_ratio;
    // Initialize |next_| with the initial TET and HDR ratio to jump start the
    // AE loop.
    next_.tet = tuning_parameters_.initial_tet;
    next_.hdr_ratio = tuning_parameters_.initial_hdr_ratio;
  }
  current_ae_parameters_.short_tet = IirFilterLog2(
      prev_short_tet, raw_ae_parameters.short_tet, kFilterStrength);
  current_ae_parameters_.long_tet =
      IirFilterLog2(prev_long_tet, raw_ae_parameters.long_tet, kFilterStrength);
  current_ae_parameters_.log_scene_brightness =
      raw_ae_parameters.log_scene_brightness;

  const float hdr_ratio =
      current_ae_parameters_.long_tet / current_ae_parameters_.short_tet;
  VLOGFID(1, frame_info.frame_number)
      << "Filtered AE parameters:"
      << " short_tet=" << current_ae_parameters_.short_tet
      << " long_tet=" << current_ae_parameters_.long_tet
      << " hdr_ratio=" << hdr_ratio;

  gcam_ae_metrics_.accumulated_hdr_ratio += hdr_ratio;
  ++gcam_ae_metrics_.num_hdr_ratio_samples;
  gcam_ae_metrics_.accumulated_tet += current_ae_parameters_.short_tet;
  ++gcam_ae_metrics_.num_tet_samples;

  const float new_tet = current_ae_parameters_.short_tet;
  const float new_hdr_ratio =
      current_ae_parameters_.long_tet / current_ae_parameters_.short_tet;
  const float actual_tet_set = frame_info.exposure_time_ms *
                               frame_info.analog_gain * frame_info.digital_gain;

  auto get_tet_step = [&](float target_brightness,
                          float previous_brightness) -> float {
    float tet_step = tuning_parameters_.large_step_log2;
    if (std::fabsf(target_brightness - previous_brightness) <
        tuning_parameters_.log_scene_brightness_threshold) {
      tet_step = tuning_parameters_.small_step_log2;
    }
    VLOGFID(1, frame_info.frame_number)
        << "target_brightness=" << target_brightness;
    VLOGFID(1, frame_info.frame_number)
        << "previous_brightness=" << previous_brightness;
    VLOGFID(1, frame_info.frame_number) << "tet_step=" << tet_step;
    return tet_step;
  };

  // Compute state transition.
  MaybeToggleAeLock(frame_info);
  State next_state;
  switch (current_state_) {
    case State::kInactive:
      next_state = State::kSearching;

      // For camera cold start.
      convergence_starting_frame_ = frame_info.frame_number;
      break;

    case State::kSearching:
      SearchTargetTet(frame_info, inputs, new_tet);
      if (target_) {
        next_state = State::kConverging;
      } else {
        next_state = State::kSearching;
      }
      break;

    case State::kConverging: {
      SearchTargetTet(frame_info, inputs, new_tet);
      if (!target_) {
        next_state = State::kSearching;
        break;
      }
      ConvergeToTargetTet(frame_info, inputs, actual_tet_set);
      if (converged_) {
        if (ae_locked_) {
          next_state = State::kLocked;
        } else {
          if (converged_start_time_ &&
              ElapsedTimeMs(*converged_start_time_) >
                  tuning_parameters_.tet_converge_stabilize_duration_ms) {
            next_state = State::kConverged;

            // Record convergence latency whenever we transition to the
            // Converged state. Only count the metrics here so that we exclude
            // the AE lock convergence latency.
            if (convergence_starting_frame_ != kInvalidFrame) {
              gcam_ae_metrics_.accumulated_convergence_latency_frames +=
                  frame_info.frame_number - convergence_starting_frame_;
              ++gcam_ae_metrics_.num_convergence_samples;
              convergence_starting_frame_ = kInvalidFrame;
            }
            break;
          }
          if (!converged_start_time_) {
            converged_start_time_ = base::TimeTicks::Now();
          }
          next_state = State::kConverging;
        }
      } else {
        converged_start_time_.reset();
        next_state = State::kConverging;
      }
      break;
    }

    case State::kConverged: {
      SearchTargetTet(frame_info, inputs, new_tet);
      if (ae_locked_) {
        next_state = State::kConverging;
        break;
      }

      // Avoid changing TET when the frame brightness change is less than
      // |tuning_parameters_.tet_rescan_threshold_log2|.
      if (target_ &&
          std::fabs(std::log2f(converged_->tet) - std::log2f(target_->tet)) <=
              tuning_parameters_.tet_rescan_threshold_log2) {
        last_converged_time_ = base::TimeTicks::Now();
        next_state = State::kConverged;
        break;
      }

      // Searching for or converging to a new TET target if we observed that the
      // frame brightness has chnaged for more than |tet_retention_duration_ms_|
      // ms.
      if (ElapsedTimeMs(last_converged_time_) > *tet_retention_duration_ms_) {
        if (target_) {
          next_state = State::kConverging;
          tet_step_log2_ = get_tet_step(target_->log_scene_brightness,
                                        converged_->log_scene_brightness);
        } else {
          next_state = State::kSearching;
          tet_step_log2_ =
              get_tet_step(current_ae_parameters_.log_scene_brightness,
                           converged_->log_scene_brightness);
        }
        // Start convergence timer whenever we transition out of the Converged
        // state.
        convergence_starting_frame_ = frame_info.frame_number;
        break;
      } else {
        next_state = State::kConverged;
      }
      break;
    }

    case State::kLocked:
      SearchTargetTet(frame_info, inputs, new_tet);
      if (ae_locked_) {
        DCHECK(target_);
        if (std::fabs(std::log2f(actual_tet_set) - std::log2f(target_->tet)) <=
            tuning_parameters_.tet_rescan_threshold_log2) {
          next_state = State::kLocked;
        } else {
          next_state = State::kConverging;
        }
      } else {
        if (!target_) {
          next_state = State::kSearching;
          tet_step_log2_ =
              get_tet_step(current_ae_parameters_.log_scene_brightness,
                           converged_->log_scene_brightness);
        } else {
          next_state = State::kConverging;
          // Determine the TET transition step bound on the brightness
          // difference.
          tet_step_log2_ = get_tet_step(target_->log_scene_brightness,
                                        converged_->log_scene_brightness);
        }
      }
      break;
  }

  VLOGFID(1, frame_info.frame_number)
      << "state=" << current_state_ << " next_state=" << next_state
      << " actual_tet_set=" << actual_tet_set;
  if (current_state_ != next_state) {
    TRACE_GCAM_AE_TRACK_END(perfetto::Track(kAeStateTrack));
    TRACE_GCAM_AE_TRACK_BEGIN(GetAeStateString(next_state),
                              perfetto::Track(kAeStateTrack), "frame_number",
                              frame_info.frame_number, "from", current_state_,
                              "to", next_state);
  }

  // Execute state entry actions.
  switch (next_state) {
    case State::kInactive:
      break;

    case State::kSearching: {
      next_.tet = SmoothTetTransition(new_tet, next_.tet, tet_step_log2_);
      next_.hdr_ratio = SmoothHdrRatioTransition(
          new_hdr_ratio, next_.hdr_ratio, tuning_parameters_.hdr_ratio_step);
      next_.log_scene_brightness = current_ae_parameters_.log_scene_brightness;
      break;
    }

    case State::kConverging: {
      next_.tet = SmoothTetTransition(target_->tet, next_.tet, tet_step_log2_);
      next_.hdr_ratio =
          SmoothHdrRatioTransition(target_->hdr_ratio, next_.hdr_ratio,
                                   tuning_parameters_.hdr_ratio_step);
      next_.log_scene_brightness = current_ae_parameters_.log_scene_brightness;
      break;
    }

    case State::kConverged:
      next_.tet = converged_->tet;
      next_.hdr_ratio =
          SmoothHdrRatioTransition(converged_->hdr_ratio, next_.hdr_ratio,
                                   tuning_parameters_.hdr_ratio_step);
      next_.log_scene_brightness = converged_->log_scene_brightness;
      break;

    case State::kLocked:
      DCHECK(converged_);
      // AE compensation is still effective when AE is locked. |converged_| here
      // has the TET value with AE compensation applied on top of the TET stored
      // in |locked_|.
      next_.tet = converged_->tet;
      next_.hdr_ratio = locked_->hdr_ratio;
      next_.log_scene_brightness = locked_->log_scene_brightness;
      break;
  }

  constexpr int kInvalidDuration = -1;
  VLOGFID(1, frame_info.frame_number)
      << "target=" << (target_ ? target_->ToString() : "n/a");
  VLOGFID(1, frame_info.frame_number)
      << "converged=" << (converged_ ? converged_->ToString() : "n/a");
  VLOGFID(1, frame_info.frame_number)
      << "tet_retention_duration_ms="
      << (tet_retention_duration_ms_ ? *tet_retention_duration_ms_
                                     : kInvalidDuration);
  VLOGFID(1, frame_info.frame_number) << "ae_locked=" << ae_locked_;
  VLOGFID(1, frame_info.frame_number)
      << "locked=" << (locked_ ? locked_->ToString() : "n/a");
  VLOGFID(1, frame_info.frame_number) << "next=" << next_.ToString();

  if (metadata_logger) {
    metadata_logger->Log(frame_info.frame_number, kTagShortTet,
                         raw_ae_parameters.short_tet);
    metadata_logger->Log(frame_info.frame_number, kTagLongTet,
                         raw_ae_parameters.long_tet);
    metadata_logger->Log(frame_info.frame_number, kTagLogSceneBrightness,
                         raw_ae_parameters.log_scene_brightness);
    metadata_logger->Log(frame_info.frame_number, kTagFilteredShortTet,
                         current_ae_parameters_.short_tet);
    metadata_logger->Log(frame_info.frame_number, kTagFilteredLongTet,
                         current_ae_parameters_.long_tet);
    metadata_logger->Log(frame_info.frame_number, kTagAeState,
                         static_cast<int32_t>(current_state_));
    metadata_logger->Log(frame_info.frame_number, kTagActualTet,
                         actual_tet_set);
  }

  previous_tet_ = new_tet;
  current_state_ = next_state;
}

void AeStateMachine::OnReset() {
  base::AutoLock lock(lock_);
  current_state_ = State::kInactive;
  previous_tet_ = 0;
  next_ = ExposureDescriptor();
  target_.reset();
  converged_.reset();
  converged_start_time_.reset();
  tet_retention_duration_ms_.reset();
  locked_.reset();
  ae_locked_ = false;
}

void AeStateMachine::OnOptionsUpdated(const base::Value::Dict& json_values) {
  base::AutoLock lock(lock_);

  LoadIfExist(json_values, kTetTargetThresholdLog2,
              &tuning_parameters_.tet_target_threshold_log2);
  LoadIfExist(json_values, kSmallStepLog2, &tuning_parameters_.small_step_log2);
  LoadIfExist(json_values, kLargeStepLog2, &tuning_parameters_.large_step_log2);
  LoadIfExist(json_values, kLogSceneBrightnessThreshold,
              &tuning_parameters_.log_scene_brightness_threshold);
  LoadIfExist(json_values, kTetConvergeStabilizeDurationMs,
              &tuning_parameters_.tet_converge_stabilize_duration_ms);
  LoadIfExist(json_values, kTetConvergeThresholdLog2,
              &tuning_parameters_.tet_converge_threshold_log2);
  LoadIfExist(json_values, kTetRescanThresholdLog2,
              &tuning_parameters_.tet_rescan_threshold_log2);
  LoadIfExist(json_values, kTetRetentionDurationMsDefault,
              &tuning_parameters_.tet_retention_duration_ms_default);
  LoadIfExist(json_values, kTetRetentionDurationMsWithFace,
              &tuning_parameters_.tet_retention_duration_ms_with_face);
  LoadIfExist(json_values, kInitialTet, &tuning_parameters_.initial_tet);
  LoadIfExist(json_values, kInitialHdrRatio,
              &tuning_parameters_.initial_hdr_ratio);
  LoadIfExist(json_values, kHdrRatioStep, &tuning_parameters_.hdr_ratio_step);

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "AeStateMachine tuning parameters:"
             << " tet_target_threshold_log2="
             << tuning_parameters_.tet_target_threshold_log2
             << " small_step_log2=" << tuning_parameters_.small_step_log2
             << " large_step_log2=" << tuning_parameters_.large_step_log2
             << " log_scene_brightness_threshold="
             << tuning_parameters_.log_scene_brightness_threshold
             << " tet_converge_stabilize_duration_ms="
             << tuning_parameters_.tet_converge_stabilize_duration_ms
             << " tet_converge_threshold_log2="
             << tuning_parameters_.tet_converge_threshold_log2
             << " tet_rescan_threshold_log2="
             << tuning_parameters_.tet_rescan_threshold_log2
             << " tet_retention_duration_ms_default="
             << tuning_parameters_.tet_retention_duration_ms_default
             << " tet_retention_duration_ms_with_face="
             << tuning_parameters_.tet_retention_duration_ms_with_face
             << " initial_tet=" << tuning_parameters_.initial_tet
             << " hdr_ratio_step=" << tuning_parameters_.hdr_ratio_step;
  }

  if (!current_ae_parameters_.IsValid()) {
    // Initialize |next_| with the initial TET and HDR ratio, so that the first
    // few frames that fill up the pipeline are not totally black.
    next_.tet = tuning_parameters_.initial_tet;
    next_.hdr_ratio = tuning_parameters_.initial_hdr_ratio;
  }
}

float AeStateMachine::GetCaptureTet() {
  base::AutoLock lock(lock_);
  return next_.tet;
}

float AeStateMachine::GetFilteredHdrRatio() {
  base::AutoLock lock(lock_);
  return next_.hdr_ratio;
}

uint8_t AeStateMachine::GetAndroidAeState() {
  // We don't support flash, so there's no FLASH_REQUIRED state.
  switch (current_state_) {
    case AeStateMachine::State::kInactive:
      return ANDROID_CONTROL_AE_STATE_INACTIVE;
    case AeStateMachine::State::kSearching:
    case AeStateMachine::State::kConverging:
      return ANDROID_CONTROL_AE_STATE_SEARCHING;
    case AeStateMachine::State::kConverged:
      return ANDROID_CONTROL_AE_STATE_CONVERGED;
    case AeStateMachine::State::kLocked:
      return ANDROID_CONTROL_AE_STATE_LOCKED;
  }
}

std::ostream& operator<<(std::ostream& os, AeStateMachine::State state) {
  std::string state_str;
  switch (state) {
    case AeStateMachine::State::kInactive:
      state_str = "Inactive";
      break;
    case AeStateMachine::State::kSearching:
      state_str = "Searching";
      break;
    case AeStateMachine::State::kConverging:
      state_str = "Converging";
      break;
    case AeStateMachine::State::kConverged:
      state_str = "Converged";
      break;
    case AeStateMachine::State::kLocked:
      state_str = "Locked";
      break;
  }
  return os << state_str;
}

void AeStateMachine::SearchTargetTet(const AeFrameInfo& frame_info,
                                     const InputParameters& inputs,
                                     const float new_tet) {
  if (ae_locked_) {
    // AE compensation is still effective when AE is locked.
    target_ = {
        .tet =
            locked_->tet * std::exp2f(frame_info.client_ae_compensation_log2),
        .hdr_ratio = locked_->hdr_ratio,
        .log_scene_brightness = locked_->log_scene_brightness,
    };
    return;
  }

  const float previous_log = std::log2f(previous_tet_);
  const float new_log = std::log2f(new_tet);
  const float search_tet_delta_log = std::fabs(previous_log - new_log);
  VLOGFID(1, frame_info.frame_number)
      << "search_tet_delta_log=" << search_tet_delta_log;
  if (search_tet_delta_log <= tuning_parameters_.tet_target_threshold_log2) {
    target_ = {
        // Make sure we set a target TET that's achievable by the camera.
        .tet = inputs.tet_range.Clamp(new_tet),
        .hdr_ratio =
            current_ae_parameters_.long_tet / current_ae_parameters_.short_tet,
        .log_scene_brightness = current_ae_parameters_.log_scene_brightness,
    };
  } else {
    target_.reset();
  }
}

void AeStateMachine::ConvergeToTargetTet(const AeFrameInfo& frame_info,
                                         const InputParameters& inputs,
                                         const float actual_tet_set) {
  const float actual_tet_set_log = std::log2f(actual_tet_set);
  const float converge_tet_delta_log =
      std::fabs(actual_tet_set_log - std::log2f(target_->tet));
  VLOGFID(1, frame_info.frame_number)
      << "converge_tet_delta_log=" << converge_tet_delta_log;
  if (converge_tet_delta_log < tuning_parameters_.tet_converge_threshold_log2) {
    converged_ = *target_;
    tet_retention_duration_ms_ =
        frame_info.faces->empty()
            ? tuning_parameters_.tet_retention_duration_ms_default
            : tuning_parameters_.tet_retention_duration_ms_with_face;
  } else {
    converged_.reset();
    tet_retention_duration_ms_.reset();
  }
}

void AeStateMachine::MaybeToggleAeLock(const AeFrameInfo& frame_info) {
  if (frame_info.client_request_settings.ae_lock) {
    if (*frame_info.client_request_settings.ae_lock ==
            ANDROID_CONTROL_AE_LOCK_ON &&
        !ae_locked_) {
      ae_locked_ = true;
      locked_ = next_;
    } else if (*frame_info.client_request_settings.ae_lock ==
                   ANDROID_CONTROL_AE_LOCK_OFF &&
               ae_locked_) {
      ae_locked_ = false;
      locked_.reset();
    }
  }
}

void AeStateMachine::UploadMetrics() {
  base::AutoLock lock(lock_);
  if (gcam_ae_metrics_.num_convergence_samples > 0) {
    camera_metrics_->SendGcamAeAvgConvergenceLatency(
        gcam_ae_metrics_.accumulated_convergence_latency_frames /
        gcam_ae_metrics_.num_convergence_samples);
  }
  if (gcam_ae_metrics_.num_hdr_ratio_samples > 0) {
    camera_metrics_->SendGcamAeAvgHdrRatio(
        gcam_ae_metrics_.accumulated_hdr_ratio /
        gcam_ae_metrics_.num_hdr_ratio_samples);
  }
  if (gcam_ae_metrics_.num_tet_samples > 0) {
    camera_metrics_->SendGcamAeAvgTet(gcam_ae_metrics_.accumulated_tet /
                                      gcam_ae_metrics_.num_tet_samples);
  }
}

}  // namespace cros
