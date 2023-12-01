/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_AE_STATE_MACHINE_H_
#define CAMERA_FEATURES_GCAM_AE_AE_STATE_MACHINE_H_

#include <memory>
#include <optional>
#include <string>

#include <base/synchronization/lock.h>
#include <base/timer/timer.h>

#include "common/camera_hal3_helpers.h"
#include "common/metadata_logger.h"
#include "cros-camera/camera_metrics.h"
#include "features/gcam_ae/ae_info.h"
#include "features/gcam_ae/gcam_ae_metrics.h"

namespace cros {

class AeStateMachine {
 public:
  struct InputParameters {
    // The AE metadata of the incoming frame.
    const AeFrameInfo& ae_frame_info;

    // The TET calculated by the AE algorithm based on |ae_frame_info| and AE
    // statistics data.
    const AeParameters& ae_parameters;

    // The usable range for the minimum and maximum TETs. The default value is
    // essentially unlimited.
    const Range<float> tet_range = {1e-6, 1e6};
  };

  // Expose the initial TET and HDR ratio keys for GcamAeStreamManipulator to
  // cache the last TET and HDR ratio values when the camera device is closed.
  static constexpr char kInitialTet[] = "initial_tet";
  static constexpr char kInitialHdrRatio[] = "initial_hdr_ratio";

  struct TuningParameters {
    // The threshold in log2 space for TET target stabilization. See the
    // comments for the kSearching state below.
    float tet_target_threshold_log2 = 0.1f;

    // The TET step in log2 space for TET convergence. See the comments of the
    // kConverging state below.
    float small_step_log2 = 0.1f;
    float large_step_log2 = 0.5f;
    float log_scene_brightness_threshold = 1.5f;

    // The duration for which the converged TET needs to keep stable in order to
    // transition to the kConverged state. See the comments of the kConverging
    // state below.
    int tet_converge_stabilize_duration_ms = 1000;

    // The threshold in log2 space for declaring converged TET. See the comments
    // of the kConverged state below.
    float tet_converge_threshold_log2 = 0.1f;

    // The TET rescan threshold in log2 space exceeding. See the comments of the
    // kConverged state below.
    float tet_rescan_threshold_log2 = 0.2f;

    // The duration in ms to fix the TET before triggering another AE rescan.
    // See the comments for the kConverged state below.
    int tet_retention_duration_ms_default = 1000;
    int tet_retention_duration_ms_with_face = 3000;

    // The initial TET value. Useful for smoothing the TET transition during
    // camera initialization.
    float initial_tet = 33.33f;
    float initial_hdr_ratio = 1.0f;

    // The bound for the inter-frame HDR ratio transition. We need to bound the
    // HDR ratio delta to avoid having sudden frame brightness changes.
    float hdr_ratio_step = 0.2f;
  };

  // We get the following inputs for each AE iteration:
  //   - |previous_tet|: The TET computed in the previous iteration.
  //   - |new_tet|: The new TET computed from the AE stats of the latest frame.
  //   - |actual_tet_set|: The actual TET used to capture the latest frame.
  //   - |tet_step_log2|: The TET step size limit in log2 space used to bound
  //         TET change in kSearching and kConverging states.
  //
  // and we want to determine the following TET values:
  //   - |target_tet|: The TET target that the state machine will converge to
  //         for the next frames.
  //   - |converged_tet|: The TET that the state machine has converged to.
  //   - |next_tet_to_set|: The TET that will be used to capture the future
  //         frames.
  //
  // |target_tet| and |converged_tet| can be different due to TET retention. In
  // some cases we'd want to keep the |converged_tet| unchanged, but still
  // actively searching (and setting) new |target_tet|.
  //
  // State transition is checked when every new per-frame TET is calculated.
  //
  // Define the SearchTargetTet() procedure as:
  //
  //   tet_delta = abs(log2(|new_tet|) - log2(|previous_tet|))
  //   if (tet_delta < tet_target_threshold_log2):
  //     |target_tet| = |new_tet|
  //   else:
  //     |target_tet| = nil
  //
  // Define the ConvergeToTargetTet() procedure as:
  //
  //   tet_delta = abs(log2(|actual_tet_set|) - log2(|target_tet|))
  //   if (tet_delta < tet_converge_threshold_log2):
  //     |converged_tet| = |actual_tet_set|
  //   else:
  //     |converged_tet| = nil
  enum class State {
    // The entry state. The state machine is in this state when the camera
    // device is closed.
    //
    // Entry action:
    // * This state does nothing.
    //
    // Transitions to:
    // * kInitializing: on receiving the first set of AE parameters.
    kInactive = 0,

    // The AE algorithm is searching for a stable TET.
    //
    // Entry Actions:
    // * Set |next_tet_to_set| to
    //     min(exp2(log2(|actual_tet_set|) + |tet_step_log2|), |new_tet|)
    //   if |new_tet| > |actual_tet_set|, or
    //     max(exp2(log2(|actual_tet_set|) - |tet_step_log2|), |new_tet|)
    //   if |new_tet| <= |actual_tet_set|.
    //
    // State transitions:
    // * Run SearchTargetTet()
    //   * kSearching: if |target_tet| is not set
    //   * kConverging: if |target_tet| is set
    kSearching = 1,

    // The AE algorithm is converging the TET towards the target TET the
    // state machine has settled to through the SearchTargetTet() procedure.
    //
    // Entry Action:
    // * Set |next_tet_to_set| to
    //     min(exp2(log2(|actual_tet_set|) + |tet_step_log2|), |target_tet|)
    //   if |target_tet| > |actual_tet_set|, or
    //     max(exp2(log2(|actual_tet_set|) - |tet_step_log2|), |target_tet|)
    //   if |target_tet| <= |actual_tet_set|.
    //
    // State transitions:
    // * Run SearchTargetTet()
    //   * kSearching: if |target_tet| is not set
    // * Run ConvergeToTargetTet()
    //   * kConverging: if |converged_tet| is not set, or if |converged_tet| is
    //         not stabilized for more than tet_converge_stabilize_duration_ms
    //         ms.
    //   * kConverged: if |converged_tet| is set and is stabilized for more than
    //         tet_converge_stabilize_duration_ms ms.
    kConverging = 2,

    // The AE algorithm has stabilized the TET to the stable TET the algorithm
    // has converged to.
    //
    // Entry Action:
    // * Set |next_tet_to_set| to |converged_tet|
    //
    // State transitions:
    // * Run SearchTargetTet()
    //   * kConverged: if abs(log2(|converged_tet|) - log2(|target_tet|)) <=
    //         tet_rescan_threshold_log2
    //   * kSearching: if |target_tet| is not set or diverges from
    //         |converged_tet| for more than tet_retention_duration_ms_default
    //         or tet_retention_duration_ms_with_face ms depending on if a face
    //         is detected, and |target_tet| is not set when the state
    //         transitions.
    //   * kConverging: if |target_tet| is not set or diverges from
    //         |converged_tet| for more than tet_retention_duration_ms_default
    //         or tet_retention_duration_ms_with_face ms depending on if a face
    //         is detected, and |target_tet| is set when the state transitions.
    //
    // When transitioning out of the kConverged state, select the
    // |tet_step_log2| value based on the log scene brightness of the current
    // and the target exposure settings.
    kConverged = 3,

    // The exposure is locked and |next_tet_to_set| will remain unchanged. Any
    // state can transition to the locked state when the ANDROID_CONTROL_AE_LOCK
    // capture setting is set.
    //
    // Entry Action:
    // * None as we need to keep |next_tet_to_set| unchanged
    //
    // State transitions:
    // * Run SearchTargetTet()
    //   * kSearching: if AE lock is turned off and |target_tet| is not set
    //   * kConverging: if AE lock is turned off and |target_tet| is set
    //
    // When transitioning out of the kLocked state, select the |tet_step_log2|
    // value based on the log scene brightness of the current
    // and the target exposure settings.
    kLocked = 4,
  };

  AeStateMachine();
  ~AeStateMachine();

  void OnNewAeParameters(InputParameters inputs,
                         MetadataLogger* metadata_logger = nullptr);
  void OnReset();
  void OnOptionsUpdated(const base::Value::Dict& json_values);

  float GetCaptureTet();
  float GetFilteredHdrRatio();
  uint8_t GetAndroidAeState();

  AeStateMachine(const AeStateMachine& other) = delete;
  AeStateMachine& operator=(const AeStateMachine& other) = delete;

 private:
  struct ExposureDescriptor {
    static constexpr float kInvalidTet = -1.0f;
    static constexpr float kInvalidHdrRatio = -1.0f;

    float tet = kInvalidTet;
    float hdr_ratio = kInvalidHdrRatio;
    float log_scene_brightness = kLogSceneBrightnessUnknown;

    std::string ToString() const;
  };

  void SearchTargetTet(const AeFrameInfo& frame_info,
                       const InputParameters& inputs,
                       const float new_tet);
  void ConvergeToTargetTet(const AeFrameInfo& frame_info,
                           const InputParameters& inputs,
                           const float actual_tet_set);
  void MaybeToggleAeLock(const AeFrameInfo& frame_info);

  void UploadMetrics();

  // For synchronizing all the internal state.
  base::Lock lock_;

  State current_state_ GUARDED_BY(lock_) = State::kInactive;
  TuningParameters tuning_parameters_ GUARDED_BY(lock_);

  // The most recent short and long TETs filtered from the incoming AE
  // parameters.
  AeParameters current_ae_parameters_ GUARDED_BY(lock_);

  // The most recent TET calculated by the state machine.
  float previous_tet_ GUARDED_BY(lock_) = 0;

  // The TET value to set to the vendor camera HAL for actual frame exposure of
  // the next frame(s).
  ExposureDescriptor next_ GUARDED_BY(lock_) = {
      .tet = 0.0f,
      .hdr_ratio = 1.0f,
  };

  // The TET step size limit in log2 space used to bound TET change in
  // kSearching and kConverging states.
  float tet_step_log2_ = 0.0f;

  // The target TET for the state machine to converge the actual TET to.
  std::optional<ExposureDescriptor> target_ GUARDED_BY(lock_);

  // The converged TET that the state machine has settled with.
  std::optional<ExposureDescriptor> converged_ GUARDED_BY(lock_);
  std::optional<base::TimeTicks> converged_start_time_ GUARDED_BY(lock_);
  std::optional<int> tet_retention_duration_ms_ GUARDED_BY(lock_);
  static constexpr int kInvalidFrame = -1;
  int convergence_starting_frame_ GUARDED_BY(lock_) = kInvalidFrame;

  // The last time when |converged_tet_| is still considered valid.
  base::TimeTicks last_converged_time_ GUARDED_BY(lock_);

  // Whether the AE needs to be locked.
  std::optional<ExposureDescriptor> locked_ GUARDED_BY(lock_);
  bool ae_locked_ GUARDED_BY(lock_) = false;

  GcamAeMetrics gcam_ae_metrics_ GUARDED_BY(lock_);
  std::unique_ptr<CameraMetrics> camera_metrics_;
};

std::ostream& operator<<(std::ostream& os, AeStateMachine::State state);

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_AE_STATE_MACHINE_H_
