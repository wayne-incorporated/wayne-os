/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_TRACING_H_
#define CAMERA_FEATURES_GCAM_AE_TRACING_H_

#include "cros-camera/tracing.h"

#define TRACE_GCAM_AE(...) \
  TRACE_EVENT_AUTOGEN(kCameraTraceCategoryGcamAe, ##__VA_ARGS__)

#define TRACE_GCAM_AE_BEGIN(...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryGcamAe, ##__VA_ARGS__)

#define TRACE_GCAM_AE_END() TRACE_EVENT_END(kCameraTraceCategoryGcamAe)

#define TRACE_GCAM_AE_TRACK_BEGIN(event, track, ...) \
  TRACE_EVENT_BEGIN(kCameraTraceCategoryGcamAe, event, track, ##__VA_ARGS__)

#define TRACE_GCAM_AE_TRACK_END(track) \
  TRACE_EVENT_END(kCameraTraceCategoryGcamAe, track)

constexpr char kEventRun[] = "GcamAe::Run";

// Event track for the AE state transitions.
constexpr int kAeStateTrack = 0x1234AE00;

// Static strings for the AE state events.
constexpr char kAeStateInactive[] = "Inactive";
constexpr char kAeStateSearching[] = "Searching";
constexpr char kAeStateConverging[] = "Converging";
constexpr char kAeStateConverged[] = "Converged";
constexpr char kAeStateLocked[] = "Locked";

#endif  // CAMERA_FEATURES_GCAM_AE_TRACING_H_
