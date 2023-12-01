/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_UTILS_H_
#define CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_UTILS_H_

#include "common/stream_manipulator.h"

#include "cros-camera/export.h"

extern "C" {
CROS_CAMERA_EXPORT cros::StreamManipulator*
MakeFrameAnnotatorStreamManipulator();
}

#endif  // CAMERA_FEATURES_FRAME_ANNOTATOR_LIBS_UTILS_H_
