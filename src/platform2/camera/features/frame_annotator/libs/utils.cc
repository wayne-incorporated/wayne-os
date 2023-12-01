/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/frame_annotator/libs/utils.h"

#include "cros-camera/export.h"
#include "features/frame_annotator/libs/frame_annotator_stream_manipulator.h"

extern "C" {
cros::StreamManipulator* MakeFrameAnnotatorStreamManipulator() {
  return new cros::FrameAnnotatorStreamManipulator();
}
}
