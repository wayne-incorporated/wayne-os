// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_CAPABILITIES_CAMERA_H_
#define MEDIA_CAPABILITIES_CAMERA_H_

#include <vector>

class Capability;
std::vector<Capability> DetectCameraCapabilities();
#endif  // MEDIA_CAPABILITIES_CAMERA_H_
