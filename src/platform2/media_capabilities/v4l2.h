// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_CAPABILITIES_V4L2_H_
#define MEDIA_CAPABILITIES_V4L2_H_

#include <vector>

class Capability;
std::vector<Capability> DetectV4L2Capabilities();
#endif  // MEDIA_CAPABILITIES_V4L2_H_
