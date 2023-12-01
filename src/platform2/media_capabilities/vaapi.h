// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_CAPABILITIES_VAAPI_H_
#define MEDIA_CAPABILITIES_VAAPI_H_

#include <vector>

class Capability;
std::vector<Capability> DetectVaapiCapabilities();
#endif  // MEDIA_CAPABILITIES_VAAPI_H_
