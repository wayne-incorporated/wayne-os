// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_GPU_FORMAT_UTIL_H_
#define ARC_VM_LIBVDA_GPU_FORMAT_UTIL_H_

#include "arc/vm/libvda/gpu/mojom/video.mojom.h"
#include "arc/vm/libvda/libvda_common.h"

namespace arc {

video_codec_profile_t ConvertMojoProfileToCodecProfile(
    arc::mojom::VideoCodecProfile profile);

arc::mojom::VideoCodecProfile ConvertCodecProfileToMojoProfile(
    video_codec_profile_t profile);

}  // namespace arc

#endif  // ARC_VM_LIBVDA_GPU_FORMAT_UTIL_H_
