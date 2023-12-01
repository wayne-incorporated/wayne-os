// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_GPU_DECODE_HELPERS_H_
#define ARC_VM_LIBVDA_DECODE_GPU_DECODE_HELPERS_H_

#include <stdint.h>

#include "arc/vm/libvda/gpu/mojom/video.mojom.h"
#include "arc/vm/libvda/gpu/mojom/video_decode_accelerator.mojom.h"
#include "arc/vm/libvda/libvda_decode.h"

namespace arc {

// TODO(alexlau): Query for this instead of hard coding.
constexpr vda_input_format_t kInputFormats[] = {
    {VP8PROFILE_MIN /* profile */, 2 /* min_width */, 2 /* min_height */,
     1920 /* max_width */, 1080 /* max_height */},
    {VP9PROFILE_PROFILE0 /* profile */, 2 /* min_width */, 2 /* min_height */,
     1920 /* max_width */, 1080 /* max_height */},
    {H264PROFILE_MAIN /* profile */, 2 /* min_width */, 2 /* min_height */,
     1920 /* max_width */, 1080 /* max_height */},
    {HEVCPROFILE_MAIN /* profile */, 2 /* min_width */, 2 /* min_height */,
     1920 /* max_width */, 1080 /* max_height */}};

// Convert the specified pixel |format| to a HAL pixel format.
arc::mojom::HalPixelFormat ConvertPixelFormatToHalPixelFormat(
    vda_pixel_format_t format);
// Check whether the specified |num_planes| is valid for the |format|.
bool CheckValidOutputFormat(vda_pixel_format_t format, size_t num_planes);

// Convert the specified mojo decoder |status| to a VD decoder status.
vd_decoder_status_t ConvertDecoderStatus(arc::mojom::DecoderStatus status);

// Convert the specified VD decoder |status| to a VDA result.
// TODO(b/189278506): Remove once we move to VD-based event pipe.
vda_result_t ToVDAResult(vd_decoder_status_t status);

}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_GPU_DECODE_HELPERS_H_
