// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/gpu/decode_helpers.h"

namespace arc {

arc::mojom::HalPixelFormat ConvertPixelFormatToHalPixelFormat(
    vda_pixel_format_t format) {
  switch (format) {
    case YV12:
      return arc::mojom::HalPixelFormat::HAL_PIXEL_FORMAT_YV12;
    case NV12:
      return arc::mojom::HalPixelFormat::HAL_PIXEL_FORMAT_NV12;
    default:
      NOTREACHED();
  }
}

bool CheckValidOutputFormat(vda_pixel_format_t format, size_t num_planes) {
  switch (format) {
    case NV12:
      if (num_planes != 2) {
        LOG(ERROR) << "Invalid number of planes for NV12 format, expected 2 "
                      "but received "
                   << num_planes;
        return false;
      }
      break;
    case YV12:
      if (num_planes != 3) {
        LOG(ERROR) << "Invalid number of planes for YV12 format, expected 3 "
                      "but received "
                   << num_planes;
        return false;
      }
      break;
    default:
      LOG(WARNING) << "Unexpected format: " << format;
      return false;
  }
  return true;
}

vd_decoder_status_t ConvertDecoderStatus(arc::mojom::DecoderStatus status) {
  switch (status) {
    case arc::mojom::DecoderStatus::OK:
      return OK;
    case arc::mojom::DecoderStatus::ABORTED:
      return ABORTED;
    case arc::mojom::DecoderStatus::FAILED:
      return FAILED;
    case arc::mojom::DecoderStatus::INVALID_ARGUMENT:
      return INVALID_ARGUMENT_VD;
    case arc::mojom::DecoderStatus::CREATION_FAILED:
      return CREATION_FAILED;
    default:
      DLOG(ERROR) << "Unknown status code: " << status;
      return INVALID_ARGUMENT_VD;
  }
}

vda_result_t ToVDAResult(vd_decoder_status_t status) {
  switch (status) {
    case OK:
      return SUCCESS;
    case ABORTED:
      return CANCELLED;
    case FAILED:
      return PLATFORM_FAILURE;
    case INVALID_ARGUMENT_VD:
      return INVALID_ARGUMENT;
    case CREATION_FAILED:
      return PLATFORM_FAILURE;
    default:
      DLOG(ERROR) << "Unknown status code: " << status;
      return PLATFORM_FAILURE;
  }
}

}  // namespace arc
