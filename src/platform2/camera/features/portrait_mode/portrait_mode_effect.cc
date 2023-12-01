/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/portrait_mode/portrait_mode_effect.h"

#include <linux/videodev2.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/command_line.h>
#include <base/functional/bind.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/memory/unsafe_shared_memory_region.h>
#include <base/numerics/safe_conversions.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/launch.h>
#include <base/time/time.h>
#include <base/values.h>
#include <libyuv.h>
#include <libyuv/convert_argb.h>
#include <system/camera_metadata.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_gpu_algo_header.h"
#include "cros-camera/common.h"

namespace cros {

PortraitModeEffect::PortraitModeEffect()
    : buffer_manager_(CameraBufferManager::GetInstance()),
      gpu_algo_manager_(nullptr),
      condvar_(&lock_) {}

int32_t PortraitModeEffect::Initialize(CameraMojoChannelManagerToken* token) {
  gpu_algo_manager_ = GPUAlgoManager::GetInstance(token);
  if (!gpu_algo_manager_) {
    LOGF(WARNING)
        << "Cannot connect to GPU algorithm service. Disable portrait mode.";
    return 0;
  }
  return 0;
}

int32_t PortraitModeEffect::ReprocessRequest(
    bool can_process_portrait,
    buffer_handle_t input_buffer,
    uint32_t orientation,
    SegmentationResult* segmentation_result,
    buffer_handle_t output_buffer) {
  constexpr base::TimeDelta kPortraitProcessorTimeout = base::Seconds(15);
  if (!input_buffer || !output_buffer) {
    return -EINVAL;
  }
  ScopedMapping input_mapping(input_buffer);
  ScopedMapping output_mapping(output_buffer);
  uint32_t width = input_mapping.width();
  uint32_t height = input_mapping.height();
  uint32_t v4l2_format = input_mapping.v4l2_format();
  DCHECK_EQ(output_mapping.width(), width);
  DCHECK_EQ(output_mapping.height(), height);
  DCHECK_EQ(output_mapping.v4l2_format(), v4l2_format);

  if (can_process_portrait) {
    const uint32_t kRGBNumOfChannels = 3;
    size_t rgb_buf_size = width * height * kRGBNumOfChannels;
    base::UnsafeSharedMemoryRegion input_rgb_shm_region =
        base::UnsafeSharedMemoryRegion::Create(rgb_buf_size);
    base::WritableSharedMemoryMapping input_rgb_shm_mapping =
        input_rgb_shm_region.Map();
    if (!input_rgb_shm_mapping.IsValid()) {
      LOGF(ERROR) << "Failed to create shared memory for input RGB buffer";
      return -ENOMEM;
    }
    base::UnsafeSharedMemoryRegion output_rgb_shm_region =
        base::UnsafeSharedMemoryRegion::Create(rgb_buf_size);
    base::WritableSharedMemoryMapping output_rgb_shm_mapping =
        output_rgb_shm_region.Map();
    if (!output_rgb_shm_mapping.IsValid()) {
      LOGF(ERROR) << "Failed to create shared memory for output RGB buffer";
      return -ENOMEM;
    }
    uint32_t rgb_buf_stride = width * kRGBNumOfChannels;
    int result = 0;
    base::ScopedClosureRunner result_metadata_runner(
        base::BindOnce(&PortraitModeEffect::UpdateSegmentationResult,
                       base::Unretained(this), segmentation_result, &result));
    result = ConvertYUVToRGB(input_mapping, input_rgb_shm_mapping.memory(),
                             rgb_buf_stride);
    if (result != 0) {
      LOGF(ERROR) << "Failed to convert from YUV to RGB";
      return result;
    }

    LOGF(INFO) << "Starting portrait processing";
    // Duplicate the file descriptors since shm_open() returns descriptors
    // associated with FD_CLOEXEC, which causes the descriptors to be closed at
    // the call of execve(). Duplicated descriptors do not share the
    // close-on-exec flag.
    base::ScopedFD dup_input_rgb_buf_fd(
        HANDLE_EINTR(dup(input_rgb_shm_region.GetPlatformHandle().fd)));
    base::ScopedFD dup_output_rgb_buf_fd(
        HANDLE_EINTR(dup(output_rgb_shm_region.GetPlatformHandle().fd)));

    class ScopedHandle {
     public:
      explicit ScopedHandle(GPUAlgoManager* algo, int fd)
          : algo_(algo), handle_(-1) {
        if (algo_ != nullptr) {
          handle_ = algo_->RegisterBuffer(fd);
        }
      }
      ~ScopedHandle() {
        if (IsValid()) {
          std::vector<int32_t> handles({handle_});
          algo_->DeregisterBuffers(handles);
        }
      }
      bool IsValid() const { return handle_ >= 0; }
      int32_t Get() const { return handle_; }

     private:
      GPUAlgoManager* algo_;
      int32_t handle_;
    };

    ScopedHandle input_buffer_handle(gpu_algo_manager_,
                                     dup_input_rgb_buf_fd.release());
    ScopedHandle output_buffer_handle(gpu_algo_manager_,
                                      dup_output_rgb_buf_fd.release());
    if (!input_buffer_handle.IsValid() || !output_buffer_handle.IsValid()) {
      LOGF(ERROR) << "Failed to register buffers";
      result = -EINVAL;
      return result;
    }
    std::vector<uint8_t> req_header(sizeof(CameraGPUAlgoCmdHeader));
    auto* header = reinterpret_cast<CameraGPUAlgoCmdHeader*>(req_header.data());
    header->command = CameraGPUAlgoCommand::PORTRAIT_MODE;
    auto& params = header->params.portrait_mode;
    params.input_buffer_handle = input_buffer_handle.Get();
    params.output_buffer_handle = output_buffer_handle.Get();
    params.width = width;
    params.height = height;
    params.orientation = orientation;
    return_status_ = -ETIMEDOUT;
    gpu_algo_manager_->Request(
        req_header, -1 /* buffers are passed in the header */,
        base::BindOnce(&PortraitModeEffect::ReturnCallback,
                       base::AsWeakPtr(this)));
    base::AutoLock auto_lock(lock_);
    condvar_.TimedWait(kPortraitProcessorTimeout);
    result = return_status_;

    LOGF(INFO) << "Portrait processing finished, result: " << result;
    if (result == -EINVAL || result == -ETIMEDOUT) {
      return result;
    } else if (result == -ECANCELED) {
      // Portrait processing finishes with non-zero result when there's no human
      // face in the image. Returns 0 here with the status set in the vendor tag
      // by |result_metadata_runner|.
      return 0;
    }

    result = ConvertRGBToYUV(output_rgb_shm_mapping.memory(), rgb_buf_stride,
                             output_mapping);
    if (result != 0) {
      LOGF(ERROR) << "Failed to convert from RGB to YUV";
    }
    return result;
  } else {
    // TODO(julianachang): Add unit tests to test whether we want to reprocess
    // this request without portrait processing, or just remove this part.
    LOGF(WARNING) << "Portrait mode is turned off. Just copy the image.";
    switch (v4l2_format) {
      case V4L2_PIX_FMT_NV12:
      case V4L2_PIX_FMT_NV12M:
      case V4L2_PIX_FMT_NV21:
      case V4L2_PIX_FMT_NV21M:
        if (libyuv::NV12Copy(
                input_mapping.plane(0).addr, input_mapping.plane(0).stride,
                input_mapping.plane(1).addr, input_mapping.plane(1).stride,
                output_mapping.plane(0).addr, output_mapping.plane(0).stride,
                output_mapping.plane(1).addr, output_mapping.plane(1).stride,
                width, height) != 0) {
          LOGF(ERROR) << "Failed to copy NV12/NV21";
          return -EINVAL;
        }
        break;
      case V4L2_PIX_FMT_YUV420:
      case V4L2_PIX_FMT_YUV420M:
      case V4L2_PIX_FMT_YVU420:
      case V4L2_PIX_FMT_YVU420M:
        if (libyuv::I420Copy(
                input_mapping.plane(0).addr, input_mapping.plane(0).stride,
                input_mapping.plane(1).addr, input_mapping.plane(1).stride,
                input_mapping.plane(2).addr, input_mapping.plane(2).stride,
                output_mapping.plane(0).addr, output_mapping.plane(0).stride,
                output_mapping.plane(1).addr, output_mapping.plane(1).stride,
                output_mapping.plane(2).addr, output_mapping.plane(2).stride,
                width, height) != 0) {
          LOGF(ERROR) << "Failed to copy YUV420";
          return -EINVAL;
        }
        break;
      default:
        LOGF(ERROR) << "Unsupported format " << FormatToString(v4l2_format);
        return -EINVAL;
    }
  }
  return 0;
}

void PortraitModeEffect::UpdateSegmentationResult(
    SegmentationResult* segmentation_result, const int* result) {
  *segmentation_result =
      (*result == 0)            ? SegmentationResult::kSuccess
      : (*result == -ETIMEDOUT) ? SegmentationResult::kTimeout
      : (*result == -ECANCELED) ? SegmentationResult::kNoFaces
                                : SegmentationResult::kFailure;
}

void PortraitModeEffect::ReturnCallback(uint32_t status,
                                        int32_t buffer_handle) {
  base::AutoLock auto_lock(lock_);
  return_status_ = -status;
  condvar_.Signal();
}

int PortraitModeEffect::ConvertYUVToRGB(const ScopedMapping& mapping,
                                        void* rgb_buf_addr,
                                        uint32_t rgb_buf_stride) {
  switch (mapping.v4l2_format()) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:
      if (libyuv::NV12ToRGB24(mapping.plane(0).addr, mapping.plane(0).stride,
                              mapping.plane(1).addr, mapping.plane(1).stride,
                              static_cast<uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from NV12 to RGB";
        return -EINVAL;
      }
      break;
    case V4L2_PIX_FMT_NV21:
    case V4L2_PIX_FMT_NV21M:
      if (libyuv::NV21ToRGB24(mapping.plane(0).addr, mapping.plane(0).stride,
                              mapping.plane(1).addr, mapping.plane(1).stride,
                              static_cast<uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from NV21 to RGB";
        return -EINVAL;
      }
      break;
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M:
      if (libyuv::I420ToRGB24(mapping.plane(0).addr, mapping.plane(0).stride,
                              mapping.plane(1).addr, mapping.plane(1).stride,
                              mapping.plane(2).addr, mapping.plane(2).stride,
                              static_cast<uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from YUV420 to RGB";
        return -EINVAL;
      }
      break;
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M:
      if (libyuv::I420ToRGB24(mapping.plane(0).addr, mapping.plane(0).stride,
                              mapping.plane(2).addr, mapping.plane(2).stride,
                              mapping.plane(1).addr, mapping.plane(1).stride,
                              static_cast<uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from YVU420 to RGB";
        return -EINVAL;
      }
      break;
    default:
      LOGF(ERROR) << "Unsupported format "
                  << FormatToString(mapping.v4l2_format());
      return -EINVAL;
  }
  return 0;
}

int PortraitModeEffect::ConvertRGBToYUV(void* rgb_buf_addr,
                                        uint32_t rgb_buf_stride,
                                        const ScopedMapping& mapping) {
  auto convert_rgb_to_nv = [](const uint8_t* rgb_addr,
                              const ScopedMapping& mapping) {
    // TODO(hywu): convert RGB to NV12/NV21 directly
    auto div_round_up = [](uint32_t n, uint32_t d) {
      return ((n + d - 1) / d);
    };
    const uint32_t kRGBNumOfChannels = 3;
    uint32_t width = mapping.width();
    uint32_t height = mapping.height();
    uint32_t ystride = width;
    uint32_t cstride = div_round_up(width, 2);
    uint32_t total_size =
        width * height + cstride * div_round_up(height, 2) * 2;
    uint32_t uv_plane_size = cstride * div_round_up(height, 2);
    auto i420_y = std::make_unique<uint8_t[]>(total_size);
    uint8_t* i420_cb = i420_y.get() + width * height;
    uint8_t* i420_cr = i420_cb + uv_plane_size;
    if (libyuv::RGB24ToI420(static_cast<const uint8_t*>(rgb_addr),
                            width * kRGBNumOfChannels, i420_y.get(), ystride,
                            i420_cb, cstride, i420_cr, cstride, width,
                            height) != 0) {
      LOGF(ERROR) << "Failed to convert from RGB to I420";
      return -EINVAL;
    }
    if (mapping.v4l2_format() == V4L2_PIX_FMT_NV12) {
      if (libyuv::I420ToNV12(i420_y.get(), ystride, i420_cb, cstride, i420_cr,
                             cstride, mapping.plane(0).addr,
                             mapping.plane(0).stride, mapping.plane(1).addr,
                             mapping.plane(1).stride, width, height) != 0) {
        LOGF(ERROR) << "Failed to convert from I420 to NV12";
        return -EINVAL;
      }
    } else if (mapping.v4l2_format() == V4L2_PIX_FMT_NV21) {
      if (libyuv::I420ToNV21(i420_y.get(), ystride, i420_cb, cstride, i420_cr,
                             cstride, mapping.plane(0).addr,
                             mapping.plane(0).stride, mapping.plane(1).addr,
                             mapping.plane(1).stride, width, height) != 0) {
        LOGF(ERROR) << "Failed to convert from I420 to NV21";
        return -EINVAL;
      }
    } else {
      return -EINVAL;
    }
    return 0;
  };
  switch (mapping.v4l2_format()) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:
    case V4L2_PIX_FMT_NV21:
    case V4L2_PIX_FMT_NV21M:
      if (convert_rgb_to_nv(static_cast<const uint8_t*>(rgb_buf_addr),
                            mapping) != 0) {
        return -EINVAL;
      }
      break;
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M:
      if (libyuv::RGB24ToI420(static_cast<const uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.plane(0).addr,
                              mapping.plane(0).stride, mapping.plane(1).addr,
                              mapping.plane(1).stride, mapping.plane(2).addr,
                              mapping.plane(2).stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from RGB to YUV420";
        return -EINVAL;
      }
      break;
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M:
      if (libyuv::RGB24ToI420(static_cast<const uint8_t*>(rgb_buf_addr),
                              rgb_buf_stride, mapping.plane(0).addr,
                              mapping.plane(0).stride, mapping.plane(2).addr,
                              mapping.plane(2).stride, mapping.plane(1).addr,
                              mapping.plane(1).stride, mapping.width(),
                              mapping.height()) != 0) {
        LOGF(ERROR) << "Failed to convert from RGB to YVU420";
        return -EINVAL;
      }
      break;
    default:
      LOGF(ERROR) << "Unsupported format "
                  << FormatToString(mapping.v4l2_format());
      return -EINVAL;
  }
  return 0;
}

}  // namespace cros
