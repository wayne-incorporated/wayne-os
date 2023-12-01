// This code is a basic stub to represent the BufferUsage
// type that is referenced in the generated AIDL code.
//
// It is unused within the runtime, since we don't support
// hardware buffers, however it is required for the system
// to compile unmodified.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_enums.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace graphics {
namespace common {
enum class BufferUsage : int64_t {
  CPU_READ_MASK = 15L,
  CPU_READ_NEVER = 0L,
  CPU_READ_RARELY = 2L,
  CPU_READ_OFTEN = 3L,
  CPU_WRITE_MASK = 240L,
  CPU_WRITE_NEVER = 0L,
  CPU_WRITE_RARELY = 32L,
  CPU_WRITE_OFTEN = 48L,
  GPU_TEXTURE = 256L,
  GPU_RENDER_TARGET = 512L,
  COMPOSER_OVERLAY = 2048L,
  COMPOSER_CLIENT_TARGET = 4096L,
  PROTECTED = 16384L,
  COMPOSER_CURSOR = 32768L,
  VIDEO_ENCODER = 65536L,
  CAMERA_OUTPUT = 131072L,
  CAMERA_INPUT = 262144L,
  RENDERSCRIPT = 1048576L,
  VIDEO_DECODER = 4194304L,
  SENSOR_DIRECT_DATA = 8388608L,
  GPU_DATA_BUFFER = 16777216L,
  GPU_CUBE_MAP = 33554432L,
  GPU_MIPMAP_COMPLETE = 67108864L,
  HW_IMAGE_ENCODER = 134217728L,
  FRONT_BUFFER = 4294967296L,
  VENDOR_MASK = -268435456L,
  VENDOR_MASK_HI = -281474976710656L,
};

}  // namespace common
}  // namespace graphics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace aidl {
namespace android {
namespace hardware {
namespace graphics {
namespace common {
[[nodiscard]] static inline std::string toString(BufferUsage val) {
  switch (val) {
    case BufferUsage::CPU_READ_MASK:
      return "CPU_READ_MASK";
    case BufferUsage::CPU_READ_NEVER:
      return "CPU_READ_NEVER";
    case BufferUsage::CPU_READ_RARELY:
      return "CPU_READ_RARELY";
    case BufferUsage::CPU_READ_OFTEN:
      return "CPU_READ_OFTEN";
    case BufferUsage::CPU_WRITE_MASK:
      return "CPU_WRITE_MASK";
    case BufferUsage::CPU_WRITE_RARELY:
      return "CPU_WRITE_RARELY";
    case BufferUsage::CPU_WRITE_OFTEN:
      return "CPU_WRITE_OFTEN";
    case BufferUsage::GPU_TEXTURE:
      return "GPU_TEXTURE";
    case BufferUsage::GPU_RENDER_TARGET:
      return "GPU_RENDER_TARGET";
    case BufferUsage::COMPOSER_OVERLAY:
      return "COMPOSER_OVERLAY";
    case BufferUsage::COMPOSER_CLIENT_TARGET:
      return "COMPOSER_CLIENT_TARGET";
    case BufferUsage::PROTECTED:
      return "PROTECTED";
    case BufferUsage::COMPOSER_CURSOR:
      return "COMPOSER_CURSOR";
    case BufferUsage::VIDEO_ENCODER:
      return "VIDEO_ENCODER";
    case BufferUsage::CAMERA_OUTPUT:
      return "CAMERA_OUTPUT";
    case BufferUsage::CAMERA_INPUT:
      return "CAMERA_INPUT";
    case BufferUsage::RENDERSCRIPT:
      return "RENDERSCRIPT";
    case BufferUsage::VIDEO_DECODER:
      return "VIDEO_DECODER";
    case BufferUsage::SENSOR_DIRECT_DATA:
      return "SENSOR_DIRECT_DATA";
    case BufferUsage::GPU_DATA_BUFFER:
      return "GPU_DATA_BUFFER";
    case BufferUsage::GPU_CUBE_MAP:
      return "GPU_CUBE_MAP";
    case BufferUsage::GPU_MIPMAP_COMPLETE:
      return "GPU_MIPMAP_COMPLETE";
    case BufferUsage::HW_IMAGE_ENCODER:
      return "HW_IMAGE_ENCODER";
    case BufferUsage::FRONT_BUFFER:
      return "FRONT_BUFFER";
    case BufferUsage::VENDOR_MASK:
      return "VENDOR_MASK";
    case BufferUsage::VENDOR_MASK_HI:
      return "VENDOR_MASK_HI";
    default:
      return std::to_string(static_cast<int64_t>(val));
  }
}
}  // namespace common
}  // namespace graphics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
namespace ndk {
namespace internal {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++17-extensions"
template <>
constexpr inline std::array<
    aidl::android::hardware::graphics::common::BufferUsage,
    27>
    enum_values<aidl::android::hardware::graphics::common::BufferUsage> = {
        aidl::android::hardware::graphics::common::BufferUsage::CPU_READ_MASK,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_READ_NEVER,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_READ_RARELY,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_READ_OFTEN,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_WRITE_MASK,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_WRITE_NEVER,
        aidl::android::hardware::graphics::common::BufferUsage::
            CPU_WRITE_RARELY,
        aidl::android::hardware::graphics::common::BufferUsage::CPU_WRITE_OFTEN,
        aidl::android::hardware::graphics::common::BufferUsage::GPU_TEXTURE,
        aidl::android::hardware::graphics::common::BufferUsage::
            GPU_RENDER_TARGET,
        aidl::android::hardware::graphics::common::BufferUsage::
            COMPOSER_OVERLAY,
        aidl::android::hardware::graphics::common::BufferUsage::
            COMPOSER_CLIENT_TARGET,
        aidl::android::hardware::graphics::common::BufferUsage::PROTECTED,
        aidl::android::hardware::graphics::common::BufferUsage::COMPOSER_CURSOR,
        aidl::android::hardware::graphics::common::BufferUsage::VIDEO_ENCODER,
        aidl::android::hardware::graphics::common::BufferUsage::CAMERA_OUTPUT,
        aidl::android::hardware::graphics::common::BufferUsage::CAMERA_INPUT,
        aidl::android::hardware::graphics::common::BufferUsage::RENDERSCRIPT,
        aidl::android::hardware::graphics::common::BufferUsage::VIDEO_DECODER,
        aidl::android::hardware::graphics::common::BufferUsage::
            SENSOR_DIRECT_DATA,
        aidl::android::hardware::graphics::common::BufferUsage::GPU_DATA_BUFFER,
        aidl::android::hardware::graphics::common::BufferUsage::GPU_CUBE_MAP,
        aidl::android::hardware::graphics::common::BufferUsage::
            GPU_MIPMAP_COMPLETE,
        aidl::android::hardware::graphics::common::BufferUsage::
            HW_IMAGE_ENCODER,
        aidl::android::hardware::graphics::common::BufferUsage::FRONT_BUFFER,
        aidl::android::hardware::graphics::common::BufferUsage::VENDOR_MASK,
        aidl::android::hardware::graphics::common::BufferUsage::VENDOR_MASK_HI,
};
#pragma clang diagnostic pop
}  // namespace internal
}  // namespace ndk
