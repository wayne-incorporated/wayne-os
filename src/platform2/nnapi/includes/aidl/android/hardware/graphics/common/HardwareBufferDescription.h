// This code is a basic stub to represent the HardwareBufferDescription
// type that is referenced in the generated AIDL code.
//
// It is unused within the runtime, since we don't support
// hardware buffers, however it is required for the system
// to compile unmodified.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/graphics/common/BufferUsage.h>
#include <aidl/android/hardware/graphics/common/PixelFormat.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace graphics {
namespace common {
class HardwareBufferDescription {
 public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t width = 0;
  int32_t height = 0;
  int32_t layers = 0;
  ::aidl::android::hardware::graphics::common::PixelFormat format =
      ::aidl::android::hardware::graphics::common::PixelFormat::UNSPECIFIED;
  ::aidl::android::hardware::graphics::common::BufferUsage usage =
      ::aidl::android::hardware::graphics::common::BufferUsage::CPU_READ_NEVER;
  int32_t stride = 0;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) !=
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }
  inline bool operator<(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) <
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }
  inline bool operator<=(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) <=
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }
  inline bool operator==(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) ==
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }
  inline bool operator>(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) >
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }
  inline bool operator>=(const HardwareBufferDescription& rhs) const {
    return std::tie(width, height, layers, format, usage, stride) >=
           std::tie(rhs.width, rhs.height, rhs.layers, rhs.format, rhs.usage,
                    rhs.stride);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability =
      ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "HardwareBufferDescription{";
    os << "width: " << ::android::internal::ToString(width);
    os << ", height: " << ::android::internal::ToString(height);
    os << ", layers: " << ::android::internal::ToString(layers);
    os << ", format: " << ::android::internal::ToString(format);
    os << ", usage: " << ::android::internal::ToString(usage);
    os << ", stride: " << ::android::internal::ToString(stride);
    os << "}";
    return os.str();
  }
};
}  // namespace common
}  // namespace graphics
}  // namespace hardware
}  // namespace android
}  // namespace aidl
