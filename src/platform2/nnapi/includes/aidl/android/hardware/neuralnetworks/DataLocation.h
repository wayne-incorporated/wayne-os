#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class DataLocation {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t poolIndex = 0;
  int64_t offset = 0L;
  int64_t length = 0L;
  int64_t padding = 0L;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) != std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }
  inline bool operator<(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) < std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }
  inline bool operator<=(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) <= std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }
  inline bool operator==(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) == std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }
  inline bool operator>(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) > std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }
  inline bool operator>=(const DataLocation& rhs) const {
    return std::tie(poolIndex, offset, length, padding) >= std::tie(rhs.poolIndex, rhs.offset, rhs.length, rhs.padding);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "DataLocation{";
    os << "poolIndex: " << ::android::internal::ToString(poolIndex);
    os << ", offset: " << ::android::internal::ToString(offset);
    os << ", length: " << ::android::internal::ToString(length);
    os << ", padding: " << ::android::internal::ToString(padding);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
