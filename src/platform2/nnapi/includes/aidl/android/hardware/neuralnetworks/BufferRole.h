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
class BufferRole {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t modelIndex = 0;
  int32_t ioIndex = 0;
  float probability = 0.000000f;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) != std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }
  inline bool operator<(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) < std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }
  inline bool operator<=(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) <= std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }
  inline bool operator==(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) == std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }
  inline bool operator>(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) > std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }
  inline bool operator>=(const BufferRole& rhs) const {
    return std::tie(modelIndex, ioIndex, probability) >= std::tie(rhs.modelIndex, rhs.ioIndex, rhs.probability);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "BufferRole{";
    os << "modelIndex: " << ::android::internal::ToString(modelIndex);
    os << ", ioIndex: " << ::android::internal::ToString(ioIndex);
    os << ", probability: " << ::android::internal::ToString(probability);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
