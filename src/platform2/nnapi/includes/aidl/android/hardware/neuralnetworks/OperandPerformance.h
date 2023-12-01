#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/OperandType.h>
#include <aidl/android/hardware/neuralnetworks/PerformanceInfo.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class OperandPerformance {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  ::aidl::android::hardware::neuralnetworks::OperandType type = ::aidl::android::hardware::neuralnetworks::OperandType::FLOAT32;
  ::aidl::android::hardware::neuralnetworks::PerformanceInfo info;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const OperandPerformance& rhs) const {
    return std::tie(type, info) != std::tie(rhs.type, rhs.info);
  }
  inline bool operator<(const OperandPerformance& rhs) const {
    return std::tie(type, info) < std::tie(rhs.type, rhs.info);
  }
  inline bool operator<=(const OperandPerformance& rhs) const {
    return std::tie(type, info) <= std::tie(rhs.type, rhs.info);
  }
  inline bool operator==(const OperandPerformance& rhs) const {
    return std::tie(type, info) == std::tie(rhs.type, rhs.info);
  }
  inline bool operator>(const OperandPerformance& rhs) const {
    return std::tie(type, info) > std::tie(rhs.type, rhs.info);
  }
  inline bool operator>=(const OperandPerformance& rhs) const {
    return std::tie(type, info) >= std::tie(rhs.type, rhs.info);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "OperandPerformance{";
    os << "type: " << ::android::internal::ToString(type);
    os << ", info: " << ::android::internal::ToString(info);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
