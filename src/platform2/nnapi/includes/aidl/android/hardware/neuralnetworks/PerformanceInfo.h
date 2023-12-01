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
class PerformanceInfo {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  float execTime = 0.000000f;
  float powerUsage = 0.000000f;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) != std::tie(rhs.execTime, rhs.powerUsage);
  }
  inline bool operator<(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) < std::tie(rhs.execTime, rhs.powerUsage);
  }
  inline bool operator<=(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) <= std::tie(rhs.execTime, rhs.powerUsage);
  }
  inline bool operator==(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) == std::tie(rhs.execTime, rhs.powerUsage);
  }
  inline bool operator>(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) > std::tie(rhs.execTime, rhs.powerUsage);
  }
  inline bool operator>=(const PerformanceInfo& rhs) const {
    return std::tie(execTime, powerUsage) >= std::tie(rhs.execTime, rhs.powerUsage);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "PerformanceInfo{";
    os << "execTime: " << ::android::internal::ToString(execTime);
    os << ", powerUsage: " << ::android::internal::ToString(powerUsage);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
