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
class Timing {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int64_t timeOnDeviceNs = 0L;
  int64_t timeInDriverNs = 0L;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) != std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }
  inline bool operator<(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) < std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }
  inline bool operator<=(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) <= std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }
  inline bool operator==(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) == std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }
  inline bool operator>(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) > std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }
  inline bool operator>=(const Timing& rhs) const {
    return std::tie(timeOnDeviceNs, timeInDriverNs) >= std::tie(rhs.timeOnDeviceNs, rhs.timeInDriverNs);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Timing{";
    os << "timeOnDeviceNs: " << ::android::internal::ToString(timeOnDeviceNs);
    os << ", timeInDriverNs: " << ::android::internal::ToString(timeInDriverNs);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
