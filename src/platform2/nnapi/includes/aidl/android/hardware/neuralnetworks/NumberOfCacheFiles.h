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
class NumberOfCacheFiles {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t numModelCache = 0;
  int32_t numDataCache = 0;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) != std::tie(rhs.numModelCache, rhs.numDataCache);
  }
  inline bool operator<(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) < std::tie(rhs.numModelCache, rhs.numDataCache);
  }
  inline bool operator<=(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) <= std::tie(rhs.numModelCache, rhs.numDataCache);
  }
  inline bool operator==(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) == std::tie(rhs.numModelCache, rhs.numDataCache);
  }
  inline bool operator>(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) > std::tie(rhs.numModelCache, rhs.numDataCache);
  }
  inline bool operator>=(const NumberOfCacheFiles& rhs) const {
    return std::tie(numModelCache, numDataCache) >= std::tie(rhs.numModelCache, rhs.numDataCache);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "NumberOfCacheFiles{";
    os << "numModelCache: " << ::android::internal::ToString(numModelCache);
    os << ", numDataCache: " << ::android::internal::ToString(numDataCache);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
