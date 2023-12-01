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
class TokenValuePair {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  int32_t token = 0;
  std::vector<uint8_t> value;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const TokenValuePair& rhs) const {
    return std::tie(token, value) != std::tie(rhs.token, rhs.value);
  }
  inline bool operator<(const TokenValuePair& rhs) const {
    return std::tie(token, value) < std::tie(rhs.token, rhs.value);
  }
  inline bool operator<=(const TokenValuePair& rhs) const {
    return std::tie(token, value) <= std::tie(rhs.token, rhs.value);
  }
  inline bool operator==(const TokenValuePair& rhs) const {
    return std::tie(token, value) == std::tie(rhs.token, rhs.value);
  }
  inline bool operator>(const TokenValuePair& rhs) const {
    return std::tie(token, value) > std::tie(rhs.token, rhs.value);
  }
  inline bool operator>=(const TokenValuePair& rhs) const {
    return std::tie(token, value) >= std::tie(rhs.token, rhs.value);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "TokenValuePair{";
    os << "token: " << ::android::internal::ToString(token);
    os << ", value: " << ::android::internal::ToString(value);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
