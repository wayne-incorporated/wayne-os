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
class ExtensionNameAndPrefix {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::string name;
  char16_t prefix = '\0';

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) != std::tie(rhs.name, rhs.prefix);
  }
  inline bool operator<(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) < std::tie(rhs.name, rhs.prefix);
  }
  inline bool operator<=(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) <= std::tie(rhs.name, rhs.prefix);
  }
  inline bool operator==(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) == std::tie(rhs.name, rhs.prefix);
  }
  inline bool operator>(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) > std::tie(rhs.name, rhs.prefix);
  }
  inline bool operator>=(const ExtensionNameAndPrefix& rhs) const {
    return std::tie(name, prefix) >= std::tie(rhs.name, rhs.prefix);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "ExtensionNameAndPrefix{";
    os << "name: " << ::android::internal::ToString(name);
    os << ", prefix: " << ::android::internal::ToString(prefix);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
