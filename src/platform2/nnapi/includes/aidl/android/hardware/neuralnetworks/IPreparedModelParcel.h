#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/IPreparedModel.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IPreparedModelParcel {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel> preparedModel;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) != std::tie(rhs.preparedModel);
  }
  inline bool operator<(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) < std::tie(rhs.preparedModel);
  }
  inline bool operator<=(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) <= std::tie(rhs.preparedModel);
  }
  inline bool operator==(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) == std::tie(rhs.preparedModel);
  }
  inline bool operator>(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) > std::tie(rhs.preparedModel);
  }
  inline bool operator>=(const IPreparedModelParcel& rhs) const {
    return std::tie(preparedModel) >= std::tie(rhs.preparedModel);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "IPreparedModelParcel{";
    os << "preparedModel: " << ::android::internal::ToString(preparedModel);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
