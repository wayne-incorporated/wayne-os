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
class SymmPerChannelQuantParams {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::vector<float> scales;
  int32_t channelDim = 0;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) != std::tie(rhs.scales, rhs.channelDim);
  }
  inline bool operator<(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) < std::tie(rhs.scales, rhs.channelDim);
  }
  inline bool operator<=(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) <= std::tie(rhs.scales, rhs.channelDim);
  }
  inline bool operator==(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) == std::tie(rhs.scales, rhs.channelDim);
  }
  inline bool operator>(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) > std::tie(rhs.scales, rhs.channelDim);
  }
  inline bool operator>=(const SymmPerChannelQuantParams& rhs) const {
    return std::tie(scales, channelDim) >= std::tie(rhs.scales, rhs.channelDim);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "SymmPerChannelQuantParams{";
    os << "scales: " << ::android::internal::ToString(scales);
    os << ", channelDim: " << ::android::internal::ToString(channelDim);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
