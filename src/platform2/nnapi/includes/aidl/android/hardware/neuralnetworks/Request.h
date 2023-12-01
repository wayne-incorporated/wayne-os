#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <android/binder_parcelable_utils.h>
#include <android/binder_to_string.h>
#include <aidl/android/hardware/neuralnetworks/RequestArgument.h>
#include <aidl/android/hardware/neuralnetworks/RequestMemoryPool.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class Request {
public:
  typedef std::false_type fixed_size;
  static const char* descriptor;

  std::vector<::aidl::android::hardware::neuralnetworks::RequestArgument> inputs;
  std::vector<::aidl::android::hardware::neuralnetworks::RequestArgument> outputs;
  std::vector<::aidl::android::hardware::neuralnetworks::RequestMemoryPool> pools;

  binder_status_t readFromParcel(const AParcel* parcel);
  binder_status_t writeToParcel(AParcel* parcel) const;

  inline bool operator!=(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) != std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }
  inline bool operator<(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) < std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }
  inline bool operator<=(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) <= std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }
  inline bool operator==(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) == std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }
  inline bool operator>(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) > std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }
  inline bool operator>=(const Request& rhs) const {
    return std::tie(inputs, outputs, pools) >= std::tie(rhs.inputs, rhs.outputs, rhs.pools);
  }

  static const ::ndk::parcelable_stability_t _aidl_stability = ::ndk::STABILITY_VINTF;
  inline std::string toString() const {
    std::ostringstream os;
    os << "Request{";
    os << "inputs: " << ::android::internal::ToString(inputs);
    os << ", outputs: " << ::android::internal::ToString(outputs);
    os << ", pools: " << ::android::internal::ToString(pools);
    os << "}";
    return os.str();
  }
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
