#include "aidl/android/hardware/neuralnetworks/OperandExtraParams.h"

#include <android/binder_parcel_utils.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
const char* OperandExtraParams::descriptor = "android.hardware.neuralnetworks.OperandExtraParams";

binder_status_t OperandExtraParams::readFromParcel(const AParcel* _parcel) {
  binder_status_t _aidl_ret_status;
  int32_t _aidl_tag;
  if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_tag)) != STATUS_OK) return _aidl_ret_status;
  switch (static_cast<Tag>(_aidl_tag)) {
  case channelQuant: {
    ::aidl::android::hardware::neuralnetworks::SymmPerChannelQuantParams _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<::aidl::android::hardware::neuralnetworks::SymmPerChannelQuantParams>) {
      set<channelQuant>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<channelQuant>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  case extension: {
    std::vector<uint8_t> _aidl_value;
    if ((_aidl_ret_status = ::ndk::AParcel_readData(_parcel, &_aidl_value)) != STATUS_OK) return _aidl_ret_status;
    if constexpr (std::is_trivially_copyable_v<std::vector<uint8_t>>) {
      set<extension>(_aidl_value);
    } else {
      // NOLINTNEXTLINE(performance-move-const-arg)
      set<extension>(std::move(_aidl_value));
    }
    return STATUS_OK; }
  }
  return STATUS_BAD_VALUE;
}
binder_status_t OperandExtraParams::writeToParcel(AParcel* _parcel) const {
  binder_status_t _aidl_ret_status = ::ndk::AParcel_writeData(_parcel, static_cast<int32_t>(getTag()));
  if (_aidl_ret_status != STATUS_OK) return _aidl_ret_status;
  switch (getTag()) {
  case channelQuant: return ::ndk::AParcel_writeData(_parcel, get<channelQuant>());
  case extension: return ::ndk::AParcel_writeData(_parcel, get<extension>());
  }
  __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__, "can't reach here");
}

}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
