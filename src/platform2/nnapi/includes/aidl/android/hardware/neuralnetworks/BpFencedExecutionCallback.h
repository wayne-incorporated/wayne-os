#pragma once

#include "aidl/android/hardware/neuralnetworks/IFencedExecutionCallback.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpFencedExecutionCallback : public ::ndk::BpCInterface<IFencedExecutionCallback> {
public:
  explicit BpFencedExecutionCallback(const ::ndk::SpAIBinder& binder);
  virtual ~BpFencedExecutionCallback();

  ::ndk::ScopedAStatus getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* out_timingLaunched, ::aidl::android::hardware::neuralnetworks::Timing* out_timingFenced, ::aidl::android::hardware::neuralnetworks::ErrorStatus* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  int32_t _aidl_cached_version = -1;
  std::string _aidl_cached_hash = "-1";
  std::mutex _aidl_cached_hash_mutex;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
