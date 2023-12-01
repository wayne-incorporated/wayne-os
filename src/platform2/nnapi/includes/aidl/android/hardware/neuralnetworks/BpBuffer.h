#pragma once

#include "aidl/android/hardware/neuralnetworks/IBuffer.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpBuffer : public ::ndk::BpCInterface<IBuffer> {
public:
  explicit BpBuffer(const ::ndk::SpAIBinder& binder);
  virtual ~BpBuffer();

  ::ndk::ScopedAStatus copyFrom(const ::aidl::android::hardware::neuralnetworks::Memory& in_src, const std::vector<int32_t>& in_dimensions) override;
  ::ndk::ScopedAStatus copyTo(const ::aidl::android::hardware::neuralnetworks::Memory& in_dst) override;
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
