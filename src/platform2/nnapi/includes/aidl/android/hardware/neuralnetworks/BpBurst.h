#pragma once

#include "aidl/android/hardware/neuralnetworks/IBurst.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpBurst : public ::ndk::BpCInterface<IBurst> {
public:
  explicit BpBurst(const ::ndk::SpAIBinder& binder);
  virtual ~BpBurst();

  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus releaseMemoryResource(int64_t in_memoryIdentifierToken) override;
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
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
