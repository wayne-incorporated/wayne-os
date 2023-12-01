#pragma once

#include "aidl/android/hardware/neuralnetworks/IExecution.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpExecution : public ::ndk::BpCInterface<IExecution> {
public:
  explicit BpExecution(const ::ndk::SpAIBinder& binder);
  virtual ~BpExecution();

  ::ndk::ScopedAStatus executeSynchronously(int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFenced(const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
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
