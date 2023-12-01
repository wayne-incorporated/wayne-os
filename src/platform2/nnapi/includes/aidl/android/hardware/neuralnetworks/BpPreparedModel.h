#pragma once

#include "aidl/android/hardware/neuralnetworks/IPreparedModel.h"

#include <android/binder_ibinder.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class BpPreparedModel : public ::ndk::BpCInterface<IPreparedModel> {
public:
  explicit BpPreparedModel(const ::ndk::SpAIBinder& binder);
  virtual ~BpPreparedModel();

  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFenced(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus configureExecutionBurst(std::shared_ptr<::aidl::android::hardware::neuralnetworks::IBurst>* _aidl_return) override;
  ::ndk::ScopedAStatus createReusableExecution(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, std::shared_ptr<::aidl::android::hardware::neuralnetworks::IExecution>* _aidl_return) override;
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFencedWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
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
