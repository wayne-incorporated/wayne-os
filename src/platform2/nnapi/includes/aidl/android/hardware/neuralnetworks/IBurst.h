#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionConfig.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionResult.h>
#include <aidl/android/hardware/neuralnetworks/Request.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IBurst : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IBurst();
  virtual ~IBurst();

  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_executeSynchronously = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_releaseMemoryResource = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_executeSynchronouslyWithConfig = FIRST_CALL_TRANSACTION + 2;

  static std::shared_ptr<IBurst> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IBurst>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IBurst>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IBurst>& impl);
  static const std::shared_ptr<IBurst>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus releaseMemoryResource(int64_t in_memoryIdentifierToken) = 0;
  virtual ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IBurst> default_impl;
};
class IBurstDefault : public IBurst {
public:
  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus releaseMemoryResource(int64_t in_memoryIdentifierToken) override;
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<int64_t>& in_memoryIdentifierTokens, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
