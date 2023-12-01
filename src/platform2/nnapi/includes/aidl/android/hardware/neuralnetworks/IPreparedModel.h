#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionConfig.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionResult.h>
#include <aidl/android/hardware/neuralnetworks/FencedExecutionResult.h>
#include <aidl/android/hardware/neuralnetworks/IBurst.h>
#include <aidl/android/hardware/neuralnetworks/IExecution.h>
#include <aidl/android/hardware/neuralnetworks/Request.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IPreparedModel : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IPreparedModel();
  virtual ~IPreparedModel();

  enum : int64_t { DEFAULT_LOOP_TIMEOUT_DURATION_NS = 2000000000L };
  enum : int64_t { MAXIMUM_LOOP_TIMEOUT_DURATION_NS = 15000000000L };
  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_executeSynchronously = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_executeFenced = FIRST_CALL_TRANSACTION + 1;
  static constexpr uint32_t TRANSACTION_configureExecutionBurst = FIRST_CALL_TRANSACTION + 2;
  static constexpr uint32_t TRANSACTION_createReusableExecution = FIRST_CALL_TRANSACTION + 3;
  static constexpr uint32_t TRANSACTION_executeSynchronouslyWithConfig = FIRST_CALL_TRANSACTION + 4;
  static constexpr uint32_t TRANSACTION_executeFencedWithConfig = FIRST_CALL_TRANSACTION + 5;

  static std::shared_ptr<IPreparedModel> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IPreparedModel>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IPreparedModel>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IPreparedModel>& impl);
  static const std::shared_ptr<IPreparedModel>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus executeFenced(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus configureExecutionBurst(std::shared_ptr<::aidl::android::hardware::neuralnetworks::IBurst>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus createReusableExecution(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, std::shared_ptr<::aidl::android::hardware::neuralnetworks::IExecution>* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus executeFencedWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IPreparedModel> default_impl;
};
class IPreparedModelDefault : public IPreparedModel {
public:
  ::ndk::ScopedAStatus executeSynchronously(const ::aidl::android::hardware::neuralnetworks::Request& in_request, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFenced(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, bool in_measureTiming, int64_t in_deadlineNs, int64_t in_loopTimeoutDurationNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus configureExecutionBurst(std::shared_ptr<::aidl::android::hardware::neuralnetworks::IBurst>* _aidl_return) override;
  ::ndk::ScopedAStatus createReusableExecution(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, std::shared_ptr<::aidl::android::hardware::neuralnetworks::IExecution>* _aidl_return) override;
  ::ndk::ScopedAStatus executeSynchronouslyWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFencedWithConfig(const ::aidl::android::hardware::neuralnetworks::Request& in_request, const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, const ::aidl::android::hardware::neuralnetworks::ExecutionConfig& in_config, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
