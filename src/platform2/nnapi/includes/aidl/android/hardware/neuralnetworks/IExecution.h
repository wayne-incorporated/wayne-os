#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/ExecutionResult.h>
#include <aidl/android/hardware/neuralnetworks/FencedExecutionResult.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IExecution : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IExecution();
  virtual ~IExecution();

  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_executeSynchronously = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_executeFenced = FIRST_CALL_TRANSACTION + 1;

  static std::shared_ptr<IExecution> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IExecution>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IExecution>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IExecution>& impl);
  static const std::shared_ptr<IExecution>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus executeSynchronously(int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus executeFenced(const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IExecution> default_impl;
};
class IExecutionDefault : public IExecution {
public:
  ::ndk::ScopedAStatus executeSynchronously(int64_t in_deadlineNs, ::aidl::android::hardware::neuralnetworks::ExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus executeFenced(const std::vector<::ndk::ScopedFileDescriptor>& in_waitFor, int64_t in_deadlineNs, int64_t in_durationNs, ::aidl::android::hardware::neuralnetworks::FencedExecutionResult* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
