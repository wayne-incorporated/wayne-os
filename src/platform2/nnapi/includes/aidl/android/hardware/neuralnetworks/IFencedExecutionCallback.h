#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/ErrorStatus.h>
#include <aidl/android/hardware/neuralnetworks/Timing.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IFencedExecutionCallback : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IFencedExecutionCallback();
  virtual ~IFencedExecutionCallback();

  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_getExecutionInfo = FIRST_CALL_TRANSACTION + 0;

  static std::shared_ptr<IFencedExecutionCallback> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IFencedExecutionCallback>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IFencedExecutionCallback>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IFencedExecutionCallback>& impl);
  static const std::shared_ptr<IFencedExecutionCallback>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* out_timingLaunched, ::aidl::android::hardware::neuralnetworks::Timing* out_timingFenced, ::aidl::android::hardware::neuralnetworks::ErrorStatus* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IFencedExecutionCallback> default_impl;
};
class IFencedExecutionCallbackDefault : public IFencedExecutionCallback {
public:
  ::ndk::ScopedAStatus getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* out_timingLaunched, ::aidl::android::hardware::neuralnetworks::Timing* out_timingFenced, ::aidl::android::hardware::neuralnetworks::ErrorStatus* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
