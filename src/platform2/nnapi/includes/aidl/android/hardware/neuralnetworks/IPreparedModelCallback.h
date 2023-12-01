#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/ErrorStatus.h>
#include <aidl/android/hardware/neuralnetworks/IPreparedModel.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IPreparedModelCallback : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IPreparedModelCallback();
  virtual ~IPreparedModelCallback();

  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_notify = FIRST_CALL_TRANSACTION + 0;

  static std::shared_ptr<IPreparedModelCallback> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IPreparedModelCallback>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IPreparedModelCallback>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IPreparedModelCallback>& impl);
  static const std::shared_ptr<IPreparedModelCallback>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus notify(::aidl::android::hardware::neuralnetworks::ErrorStatus in_status, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& in_preparedModel) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IPreparedModelCallback> default_impl;
};
class IPreparedModelCallbackDefault : public IPreparedModelCallback {
public:
  ::ndk::ScopedAStatus notify(::aidl::android::hardware::neuralnetworks::ErrorStatus in_status, const std::shared_ptr<::aidl::android::hardware::neuralnetworks::IPreparedModel>& in_preparedModel) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
