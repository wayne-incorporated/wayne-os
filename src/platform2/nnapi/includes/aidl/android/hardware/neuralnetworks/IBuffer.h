#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <android/binder_interface_utils.h>
#include <aidl/android/hardware/neuralnetworks/Memory.h>
#ifdef BINDER_STABILITY_SUPPORT
#include <android/binder_stability.h>
#endif  // BINDER_STABILITY_SUPPORT

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
class IBuffer : public ::ndk::ICInterface {
public:
  static const char* descriptor;
  IBuffer();
  virtual ~IBuffer();

  static const int32_t version = 4;
  static inline const std::string hash = "notfrozen";
  static constexpr uint32_t TRANSACTION_copyFrom = FIRST_CALL_TRANSACTION + 0;
  static constexpr uint32_t TRANSACTION_copyTo = FIRST_CALL_TRANSACTION + 1;

  static std::shared_ptr<IBuffer> fromBinder(const ::ndk::SpAIBinder& binder);
  static binder_status_t writeToParcel(AParcel* parcel, const std::shared_ptr<IBuffer>& instance);
  static binder_status_t readFromParcel(const AParcel* parcel, std::shared_ptr<IBuffer>* instance);
  static bool setDefaultImpl(const std::shared_ptr<IBuffer>& impl);
  static const std::shared_ptr<IBuffer>& getDefaultImpl();
  virtual ::ndk::ScopedAStatus copyFrom(const ::aidl::android::hardware::neuralnetworks::Memory& in_src, const std::vector<int32_t>& in_dimensions) = 0;
  virtual ::ndk::ScopedAStatus copyTo(const ::aidl::android::hardware::neuralnetworks::Memory& in_dst) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) = 0;
  virtual ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) = 0;
private:
  static std::shared_ptr<IBuffer> default_impl;
};
class IBufferDefault : public IBuffer {
public:
  ::ndk::ScopedAStatus copyFrom(const ::aidl::android::hardware::neuralnetworks::Memory& in_src, const std::vector<int32_t>& in_dimensions) override;
  ::ndk::ScopedAStatus copyTo(const ::aidl::android::hardware::neuralnetworks::Memory& in_dst) override;
  ::ndk::ScopedAStatus getInterfaceVersion(int32_t* _aidl_return) override;
  ::ndk::ScopedAStatus getInterfaceHash(std::string* _aidl_return) override;
  ::ndk::SpAIBinder asBinder() override;
  bool isRemote() override;
};
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
