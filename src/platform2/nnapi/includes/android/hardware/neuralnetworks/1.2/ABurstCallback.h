#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCALLBACK_H

#include <android/hardware/neuralnetworks/1.2/IBurstCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_2 {

class ABurstCallback
    : public ::android::hardware::neuralnetworks::V1_2::IBurstCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_2::IBurstCallback Pure;
  ABurstCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IBurstCallback>& impl);
  // Methods from ::android::hardware::neuralnetworks::V1_2::IBurstCallback
  // follow.
  virtual ::android::hardware::Return<void> getMemories(
      const ::android::hardware::hidl_vec<int32_t>& slots,
      getMemories_cb _hidl_cb) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_2::IBurstCallback>
      mImpl;
};

}  // namespace V1_2
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCALLBACK_H
