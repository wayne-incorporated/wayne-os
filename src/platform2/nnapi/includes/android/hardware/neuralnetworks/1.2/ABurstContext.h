#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCONTEXT_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCONTEXT_H

#include <android/hardware/neuralnetworks/1.2/IBurstContext.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_2 {

class ABurstContext
    : public ::android::hardware::neuralnetworks::V1_2::IBurstContext {
 public:
  typedef ::android::hardware::neuralnetworks::V1_2::IBurstContext Pure;
  ABurstContext(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IBurstContext>& impl);
  // Methods from ::android::hardware::neuralnetworks::V1_2::IBurstContext
  // follow.
  virtual ::android::hardware::Return<void> freeMemory(int32_t slot) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_2::IBurstContext> mImpl;
};

}  // namespace V1_2
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_2_ABURSTCONTEXT_H
