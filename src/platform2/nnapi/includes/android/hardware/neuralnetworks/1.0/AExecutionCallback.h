#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_AEXECUTIONCALLBACK_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_AEXECUTIONCALLBACK_H

#include <android/hardware/neuralnetworks/1.0/IExecutionCallback.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_0 {

class AExecutionCallback
    : public ::android::hardware::neuralnetworks::V1_0::IExecutionCallback {
 public:
  typedef ::android::hardware::neuralnetworks::V1_0::IExecutionCallback Pure;
  AExecutionCallback(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_0::IExecutionCallback>& impl);
  // Methods from ::android::hardware::neuralnetworks::V1_0::IExecutionCallback
  // follow.
  virtual ::android::hardware::Return<void> notify(
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus status) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_0::IExecutionCallback>
      mImpl;
};

}  // namespace V1_0
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_0_AEXECUTIONCALLBACK_H
