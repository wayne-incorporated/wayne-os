#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_ABUFFER_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_ABUFFER_H

#include <android/hardware/neuralnetworks/1.3/IBuffer.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_3 {

class ABuffer : public ::android::hardware::neuralnetworks::V1_3::IBuffer {
 public:
  typedef ::android::hardware::neuralnetworks::V1_3::IBuffer Pure;
  ABuffer(
      const ::android::sp<::android::hardware::neuralnetworks::V1_3::IBuffer>&
          impl);
  // Methods from ::android::hardware::neuralnetworks::V1_3::IBuffer follow.
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_3::ErrorStatus>
  copyTo(const ::android::hardware::hidl_memory& dst) override;
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_3::ErrorStatus>
  copyFrom(const ::android::hardware::hidl_memory& src,
           const ::android::hardware::hidl_vec<uint32_t>& dimensions) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_3::IBuffer> mImpl;
};

}  // namespace V1_3
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_ABUFFER_H
