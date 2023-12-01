#ifndef HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODEL_H
#define HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODEL_H

#include <android/hardware/neuralnetworks/1.3/IPreparedModel.h>
namespace android {
namespace hardware {
namespace neuralnetworks {
namespace V1_3 {

class APreparedModel
    : public ::android::hardware::neuralnetworks::V1_3::IPreparedModel {
 public:
  typedef ::android::hardware::neuralnetworks::V1_3::IPreparedModel Pure;
  APreparedModel(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_3::IPreparedModel>& impl);
  // Methods from ::android::hardware::neuralnetworks::V1_0::IPreparedModel
  // follow.
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus>
  execute(const ::android::hardware::neuralnetworks::V1_0::Request& request,
          const ::android::sp<
              ::android::hardware::neuralnetworks::V1_0::IExecutionCallback>&
              callback) override;

  // Methods from ::android::hardware::neuralnetworks::V1_2::IPreparedModel
  // follow.
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_0::ErrorStatus>
  execute_1_2(
      const ::android::hardware::neuralnetworks::V1_0::Request& request,
      ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IExecutionCallback>&
          callback) override;
  virtual ::android::hardware::Return<void> executeSynchronously(
      const ::android::hardware::neuralnetworks::V1_0::Request& request,
      ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure,
      executeSynchronously_cb _hidl_cb) override;
  virtual ::android::hardware::Return<void> configureExecutionBurst(
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_2::IBurstCallback>& callback,
      const ::android::hardware::MQDescriptorSync<
          ::android::hardware::neuralnetworks::V1_2::FmqRequestDatum>&
          requestChannel,
      const ::android::hardware::MQDescriptorSync<
          ::android::hardware::neuralnetworks::V1_2::FmqResultDatum>&
          resultChannel,
      configureExecutionBurst_cb _hidl_cb) override;

  // Methods from ::android::hardware::neuralnetworks::V1_3::IPreparedModel
  // follow.
  virtual ::android::hardware::Return<
      ::android::hardware::neuralnetworks::V1_3::ErrorStatus>
  execute_1_3(
      const ::android::hardware::neuralnetworks::V1_3::Request& request,
      ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint&
          deadline,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration&
          loopTimeoutDuration,
      const ::android::sp<
          ::android::hardware::neuralnetworks::V1_3::IExecutionCallback>&
          callback) override;
  virtual ::android::hardware::Return<void> executeSynchronously_1_3(
      const ::android::hardware::neuralnetworks::V1_3::Request& request,
      ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint&
          deadline,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration&
          loopTimeoutDuration,
      executeSynchronously_1_3_cb _hidl_cb) override;
  virtual ::android::hardware::Return<void> executeFenced(
      const ::android::hardware::neuralnetworks::V1_3::Request& request,
      const ::android::hardware::hidl_vec<::android::hardware::hidl_handle>&
          waitFor,
      ::android::hardware::neuralnetworks::V1_2::MeasureTiming measure,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimePoint&
          deadline,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration&
          loopTimeoutDuration,
      const ::android::hardware::neuralnetworks::V1_3::OptionalTimeoutDuration&
          duration,
      executeFenced_cb _hidl_cb) override;

  // Methods from ::android::hidl::base::V1_0::IBase follow.

 private:
  ::android::sp<::android::hardware::neuralnetworks::V1_3::IPreparedModel>
      mImpl;
};

}  // namespace V1_3
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
#endif  // HIDL_GENERATED_ANDROID_HARDWARE_NEURALNETWORKS_V1_3_APREPAREDMODEL_H
