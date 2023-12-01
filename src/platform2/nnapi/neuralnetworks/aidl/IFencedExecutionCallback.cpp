#include "aidl/android/hardware/neuralnetworks/IFencedExecutionCallback.h"

#include <android/binder_parcel_utils.h>
#include <aidl/android/hardware/neuralnetworks/BnFencedExecutionCallback.h>
#include <aidl/android/hardware/neuralnetworks/BpFencedExecutionCallback.h>

namespace aidl {
namespace android {
namespace hardware {
namespace neuralnetworks {
static binder_status_t _aidl_android_hardware_neuralnetworks_IFencedExecutionCallback_onTransact(AIBinder* _aidl_binder, transaction_code_t _aidl_code, const AParcel* _aidl_in, AParcel* _aidl_out) {
  (void)_aidl_in;
  (void)_aidl_out;
  binder_status_t _aidl_ret_status = STATUS_UNKNOWN_TRANSACTION;
  std::shared_ptr<BnFencedExecutionCallback> _aidl_impl = std::static_pointer_cast<BnFencedExecutionCallback>(::ndk::ICInterface::asInterface(_aidl_binder));
  switch (_aidl_code) {
    case (FIRST_CALL_TRANSACTION + 0 /*getExecutionInfo*/): {
      ::aidl::android::hardware::neuralnetworks::Timing out_timingLaunched;
      ::aidl::android::hardware::neuralnetworks::Timing out_timingFenced;
      ::aidl::android::hardware::neuralnetworks::ErrorStatus _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getExecutionInfo(&out_timingLaunched, &out_timingFenced, &_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, out_timingLaunched);
      if (_aidl_ret_status != STATUS_OK) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, out_timingFenced);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/): {
      int32_t _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceVersion(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
    case (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/): {
      std::string _aidl_return;

      ::ndk::ScopedAStatus _aidl_status = _aidl_impl->getInterfaceHash(&_aidl_return);
      _aidl_ret_status = AParcel_writeStatusHeader(_aidl_out, _aidl_status.get());
      if (_aidl_ret_status != STATUS_OK) break;

      if (!AStatus_isOk(_aidl_status.get())) break;

      _aidl_ret_status = ::ndk::AParcel_writeData(_aidl_out, _aidl_return);
      if (_aidl_ret_status != STATUS_OK) break;

      break;
    }
  }
  return _aidl_ret_status;
}

static AIBinder_Class* _g_aidl_android_hardware_neuralnetworks_IFencedExecutionCallback_clazz = ::ndk::ICInterface::defineClass(IFencedExecutionCallback::descriptor, _aidl_android_hardware_neuralnetworks_IFencedExecutionCallback_onTransact);

BpFencedExecutionCallback::BpFencedExecutionCallback(const ::ndk::SpAIBinder& binder) : BpCInterface(binder) {}
BpFencedExecutionCallback::~BpFencedExecutionCallback() {}

::ndk::ScopedAStatus BpFencedExecutionCallback::getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* out_timingLaunched, ::aidl::android::hardware::neuralnetworks::Timing* out_timingFenced, ::aidl::android::hardware::neuralnetworks::ErrorStatus* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 0 /*getExecutionInfo*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFencedExecutionCallback::getDefaultImpl()) {
    _aidl_status = IFencedExecutionCallback::getDefaultImpl()->getExecutionInfo(out_timingLaunched, out_timingFenced, _aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), out_timingLaunched);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), out_timingFenced);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpFencedExecutionCallback::getInterfaceVersion(int32_t* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  if (_aidl_cached_version != -1) {
    *_aidl_return = _aidl_cached_version;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777214 /*getInterfaceVersion*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFencedExecutionCallback::getDefaultImpl()) {
    _aidl_status = IFencedExecutionCallback::getDefaultImpl()->getInterfaceVersion(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_version = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
::ndk::ScopedAStatus BpFencedExecutionCallback::getInterfaceHash(std::string* _aidl_return) {
  binder_status_t _aidl_ret_status = STATUS_OK;
  ::ndk::ScopedAStatus _aidl_status;
  const std::lock_guard<std::mutex> lock(_aidl_cached_hash_mutex);
  if (_aidl_cached_hash != "-1") {
    *_aidl_return = _aidl_cached_hash;
    _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
    return _aidl_status;
  }
  ::ndk::ScopedAParcel _aidl_in;
  ::ndk::ScopedAParcel _aidl_out;

  _aidl_ret_status = AIBinder_prepareTransaction(asBinder().get(), _aidl_in.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AIBinder_transact(
    asBinder().get(),
    (FIRST_CALL_TRANSACTION + 16777213 /*getInterfaceHash*/),
    _aidl_in.getR(),
    _aidl_out.getR(),
    0
    #ifdef BINDER_STABILITY_SUPPORT
    | FLAG_PRIVATE_LOCAL
    #endif  // BINDER_STABILITY_SUPPORT
    );
  if (_aidl_ret_status == STATUS_UNKNOWN_TRANSACTION && IFencedExecutionCallback::getDefaultImpl()) {
    _aidl_status = IFencedExecutionCallback::getDefaultImpl()->getInterfaceHash(_aidl_return);
    goto _aidl_status_return;
  }
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_ret_status = AParcel_readStatusHeader(_aidl_out.get(), _aidl_status.getR());
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  if (!AStatus_isOk(_aidl_status.get())) goto _aidl_status_return;
  _aidl_ret_status = ::ndk::AParcel_readData(_aidl_out.get(), _aidl_return);
  if (_aidl_ret_status != STATUS_OK) goto _aidl_error;

  _aidl_cached_hash = *_aidl_return;
  _aidl_error:
  _aidl_status.set(AStatus_fromStatus(_aidl_ret_status));
  _aidl_status_return:
  return _aidl_status;
}
// Source for BnFencedExecutionCallback
BnFencedExecutionCallback::BnFencedExecutionCallback() {}
BnFencedExecutionCallback::~BnFencedExecutionCallback() {}
::ndk::SpAIBinder BnFencedExecutionCallback::createBinder() {
  AIBinder* binder = AIBinder_new(_g_aidl_android_hardware_neuralnetworks_IFencedExecutionCallback_clazz, static_cast<void*>(this));
  #ifdef BINDER_STABILITY_SUPPORT
  AIBinder_markVintfStability(binder);
  #endif  // BINDER_STABILITY_SUPPORT
  return ::ndk::SpAIBinder(binder);
}
::ndk::ScopedAStatus BnFencedExecutionCallback::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = IFencedExecutionCallback::version;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus BnFencedExecutionCallback::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = IFencedExecutionCallback::hash;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
// Source for IFencedExecutionCallback
const char* IFencedExecutionCallback::descriptor = "android.hardware.neuralnetworks.IFencedExecutionCallback";
IFencedExecutionCallback::IFencedExecutionCallback() {}
IFencedExecutionCallback::~IFencedExecutionCallback() {}


std::shared_ptr<IFencedExecutionCallback> IFencedExecutionCallback::fromBinder(const ::ndk::SpAIBinder& binder) {
  if (!AIBinder_associateClass(binder.get(), _g_aidl_android_hardware_neuralnetworks_IFencedExecutionCallback_clazz)) { return nullptr; }
  std::shared_ptr<::ndk::ICInterface> interface = ::ndk::ICInterface::asInterface(binder.get());
  if (interface) {
    return std::static_pointer_cast<IFencedExecutionCallback>(interface);
  }
  return ::ndk::SharedRefBase::make<BpFencedExecutionCallback>(binder);
}

binder_status_t IFencedExecutionCallback::writeToParcel(AParcel* parcel, const std::shared_ptr<IFencedExecutionCallback>& instance) {
  return AParcel_writeStrongBinder(parcel, instance ? instance->asBinder().get() : nullptr);
}
binder_status_t IFencedExecutionCallback::readFromParcel(const AParcel* parcel, std::shared_ptr<IFencedExecutionCallback>* instance) {
  ::ndk::SpAIBinder binder;
  binder_status_t status = AParcel_readStrongBinder(parcel, binder.getR());
  if (status != STATUS_OK) return status;
  *instance = IFencedExecutionCallback::fromBinder(binder);
  return STATUS_OK;
}
bool IFencedExecutionCallback::setDefaultImpl(const std::shared_ptr<IFencedExecutionCallback>& impl) {
  // Only one user of this interface can use this function
  // at a time. This is a heuristic to detect if two different
  // users in the same process use this function.
  assert(!IFencedExecutionCallback::default_impl);
  if (impl) {
    IFencedExecutionCallback::default_impl = impl;
    return true;
  }
  return false;
}
const std::shared_ptr<IFencedExecutionCallback>& IFencedExecutionCallback::getDefaultImpl() {
  return IFencedExecutionCallback::default_impl;
}
std::shared_ptr<IFencedExecutionCallback> IFencedExecutionCallback::default_impl = nullptr;
::ndk::ScopedAStatus IFencedExecutionCallbackDefault::getExecutionInfo(::aidl::android::hardware::neuralnetworks::Timing* /*out_timingLaunched*/, ::aidl::android::hardware::neuralnetworks::Timing* /*out_timingFenced*/, ::aidl::android::hardware::neuralnetworks::ErrorStatus* /*_aidl_return*/) {
  ::ndk::ScopedAStatus _aidl_status;
  _aidl_status.set(AStatus_fromStatus(STATUS_UNKNOWN_TRANSACTION));
  return _aidl_status;
}
::ndk::ScopedAStatus IFencedExecutionCallbackDefault::getInterfaceVersion(int32_t* _aidl_return) {
  *_aidl_return = 0;
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::ScopedAStatus IFencedExecutionCallbackDefault::getInterfaceHash(std::string* _aidl_return) {
  *_aidl_return = "";
  return ::ndk::ScopedAStatus(AStatus_newOk());
}
::ndk::SpAIBinder IFencedExecutionCallbackDefault::asBinder() {
  return ::ndk::SpAIBinder();
}
bool IFencedExecutionCallbackDefault::isRemote() {
  return false;
}
}  // namespace neuralnetworks
}  // namespace hardware
}  // namespace android
}  // namespace aidl
