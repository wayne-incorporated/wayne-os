// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides an implementation of the various
// Android C APIs that are referenced from within the
// generated AIDL code. Given our usage of the AIDL
// driver doesn't actually use Binder, these methods are
// never actually called but the linker does require an
// implementation of them.
//
// This is done to avoid making changes to the generated
// AIDL code so that we can easily reproduce that code
// if necessary.

#include <android/binder_ibinder.h>
#include <base/immediate_crash.h>
#include <base/logging.h>
#include <base/notreached.h>

AStatus* AStatus_newOk() {
  // This method is called by getInterfaceVersion and getInterfaceHash within
  // Bn classes which are final and not overridden by the aidl adapter, so we
  // just return nullptr which is handled as OK in ScopedAStatus.
  return nullptr;
}

bool AStatus_isOk(const AStatus*) {
  NOTIMPLEMENTED() << "AStatus_isOk shouldn't get called";
  base::ImmediateCrash();
}

AStatus* AStatus_fromStatus(binder_status_t) {
  NOTIMPLEMENTED() << "AStatus_fromStatus shouldn't get called";
  base::ImmediateCrash();
}

int32_t AParcel_getDataPosition(const AParcel*) {
  NOTIMPLEMENTED() << "AParcel_getDataPosition shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readByteArray(const AParcel*,
                                      void*,
                                      AParcel_byteArrayAllocator) {
  NOTIMPLEMENTED() << "AParcel_readByteArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeByteArray(AParcel*, const int8_t*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeByteArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeFloatArray(AParcel*, const float*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeFloatArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readBoolArray(const AParcel*,
                                      void*,
                                      AParcel_boolArrayAllocator,
                                      AParcel_boolArraySetter) {
  NOTIMPLEMENTED() << "AParcel_readBoolArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readFloatArray(const AParcel*,
                                       void*,
                                       AParcel_floatArrayAllocator) {
  NOTIMPLEMENTED() << "AParcel_readFloatArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readParcelFileDescriptor(const AParcel*, int*) {
  NOTIMPLEMENTED() << "AParcel_readParcelFileDescriptor shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeParcelFileDescriptor(AParcel*, int) {
  NOTIMPLEMENTED() << "AParcel_writeParcelFileDescriptor shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readFloat(const AParcel*, float*) {
  NOTIMPLEMENTED() << "AParcel_readFloat shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeFloat(AParcel*, float) {
  NOTIMPLEMENTED() << "AParcel_writeFloat shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeStrongBinder(AParcel*, AIBinder*) {
  NOTIMPLEMENTED() << "AParcel_writeStrongBinder shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readStrongBinder(const AParcel*, AIBinder**) {
  NOTIMPLEMENTED() << "AParcel_readStrongBinder shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readInt32Array(const AParcel*,
                                       void*,
                                       AParcel_int32ArrayAllocator) {
  NOTIMPLEMENTED() << "AParcel_readInt32Array shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeInt32Array(AParcel*, const int32_t*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeInt32Array shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readStatusHeader(const AParcel*, AStatus**) {
  NOTIMPLEMENTED() << "AParcel_readStatusHeader shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readParcelableArray(const AParcel*,
                                            void*,
                                            AParcel_parcelableArrayAllocator,
                                            AParcel_readParcelableElement) {
  NOTIMPLEMENTED() << "AParcel_readParcelableArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_setDataPosition(const AParcel*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_setDataPosition shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readChar(const AParcel*, char16_t*) {
  NOTIMPLEMENTED() << "AParcel_readChar shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeChar(AParcel*, char16_t) {
  NOTIMPLEMENTED() << "AParcel_writeChar shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeParcelableArray(AParcel*,
                                             const void*,
                                             int32_t,
                                             AParcel_writeParcelableElement) {
  NOTIMPLEMENTED() << "AParcel_writeParcelableArray shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeStatusHeader(AParcel*, const AStatus*) {
  NOTIMPLEMENTED() << "AParcel_writeStatusHeader shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeInt32(AParcel*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeInt32 shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeInt64(AParcel*, int64_t) {
  NOTIMPLEMENTED() << "AParcel_writeInt64 shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readString(const AParcel*,
                                   void*,
                                   AParcel_stringAllocator) {
  NOTIMPLEMENTED() << "AParcel_readString shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readInt64(const AParcel*, int64_t*) {
  NOTIMPLEMENTED() << "AParcel_readInt64 shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readInt32(const AParcel*, int32_t*) {
  NOTIMPLEMENTED() << "AParcel_readInt32 shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readBool(const AParcel*, bool*) {
  NOTIMPLEMENTED() << "AParcel_readBool shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeString(AParcel*, const char*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeString shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_readInt64Array(const AParcel*,
                                       void*,
                                       AParcel_int64ArrayAllocator) {
  NOTIMPLEMENTED() << "AParcel_readInt64Array shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeInt64Array(AParcel*, const int64_t*, int32_t) {
  NOTIMPLEMENTED() << "AParcel_writeInt64Array shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AParcel_writeBool(AParcel*, bool) {
  NOTIMPLEMENTED() << "AParcel_writeBool shouldn't get called";
  base::ImmediateCrash();
}

void AParcel_delete(AParcel*) {
  NOTIMPLEMENTED() << "AParcel_delete shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AIBinder_prepareTransaction(AIBinder*, AParcel**) {
  NOTIMPLEMENTED() << "AIBinder_prepareTransaction shouldn't get called";
  base::ImmediateCrash();
}

void AIBinder_decStrong(AIBinder*) {
  NOTIMPLEMENTED() << "AIBinder_decStrong shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AIBinder_transact(
    AIBinder*, transaction_code_t, AParcel**, AParcel**, binder_flags_t) {
  NOTIMPLEMENTED() << "AIBinder_transact shouldn't get called";
  base::ImmediateCrash();
}

void AIBinder_Weak_delete(AIBinder_Weak*) {
  NOTIMPLEMENTED() << "AIBinder_Weak_delete shouldn't get called";
  base::ImmediateCrash();
}

AIBinder* AIBinder_new(const AIBinder_Class*, void*) {
  NOTIMPLEMENTED() << "AIBinder_new shouldn't get called";
  base::ImmediateCrash();
}

bool AIBinder_associateClass(AIBinder*, const AIBinder_Class*) {
  NOTIMPLEMENTED() << "AIBinder_associateClass shouldn't get called";
  base::ImmediateCrash();
}

bool AIBinder_isRemote(const AIBinder*) {
  NOTIMPLEMENTED() << "AIBinder_isRemote shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AIBinder_dump(AIBinder*, int, const char**, uint32_t) {
  NOTIMPLEMENTED() << "AIBinder_dump shouldn't get called";
  base::ImmediateCrash();
}

void AIBinder_incStrong(AIBinder*) {
  NOTIMPLEMENTED() << "AIBinder_incStrong shouldn't get called";
  base::ImmediateCrash();
}

AIBinder_Class* AIBinder_Class_define(const char*,
                                      AIBinder_Class_onCreate,
                                      AIBinder_Class_onDestroy,
                                      AIBinder_Class_onTransact) {
  NOTIMPLEMENTED() << "AIBinder_Class_define shouldn't get called";
  base::ImmediateCrash();
}

void AIBinder_Class_setOnDump(AIBinder_Class*, AIBinder_onDump) {
  NOTIMPLEMENTED() << "AIBinder_Class_setOnDump shouldn't get called";
  base::ImmediateCrash();
}

binder_status_t AIBinder_ping(AIBinder* /*binder*/) {
  // Just return OK to not fail the aidl vts tests
  return STATUS_OK;
}
