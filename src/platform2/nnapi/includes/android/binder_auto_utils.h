// This code is taken from
// src/aosp/frameworks/native/libs/binder/ndk/include_cpp/android/
//
// This file provides the pieces of the Binder framework
// that are referenced from within the generated AIDL code.
//
// Changes have been made to enable compilation within ChromeOS,
// look for 'NNAPI_CHROMEOS'. ScopedAStatus is also heavily
// modified.
//
// This is done to avoid making changes to the generated
// AIDL code so that we can easily reproduce that code
// if necessary.

/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_auto_utils.h
 * @brief These objects provide a more C++-like thin interface to the binder.
 */

#pragma once

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <utils/Errors.h>

#include <assert.h>

#include <unistd.h>
#include <cstddef>
#include <string>

namespace ndk {

/**
 * Represents one strong pointer to an AIBinder object.
 */
class SpAIBinder {
   public:
    /**
     * Default constructor.
     */
    SpAIBinder() : mBinder(nullptr) {}

    /**
     * Takes ownership of one strong refcount of binder.
     */
    explicit SpAIBinder(AIBinder* binder) : mBinder(binder) {}

    /**
     * Convenience operator for implicitly constructing an SpAIBinder from nullptr. This is not
     * explicit because it is not taking ownership of anything.
     */
    SpAIBinder(std::nullptr_t) : SpAIBinder() {}  // NOLINT(google-explicit-constructor)

    /**
     * This will delete the underlying object if it exists. See operator=.
     */
    SpAIBinder(const SpAIBinder& other) { *this = other; }

    /**
     * This deletes the underlying object if it exists. See set.
     */
    ~SpAIBinder() { set(nullptr); }

    /**
     * This takes ownership of a binder from another AIBinder object but it does not affect the
     * ownership of that other object.
     */
    SpAIBinder& operator=(const SpAIBinder& other) {
        if (this == &other) {
            return *this;
        }
        AIBinder_incStrong(other.mBinder);
        set(other.mBinder);
        return *this;
    }

    /**
     * Takes ownership of one strong refcount of binder
     */
    void set(AIBinder*) {
#if !defined(NNAPI_CHROMEOS)
        AIBinder* old = *const_cast<AIBinder* volatile*>(&mBinder);
        if (old != nullptr) AIBinder_decStrong(old);
        if (old != *const_cast<AIBinder* volatile*>(&mBinder)) {
            __assert(__FILE__, __LINE__, "Race detected.");
        }
        mBinder = binder;
#endif // NNAPI_CHROMEOS (removing binder references)
    }

    /**
     * This returns the underlying binder object for transactions. If it is used to create another
     * SpAIBinder object, it should first be incremented.
     */
    AIBinder* get() const { return mBinder; }

    /**
     * This allows the value in this class to be set from beneath it. If you call this method and
     * then change the value of T*, you must take ownership of the value you are replacing and add
     * ownership to the object that is put in here.
     *
     * Recommended use is like this:
     *   SpAIBinder a;  // will be nullptr
     *   SomeInitFunction(a.getR());  // value is initialized with refcount
     *
     * Other usecases are discouraged.
     *
     */
    AIBinder** getR() { return &mBinder; }

    bool operator!=(const SpAIBinder& rhs) const { return get() != rhs.get(); }
    bool operator<(const SpAIBinder& rhs) const { return get() < rhs.get(); }
    bool operator<=(const SpAIBinder& rhs) const { return get() <= rhs.get(); }
    bool operator==(const SpAIBinder& rhs) const { return get() == rhs.get(); }
    bool operator>(const SpAIBinder& rhs) const { return get() > rhs.get(); }
    bool operator>=(const SpAIBinder& rhs) const { return get() >= rhs.get(); }

   private:
    AIBinder* mBinder = nullptr;
};

namespace impl {

/**
 * This baseclass owns a single object, used to make various classes RAII.
 */
template <typename T, void (*Destroy)(T), T DEFAULT>
class ScopedAResource {
   public:
    /**
     * Takes ownership of t.
     */
    explicit ScopedAResource(T t = DEFAULT) : mT(t) {}

    /**
     * This deletes the underlying object if it exists. See set.
     */
    ~ScopedAResource() { set(DEFAULT); }

    /**
     * Takes ownership of t.
     */
    void set(T t) {
        Destroy(mT);
        mT = t;
    }

    /**
     * This returns the underlying object to be modified but does not affect ownership.
     */
    T get() { return mT; }

    /**
     * This returns the const underlying object but does not affect ownership.
     */
    const T get() const { return mT; }

    /**
     * Release the underlying resource.
     */
    [[nodiscard]] T release() {
        T a = mT;
        mT = DEFAULT;
        return a;
    }

    /**
     * This allows the value in this class to be set from beneath it. If you call this method and
     * then change the value of T*, you must take ownership of the value you are replacing and add
     * ownership to the object that is put in here.
     *
     * Recommended use is like this:
     *   ScopedAResource<T> a; // will be nullptr
     *   SomeInitFunction(a.getR()); // value is initialized with refcount
     *
     * Other usecases are discouraged.
     *
     */
    T* getR() { return &mT; }

    // copy-constructing/assignment is disallowed
    ScopedAResource(const ScopedAResource&) = delete;
    ScopedAResource& operator=(const ScopedAResource&) = delete;

    // move-constructing/assignment is okay
    ScopedAResource(ScopedAResource&& other) noexcept : mT(std::move(other.mT)) {
        other.mT = DEFAULT;
    }
    ScopedAResource& operator=(ScopedAResource&& other) noexcept {
        set(other.mT);
        other.mT = DEFAULT;
        return *this;
    }

   private:
    T mT;
};

}  // namespace impl

/**
 * Convenience wrapper. See AParcel.
 */
class ScopedAParcel : public impl::ScopedAResource<AParcel*, AParcel_delete, nullptr> {
   public:
    /**
     * Takes ownership of a.
     */
    explicit ScopedAParcel(AParcel* a = nullptr) : ScopedAResource(a) {}
    ~ScopedAParcel() {}
    ScopedAParcel(ScopedAParcel&&) = default;
    ScopedAParcel& operator=(ScopedAParcel&&) = default;

    bool operator!=(const ScopedAParcel& rhs) const { return get() != rhs.get(); }
    bool operator<(const ScopedAParcel& rhs) const { return get() < rhs.get(); }
    bool operator<=(const ScopedAParcel& rhs) const { return get() <= rhs.get(); }
    bool operator==(const ScopedAParcel& rhs) const { return get() == rhs.get(); }
    bool operator>(const ScopedAParcel& rhs) const { return get() > rhs.get(); }
    bool operator>=(const ScopedAParcel& rhs) const { return get() >= rhs.get(); }
};


// Heavily modified to not use the binder status interface
class ScopedAStatus {
   public:
    ScopedAStatus(binder_exception_t exceptionCode, int32_t errorCode)
        : exception_(exceptionCode), error_code_(errorCode) {}
    ScopedAStatus(AStatus*) {}
    ScopedAStatus() = default;
    ~ScopedAStatus() {}
    ScopedAStatus(ScopedAStatus&&) = default;
    ScopedAStatus& operator=(ScopedAStatus&&) = default;

    AStatus* get() { return nullptr; }
    AStatus** getR() { return nullptr; }
    void set(AStatus *) {  }

    bool isOk() const { return exception_ == EX_NONE; }
    binder_exception_t getExceptionCode() const { return exception_; }
    int32_t getServiceSpecificError() const {
      return exception_ == EX_SERVICE_SPECIFIC ? error_code_ : android::OK;
    }
    binder_status_t getStatus() const {
      return exception_ == EX_TRANSACTION_FAILED ? error_code_ : STATUS_OK;
    }
    const char* getMessage() const { return ""; }
    std::string getDescription() const { return ""; }

    /**
     * Convenience methods for creating scoped statuses.
     */
    static ScopedAStatus ok() { return ScopedAStatus(); }
    static ScopedAStatus fromExceptionCode(binder_exception_t exception) {
      if (exception == EX_TRANSACTION_FAILED) {
        return ScopedAStatus(exception, STATUS_FAILED_TRANSACTION);
      }
      return ScopedAStatus(exception, android::OK);
    }
    static ScopedAStatus fromExceptionCodeWithMessage(binder_exception_t exception,
                                                      const char* /*message*/) {
      return fromExceptionCode(exception);
    }
    static ScopedAStatus fromServiceSpecificError(int32_t serviceSpecific) {
      return ScopedAStatus(EX_SERVICE_SPECIFIC, serviceSpecific);
    }
    static ScopedAStatus fromServiceSpecificErrorWithMessage(int32_t serviceSpecific,
                                                             const char* /*message*/) {
      return fromServiceSpecificError(serviceSpecific);
    }
    static ScopedAStatus fromStatus(binder_status_t status) {
      ScopedAStatus ret;
      ret.exception_ = (status == STATUS_OK) ? EX_NONE : EX_TRANSACTION_FAILED;
      ret.error_code_ = status;
      return ret;
    }
  private:
    binder_exception_t exception_ = EX_NONE;
    int32_t error_code_ = android::OK;
};

/**
 * Convenience wrapper. See AIBinder_DeathRecipient.
 */
class ScopedAIBinder_DeathRecipient
    : public impl::ScopedAResource<AIBinder_DeathRecipient*,
                                   /*AIBinder_DeathRecipient_delete*/ nullptr,
                                   nullptr> {
   public:
    /**
     * Takes ownership of a.
     */
    explicit ScopedAIBinder_DeathRecipient(AIBinder_DeathRecipient* a = nullptr)
        : ScopedAResource(a) {}
    ~ScopedAIBinder_DeathRecipient() {}
    ScopedAIBinder_DeathRecipient(ScopedAIBinder_DeathRecipient&&) = default;
    ScopedAIBinder_DeathRecipient& operator=(ScopedAIBinder_DeathRecipient&&) = default;
};

/**
 * Convenience wrapper. See AIBinder_Weak.
 */
class ScopedAIBinder_Weak
    : public impl::ScopedAResource<AIBinder_Weak*, AIBinder_Weak_delete, nullptr> {
   public:
    /**
     * Takes ownership of a.
     */
    explicit ScopedAIBinder_Weak(AIBinder_Weak* a = nullptr) : ScopedAResource(a) {}
    ~ScopedAIBinder_Weak() {}
    ScopedAIBinder_Weak(ScopedAIBinder_Weak&&) = default;
    ScopedAIBinder_Weak& operator=(ScopedAIBinder_Weak&&) = default;

    /**
     * See AIBinder_Weak_promote.
     */
    SpAIBinder promote() { return SpAIBinder(AIBinder_Weak_promote(get())); }
};

namespace internal {

static void closeWithError(int fd) {
    if (fd == -1) return;
    int ret = close(fd);
    if (ret != 0) {
#if !defined(NNAPI_CHROMEOS)
        syslog(LOG_ERR, "Could not close FD %d: %s", fd, strerror(errno));
#endif //  NNAPI_CHROMEOS (syslog not defined)
    }
}

}  // namespace internal

/**
 * Convenience wrapper for a file descriptor.
 */
class ScopedFileDescriptor : public impl::ScopedAResource<int, internal::closeWithError, -1> {
   public:
    /**
     * Takes ownership of a.
     */
    ScopedFileDescriptor() : ScopedFileDescriptor(-1) {}
    explicit ScopedFileDescriptor(int a) : ScopedAResource(a) {}
    ~ScopedFileDescriptor() {}
    ScopedFileDescriptor(ScopedFileDescriptor&&) = default;
    ScopedFileDescriptor& operator=(ScopedFileDescriptor&&) = default;

    ScopedFileDescriptor dup() const { return ScopedFileDescriptor(::dup(get())); }

    bool operator!=(const ScopedFileDescriptor& rhs) const { return get() != rhs.get(); }
    bool operator<(const ScopedFileDescriptor& rhs) const { return get() < rhs.get(); }
    bool operator<=(const ScopedFileDescriptor& rhs) const { return get() <= rhs.get(); }
    bool operator==(const ScopedFileDescriptor& rhs) const { return get() == rhs.get(); }
    bool operator>(const ScopedFileDescriptor& rhs) const { return get() > rhs.get(); }
    bool operator>=(const ScopedFileDescriptor& rhs) const { return get() >= rhs.get(); }
};

}  // namespace ndk

/** @} */
