// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_SODA_H_
#define ML_SODA_H_

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/no_destructor.h>
#include <base/scoped_native_library.h>
#include <chromeos/libsoda/soda_async_impl.h>

namespace ml {
// A singleton proxy class for the soda DSO.
// Usage:
//   auto* const soda_library = SodaLibrary::GetInstanceAt("path/to/lib.so");
//   if (soda_library->GetStatus() == SodaLibrary::kOk) {
//     // Do the real speech recognition here.
//     auto soda_instance = soda_library->CreateSodaAsync();
//     ...
//   } else {
//     // Otherwise, use SodaLibrary::GetStatus() to get the error type.
//     // Maybe return "not installed".
//     ...
//   }
class SodaLibrary {
 public:
  enum class Status {
    kOk = 0,
    kUninitialized = 1,
    kLoadLibraryFailed = 2,
    kFunctionLookupFailed = 3,
  };

  virtual ~SodaLibrary() = default;

  // Gets an instance by loading the .so at the specified path. The result is
  // cached and reused if the same library_path is passed again to this
  // function.
  static SodaLibrary* GetInstanceAt(const base::FilePath& library_path);

  // Get whether the library is successfully initialized.
  // Initially, the status is `Status::kUninitialized` (this value should never
  // be returned).
  // If libsoda.so can not be loaded, return `kLoadLibraryFailed`. This
  // usually means on-device speech recognition is not supported.
  // If the functions can not be successfully looked up, return
  // `kFunctionLookupFailed`.
  // Return `Status::kOk` if everything works fine.
  Status GetStatus() const;

  // The following public member functions define the interface functions of
  // the libsoda.so library.

  // The extended version APIs
  void* CreateExtendedSodaAsync(const ExtendedSodaConfig& config) const;
  void DeleteExtendedSodaAsync(void* extended_soda_async_handle) const;
  void ExtendedAddAudio(void* extended_soda_async_handle,
                        const std::vector<uint8_t>& audio) const;
  void ExtendedSodaStop(void* extended_soda_async_handle) const;
  void ExtendedSodaStart(void* extended_soda_async_handle) const;
  void ExtendedSodaMarkDone(void* extended_soda_async_handle) const;

 private:
  friend class base::NoDestructor<SodaLibrary>;

  // Initializes the soda library.
  explicit SodaLibrary(const base::FilePath& library_path);
  SodaLibrary(const SodaLibrary&) = delete;
  SodaLibrary& operator=(const SodaLibrary&) = delete;

  std::optional<base::ScopedNativeLibrary> library_;
  Status status_;

  // These pointers are used to store the "extended" interface function
  // pointers. They have more control about when speech starts/stops etc.
  CreateExtendedSodaAsyncFn create_extended_soda_async_;
  DeleteExtendedSodaAsyncFn delete_extended_soda_async_;
  ExtendedAddAudioFn extended_add_audio_;
  ExtendedSodaStopFn extended_soda_stop_;
  ExtendedSodaStartFn extended_soda_start_;
  ExtendedSodaMarkDoneFn extended_soda_mark_done_;
};

}  // namespace ml

#endif  // ML_SODA_H_
