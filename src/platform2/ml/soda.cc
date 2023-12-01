// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <unordered_map>
#include <vector>

#include "ml/soda.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/native_library.h>

namespace ml {

namespace {

}  // namespace

SodaLibrary::SodaLibrary(const base::FilePath& library_path)
    : status_(Status::kUninitialized) {
  // Load the library with an option preferring own symbols. Otherwise the
  // library will try to call, e.g., external tflite, which leads to crash.
  base::NativeLibraryOptions native_library_options;
  base::NativeLibraryLoadError load_error;
  native_library_options.prefer_own_symbols = true;
  library_.emplace(base::LoadNativeLibraryWithOptions(
      library_path, native_library_options, &load_error));
  if (!library_->is_valid()) {
    LOG(ERROR) << "Soda library load error: " << load_error.ToString();
    status_ = Status::kLoadLibraryFailed;
    return;
  }

// Helper macro to look up functions from the library, assuming the function
// pointer type is named as (name+"Fn"), which is the case in
// "libhandwriting/interface.h".
#define ML_SODA_LOOKUP_FUNCTION(function_ptr, name)                    \
  function_ptr =                                                       \
      reinterpret_cast<name##Fn>(library_->GetFunctionPointer(#name)); \
  if (function_ptr == NULL) {                                          \
    status_ = Status::kFunctionLookupFailed;                           \
    return;                                                            \
  }

  ML_SODA_LOOKUP_FUNCTION(create_extended_soda_async_, CreateExtendedSodaAsync);
  ML_SODA_LOOKUP_FUNCTION(delete_extended_soda_async_, DeleteExtendedSodaAsync);
  ML_SODA_LOOKUP_FUNCTION(extended_add_audio_, ExtendedAddAudio);
  ML_SODA_LOOKUP_FUNCTION(extended_soda_stop_, ExtendedSodaStop);
  ML_SODA_LOOKUP_FUNCTION(extended_soda_start_, ExtendedSodaStart);
  ML_SODA_LOOKUP_FUNCTION(extended_soda_mark_done_, ExtendedSodaMarkDone);
#undef ML_SODA_LOOKUP_FUNCTION

  status_ = Status::kOk;
}

SodaLibrary::Status SodaLibrary::GetStatus() const {
  return status_;
}

SodaLibrary* SodaLibrary::GetInstanceAt(const base::FilePath& library_path) {
  static base::NoDestructor<std::unordered_map<base::FilePath, SodaLibrary*>>
      instances;
  auto* const std_map = instances.get();
  auto it = std_map->find(library_path);
  SodaLibrary* instance;
  if (it == std_map->end()) {
    // make a new one!
    instance = new SodaLibrary(library_path);
    std_map->insert({library_path, instance});
  } else {
    instance = it->second;
  }
  return instance;
}

// Extended APIs
void* SodaLibrary::CreateExtendedSodaAsync(
    const ExtendedSodaConfig& config) const {
  DCHECK(status_ == Status::kOk);
  return (*create_extended_soda_async_)(config);
}

void SodaLibrary::DeleteExtendedSodaAsync(
    void* extended_soda_async_handle) const {
  DCHECK(status_ == Status::kOk);
  (*delete_extended_soda_async_)(extended_soda_async_handle);
}

void SodaLibrary::ExtendedAddAudio(void* extended_soda_async_handle,
                                   const std::vector<uint8_t>& audio) const {
  DCHECK(status_ == Status::kOk);
  // audio.data() returns const unsigned char* which is not quite the
  // same. reinterpret_cast for convenience.
  (*extended_add_audio_)(extended_soda_async_handle,
                         reinterpret_cast<const char*>(audio.data()),
                         audio.size());
}

void SodaLibrary::ExtendedSodaStop(void* extended_soda_async_handle) const {
  DCHECK(status_ == Status::kOk);
  (*extended_soda_stop_)(extended_soda_async_handle);
}

void SodaLibrary::ExtendedSodaStart(void* extended_soda_async_handle) const {
  DCHECK(status_ == Status::kOk);
  (*extended_soda_start_)(extended_soda_async_handle);
}

void SodaLibrary::ExtendedSodaMarkDone(void* extended_soda_async_handle) const {
  DCHECK(status_ == Status::kOk);
  (*extended_soda_mark_done_)(extended_soda_async_handle);
}

}  // namespace ml
