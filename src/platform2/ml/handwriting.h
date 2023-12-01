// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_HANDWRITING_H_
#define ML_HANDWRITING_H_

#include <string>

#include <base/no_destructor.h>
#include <base/scoped_native_library.h>
#include <chromeos/libhandwriting/handwriting_interface.h>

#include "chrome/knowledge/handwriting/handwriting_interface.pb.h"
#include "ml/mojom/handwriting_recognizer.mojom.h"
#include "ml/util.h"

namespace ml {
// A singleton proxy class for the handwriting DSO.
// Usage:
//   auto* const hwr_library = HandwritingLibrary::GetInstance();
//   if (hwr_library->GetStatus() == HandwritingLibrary::kOk) {
//     // Do the real handwriting here.
//     recognizer = hwr_library->CreateHandwritingRecognizer();
//     ...
//   } else {
//     // Otherwise, use HandwritingLibrary::GetStatus() to get the error type.
//     // Maybe return "not installed".
//     ...
//   }
class HandwritingLibrary {
 public:
  enum class Status {
    kOk = 0,
    kUninitialized = 1,
    kLoadLibraryFailed = 2,
    kFunctionLookupFailed = 3,
    kNotSupported = 4,
  };

  // Default handwriting directory on rootfs for library and models.
  static constexpr char kHandwritingDefaultInstallDir[] =
      "/opt/google/chrome/ml_models/handwriting";

  // Returns whether HandwritingLibrary is supported.
  static constexpr bool IsHandwritingLibrarySupported() {
    return (IsUseLibHandwritingEnabled() || IsUseLibHandwritingDlcEnabled()) &&
           !IsAsan();
  }

  // Returns whether HandwritingLibrary is supported for unit tests.
  static constexpr bool IsHandwritingLibraryUnitTestSupported() {
    return IsUseLibHandwritingEnabled() && !IsAsan();
  }

  // Returns bool of use.ondevice_handwriting.
  static constexpr bool IsUseLibHandwritingEnabled() {
    return USE_ONDEVICE_HANDWRITING;
  }

  // Returns bool of use.ondevice_handwriting_dlc.
  static constexpr bool IsUseLibHandwritingDlcEnabled() {
    return USE_ONDEVICE_HANDWRITING_DLC;
  }

  // Returns whether LanguagePacks is enabled.
  // Currently it's enabled whenever ondevice_handwriting is.
  static constexpr bool IsUseLanguagePacksEnabled() {
    return USE_ONDEVICE_HANDWRITING;
  }

  // Gets the singleton HandwritingLibrary. The singleton is initialized with
  // `lib_path` on the first call to GetInstance; for the rest of the calls,
  // the `lib_path` is ignored, and the existing singleton is returned.
  // The `lib_path` should be either a path on rootfs or a path returned by
  // DlcService.
  static HandwritingLibrary* GetInstance(
      const std::string& lib_path = kHandwritingDefaultInstallDir);

  // Sets a fake impl of HandwritingLibrary which doesn't dlopen the library.
  // This is only used in fuzzer test.
  static void UseFakeHandwritingLibraryForTesting(
      HandwritingLibrary* fake_handwriting_library);

  // Get whether the library is successfully initialized.
  // Initially, the status is `Status::kUninitialized` (this value should never
  // be returned).
  // If libhandwriting.so can not be loaded, return `kLoadLibraryFailed`. This
  // usually means on-device handwriting is not supported.
  // If the functions can not be successfully looked up, return
  // `kFunctionLookupFailed`.
  // Return `Status::kOk` if everything works fine.
  virtual Status GetStatus() const = 0;

  // The following public member functions define the interface functions of
  // the libhandwriting.so library. Function `InitHandwritingRecognizerLibrary`
  // and `DeleteHandwritingResultData` do not need interfaces because the client
  // won't call it.

  // Creates and returns a handwriting recognizer which is needed for using the
  // other interface. The memory is owned by the user and should be deleted
  // using `DestroyHandwritingRecognizer` after usage.
  virtual HandwritingRecognizer CreateHandwritingRecognizer() const = 0;

  // Loads the models with `spec` which holds the path to the data files of the
  // model (machine learning models, configurations etc.).
  // Returns true if HandwritingRecognizer is correctly loaded and
  // initialized. Returns false otherwise.
  virtual bool LoadHandwritingRecognizer(
      HandwritingRecognizer recognizer,
      chromeos::machine_learning::mojom::HandwritingRecognizerSpecPtr spec)
      const = 0;
  // This method will be deprecated in favor of the one above.
  // TODO(claudiomagni): Remove this method once Language Packs is fully done.
  virtual bool LoadHandwritingRecognizerFromRootFs(
      HandwritingRecognizer recognizer, const std::string& language) const = 0;

  // Sends the specified `request` to `recognizer`, if succeeds, `result` (which
  // should not be null) is populated with the recognition result.
  // Returns true if succeeds, otherwise returns false.
  virtual bool RecognizeHandwriting(
      HandwritingRecognizer recognizer,
      const chrome_knowledge::HandwritingRecognizerRequest& request,
      chrome_knowledge::HandwritingRecognizerResult* result) const = 0;

  // Destroys the handwriting recognizer created by
  // `CreateHandwritingRecognizer`. Must be called if the handwriting recognizer
  // will not be used anymore, otherwise there will be memory leak.
  virtual void DestroyHandwritingRecognizer(
      HandwritingRecognizer recognizer) const = 0;

 protected:
  HandwritingLibrary() = default;
  virtual ~HandwritingLibrary() = default;

 private:
  friend class base::NoDestructor<HandwritingLibrary>;
  FRIEND_TEST(HandwritingLibraryTest, CanLoadLibrary);

  // Currently HandwritingLibrary is supported only when the "sanitizer" is not
  // enabled (see https://crbug.com/1082632).
  static constexpr bool IsAsan() { return __has_feature(address_sanitizer); }
};

}  // namespace ml

#endif  // ML_HANDWRITING_H_
