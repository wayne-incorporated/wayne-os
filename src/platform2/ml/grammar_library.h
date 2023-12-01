// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_GRAMMAR_LIBRARY_H_
#define ML_GRAMMAR_LIBRARY_H_

#include <base/no_destructor.h>
#include <base/scoped_native_library.h>
#include <chromeos/libgrammar/grammar_interface.h>
#include <optional>

#include "chrome/knowledge/grammar/grammar_interface.pb.h"
#include "ml/util.h"

namespace ml {

// A singleton proxy class for the grammar DSO.
// Usage:
//   auto* const instance = ml::GrammarLibrary::GetInstance();
//   if (instance->GetStatus() == ml::GrammarLibrary::Status::kOk) {
//     instance->InitEnvironment();
//     // Do the real grammar check here.
//     GrammarChecker const checker = instance->CreateGrammarChecker();
//     ...
//   } else {
//     // Otherwise, use GrammarLibrary::GetStatus() to get the error type.
//     // Maybe return "not installed".
//     ...
//   }
class GrammarLibrary {
 public:
  enum class Status {
    kOk = 0,
    kUninitialized = 1,
    kLoadLibraryFailed = 2,
    kFunctionLookupFailed = 3,
    kNotSupported = 4,
  };

  ~GrammarLibrary() = default;

  static GrammarLibrary* GetInstance();

  // Get whether the library is successfully initialized.
  // Initially, the status is `Status::kUninitialized` (this value should never
  // be returned).
  // If libgrammar.so can not be loaded, return `kLoadLibraryFailed`. This
  // usually means on-device handwriting is not supported.
  // If the functions can not be successfully looked up, return
  // `kFunctionLookupFailed`.
  // Return `Status::kOk` if everything works fine.
  Status GetStatus() const;

  // Returns whether GrammarLibrary is supported.
  static constexpr bool IsGrammarLibrarySupported() {
    return USE_ONDEVICE_GRAMMAR && !IsAsan();
  }

  // The following public member functions define the interface functions of
  // the libgrammar.so library. Function `DeleteGrammarCheckerResultData` do
  // not need interfaces because the client won't call it.

  // Creates and returns a grammar checker which is needed for using the other
  // interfaces. The memory is owned by the user and should be deleted using
  // `DestroyHandwritingRecognizer` after usage.
  GrammarChecker CreateGrammarChecker() const;

  // Load the grammar checker models.
  // Returns true if GrammarChecker is correctly loaded and initialized.
  // Returns false otherwise.
  bool LoadGrammarChecker(GrammarChecker checker) const;

  // Sends the specified `request` to `checker`, if succeeds, `result` (which
  // should not be null) is populated with the grammar check results.
  // Returns true if succeeds, otherwise returns false.
  bool CheckGrammar(GrammarChecker checker,
                    const chrome_knowledge::GrammarCheckerRequest& request,
                    chrome_knowledge::GrammarCheckerResult* result) const;

  // Destroys the grammar checker created by `CreateGrammarChecker`. Must be
  // called if the grammar checker will not be used anymore, otherwise there
  // will be memory leak.
  void DestroyGrammarChecker(GrammarChecker checker) const;

 private:
  friend class base::NoDestructor<GrammarLibrary>;

  // Initialize the grammar library.
  GrammarLibrary();
  GrammarLibrary(const GrammarLibrary&) = delete;
  GrammarLibrary& operator=(const GrammarLibrary&) = delete;

  std::optional<base::ScopedNativeLibrary> library_;
  Status status_;

  // Store the interface function pointers.
  CreateGrammarCheckerFn create_grammar_checker_;
  LoadGrammarCheckerFn load_grammar_checker_;
  CheckGrammarFn check_grammar_;
  DeleteGrammarCheckerResultDataFn delete_grammar_checker_result_data_;
  DestroyGrammarCheckerFn destroy_grammar_checker_;
};

}  // namespace ml

#endif  // ML_GRAMMAR_LIBRARY_H_
