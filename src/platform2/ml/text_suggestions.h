// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_TEXT_SUGGESTIONS_H_
#define ML_TEXT_SUGGESTIONS_H_

#include <optional>

#include <base/no_destructor.h>
#include <base/scoped_native_library.h>
#include <chromeos/libsuggest/text_suggester_interface.h>

#include "chrome/knowledge/suggest/text_suggester_interface.pb.h"
#include "ml/util.h"

namespace ml {

// A singleton proxy class for the text suggestions DSO.
// Usage:
//   auto* const instance = ml::TextSuggestions::GetInstance();
//   if (instance->GetStatus() == ml::TextSuggestions::Status::kOk) {
//     instance->InitEnvironment();
//     // Generate suggestions here.
//     TextSuggester const checker = instance->CreateTextSuggester();
//     ...
//   } else {
//     // Otherwise, use TextSuggestions::GetStatus() to get the error type.
//     // Maybe return "not installed".
//     ...
//   }

class TextSuggestions {
 public:
  enum class Status {
    kOk = 0,
    kUninitialized = 1,
    kLoadLibraryFailed = 2,
    kFunctionLookupFailed = 3,
    kNotSupported = 4,
  };

  ~TextSuggestions();

  static TextSuggestions* GetInstance();

  // This returns a status specifying whether the library has been
  // successfully initialized or not.
  Status GetStatus() const;

  // Returns whether TextSuggestions are supported.
  static constexpr bool IsTextSuggestionsSupported() {
    return USE_ONDEVICE_TEXT_SUGGESTIONS && !IsAsan();
  }

  // Creates and returns a text suggester which is needed for using the other
  // interfaces. The memory is owned by the user and should be deleted using
  // `DestroyTextSuggester` after usage.
  TextSuggester CreateTextSuggester() const;

  // Load the text suggester models.
  // Returns true if TextSuggester is correctly loaded and initialized.
  // Returns false otherwise.
  bool LoadTextSuggester(
      TextSuggester suggester,
      const chrome_knowledge::MultiWordExperiment& experiment) const;

  // Sends the specified `request` to `suggester`. If the call is successful,
  // `result` (which should not be null) is populated with the text suggester
  // results. Returns true if the call succeeds, otherwise returns false.
  bool GenerateSuggestions(
      TextSuggester suggester,
      const chrome_knowledge::TextSuggesterRequest& request,
      chrome_knowledge::TextSuggesterResult* result) const;

  // Destroys a text suggester created by `CreateTextSuggester`. Must be
  // called if the text suggester will not be used anymore, otherwise
  // there will be memory leak.
  void DestroyTextSuggester(TextSuggester suggester) const;

 private:
  friend class base::NoDestructor<TextSuggestions>;

  // Initialize the text suggestions library
  TextSuggestions();
  TextSuggestions(const TextSuggestions&) = delete;
  TextSuggestions& operator=(const TextSuggestions&) = delete;

  std::optional<base::ScopedNativeLibrary> library_;
  Status status_;

  // Store the interface function pointers
  CreateTextSuggesterFn create_text_suggester_;
  LoadTextSuggesterFn load_text_suggester_;
  SuggestCandidatesFn suggest_candidates_;
  DeleteSuggestCandidatesResultDataFn delete_suggest_candidates_result_data_;
  DestroyTextSuggesterFn destroy_text_suggester_;
};

}  // namespace ml

#endif  // ML_TEXT_SUGGESTIONS_H_
