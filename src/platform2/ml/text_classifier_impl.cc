// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/text_classifier_impl.h"

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/debug/leak_annotations.h>
#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>
#include <lang_id/lang-id-wrapper.h>
#include <utils/utf8/unicodetext.h>

#include "ml/mojom/text_classifier.mojom.h"
#include "ml/request_metrics.h"

namespace ml {

namespace {

using ::chromeos::machine_learning::mojom::CodepointSpan;
using ::chromeos::machine_learning::mojom ::
    REMOVED_TextSuggestSelectionRequestPtr;
using ::chromeos::machine_learning::mojom::TextAnnotation;
using ::chromeos::machine_learning::mojom::TextAnnotationPtr;
using ::chromeos::machine_learning::mojom::TextAnnotationRequestPtr;
using ::chromeos::machine_learning::mojom::TextClassifier;
using ::chromeos::machine_learning::mojom::TextEntity;
using ::chromeos::machine_learning::mojom::TextEntityData;
using ::chromeos::machine_learning::mojom::TextEntityDataPtr;
using ::chromeos::machine_learning::mojom::TextEntityPtr;
using ::chromeos::machine_learning::mojom::TextLanguage;
using ::chromeos::machine_learning::mojom::TextLanguagePtr;

constexpr char kTextClassifierModelFilePath[] =
    "/opt/google/chrome/ml_models/"
    "mlservice-model-text_classifier_en-v714_vocab-"
    "with_beginner_words-20220318.fb";

constexpr char kLanguageIdentificationModelFilePath[] =
    "/opt/google/chrome/ml_models/"
    "mlservice-model-language_identification-20190924.smfb";

}  // namespace

bool TextClassifierImpl::Create(
    mojo::PendingReceiver<TextClassifier> receiver) {
  // Attempt to load model.
  auto annotator_model_mmap = std::make_unique<libtextclassifier3::ScopedMmap>(
      kTextClassifierModelFilePath);
  if (!annotator_model_mmap->handle().ok()) {
    LOG(ERROR) << "Failed to load the text classifier model file.";
    return false;
  }

  auto text_classifier_impl = new TextClassifierImpl(
      &annotator_model_mmap, kLanguageIdentificationModelFilePath,
      std::move(receiver));
  if (text_classifier_impl->annotator_ == nullptr ||
      text_classifier_impl->language_identifier_ == nullptr) {
    // Fails to create annotator, return nullptr.
    delete text_classifier_impl;
    return false;
  }

  // In production, `text_classifier_impl` is intentionally leaked, because this
  // model runs in its own process and the model's memory is freed when the
  // process exits. However, when being tested with ASAN, this memory leak
  // causes an error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(text_classifier_impl);

  //  Set the disconnection handler to quit the message loop (i.e. exit the
  //  process) when the connection is gone, because this model is always run in
  //  a dedicated process.
  text_classifier_impl->receiver_.set_disconnect_handler(
      base::BindOnce(&brillo::MessageLoop::BreakLoop,
                     base::Unretained(brillo::MessageLoop::current())));
  return true;
}

TextClassifierImpl::TextClassifierImpl(
    std::unique_ptr<libtextclassifier3::ScopedMmap>* annotator_model_mmap,
    const std::string& langid_model_path,
    mojo::PendingReceiver<TextClassifier> receiver)
    : annotator_(libtextclassifier3::Annotator::FromScopedMmap(
          annotator_model_mmap, nullptr, nullptr)),
      language_identifier_(
          libtextclassifier3::langid::LoadFromPath(langid_model_path)),
      receiver_(this, std::move(receiver)) {}

void TextClassifierImpl::Annotate(TextAnnotationRequestPtr request,
                                  AnnotateCallback callback) {
  RequestMetrics request_metrics("TextClassifier", "Annotate");
  request_metrics.StartRecordingPerformanceMetrics();

  // Parse and set up the options.
  libtextclassifier3::AnnotationOptions option;
  if (request->default_locales) {
    option.locales = request->default_locales.value();
  }
  if (request->reference_time) {
    option.reference_time_ms_utc =
        request->reference_time->ToTimeT() * base::Time::kMillisecondsPerSecond;
  }
  if (request->reference_timezone) {
    option.reference_timezone = request->reference_timezone.value();
  }
  if (request->enabled_entities) {
    option.entity_types.insert(request->enabled_entities.value().begin(),
                               request->enabled_entities.value().end());
  }
  option.detected_text_language_tags =
      request->detected_text_language_tags.value_or("en");
  option.annotation_usecase =
      static_cast<libtextclassifier3::AnnotationUsecase>(
          request->annotation_usecase);

  // Uses the vocab based model.
  option.use_vocab_annotator = true;

  // Trigger dictionary for simple words (see b/222559828).
  option.trigger_dictionary_on_beginner_words =
      request->trigger_dictionary_on_beginner_words;

  // Do the annotation.
  const std::vector<libtextclassifier3::AnnotatedSpan> annotated_spans =
      annotator_->Annotate(request->text, option);

  // Parse the result.
  std::vector<TextAnnotationPtr> annotations;
  for (const auto& annotated_result : annotated_spans) {
    DCHECK(annotated_result.span.second >= annotated_result.span.first);
    std::vector<TextEntityPtr> entities;
    for (const auto& classification : annotated_result.classification) {
      // First, get entity data.
      TextEntityDataPtr entity_data;
      if (classification.collection == "number") {
        entity_data = TextEntityData::NewNumericValue(
            classification.numeric_double_value);
      } else {
        // For the other types, just encode the substring into string_value.
        // TODO(honglinyu): add data extraction for more types when needed
        // and available.
        // Note that the returned indices by annotator is unicode codepoints.
        entity_data = TextEntityData::NewStringValue(
            libtextclassifier3::UTF8ToUnicodeText(request->text, false)
                .UTF8Substring(annotated_result.span.first,
                               annotated_result.span.second));
      }

      // Second, create the entity.
      entities.emplace_back(TextEntity::New(classification.collection,
                                            classification.score,
                                            std::move(entity_data)));
    }
    annotations.emplace_back(TextAnnotation::New(annotated_result.span.first,
                                                 annotated_result.span.second,
                                                 std::move(entities)));
  }

  std::move(callback).Run(std::move(annotations));

  request_metrics.FinishRecordingPerformanceMetrics();
}

void TextClassifierImpl::FindLanguages(const std::string& text,
                                       FindLanguagesCallback callback) {
  RequestMetrics request_metrics("TextClassifier", "FindLanguages");
  request_metrics.StartRecordingPerformanceMetrics();

  const std::vector<std::pair<std::string, float>> languages =
      libtextclassifier3::langid::GetPredictions(language_identifier_.get(),
                                                 text);

  std::vector<TextLanguagePtr> langid_result;
  for (const auto& lang : languages) {
    langid_result.emplace_back(TextLanguage::New(lang.first, lang.second));
  }

  std::move(callback).Run(std::move(langid_result));

  request_metrics.FinishRecordingPerformanceMetrics();
}

void TextClassifierImpl::REMOVED_1(
    REMOVED_TextSuggestSelectionRequestPtr request,
    REMOVED_1Callback callback) {
  NOTIMPLEMENTED();
}

}  // namespace ml
