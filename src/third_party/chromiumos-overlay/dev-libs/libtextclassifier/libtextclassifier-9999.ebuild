# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_LOCALNAME=("../platform2" "libtextclassifier")
CROS_WORKON_PROJECT=("chromiumos/platform2" "chromiumos/third_party/libtextclassifier")
CROS_WORKON_EGIT_BRANCH=("main" "master")
CROS_WORKON_DESTDIR=("${S}/platform2" "${S}/platform2/libtextclassifier")
CROS_WORKON_SUBTREE=("common-mk .gn" "")

PLATFORM_SUBDIR="libtextclassifier"

inherit cros-workon platform

DESCRIPTION="Library for classifying text"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/libtextclassifier/"

MODEL_URI=(
	"gs://chromeos-localmirror/distfiles/mlservice-model-language_identification-20190924.smfb"
	"gs://chromeos-localmirror/distfiles/mlservice-model-text_classifier_en-v714_vocab-with_beginner_words-20220318.fb"
)

SRC_URI="${MODEL_URI[*]}"

LICENSE="Apache-2.0"
SLOT="0/${PVR}"
KEYWORDS="~*"
IUSE=""

RDEPEND="
	chromeos-base/chrome-icu:=
	dev-libs/flatbuffers:=
	sci-libs/tensorflow:=
	sys-libs/zlib:=
"

# Because we are moving model files from ml to here, to avoid collisions we
# need to block the older version of ml.
RDEPEND="
	${RDEPEND}
	!<chromeos-base/ml-0.0.1-r369
"

DEPEND="
	${RDEPEND}
	dev-libs/libutf:=
	dev-libs/marisa-aosp:=
"

src_install() {
	platform_src_install

	# Installs the model files.
	insinto /opt/google/chrome/ml_models
	local model_files=( "${MODEL_URI[@]##*/}" )
	local distfile_array=( "${model_files[@]/#/${DISTDIR}/}" )
	doins "${distfile_array[@]}"

	# Installs the library.
	dolib.a "${OUT}/libtextclassifier.a"

	# Installs the header files to /usr/include/libtextclassifier/.
	local header_files=(
		"annotator/annotator.h"
		"annotator/cached-features.h"
		"annotator/contact/contact-engine-dummy.h"
		"annotator/contact/contact-engine.h"
		"annotator/datetime/datetime-grounder.h"
		"annotator/datetime/extractor.h"
		"annotator/datetime/grammar-parser.h"
		"annotator/datetime/parser.h"
		"annotator/datetime/regex-parser.h"
		"annotator/duration/duration.h"
		"annotator/entity-data_generated.h"
		"annotator/experimental/experimental-dummy.h"
		"annotator/experimental/experimental.h"
		"annotator/experimental/experimental_generated.h"
		"annotator/feature-processor.h"
		"annotator/grammar/grammar-annotator.h"
		"annotator/installed_app/installed-app-engine-dummy.h"
		"annotator/installed_app/installed-app-engine.h"
		"annotator/knowledge/knowledge-engine-dummy.h"
		"annotator/knowledge/knowledge-engine-types.h"
		"annotator/knowledge/knowledge-engine.h"
		"annotator/model-executor.h"
		"annotator/model_generated.h"
		"annotator/number/number.h"
		"annotator/person_name/person-name-engine-dummy.h"
		"annotator/person_name/person-name-engine.h"
		"annotator/person_name/person_name_model_generated.h"
		"annotator/pod_ner/pod-ner.h"
		"annotator/pod_ner/pod-ner-dummy.h"
		"annotator/strip-unpaired-brackets.h"
		"annotator/translate/translate.h"
		"annotator/types.h"
		"annotator/vocab/vocab-annotator.h"
		"annotator/vocab/vocab-annotator-dummy.h"
		"annotator/vocab/vocab-annotator-impl.h"
		"annotator/vocab/vocab-level-table.h"
		"annotator/zlib-utils.h"
		"lang_id/common/embedding-network-params.h"
		"lang_id/common/fel/task-context.h"
		"lang_id/common/lite_base/attributes.h"
		"lang_id/common/lite_base/casts.h"
		"lang_id/common/lite_base/compact-logging-levels.h"
		"lang_id/common/lite_base/compact-logging.h"
		"lang_id/common/lite_base/float16.h"
		"lang_id/common/lite_base/integral-types.h"
		"lang_id/common/lite_base/logging.h"
		"lang_id/common/lite_base/macros.h"
		"lang_id/common/lite_strings/stringpiece.h"
		"lang_id/lang-id-wrapper.h"
		"lang_id/lang-id.h"
		"lang_id/model-provider.h"
		"utils/base/arena.h"
		"utils/base/config.h"
		"utils/base/integral_types.h"
		"utils/base/logging.h"
		"utils/base/logging_levels.h"
		"utils/base/macros.h"
		"utils/base/port.h"
		"utils/base/status.h"
		"utils/base/statusor.h"
		"utils/calendar/calendar-common.h"
		"utils/calendar/calendar-icu.h"
		"utils/calendar/calendar.h"
		"utils/codepoint-range.h"
		"utils/codepoint-range_generated.h"
		"utils/container/bit-vector_generated.h"
		"utils/container/bit-vector.h"
		"utils/container/sorted-strings-table.h"
		"utils/container/string-set.h"
		"utils/flatbuffers/flatbuffers.h"
		"utils/flatbuffers/flatbuffers_generated.h"
		"utils/flatbuffers/mutable.h"
		"utils/flatbuffers/reflection.h"
		"utils/grammar/analyzer.h"
		"utils/grammar/evaluated-derivation.h"
		"utils/grammar/parsing/chart.h"
		"utils/grammar/parsing/derivation.h"
		"utils/grammar/parsing/lexer.h"
		"utils/grammar/parsing/matcher.h"
		"utils/grammar/parsing/parser.h"
		"utils/grammar/parsing/parse-tree.h"
		"utils/grammar/semantics/composer.h"
		"utils/grammar/semantics/eval-context.h"
		"utils/grammar/semantics/evaluator.h"
		"utils/grammar/semantics/expression_generated.h"
		"utils/grammar/semantics/value.h"
		"utils/grammar/text-context.h"
		"utils/grammar/rules-utils.h"
		"utils/grammar/rules_generated.h"
		"utils/grammar/types.h"
		"utils/hash/farmhash.h"
		"utils/i18n/language-tag_generated.h"
		"utils/i18n/locale.h"
		"utils/i18n/locale-list.h"
		"utils/intents/intent-config_generated.h"
		"utils/memory/mmap.h"
		"utils/normalization_generated.h"
		"utils/optional.h"
		"utils/resources_generated.h"
		"utils/strings/split.h"
		"utils/strings/stringpiece.h"
		"utils/tensor-view.h"
		"utils/tflite-model-executor.h"
		"utils/token-feature-extractor.h"
		"utils/tokenizer.h"
		"utils/tokenizer_generated.h"
		"utils/utf8/unicodetext.h"
		"utils/utf8/unilib-common.h"
		"utils/utf8/unilib-icu.h"
		"utils/utf8/unilib.h"
		"utils/variant.h"
		"utils/zlib/buffer_generated.h"
		"utils/zlib/tclib_zlib.h"
	)
	local f
	for f in "${header_files[@]}"; do
		insinto "/usr/include/libtextclassifier/${f%/*}"
		if [[ "${f}" == *_generated.h ]]; then
			doins "${OUT}/gen/libtextclassifier/${f}"
		else
			doins "${S}/${f}"
		fi
	done
}
