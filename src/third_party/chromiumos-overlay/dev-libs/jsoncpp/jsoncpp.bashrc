# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(deymo): Patch src/lib_json/json_value.cpp to make JSON_FAIL_MESSAGE
# call assert() instead of throwing an exception when exceptions are disabled.
# crbug.com/993471: Define JSON_USE_INT64_DOUBLE_CONVERSION to avoid
# -Wimplicit-int-float-conversion warnings, PR sent at
# https://github.com/open-source-parsers/jsoncpp/pull/1002.
cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
	# TODO: Remove the define after https://github.com/open-source-parsers/jsoncpp/pull/1002
	# is merged upstream.
	export CPPFLAGS+=" -DJSON_USE_INT64_DOUBLE_CONVERSION"
}
