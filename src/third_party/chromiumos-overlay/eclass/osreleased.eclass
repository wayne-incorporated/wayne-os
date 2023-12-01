# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# $Header: $

inherit eutils

# @ECLASS: osreleased.eclass
# @MAINTAINER:
# Chromium OS build team;
# @BUGREPORTS:
# Please report bugs via http://crbug.com/new (with label Build)
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for setting fields in /etc/os-release.d/

# @FUNCTION: do_osrelease_field
# @USAGE: <field_name> <field_value>
# @DESCRIPTION:
# Creates a file named /etc/os-release.d/<file_name> containing <field_value>.
# All files in os-release.d will be combined to create /etc/os-release when
# building the image.
do_osrelease_field() {
	[[ $# -eq 2 && -n $1 && -n $2 ]] || die "Usage: ${FUNCNAME} <field_name> <field_value>"
	local namevalidregex="[_A-Z]+"
	local valuevalidregex="[^\n]+"

	local field_name="$1"
	local field_value="$2"

	local filtered_name=$(echo "${field_name}" |\
		LC_ALL=C sed -r "s:${namevalidregex}::")
	local number_lines=$(echo "${field_value}" | wc -l)
	if [[ -n "${filtered_name}" ]]; then
		die "Invalid input. Field name must satisfy: ${validregex}"
	fi
	if [[ "${number_lines}" != "1" ]]; then
		die "Invalid input. Field value must not contain new lines."
	fi
	dodir /etc/os-release.d

	local field_file="${D}/etc/os-release.d/${field_name}"
	[[ -e ${field_file} ]] && die "The field ${field_name} has already been set!"
	echo "${field_value}" > "${field_file}" || \
		die "creating ${os_release} failed!"
}

# @FUNCTION: dometricsproductid
# @USAGE: <product_id>
# @DESCRIPTION:
# Sets the GOOGLE_METRICS_PRODUCT_ID field in /etc/os-release.d/;
# GOOGLE_METRICS_PRODUCT_ID should be a positive integer, matching the product
# id defined by the UMA backend protobuf (chrome_user_metrics_extension.proto).
# This product id will be used by chromeos-base/metrics to report metrics when
# the metrics_uploader USE flag is set.
# @CODE
# dometricsproductid 12
# @CODE
# will write 12 in /etc/os-release.d/GOOGLE_METRICS_PRODUCT_ID.
dometricsproductid() {
	[[ $# -eq 1 && -n $1 ]] || die "Usage: ${FUNCNAME} <product_id>"
	local product_id="$1"
	[[ -z ${product_id//[0-9]} ]] || die "The product id must be a number."

	do_osrelease_field "GOOGLE_METRICS_PRODUCT_ID" "${product_id}"
}
