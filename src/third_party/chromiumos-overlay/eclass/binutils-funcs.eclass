# Copyright 2011 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# $Header: 

# @ECLASS: binutils-funcs.eclass
# @MAINTAINER:
# Raymes Khoury <raymes@google.com>
# @DESCRIPTION:
# Functions to get the paths to binutils installations for gold and for GNU ld.

inherit toolchain-funcs

get_binutils_path() {
	local ld_path=$(readlink -f $(type -p ${1}))
	local binutils_dir=$(dirname ${ld_path})
	echo ${binutils_dir}
}

get_binutils_path_ld() {
	get_binutils_path $(tc-getLD ${1})
}

get_binutils_path_gold() {
	echo $(get_binutils_path_ld ${1})-gold
}
