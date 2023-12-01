#!/bin/bash -e
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Location of where host Clang can be installed
HOST_CLANG_PATH=/usr/bin

# Location to put build artifacts and sysroot for clang
INSTALL_DIR="${HOME}/rv-clang"

# We have to deal with differences in Clang setup, so try to find
# latest available version.
HOST_C_VER=$(for i in "${HOST_CLANG_PATH}"/clang-*; do [[ ${i} =~ ([0-9]+)$ ]] \
               && echo "${BASH_REMATCH[1]}"; done | sort -unr | head -n 1)
HOST_CXX_VER=$(for i in "${HOST_CLANG_PATH}"/clang++-*; do [[ ${i} =~ ([0-9]+)$ ]] \
               && echo "${BASH_REMATCH[1]}"; done | sort -unr | head -n 1)
HOST_CC="${HOST_CLANG_PATH}/clang"
HOST_CXX="${HOST_CLANG_PATH}/clang++"
[[ -n "${HOST_C_VER}" ]] && HOST_CC+="-${HOST_C_VER}"
[[ -n "${HOST_CXX_VER}" ]] && HOST_CXX+="-${HOST_CXX_VER}"
printf 'Using host compilers %s, %s\n' "${HOST_CC}" "${HOST_CXX}"

# This script is in /files directory
FILESDIR=$(realpath .)

# Clang version to build and appropriate patch to enable Dauntless NI
CLANG_VERSION=15
DAUNTLESS_PATCH=$(realpath llvm15-11112022-soteria.patch)
echo DAUNTLESS_PATCH = "${DAUNTLESS_PATCH}"

# Tested commit 154e88af7ec97d9b9f389e55d45bf07108a9a097 (origin/release/15.x)
LLVM=$(realpath ../llvm-project)
echo LLVM = "${LLVM}"
LLVM_GIT=https://github.com/llvm/llvm-project.git

##############################################################
# Download LLVM from upstream, apply Soteria patch
# Globals:
#   LLVM - name of temporary directory for LLVM
# Arguments:
#   $1 - version of Clang to build
#   $2 - appropriate patch to enable Dauntless new instructions
##############################################################
download_clang_sources() {
  local clang_ver="${1}"
  local patch="${2}"
  rm -rf "${LLVM}" || true
  git clone --single-branch -b "release/${clang_ver}.x" "${LLVM_GIT}" "${LLVM}"
  cd "${LLVM}"
  echo Applying patch "${patch}"
  git apply "${patch}"
  cd -
}

##############################################################
# Build Clang and related tools
# Globals:
#   LLVM - name of temporary directory for LLVM
# Arguments:
#   $1 - Install dir
##############################################################
build_clang() {
  local install_dir="${1}"

  "${FILESDIR}/build_clang_toolchain.py" \
    --install-dir="${install_dir}" \
    --llvm-dir="${LLVM}" \
    --include-dir="${FILESDIR}/include" \
    --work-dir="${LLVM}/build"
}

###########################################################################
# Build steps
###########################################################################

download_clang_sources "${CLANG_VERSION}" "${DAUNTLESS_PATCH}"
build_clang "${INSTALL_DIR}"
