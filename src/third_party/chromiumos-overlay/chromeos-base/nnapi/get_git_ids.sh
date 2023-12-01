#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This is a little helper script to print out the CROS_WORKON_COMMIT and
# CROS_WORKON_TREE values for the nnapi ebuild that represent the latest
# commits in the various dependent repositories. This is useful when
# uprev'ing the ebuild, since chromeos-base/nnapi is set to
# CROS_WORKON_MANUAL_UPREV

readonly EBUILD_FILE="nnapi-9999.ebuild"

if [[ ! -f "${EBUILD_FILE}" ]]; then
    echo "Please run this script from the dir containing ${EBUILD_FILE}"
    exit 1
fi

# Source to get the variables we need
# shellcheck source=nnapi-9999.ebuild
source "${EBUILD_FILE}" 2> /dev/null

# Get to src root
cd ../../../../ || exit 1

tree_ids=""
commits=""

# Loop through the directories
subtree_ctr=0
for i in "${CROS_WORKON_LOCALNAME[@]}"; do
  cd "${i}" || exit 1

  # Append git commit for current dir
  commit_id=$(git rev-parse HEAD)
  if [[ -n "${commits}" ]]; then
    commits="${commits} \"${commit_id}\""
  else
    commits="\"${commit_id}\""
  fi

  # Append tree id for each subtree.
  subtree=${CROS_WORKON_SUBTREE[${subtree_ctr}]}
  if [[ -n "${subtree}" ]]; then
    for tree in ${subtree}; do
      tree_id=$(git rev-parse HEAD:"${tree}")
      if [[ -n "${tree_ids}" ]]; then
        tree_ids="${tree_ids} \"${tree_id}\""
      else
        tree_ids="\"${tree_id}\""
      fi
    done
  else
    tree_id=$(git rev-parse HEAD:./)
    tree_ids="${tree_ids} \"${tree_id}\""
  fi

  cd - > /dev/null || exit 1
  subtree_ctr=$((subtree_ctr+1))
done

echo "CROS_WORKON_COMMIT=(${commits})"
echo "CROS_WORKON_TREE=(${tree_ids})"