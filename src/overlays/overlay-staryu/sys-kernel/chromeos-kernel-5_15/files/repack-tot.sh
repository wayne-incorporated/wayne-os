#!/bin/bash
#
# Copyright 2023 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

HELP_TEXT=$(cat <<END
This script repacks the kernel squash and updates the ebuild automatically
according to the given patchset url or the patch id.
If the patchset number is unspecified, this script will use the latest
patchset to generate the kernel squash.

Examples:
    bash $0 https://chromium-review.googlesource.com/c/chromiumos/third_party/kernel/+/4480559/1
    bash $0 https://crrev.com/c/4480559/
    bash $0 CL:4480559/1
    bash $0 4480559
END
)

# Board configs
BOARD=staryu
MAJOR=5
MINOR=15
BUGID=279857767

script="$(realpath "${BASH_SOURCE[0]}")"
kernel_dir="${script%overlays*}third_party/kernel/v${MAJOR}.${MINOR}"
ebuild_dir="$(dirname "${script}")/.."
pkg_name="chromeos-kernel-${MAJOR}_${MINOR}"

patch_id=""
patchset=""
base=""
tree=""

info() {
  echo -e "\e[1;32m$*\e[0m"
}

generate_new_squash() {
  info "Running \`git fetch cros\` in ${kernel_dir}..."

  pushd "${kernel_dir}" 1>/dev/null
  git fetch cros

  local patch_info

  patch_info="$(sed -E 's/[^0-9]*(.*[0-9]+).*/\1/' <<< "$1")"
  patch_id="${patch_info%/*}"
  patchset="${patch_info#*/}"

  if [[ "${patch_info}" == "${patchset}" ]]; then
    info "Getting the latest patchset number of CL:${patch_id}..."
    patchset="$(git ls-remote cros "refs/changes/${patch_id: -2}/${patch_id}*" \
      | awk -F/ '{print $5}' | sort -n | tail -n1)"
  fi

  info "Fetching CL:${patch_id}/${patchset}..."
  git fetch \
    "https://chromium.googlesource.com/chromiumos/third_party/kernel" \
    "refs/changes/${patch_id: -2}/${patch_id}/${patchset}"

  base="$(git merge-base "cros/chromeos-${MAJOR}.${MINOR}" FETCH_HEAD)"
  tree="$(git cat-file -p "${base}" | sed -n 's/^tree //p' | head -n 1)"

  info "Generating new squash..."
  git diff --full-index "${base}" FETCH_HEAD > \
    "${ebuild_dir}/files/${BOARD}-tot.patch"

  popd 1>/dev/null

  git add "files/${BOARD}-tot.patch"
}

update_ebuild() {
  info "Updating and upreving ebuild..."

  local ebuild
  local ebuild_name
  local symlink
  local old_base
  local old_tree

  pushd "${ebuild_dir}" 1>/dev/null

  ebuild="$(find "${pkg_name}"*.ebuild -type f)"
  ebuild_name="${ebuild%.ebuild}"

  old_base="$(grep CROS_WORKON_COMMIT "${ebuild}" | cut -d \" -f 2)"
  old_tree="$(grep CROS_WORKON_TREE "${ebuild}" | cut -d \" -f 2)"
  sed -i "s/${old_base}/${base}/g" "${ebuild}"
  sed -i "s/${old_tree}/${tree}/g" "${ebuild}"
  git add "${ebuild}"

  # Uprev ebuild symlink to make pre-upload check happy.
  # We'll create the synlink if it does not exist.
  symlink="$(find "${ebuild_name}"-r*.ebuild -type l)" || :

  if [[ -z ${symlink} ]]; then
    info "No symlink to the ebuild, creating a new one..."
    ln -sfT "${ebuild}" "${ebuild_name}-r1.ebuild"
    git add "${ebuild_name}-r1.ebuild"
  else
    local symlink_name="${symlink%.ebuild}"
    local rev="${symlink_name#*${ebuild_name}-r}"
    git mv "${symlink}" "${ebuild_name}-r$((rev + 1)).ebuild"
  fi

  popd 1>/dev/null
}

update_scmversion() {
  info "Updating .scmversion..."

  local old="-CL[0-9]*-v[0-9]*$"
  local new="-CL${patch_id}-v${patchset}"

  sed -i "s/${old}/${new}/g" "${ebuild_dir}/files/scmversion.patch"
  git add files/scmversion.patch
}

commit_change() {
  info "Committing change..."

  local tot_commit_id
  local tot_name

  pushd "${kernel_dir}" 1>/dev/null

  tot_commit_id="$(git log FETCH_HEAD -n 1 --pretty=format:"%h")"
  tot_name="$(git log FETCH_HEAD -n 1 --pretty=format:"%s" | \
    sed -E 's/DO-NOT-SUBMIT: (.*[^\.]).*/\1/' | tr -d '"')"

  popd 1>/dev/null

  pushd "${ebuild_dir}" 1>/dev/null

  local commit_msg
  read -r -d \" commit_msg <<END
${BOARD}: Update ebuild with private patch for kernel ${MAJOR}.${MINOR}

Apply ${tot_name} #${patchset} (CL:${patch_id}/${patchset}, ${tot_commit_id}) on commit ${base:0:13}.

The squash is created by running \`bash $(basename "$0") $1\` which does the following:

  git fetch cros

  git merge-base cros/chromeos-${MAJOR}.${MINOR} ${tot_commit_id}
  > ${base}

  git cat-file -p ${base} | sed -n 's/^tree //p' | head -n 1
  > ${tree}

Diff file is generated via:

  git diff --full-index ${base} ${tot_commit_id} > ${BOARD}-tot.patch

BUG=b:${BUGID}
TEST=cros-workon-${BOARD} stop ${pkg_name}
     emerge-${BOARD} ${pkg_name}
"
END

  git commit -m "${commit_msg}"
  git commit --amend

  popd 1>/dev/null
}

main() {
  if [[ $# != 1 ]]; then
    echo "${HELP_TEXT}"
    exit 0
  fi

  generate_new_squash "$1"
  update_ebuild
  update_scmversion
  commit_change "$1"

  info "Please run \`cros-workon-${BOARD} stop ${pkg_name} &&"\
    "emerge-${BOARD} ${pkg_name}\` in chroot to verify the result."
}

main "$@"

