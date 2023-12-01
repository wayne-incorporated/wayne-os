#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
# The base ChromiumOS SDK dir e.g. ~/chromiumos/src
CROS_SRC="$(readlink -f "${SCRIPT_DIR}/../../../../..")"

# shellcheck disable=SC1091
. "${CROS_SRC}/scripts/common.sh" || exit 1

FLAGS_HELP="$(cat <<END
Usage: $(basename "$0") [flags]

This script repacks the kernel ToT squash, updates the ebuild and
generates Git commit with the message template altogether according to the
https://chromium-review.googlesource.com/ CL ID and the patchset number.

If the CL ID is unspecified, the default ID will be used (see flags).
If the patchset number is unspecified, the latest patchset will be used.

Examples:
    # Repack based on the latest patchset from the default CL
    $0
    # Repack based on the latest patchset from https://crrev.com/c/3787742
    $0 --cl 3787742
    # Repack based on the 10th patchset from the default CL
    $0 --ps 10
END
)"

DEFINE_string board 'geralt' \
  "Board to build the kernel on."
DEFINE_string ver '6.1' \
  "Kernel version string, for example '6.1'"
DEFINE_integer bugid 245739330 \
  "Bug ID in the commit message."
DEFINE_integer cl 4259239 \
  "ChromiumOS Gerrit CL ID."
DEFINE_integer ps 0 \
  "Patchset number, 0 for the latest version."

# Parse command line flags
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

KERNEL_DIR="${CROS_SRC}/third_party/kernel/v${FLAGS_ver}"
EBUILD_DIR="${SCRIPT_DIR}/.."
PKG_NAME="chromeos-kernel-${FLAGS_ver/./_}"
base=""
tree=""
cl_commit=""

generate_new_squash() {
  info "Running \`git fetch cros\` in ${KERNEL_DIR}..."

  pushd "${KERNEL_DIR}" 1>/dev/null || die "Couldn't pushd ${KERNEL_DIR}"
  git fetch cros

  if [[ ${FLAGS_ps} == 0 ]]; then
    info "Getting the latest patchset number of https://crrev.com/c/${FLAGS_cl}..."
    FLAGS_ps="$(git ls-remote cros "refs/changes/${FLAGS_cl: -2}/${FLAGS_cl}*" \
      | awk -F/ '{print $5}' | sort -n | tail -n1)"
  fi

  info "Fetching https://crrev.com/c/${FLAGS_cl}/${FLAGS_ps}..."
  git fetch \
    "https://chromium.googlesource.com/chromiumos/third_party/kernel" \
    "refs/changes/${FLAGS_cl: -2}/${FLAGS_cl}/${FLAGS_ps}"

  base="$(git merge-base "cros/chromeos-${FLAGS_ver}" FETCH_HEAD)"
  tree="$(git rev-parse "${base}:")"

  # They are used to generate the commit message later
  cl_commit="$(git rev-parse --short FETCH_HEAD)"
  cl_title="$(git log FETCH_HEAD -n 1 --pretty=format:"%s" | \
    sed -E 's/DO-NOT-SUBMIT: (.*[^\.]).*/\1/' | tr -d '"')"

  info "Generating new squash..."
  git diff --full-index "${base}" FETCH_HEAD > \
    "${EBUILD_DIR}/files/${FLAGS_board}-tot.patch"

  popd 1>/dev/null || die "Couldn't popd"
}

update_ebuild() {
  info "Updating and upreving ebuild..."

  local ebuild
  local ebuild_name
  local symlink
  local old_base
  local old_tree

  pushd "${EBUILD_DIR}" 1>/dev/null || die "Couldn't pushd ${EBUILD_DIR}"

  ebuild="$(find "${PKG_NAME}"*.ebuild -type f)"
  ebuild_name="${ebuild%.ebuild}"

  old_base="$(grep CROS_WORKON_COMMIT "${ebuild}" | cut -d \" -f 2)"
  old_tree="$(grep CROS_WORKON_TREE "${ebuild}" | cut -d \" -f 2)"
  sed -i "/CROS_WORKON_COMMIT/s/${old_base}/${base}/g" "${ebuild}"
  sed -i "/CROS_WORKON_TREE/s/${old_tree}/${tree}/g" "${ebuild}"

  # Uprev ebuild symlink to make pre-upload check happy, and create the symlink
  # if it does not exist.
  symlink="$(find "${ebuild_name}"-r*.ebuild -type l 2>/dev/null)" || :

  if [[ -z ${symlink} ]]; then
    info "No symlink to the ebuild, creating a new one..."
    ln -sfT "${ebuild}" "${ebuild_name}-r1.ebuild"
    git add "${EBUILD_DIR}/${ebuild_name}-r1.ebuild"
  else
    local symlink_name="${symlink%.ebuild}"
    local rev="${symlink_name#*"${ebuild_name}"-r}"
    git mv "${symlink}" "${ebuild_name}-r$((rev + 1)).ebuild"
  fi

  popd 1>/dev/null || die "Couldn't popd"
}

update_scmversion() {
  info "Updating .scmversion..."

  cat > "${EBUILD_DIR}/files/scmversion.patch" <<EOF
diff --git a/.scmversion b/.scmversion
new file mode 100644
index 000000000000..aabbccddeeff
--- /dev/null
+++ b/.scmversion
@@ -0,0 +1 @@
+-CL${FLAGS_cl}-v${FLAGS_ps}
EOF
}

commit_change() {
  info "Committing change..."

  pushd "${EBUILD_DIR}" 1>/dev/null || die "Couldn't pushd ${EBUILD_DIR}"

  git add "${EBUILD_DIR}/${ebuild}"
  git add "${EBUILD_DIR}/files/${FLAGS_board}-tot.patch"
  git add "${EBUILD_DIR}/files/scmversion.patch"

  git commit --edit -m "$(cat <<EOM
${FLAGS_board}: sys-kernel: Update to private kernel ToT #${FLAGS_ps}

Apply ${cl_title} #${FLAGS_ps} (CL:${FLAGS_cl}/${FLAGS_ps}, ${cl_commit})
based on commit ${base:0:12} in ${FLAGS_ver} kernel.

The squash is created by \`$(basename "$0")\` which does the following:

  cd ~/chromiumos/src/third_party/kernel/v${FLAGS_ver}
  git fetch cros

  git merge-base cros/chromeos-${FLAGS_ver} ${cl_commit}
  > ${base:0:12}

  git rev-parse ${base:0:12}:
  > ${tree:0:12}

Diff file is generated via:

  git diff --full-index ${base:0:12} ${cl_commit} > ${FLAGS_board}-tot.patch

Change notes:
  <TODO: Add summary for major changes, or ignore this on trivial ToT rebase>

BUG=b:${FLAGS_bugid}
TEST=cros-workon-${FLAGS_board} stop ${PKG_NAME}
     emerge-${FLAGS_board} ${PKG_NAME}
EOM
)"

  popd 1>/dev/null || die "Couldn't popd"
}

main() {
  generate_new_squash
  update_ebuild
  update_scmversion
  commit_change

  info "Please run \`cros-workon-${FLAGS_board} stop ${PKG_NAME} && " \
    "emerge-${FLAGS_board} ${PKG_NAME}\` in chroot to verify the result."
}

main "$@"
