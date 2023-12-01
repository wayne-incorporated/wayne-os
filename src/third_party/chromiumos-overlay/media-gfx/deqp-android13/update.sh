#!/bin/sh

# Copyright 2019-2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

deqp_repo=$1
package_name=$(basename "$PWD")

if [ -z "${deqp_repo}" ]; then
    echo "usage:"
    echo "* first obtain local copy of dEQP repo, for instance"
    echo "  git clone https://android.googlesource.com/platform/external/deqp"
    echo "* then checkout desired branch/tag/commit in VK-GL-CTS, for instance origin/android13-tests-dev"
    echo "* finally run this script inside the chroot"
    echo "  . update.sh <deqp-repo>"
    exit 1
fi

declare -A revisions
declare -A git_repos=(
    [${package_name}]=https://android.googlesource.com/platform/external/deqp/+archive
    [SPIRV-Headers]=https://github.com/KhronosGroup/SPIRV-Headers/archive
    [SPIRV-Tools]=https://github.com/KhronosGroup/SPIRV-Tools/archive
    [glslang]=https://github.com/KhronosGroup/glslang/archive
    [amber]=https://github.com/google/amber/archive
)

for module in "${!git_repos[@]}"; do
    # Pull the git sha1 out of fetch_sources.py
    revision=$(PYTHONPATH=$deqp_repo/external python3 -c "import fetch_sources; \
	print([p for p in fetch_sources.PACKAGES if p.baseDir == '$module'.lower()][0].revision)")

    var=${module/-/_}
    var="MY_${var^^}_COMMIT"
    sed_cmd="${sed_cmd}s/${var}='.*'/${var}='$revision'/; "
    revisions[$module]=$revision
done

# Do the transfers and ebuild update.
revisions[${package_name}]=$(git -C "${deqp_repo}" show-ref -s --head ^HEAD)

sed_cmd="${sed_cmd}s/MY_DEQP_COMMIT='.*'/MY_DEQP_COMMIT='${revisions[${package_name}]}'/;"

for module in "${!git_repos[@]}"; do
    wget --no-clobber ${git_repos[$module]}/${revisions[$module]}.tar.gz -O $module-${revisions[$module]}.tar.gz
    gsutil.py cp -a public-read $module-${revisions[$module]}.tar.gz gs://chromeos-localmirror/distfiles/
done

# Edit ebuild and bump name or revision

now=$(date "+%Y.%m.%d")
old_ebuild=$(git ls-files *.ebuild)

echo old_ebuild: $old_ebuild

if [ "${old_ebuild%-r*.ebuild}" = "${package_name}-${now}" ]; then
    r=$(echo $old_ebuild | sed "s/${package_name}.*-r\([0-9]*\).ebuild/\1/")
    ebuild="${package_name}-$now-r$((r + 1)).ebuild"
    echo bump ebuild revision to: $ebuild
else
    ebuild="${package_name}-$now-r1.ebuild"
    echo bump ebuild date to: $ebuild
fi

git mv "$old_ebuild" "$ebuild"

sed -i -e "$sed_cmd" $ebuild

ebuild $ebuild manifest

git add -u
