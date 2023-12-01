# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-fwupd.eclass
# @MAINTAINER:
# The ChromiumOS Authors
# @BLURB: Unifies logic for installing fwupd firmware files.

if [[ -z ${_CROS_FWUPD_ECLASS} ]]; then
_CROS_FWUPD_ECLASS=1

inherit udev

IUSE="remote"

S="${WORKDIR}"

case "${EAPI:-0}" in
7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

# @ECLASS-VARIABLE: CROS_FWUPD_URL
# @DESCRIPTION:
# Complete URL for package data on our LVFS mirror.
: "${CROS_FWUPD_URL:=gs://chromeos-localmirror/lvfs/}"

# Force archive fetching from the LVFS mirror GS bucket instead of the common CrOS mirror buckets.
# By default, emerge will only fetch archives from our mirrors regardless of SRC_URI settings.
RESTRICT+=" mirror"

# @FUNCTION: _generate_remote_conf
# @DESCRIPTION:
# Unpack fwupd firmware files to create metainfo.xml and remote.conf.
_generate_remote_conf() {
	local file sha1sum sha256sum size

	printf "<?xml version='1.0' encoding='utf-8'?>\n \
		<components origin=\"lvfs\" version=\"0.9\">\n" > ${PN}.metainfo.xml
	for file in ${A}; do
		if [[ ${file} == *.cab ]]; then
			sha1sum=$(sha1sum "${DISTDIR}/${file}" | awk '{print $1}')
			sha256sum=$(sha256sum "${DISTDIR}/${file}" | awk '{print $1}')
			size=$(du -sbL "${DISTDIR}/${file}" | awk '{print $1}')

			cat << EOF > script.sed
s#</release>#\t<location>https://fwupd.org/downloads/${file}</location>\n\
\t<checksum type="sha1" filename="${file}"target="container">${sha1sum}</checksum>\n\
\t<checksum type="sha256" filename="${file}"target="container">${sha256sum}</checksum>\n\
\t<size type="download">${size}</size>\n\
\t</release>#g;/<?xml.*/d;/<artifacts>/,/<\/artifacts>/d;s/^/  /g
EOF
			cabextract -p -F "*.metainfo.xml" "${DISTDIR}"/"${file}" | \
				sed -f script.sed >> ${PN}.metainfo.xml || die
		fi
	done
	printf "</components>\n" >> ${PN}.metainfo.xml
	gzip ${PN}.metainfo.xml

	cat << EOF > ${PN}.conf
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

[fwupd Remote]
Enabled=true
Title=${PN}
Type=local
Keyring=none
MetadataURI=file:///usr/share/fwupd/remotes.d/vendor/${PN}.metainfo.xml.gz
FirmwareBaseURI=https://storage.googleapis.com/chromeos-localmirror/lvfs/
ApprovalRequired=false
EOF
}

# @FUNCTION: cros-fwupd_src_unpack
# @DESCRIPTION:
# Unpack fwupd firmware files.
cros-fwupd_src_unpack() {
	use remote && _generate_remote_conf
}

# @FUNCTION: cros-fwupd_src_install
# @DESCRIPTION:
# Install fwupd firmware files.
cros-fwupd_src_install() {
	local file

	if use remote; then
		insinto /usr/share/fwupd/remotes.d/vendor/
		doins ${PN}.metainfo.xml.gz
		insinto /etc/fwupd/remotes.d/
		doins ${PN}.conf
	else
		insinto /usr/share/fwupd/remotes.d/vendor/firmware
		for file in ${A}; do
			einfo "Installing firmware ${file}"
			doins "${DISTDIR}"/"${file}"
		done
	fi

	# Install udev rules for automatic firmware update.
	local srcdir="${1:-${FILESDIR}}"
	while read -d $'\0' -r file; do
		udev_dorules "${file}"
	done < <(find -H "${srcdir}" -name "*.rules" -maxdepth 1 -mindepth 1 -print0)
}

EXPORT_FUNCTIONS src_unpack src_install

fi
