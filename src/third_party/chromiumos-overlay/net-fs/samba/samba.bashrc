# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Remove unwanted binaries from the image. Only keep net and smbclient.
samba_mask="
	/usr/sbin
	/usr/bin/cifsdd
	/usr/bin/dbwrap_tool
	/usr/bin/dumpmscat
	/usr/bin/eventlogadm
	/usr/bin/findsmb
	/usr/bin/gentest
	/usr/bin/locktest
	/usr/bin/masktest
	/usr/bin/mdsearch
	/usr/bin/mvxattr
	/usr/bin/ndrdump
	/usr/bin/nmblookup
	/usr/bin/ntlm_auth
	/usr/bin/oLschema2ldif
	/usr/bin/pdbedit
	/usr/bin/pidl
	/usr/bin/profiles
	/usr/bin/regdiff
	/usr/bin/regpatch
	/usr/bin/regshell
	/usr/bin/regtree
	/usr/bin/rpcclient
	/usr/bin/samba-tool
	/usr/bin/samba-regedit
	/usr/bin/sharesec
	/usr/bin/smbcacls
	/usr/bin/smbcontrol
	/usr/bin/smbcquotas
	/usr/bin/smbget
	/usr/bin/smbpasswd
	/usr/bin/smbspool
	/usr/bin/smbstatus
	/usr/bin/smbtar
	/usr/bin/smbtree
	/usr/bin/testparm
	/usr/bin/wbinfo
	/usr/lib*/samba/idmap
	/usr/lib*/samba/libidmap-samba4.so
	/usr/lib*/samba/nss_info
	/usr/lib*/samba/vfs/*
	/usr/lib/tmpfiles.d/samba.conf
	/usr/libexec/cups/backend/smb
"
PKG_INSTALL_MASK+=" ${samba_mask}"
INSTALL_MASK+=" ${samba_mask}"
unset samba_mask

# samba does not build with sanitizers, https://crbug.com/841861
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}

# Adds a hook to pre_src_prepare to override the arguments to WAF
# in order to support cross compilation.
cros_pre_src_prepare_cross() {
	case "${ARCH}" in
		"amd64" | "arm" | "arm64")
			cp "${BASHRC_FILESDIR}/${ARCH}_waf_config_answers" "${T}" || die
			local waf="${T}/waf"
			cat<<EOF>"${waf}"
			#!/bin/sh
			# WAF_BINARY must be set from the ebuild.
			exec "${WAF_BINARY}" "\$@" --cross-compile --cross-answers="${T}/${ARCH}_waf_config_answers"
EOF

			chmod a+rx "${waf}"
			WAF_BINARY="${waf}"
			;;
		*)
			die "${P} does not support cross-compiling for ${ARCH}"
			;;
	esac
}
