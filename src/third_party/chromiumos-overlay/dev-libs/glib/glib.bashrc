# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# gresource tool is used to debug ELF files that use GResource to store blobs
# in the binary file.
# glib-mkenums is a small tool to parse C code and generate enum descriptions in
# text format, used to produce C code that contains enum values as strings.
# Install them only on the host.
if [[ $(cros_target) != "cros_host" ]]; then
	glib_mask="
		/usr/bin/gresource
		/usr/bin/glib-mkenums
	"
	PKG_INSTALL_MASK+=" ${glib_mask}"
	INSTALL_MASK+=" ${glib_mask}"
	unset glib_mask
fi
