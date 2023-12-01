# We include an up-to-date version in chromite.
# http://crbug.com/231697
if [[ $(cros_target) == "cros_host" ]]; then
	pax_utils_mask="
		/usr/bin/lddtree
	"
	PKG_INSTALL_MASK+=" ${pax_utils_mask}"
	INSTALL_MASK+=" ${pax_utils_mask}"
	unset pax_utils_mask
fi
