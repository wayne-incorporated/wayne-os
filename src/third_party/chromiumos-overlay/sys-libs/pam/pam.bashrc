# Force pam to use -j1 since it can flake.
# http://crbug.com/1042875

cros_pre_src_compile_pam_serial() {
	export MAKEOPTS+=" -j1"
}
