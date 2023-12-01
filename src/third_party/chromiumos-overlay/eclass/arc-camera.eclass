# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: arc-camera.eclass
# @BLURB: helper eclass for generating camera rules to use cameras under ARC.
# @DESCRIPTION:
# We want to generate camera rules automatically instead of adding the rules for
# every board manually.

inherit udev

# @FUNCTION: arc-camera_gen_and_install_rules
# @DESCRIPTION:
# Read camera_characteristics.conf. Then, generate 50-camera.rules based on
# camera id, vendor id as well as product id, and install the rules.
# The format of configuration file is
# "camera${CAMERA_ID}.module${MODULE_ID}.${ATTRIBUTE}=${VALUE}"
arc-camera_gen_and_install_rules() {
	local config_file="${D}/etc/camera/camera_characteristics.conf"
	local rules_file="${T}/50-camera.rules"

	if [[ ! -f "${config_file}" ]]; then
		die "camera_characteristics.conf doesn't exist"
	fi

	cat <<-EOF > "${rules_file}"
# Add a symbolic link for internal camera so the container can exclude external
# camera if needed.
EOF
	local line
	local -A vid_pid_table symlink_table usb_path_table
	while read -r line; do
		if [[ -z "${line}" || "${line}" == "#"* ]]; then
			continue
		fi
		local camera="${line%%.*}"
		local index="${line%.*}"
		local symlink="${camera/camera/camera-internal}"
		if [[ ${line} == *'usb_vid_pid'* ]]; then
			# ${line} format: camera0.module0.usb_vid_pid=0a1b:2c3d
			local vid_pid="${line#*=}"
			vid_pid_table[${index}]="${vid_pid,,}"
			symlink_table[${index}]="${symlink}"
		elif [[ ${line} == *'usb_path'* ]]; then
			# ${line} format: camera0.module0.usb_path=1-1
			local usb_path="${line#*=}"
			usb_path_table[${index}]="${usb_path}"
			symlink_table[${index}]="${symlink}"
		elif [[ ${line} == *'camera1.lens_facing=1'* ]]; then
			die "Second camera should be front camera"
		fi
	done < "${config_file}"

	local index
	for index in "${!symlink_table[@]}"; do
		local rules=""
		if [[ -n "${vid_pid_table[${index}]}" ]]; then
			rules+="SUBSYSTEM==\"video4linux\", ATTRS{idVendor}==\"\
${vid_pid_table[${index}]:0:4}\", ATTRS{idProduct}==\
\"${vid_pid_table[${index}]:5:4}\""
		fi
		if [[ -n "${usb_path_table[${index}]}" ]]; then
			rules+=", KERNELS==\"${usb_path_table[${index}]}\""
		fi
		rules+=", SYMLINK+=\"${symlink_table[${index}]}\""
		echo "${rules}" >> "${rules_file}"
	done

	udev_dorules ${rules_file}
}
