# Remove ip-up/ip-down 40-dns.sh scripts because these scripts
# modify /etc/resolv.conf, which should only be managed by the
# connection manager (shill). See https://crbug.com/207443.
ppp_scripts_mask="
	/etc/ppp/ip-up.d/40-dns.sh
	/etc/ppp/ip-down.d/40-dns.sh
"
PKG_INSTALL_MASK+=" ${ppp_scripts_mask}"
INSTALL_MASK+=" ${ppp_scripts_mask}"
unset ppp_scripts_mask
