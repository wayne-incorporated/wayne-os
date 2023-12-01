# crosdns - Hostname resolution service for Chrome OS

Design doc: go/crostini-hostnames

This provides a D-Bus service for set/removing entries from the /etc/hosts
file. Currently it is used by VMs/containers for mapping their hostnames/IPs.
Later this will be expanded to do more hostname resolution/DNS functions.
