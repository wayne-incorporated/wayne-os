Almost the same as upstream with following patches:

1. Remove man dependencies / build
3. New version of patch to avoid writing file into ro partition
	rootdir.patch is added specically for satlab, it changes two
	directories that are hard coded into docker frm /etc/docker
	to /var/run/docker as /etc/docker is a read only partition
	on satlab.