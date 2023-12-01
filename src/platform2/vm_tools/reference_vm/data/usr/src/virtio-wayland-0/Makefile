
obj-m := virtio_wl.o

# With this we don't need to change the include lines. And we tell it the
# VIRTIO_ID_WL device id, so we only use new source files and don't need any
# modifications to existing headers.
ccflags-y := -I$(PWD)/include -DVIRTIO_ID_WL=63
