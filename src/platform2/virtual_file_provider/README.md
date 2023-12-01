# Virtual File Provider

Virtual File Provider is a service which provides file descriptors which forward
access requests to chrome.
From the accessing process's perspective, the file descriptor behaves like a
regular file descriptor (unlike pipe, it's seekable), while actually there is no
real file associated with it.

## Private FUSE file system
To forward access requests on file descriptors, this service implements a FUSE
file system which is only accessible to this service itself.

## D-Bus interface
This service provides two D-Bus methods, GenerateVirtualFileId() and
OpenFileById().

GenerateVirtualFileId() generates and returns a new unique ID, to be used for
file descriptor (FD) creation on the private FUSE file system at a later stage.
For ARCVM, this is achieved by directly issuing open() on the FUSE file system
with the returned ID, whereas for ARC++ container, the FD is created by calling
OpenFileById() below.

When OpenFileById() is called with a unique ID, in the ARC++ container flow, it
creates and returns a seekable FD backed by the FUSE file system.

When the file descriptor created above is being accessed, Virtual File Provider
will send signal to forward the access request to chrome.
