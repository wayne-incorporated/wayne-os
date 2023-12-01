# SMB FUSE filesystem

This directory contains a FUSE filesystem for accessing SMB file shares.

It uses libsmbclient from the Samba project to handle the SMB protocol,
and Mojo to communicate with Chrome.
