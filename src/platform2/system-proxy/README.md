# System-proxy

This directory contains the System-proxy service which runs as a HTTP proxy on
Chrome OS and acts as a proxy authenticator at the OS level. Proxy aware system
services and ARC++ apps can connect to System-proxy which will perform the
authentication challenge to the remote proxy server and the connection setup
on behalf of the client.
