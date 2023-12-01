# ChromsOS swap management service

`swap_management` is a service for handling swap configuration and
performing privileged actions on behalf of less-privileged components.
The D-Bus service is registered under Upstart. Upstart triggers the
service once a D-Bus message is sent. The service terminates if no new
requests happen before the timeout.
