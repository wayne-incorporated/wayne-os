# faced (Face Authentication Daemon)

This daemon is intended to provide a face authentication API to ChromeOS.
The daemon itself does not perform the authentication but delegates to another
service for the decision.

## TODO

 * Add Mojo API for enrollment and authentication sessions
 * Add UMA reporting
 * Integrate with face authentication provider
