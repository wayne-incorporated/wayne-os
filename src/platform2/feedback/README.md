# Feedback Daemon

On Chrome OS, user feedback is usually sent by Chrome. This directory contains
an alternate system for sending feedback that can be used on systems that don't
include Chrome.

It consists of `feedback_daemon` and `feedback_client` executables, and is
compiled into the `chromeos-base/feedback` package.
