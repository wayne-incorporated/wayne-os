# We disable vt cursors by default on the kernel command line
# (so that it doesn't flash when doing boot splash and such).
#
# Re-enable it when launching a login shell.  This should only
# happen when logging in via vt or crosh or ssh and those are
# all fine.  Login shells shouldn't get launched normally.

# Since busybox doesn't have setterm we'll use the ANSI escape sequence instead
# http://en.wikipedia.org/wiki/ANSI_escape_code
printf "\033[?25h\033[?0c" # setterm -cursor on
