This package is modified from upstream Gentoo to bootstrap against the previous
8.6.5 version already present in our SDK instead of a binary package of itself.
The upstream binpkgs are linked against ncurses6 and are not compatible with the
libraries in the CrOS SDK.

If we eventually upgrade the SDK to include ncurses6 (and possibly other
libraries the upstream binpkg is linked against), this could be moved back to
portage-stable without preserving the local modifications.
