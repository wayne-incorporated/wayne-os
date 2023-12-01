# ARC

ARC is a project to run Play Store apps on Chrome OS.
Each subdirectory contains daemons, helpers and/or tools to run
ARC. See README.md in each subdirectory for details.

arc/container/ is for packages that are used only in P (ARC
container). arc/vm/ is for packages that are used only in R+
(ARCVM). Packages that are both for P and R+ such as
mount-passthrough/ and keymaster/ can live in arc/.
