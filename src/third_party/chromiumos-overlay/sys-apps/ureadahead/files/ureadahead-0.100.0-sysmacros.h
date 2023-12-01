This adds <sys/sysmacros.h> because the
inclusion of <sys/sysmacros.h> by <sys/types.h> is deprecated since
glibc 2.25.

diff -upr a/src/pack.c b/src/pack.c
--- a/src/pack.c
+++ b/src/pack.c
@@ -23,7 +23,7 @@
 # include <config.h>
 #endif /* HAVE_CONFIG_H */
 
-
+#include <sys/sysmacros.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/time.h>
--- a/src/trace.c
+++ b/src/trace.c
@@ -28,6 +28,7 @@
 
 #include <sys/select.h>
 #include <sys/mount.h>
+#include <sys/sysmacros.h>
 #include <sys/types.h>
 #include <sys/mman.h>
 #include <sys/stat.h>
