/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef LIBCONTAINER_LIBCONTAINER_H_
#define LIBCONTAINER_LIBCONTAINER_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/types.h>

#include <brillo/brillo_export.h>
#include <libminijail.h>

#ifdef __cplusplus
extern "C" {
#endif

struct container_config;

/* Create a container config. */
BRILLO_EXPORT struct container_config* container_config_create(void);

/* Destroy a config create with container_config_create. */
BRILLO_EXPORT void container_config_destroy(struct container_config* c);

/* config_root - Path to the root of the container itself. */
BRILLO_EXPORT int container_config_config_root(struct container_config* c,
                                               const char* config_root);

/* Get the configured container root path. */
BRILLO_EXPORT const char* container_config_get_config_root(
    const struct container_config* c);

/* rootfs - Path to the root of the container's filesystem. */
BRILLO_EXPORT int container_config_rootfs(struct container_config* c,
                                          const char* rootfs);

/* Get the configured rootfs path. */
BRILLO_EXPORT const char* container_config_get_rootfs(
    const struct container_config* c);

/* rootfs_mount_flags - Flags that will be passed to the mount() call when
 * mounting the root of the container's filesystem. */
BRILLO_EXPORT void container_config_rootfs_mount_flags(
    struct container_config* c, unsigned long flags);

/* Get the configured rootfs mount() flags. */
BRILLO_EXPORT unsigned long container_config_get_rootfs_mount_flags(
    const struct container_config* c);

/* runfs - Path to where the container filesystem has been mounted. */
BRILLO_EXPORT int container_config_premounted_runfs(struct container_config* c,
                                                    const char* runfs);

/* Get the pre-mounted runfs path. */
BRILLO_EXPORT const char* container_config_get_premounted_runfs(
    const struct container_config* c);

/* The pid of the program will be written here. */
BRILLO_EXPORT int container_config_pid_file(struct container_config* c,
                                            const char* path);

/* Get the pid file path. */
BRILLO_EXPORT const char* container_config_get_pid_file(
    const struct container_config* c);

/* The program to run and args, e.g. "/sbin/init", "--second-stage". */
BRILLO_EXPORT int container_config_program_argv(struct container_config* c,
                                                const char** argv,
                                                size_t num_args);

/* Get the number of command line args for the program to be run. */
BRILLO_EXPORT size_t
container_config_get_num_program_args(const struct container_config* c);

/* Get the program argument at the given index. */
BRILLO_EXPORT const char* container_config_get_program_arg(
    const struct container_config* c, size_t index);

/* Sets/Gets the uid the container will run as. */
BRILLO_EXPORT void container_config_uid(struct container_config* c, uid_t uid);
BRILLO_EXPORT uid_t container_config_get_uid(const struct container_config* c);

/* Mapping of UIDs in the container, e.g. "0 100000 1024" */
BRILLO_EXPORT int container_config_uid_map(struct container_config* c,
                                           const char* uid_map);

/* Sets/Gets the gid the container will run as. */
BRILLO_EXPORT void container_config_gid(struct container_config* c, gid_t gid);
BRILLO_EXPORT gid_t container_config_get_gid(const struct container_config* c);

/* Mapping of GIDs in the container, e.g. "0 100000 1024" */
BRILLO_EXPORT int container_config_gid_map(struct container_config* c,
                                           const char* gid_map);

/* Sets the additional gids the container will run as. */
BRILLO_EXPORT void container_config_additional_gids(struct container_config* c,
                                                    const gid_t* gids,
                                                    size_t num_gids);

/* Alt-Syscall table to use or NULL if none. */
BRILLO_EXPORT int container_config_alt_syscall_table(
    struct container_config* c, const char* alt_syscall_table);

/* Add a runtime limit for the contained process. */
BRILLO_EXPORT int container_config_add_rlimit(struct container_config* c,
                                              int type,
                                              rlim_t cur,
                                              rlim_t max);

/*
 * Add a filesystem to mount in the new VFS namespace.
 *
 * c - The container config in which to add the mount.
 * source - Mount source, e.g. "tmpfs" or "/data".
 * destination - Mount point in the container, e.g. "/dev".
 * type - Mount type, e.g. "tmpfs", "selinuxfs", or "devpts".
 * data - Mount data for extra options, e.g. "newinstance" or "ptmxmode=0000".
 * verity - dm-verity options (if used).
 * flags - Mount flags as defined in mount(2).
 * uid - uid to chown mount point to if created.
 * gid - gid to chown mount point to if created.
 * mode - Permissions of mount point if created.
 * mount_in_ns - True if mount should happen in the process' vfs namespace.
 * create - If true, create mount destination if it doesn't exist.
 * loopback - If true, set up a loopback device and mount that.
 */
BRILLO_EXPORT int container_config_add_mount(struct container_config* c,
                                             const char* name,
                                             const char* source,
                                             const char* destination,
                                             const char* type,
                                             const char* data,
                                             const char* verity,
                                             int flags,
                                             int uid,
                                             int gid,
                                             int mode,
                                             int mount_in_ns,
                                             int create,
                                             int loopback);

/*
 * Add a device cgroup permission.
 *
 * c - The container config in which to add the mount.
 * allow - If true allow access to the specified r/w/m.
 * type - 'c', 'b', or 'a' for char, block, or all respectively.
 * major - Major device number.
 * minor - Minor device number.
 * read - If true set reading of device to |allow|.
 * write - If true set writing of device to |allow|.
 * modify - If true set modifying of device to |allow|.
 */
BRILLO_EXPORT int container_config_add_cgroup_device(struct container_config* c,
                                                     int allow,
                                                     char type,
                                                     int major,
                                                     int minor,
                                                     int read,
                                                     int write,
                                                     int modify);

/*
 * Add a device node to create.
 *
 * c - The container config in which to add the mount.
 * type - 'c' or 'b' for char or block respectively.
 * path - Where to mknod, "/dev/zero".
 * fs_permissions - Permissions to set on the node.
 * major - Major device number.
 * minor - Minor device number.
 * copy_major - Overwrite major with the major of the existing device node.  If
 *   this is true major will be copied from an existing node.  The |major| param
 *   should be set to -1 in this case.
 * copy_minor - Overwrite minor with the minor of the existing device node.  If
 *   this is true minor will be copied from an existing node.  The |minor| param
 *   should be set to -1 in this case.
 * uid - User to own the device.
 * gid - Group to own the device.
 * read_allowed - If true allow reading from the device via "devices" cgroup.
 * write_allowed - If true allow writing to the device via "devices" cgroup.
 * modify_allowed - If true allow creation of the device via "devices" cgroup.
 */
BRILLO_EXPORT int container_config_add_device(struct container_config* c,
                                              char type,
                                              const char* path,
                                              int fs_permissions,
                                              int major,
                                              int minor,
                                              int copy_major,
                                              int copy_minor,
                                              int uid,
                                              int gid,
                                              int read_allowed,
                                              int write_allowed,
                                              int modify_allowed);

/* Set the CPU shares cgroup param for container. */
BRILLO_EXPORT int container_config_set_cpu_shares(struct container_config* c,
                                                  int shares);

/* Set the CFS CPU cgroup params for container. */
BRILLO_EXPORT int container_config_set_cpu_cfs_params(
    struct container_config* c, int quota, int period);

/* Set the RT CPU cgroup params for container. */
BRILLO_EXPORT int container_config_set_cpu_rt_params(struct container_config* c,
                                                     int rt_runtime,
                                                     int rt_period);

BRILLO_EXPORT int container_config_get_cpu_shares(struct container_config* c);
BRILLO_EXPORT int container_config_get_cpu_quota(struct container_config* c);
BRILLO_EXPORT int container_config_get_cpu_period(struct container_config* c);
BRILLO_EXPORT int container_config_get_cpu_rt_runtime(
    struct container_config* c);
BRILLO_EXPORT int container_config_get_cpu_rt_period(
    struct container_config* c);

/* Set core scheduling policy to disable sibling core sharing. */
BRILLO_EXPORT int container_config_set_core_sched(struct container_config* c,
                                                  int enable);

/*
 * Configure the owner of cgroups created for the container.
 *
 * This is needed so the container's cgroup namespace rootdir is accessible
 * inside the container.
 *
 * cgroup_parent - Parent directory under which to create the cgroup.
 * cgroup_owner - The uid that should own the cgroups that are created.
 * cgroup_group - The gid that should own the cgroups that are created.
 */
BRILLO_EXPORT int container_config_set_cgroup_parent(struct container_config* c,
                                                     const char* parent,
                                                     uid_t cgroup_owner,
                                                     gid_t cgroup_group);

/* Get the parent cgroup directory from the config.  Here for UT only. */
BRILLO_EXPORT const char* container_config_get_cgroup_parent(
    struct container_config* c);

/* Set namespaces to be used by the container. */
BRILLO_EXPORT int container_config_namespaces(struct container_config* c,
                                              const char** namespaces,
                                              size_t num_ns);

/* Get the number of namespaces to enter. */
BRILLO_EXPORT size_t
container_config_get_num_namespaces(const struct container_config* c);

/* Get the namespace at the given index. */
BRILLO_EXPORT bool container_config_has_namespace(
    const struct container_config* c, const char* ns);

/*
 * Configures the container so that any FDs open in the parent process are still
 * visible to the child.  Useful for apps that need stdin/stdout/stderr.  Use
 * with caution to avoid leaking other FDs into the namespaced app.
 */
BRILLO_EXPORT void container_config_keep_fds_open(struct container_config* c);

/*
 * Sets the capability mask of the container to |capmask|. If |ambient| is 1 it
 * will additionally set the ambient capability set.
 */
BRILLO_EXPORT void container_config_set_capmask(struct container_config* c,
                                                uint64_t capmask,
                                                int ambient);

/*
 * Skips settings the securebits in |securebits_skip_mask| when restricting
 * capabilities. This is only used when container_config_set_capmask() is used.
 */
BRILLO_EXPORT void container_config_set_securebits_skip_mask(
    struct container_config* c, uint64_t securebits_skip_mask);

/*
 * Sets whether the container's entry point should run as init. An init process
 * is responsible for setting up certain paths within the container (such as
 * /proc) and performing explicit reaping of zombie processes. The container
 * will also be torn down if the init process is killed.
 * The default is true.
 */
BRILLO_EXPORT void container_config_set_run_as_init(struct container_config* c,
                                                    int run_as_init);

/*
 * Sets the SELinux context under which the container will run.
 */
BRILLO_EXPORT int container_config_set_selinux_context(
    struct container_config* c, const char* context);

/*
 * Sets a pre-execve hook that is run in the child process just before the
 * container invokes execve(2). If this is used to run a pre-start hook which
 * should run in the caller's context, a synchronization mechanism (such as a
 * pair of pipes or sending messages through a unix domain pipe) should be used
 * to ensure this hook blocks until the pre-start hook finishes running. The
 * file descriptors used to synchronize this can be passed using
 * container_config_inherit_fds().
 */
BRILLO_EXPORT void container_config_set_pre_execve_hook(
    struct container_config* c, int (*hook)(void*), void* payload);

/*
 * Adds a hook that will be run, execve(2)-style. This new process will be run
 * outside the container in the original namespace. Any parameters that are
 * equal to the magic value "$PID" will be replaced with the container's PID. If
 * |pstdin_fd|, |pstdout_fd|, or |pstderr_fd| are set to non-null values, they
 * will contain valid file descriptors that can be used to communicate with the
 * process.
 */
BRILLO_EXPORT int container_config_add_hook(struct container_config* c,
                                            minijail_hook_event_t event,
                                            const char* filename,
                                            const char** argv,
                                            size_t num_args,
                                            int* pstdin_fd,
                                            int* pstdtout_fd,
                                            int* pstderr_fd);

/*
 * Sets the set of file descriptors to inherit.
 */
BRILLO_EXPORT int container_config_inherit_fds(struct container_config* c,
                                               const int* inherited_fds,
                                               size_t inherited_fd_count);

/* Container manipulation. */
struct container;

/*
 * Create a container based on the given config.
 *
 * name - Name of the directory holding the container config files.
 * rundir - Where to build the temporary rootfs.
 */
BRILLO_EXPORT struct container* container_new(const char* name,
                                              const char* rundir);

/* Destroy a container created with container_new. */
BRILLO_EXPORT void container_destroy(struct container* c);

/* Start the container. Returns 0 on success.
 * c - The container to run.
 * config - Details of how the container should be run.
 */
BRILLO_EXPORT int container_start(struct container* c,
                                  struct container_config* config);

/* Get the path to the root of the container. */
BRILLO_EXPORT const char* container_root(struct container* c);

/* Get the pid of the init process in the container. */
BRILLO_EXPORT int container_pid(struct container* c);

/* Wait for the container to exit. Returns 0 on success. */
BRILLO_EXPORT int container_wait(struct container* c);

/* Kill the container's init process, then wait for it to exit. */
BRILLO_EXPORT int container_kill(struct container* c);

/* Dumps the container config. The returned string has to be passed to free()
   when it is no longer needed.
   c - The config to dump.
   sort_vectors - When not 0, the function sorts the list of mount points,
                  devices, and cgroups before dumping to make it easier to
                  compare two dumps side by side.
*/
BRILLO_EXPORT char* container_config_dump(struct container_config* c,
                                          int sort_vectors);

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* LIBCONTAINER_LIBCONTAINER_H_ */
