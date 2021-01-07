/* 
 * Copyright (c) 2021 ESRLabs
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <asm/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/file.h>
#include <stdint.h>

#include "libmj_netns.h"
#include "util.h"

#define LINEBUF_MAX	128
#define PATTERN_MAX	(LINEBUF_MAX * 2)

#if defined(__ANDROID__)
  #define MKFS		"/system/bin/mkfs.ext4"
#else
  #define MKFS		"/sbin/mkfs.ext4"
#endif

/*
 * The resource container is used to seed the config files
 * during setup and to provide the binaries to launch
 * the VM.
 *
 * The resource container has the following structure:
 * 	bin	executables
 * 	var	config files and initrds
 * At runtime, the resource container must be mounted at /usr/local/share
 *
 * The config files are created from the resource container and
 * customized for each vm. The resulting configs are in the north
 * data directory <datadir>/vm_<subnet>
 * This directory is mounted into the target container at /usr/local/data
 * This directory is also used by firecracker for logfiles and must be writable
 *
 * The resuling dir struct in the target container:
 * 	/usr/local/share/bin 		ronly
 * 		executables
 * 	/usr/local/share/var 	
 * 		initrds and kernel
 *	/usr/local/data/conf		rw
 *		config files
 *	/usr/local/data/run
 *		FC runtime 
 *	/usr/local/data/datafs.img
 *		exported to VM as blkdev
 *
 * Config file templates in the resource container:
 * 	fcconf.json	Firecracker
 * 	vmconf.json	VM and application config
 */


/*
 * Command to setup the socats processes for VM communication
 * and to launch firecracker
 */
#define LAUNCH_CMD	"launchvm"
#define LAUNCH_ARGC	4

/*
 * Mount point in container for resource container
 * The ronly portion is at 'share' and the updated config
 * files and logs are at 'data/conf' and /data/run'
 */
#define CONT_MNTPOINT	"/usr/local"
#define MNT_RONLY	"share"
#define MNT_RW		"data"
#define CONFDIR		"conf"
#define RUNDIR		"run"
#define VM_CONFIG	"vmconf.json"
#define FC_CONFIG	"fcconf.json"

/*
 * Mount point in VM for app container
 */
#define APPCONT_MNTPOINT "/app"

/*
 * Directory structure in data directory during setup:
 * datadir/vm_<subnet>
 */
#define VMDIR		"vm"

/*
 * Filesystem image given to VM for writeable data
 */
#define FS_IMG		"datafs.img"
#define FSIMG_SIZE	(256 * 1024 * 1024)

struct pattern {
	char *token;
	char *replace;
};

/*
 * Update all occurrences of patterns in a line and write the
 * updated line to the destination file
 */
static int replace_write(FILE *dstfile, char *line, struct pattern *pat, int numpat)
{
	char buf1[PATTERN_MAX], buf2[PATTERN_MAX];
	char *src, *dst, *match;
	char *rem;
	int i, len, retval, error = 0;

	src = line;
	dst = buf1;

	for (i = 0 ; i < numpat; i++) {
		match = strstr(src, pat[i].token);
		if (match) {
			len = strlen(pat[i].token);

			/*
			 * Isolate the matched chars in the string
			 */
			*match = '\0';
			rem = match + len ;
			setbufstr(dst, PATTERN_MAX, "%s%s%s", src, pat[i].replace, rem);

			/*
			 * Toggle between the two temp buffers
			 * used to udpate the line
			 */
			src = dst;
			if (dst == buf1)
				dst = buf2;
			else
				dst = buf1;
		}
	}

	retval = fwrite(src, strlen(src), 1, dstfile);
	if (retval == 0) {
		error = EIO;
		warn("Can not write destination output file");
	}

out:
	return error;
}

/*
 * Each VM has it's own directory with all files inside
 * If the directory exists, the file contents will be overwritten
 */
static int verify_dir(char *dir)
{
	struct stat sb;
	int error = 0;

	error = stat(dir, &sb);
	if (error) {
		error = errno;
		if (error != ENOENT) {
			warn("Can not stat %s error %d", dir, error);
			goto out;
		}

		/*
		 * Use 777 so that all UID/GID combos can read/execute
		 */
		error = mkdir(dir, 0777);
		if (error) {
			error = errno;
			warn("Can not create %s error %d", dir, error);
		}

	} else {
		if ((sb.st_mode & S_IFMT) != S_IFDIR) {
			error = EINVAL;
			warn("%s is not a directory", dir);
		}
	}
out:
	info("verified %s error %d", dir, error);
	return error;
}


static int create_fcconf(char *datadir, char *res_mntdir, 
			 char *app_blkdev, char *vtapmac, char *tapdev)
{
	FILE *srcfile = NULL, *dstfile = NULL;
	struct pattern pat[] = {
                { .token = "TAP_MACADDR", .replace = vtapmac},
                { .token = "TAP_DEVNAME", .replace = tapdev},
                { .token = "APP_BLKDEV",  .replace = app_blkdev},
        };
	int numpat = sizeof(pat) / sizeof(struct pattern);
	char linebuf[LINEBUF_MAX];
	char srcname[PATH_MAX];
	char dstname[PATH_MAX];
	int error = 0;

	setstr(srcname, "%s/var/%s", res_mntdir, FC_CONFIG);
	setstr(dstname, "%s/%s/%s", datadir, CONFDIR, FC_CONFIG);

	info("Configuring FC from %s to %s", srcname, dstname);

	srcfile = fopen(srcname, "r");
	if (srcfile == NULL) {
		error = errno;
		warn("Can not open template file %s error %d",
			srcname, error);
		goto out;
	}

	dstfile = fopen(dstname, "w");
	if (dstfile == NULL) {
		error = errno;
		warn("Can not open target conf file %s error %d", 
			dstname, error);
		goto out;
	}

	/*
	 * Match all patterns on each line of the file, and
	 * write the result to our target file
	 */
        while(fgets(linebuf, sizeof(linebuf), srcfile) != NULL) {
                error = replace_write(dstfile, linebuf, pat, numpat);
		if (error)
			break;
	}

out:
	if (srcfile)
		fclose(srcfile);
	if (dstfile)
		fclose(dstfile);

	return error;
}


static int create_vmconf(char *datadir, char *res_mntdir, 
			 char *braddr, char *ipaddr, char *cidr_str,
			 char *init, char *argv_str, char *env_str)
{
	FILE *srcfile = NULL, *dstfile = NULL;
	struct pattern pat[] = {
                { .token = "IPADDR", .replace = ipaddr },
                { .token = "GATEWAY", .replace = braddr},
                { .token = "CIDR", .replace = cidr_str},
                { .token = "INIT", .replace = init},
		{ .token = "ARGS", .replace = argv_str},
		{ .token = "ENV", .replace = env_str},
        };
	char linebuf[LINEBUF_MAX];
	char srcname[PATH_MAX];
	char dstname[PATH_MAX];
	int numpat = sizeof(pat) / sizeof(struct pattern);
	int error = 0;

	setstr(srcname, "%s/var/%s", res_mntdir, VM_CONFIG);
	setstr(dstname, "%s/%s/%s", datadir, CONFDIR, VM_CONFIG);

	info("Configuring VM from %s to %s", srcname, dstname);

	srcfile = fopen(srcname, "r");
	if (srcfile == NULL) {
		error = errno;
		warn("Can not open template file %s error %d",
			srcname, error);
		goto out;
	}

	dstfile = fopen(dstname, "w");
	if (dstfile == NULL) {
		error = errno;
		warn("Can not open target conf file %s error %d", 
			dstname, error);
		goto out;
	}

	/*
	 * Match all patterns on each line of the file, and
	 * write the result to our target file
	 */
        while(fgets(linebuf, sizeof(linebuf), srcfile) != NULL) {
                error = replace_write(dstfile, linebuf, pat, numpat);
		if (error)
			break;
	}

out:
	if (srcfile)
		fclose(srcfile);
	if (dstfile)
		fclose(dstfile);

	return error;
}


/*
 * Setup the mount directories for the VM resource container
 *
 * src:
 * 	<rundir>/resname/ver
 * dst:
 * 	<datadir>/vm_<subnet>
 *
 * RETURNS:
 * 	srcmnt	path to resource container. This is used by
 * 	minijail to set up the mounts into the target container
 */
static int 
setup_resource_mount(char *rundir,
		     char *resname, char *resver, char **srcmnt)
{
	char path[PATH_MAX];
	int error = 0;

	setstr(path, "%s/%s/%s", rundir, resname, resver);
	error = access(path, F_OK); 
	if (error) {
		warn("Can not access resource container %s error %d",
			path, error);
		goto out;
	}

	dupstr((*srcmnt), path);
out:

	return error;
}

static int setup_mntdir(char *parent, int subnet, char **mntdir)
{
	char path[PATH_MAX];
	int error = 0;

	setstr(path, "%s/%s_%d", parent, VMDIR, subnet);
	error = verify_dir(path);
	if (error)
		goto out;

	dupstr((*mntdir), path);
out:
	return error;
}

/*
 * Make sure the target heirarchy exists
 */
static int verify_datadirs(char *datadir)
{
	int error = 0;
	char path[PATH_MAX];

	setstr(path, "%s/%s", datadir, CONFDIR);
	error = verify_dir(path);
	if (error)
		goto out;

	setstr(path, "%s/%s", datadir, RUNDIR);
	error = verify_dir(path);
	if (error)
		goto out;

out:
	return error;
}

static int 
create_conffiles(char *braddr, int subnet, char *tapdev,
	     	 char *res_mntdir, char *datadir, char *app_blkdev, 
	     	 char *init, char *argv[], char *env[])
{
	int error = 0;
	char *vtapmac = NULL, *ipaddr = NULL, *cidr_str = NULL;
	char *argv_str = NULL, *env_str = NULL;
	char appinit[PATH_MAX];

	error = setup_net_vtapmac(subnet, &vtapmac);
	if (error)
		goto out;
	error = setup_net_vmipaddr(braddr, subnet, &ipaddr);
	if (error)
		goto out;
	error = setup_net_cidr(&cidr_str);
	if (error)
		goto out;

	error = expand_argv(&argv_str, argv);
	if (error)
		goto out;
	error = expand_argv(&env_str, env);
	if (error)
		goto out;

	/*
	 * Verify the target data hierarchy
	 */
	error = verify_datadirs(datadir);
	if (error)
		goto out;

	/*
	 * Firecracker config file
	 */
	error = create_fcconf(datadir, res_mntdir, 
				app_blkdev, vtapmac, tapdev);
	if (error)
		goto out;

	/*
	 * VM config file, read by VM to configure itself
	 *
	 * FIXME: the app container is mounted at /app
	 * 	  probably should do a chroot
	 */
	setstr(appinit, "%s/%s", APPCONT_MNTPOINT, init);
	error = create_vmconf(datadir, res_mntdir, 
				braddr, ipaddr, cidr_str,
			 	appinit, argv_str, env_str);

out:
	if (vtapmac)
		free(vtapmac);
	if (ipaddr)
		free(ipaddr);
	if (cidr_str)
		free(cidr_str);
	if (argv_str)
		free(argv_str);
	if (env_str)
		free(env_str);

	return error;
}

/*
 * Create a sparse file for the data partition
 */
static int setup_data_fsimg(char *datadir)
{
	int fd = -1;
	int error = 0;
	uint8_t onebyte = 0;
	off_t offset;
	ssize_t nbytes;
	char path[PATH_MAX];
	char cmdbuf[PATH_MAX];

	setstr(path, "%s/%s", datadir, FS_IMG);

	/*
	 * Make sure any uid/gid combo can R/W to the image
	 */
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd < 0) {
		error = errno;
		warn("Can not open %s error %d", path, error);
		goto out;
	}
	offset = lseek(fd, FSIMG_SIZE - 1, SEEK_SET);
	if (offset == (off_t) -1) {
		error = errno;
		warn("Can not extend %s error %d", path, error);
		goto out;
	}
	nbytes = write(fd, &onebyte, sizeof(onebyte));
	if (nbytes != sizeof(onebyte)) {
		error = errno;
		warn("Can not write %s error %d", path, error);
		goto out;
	}
	(void)close(fd);

	setstr(cmdbuf, "mkfs.ext4 -q %s", path);
	exec_cmd(MKFS, cmdbuf);

out:
	return error;
}

/*
 * Create the mount points for inside the container
 */
int setup_resmnt(char **mntpoint)
{
	char path[PATH_MAX];
	int error = 0;

	setstr(path, "%s/%s", CONT_MNTPOINT, MNT_RONLY);
	dupstr((*mntpoint), path);

out:
	return error;
}
int setup_datamnt(char **mntpoint)
{
	char path[PATH_MAX];
	int error = 0;

	setstr(path, "%s/%s", CONT_MNTPOINT, MNT_RW);
	dupstr((*mntpoint), path);

out:
	return error;
}

/*
 * Firecracker can not handle any dashes in the VM ID
 */
static int sanitize_name(char *name, char **clean_name)
{
	char *str = NULL, *src, *dst;
	int error = 0;

	dupstr(str, name);
	memset(str, 0, strlen(name));

	src = name;
	dst = str;

	while (*src) {
		if (isalnum(*src))
			*dst++ = *src;
		src++;
	}
	*dst = '\0';
out:
	if (error == 0) {
		*clean_name = str;
	} else {
		if (str)
			free(str);
	}

	return error;
	
}

/*
 * Create the args to launch the VM wrapper instead of the app
 */
static int 
create_vm_args(char *container_name, char **vm_initstr, char ***vm_argv)
{
	int error = 0, i;
	char path[PATH_MAX];
	char *initstr = NULL;
	void *ptr = NULL;
	char *name = NULL;
	char **argv;

	error = sanitize_name(container_name, &name);
	if (error)
		goto out;

	ptr = malloc(sizeof(char *) * LAUNCH_ARGC + 1);
	if (ptr == NULL) {
		error = ENOMEM;
		goto out;
	}
	argv = (char **)ptr;
	memset(ptr, 0, sizeof(char *) * LAUNCH_ARGC + 1);

	/*
	 * FIXME: the container must have a mount point available
	 * for mounting the resource container. We don't want to
	 * use the normal resource mechanism because would require
	 * the resource even in non-VM mode, and we are trying to
	 * be transparent
	 */
	setstr(path, "%s/%s/bin/%s", CONT_MNTPOINT, MNT_RONLY, LAUNCH_CMD);
	dupstr(initstr, path);

	setstr(path, "%s", LAUNCH_CMD);
	dupstr(argv[0], path);
	setstr(path, "%s", name);
	dupstr(argv[1], path);

	error = setup_resmnt(&argv[2]);
	if (error)
		goto out;
	error = setup_datamnt(&argv[3]);
	if (error)
		goto out;
	argv[4] = NULL;

out:
	if (name)
		free(name);

	if (error == 0) {
		*vm_initstr = initstr;
		*vm_argv = argv;

	} else {
		if (ptr) {
			argv = (char **)ptr;
			for (i = 0; i < LAUNCH_ARGC; i++) {
				if (argv[i])
					free(argv[i]);
			}
			free(ptr);
		}
	}

	return error;
}

/*
 * Make sure firecracker (running as the target UID) can
 * read the block device
 */
static int fix_devperms(char *dm_dev)
{
	int error;

	error = chmod(dm_dev, 0666);
	if (error)  {
		error = errno;
		warn("Can not update permissions on %s error %d",
			dm_dev, error);
	}

	return error;
}

/*
 * All config and log files will go to a directory
 * in the rundir named
 * 	datadir/vm_<subnet>/<blah>
 *
 * The fs image for the data directory will go to
 * 	datadir/vm_<subnet>/datafs.img
 *
 * RETURNS:
 * 	res_mntpoint	resource container mount
 * 	data_mntpoint	created data dir for fs image and all
 * 			runtime and config files
 * 	vm_init		path to VM launcher
 * 	vm_argv		args to VM launcher
 *
 * FIXME: the linkage to Rust is awful
 */
int setup_vm(char *braddr, int subnet, char *tapdev,
	     char *rundir, char *container_datadir, 
	     char *container_name, char *dm_dev, 
	     char *init, char *argv[], char *env[],
	     char **res_mntpoint, char **data_mntpoint,
	     char **vm_init, char ***vm_argv)
{
	int error = 0;
	char *res_srcdir = NULL;
	char *datadir = NULL;

	info("setup_vm rundir %s datadir %s dm_dev %s init %s",
		rundir, container_datadir, dm_dev, init);

	/*
	 * north creates the block devices as 
	 *    brw------- 1 root root 254,   0 2020-12-17 11:42 /dev/block/dm-0
	 * but they need to be readable by the UID of the container.
	 *
	 * FIXME: need target UID
	 */
	error = fix_devperms(dm_dev);
	if (error)
		goto out;

	/*
	 * Directory for writeable data image and config files
	 */
	error = setup_mntdir(container_datadir, subnet, &datadir);
	if (error)
		goto out;

        /*
	 * Construct the path to the already-mounted resource
	 * container
	 *
	 * FIXME: resource name should come from manifest
         */
        error = setup_resource_mount(rundir,
				      "fc_resource", "0.0.1", &res_srcdir);
        if (error)
                goto out;

	/*
	 * Create ext4 data image
	 */
	error = setup_data_fsimg(datadir);
	if (error)
		goto out;

	/*
	 * Create the firecracker and VM config files from the templates
	 * in the resource container.
	 */
	error = create_conffiles(braddr, subnet, tapdev,
				 res_srcdir, datadir, dm_dev,
				 init, argv, env);

	if (error)
		goto out;

	/*
	 * Create the new argv for the VM launcher
	 */
	error = create_vm_args(container_name, vm_init, vm_argv);
	if (error)
		goto out;

out:
	info("setup_vm '%s' resource_mnt: %s data_mnt: %s error %d",
		container_name, 
		(error == 0) ? res_srcdir : "",
		(error == 0) ? datadir : "",
		error);

	if (error == 0) {
		*res_mntpoint = res_srcdir;
		*data_mntpoint = datadir;

	} else {
		if (res_srcdir)
			free(res_srcdir);
		if (datadir)
			free(datadir);
	}

        return error;
}

