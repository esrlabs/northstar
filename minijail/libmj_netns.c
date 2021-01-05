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
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libminijail.h"
#include "libmj_netns.h"
#include "util.h"

static char *config_bridge_addr;
static const char *def_bridge_name = "nstar0";
static const char *def_bridge_mac = "00:A0:D9:CA:FE:ED";
static const int   def_bridge_cidr = 16;
static const int   def_bridge_subnet = 0;
static const int   def_bridge_ipaddr_octet = 1;
static const char *def_vtap_macprefix = "00:A0:D9:BE:EF:";
/*
 * When ellided with the '@index', using 'macvtap' makes
 * the device name too long
 */
static const char *def_vtap_name = "mv";
static const char *def_ns_name = "ns";
static const char *def_veth_devname = "vh";
static const int   def_ns_ipaddr_octet = 10;
static int	   def_vm_ipaddr_octet = 20;

#define MACADDR_LEN	17
#define WHITESPACE      " "
#define ARGC_MAX	256

/*
 * Macros to simplfy calls to the ip utility
 */
#define CMDBUF_SIZE	128

#if defined(__ANDROID__)
  #define IP_CMD	"/system/bin/ip"
  #define IPTABLES_CMD	"/system/bin/iptables"
  #define TMPDIR	"/data/local/tmp"
#else
  #define IP_CMD	"/sbin/ip"
  #define IPTABLES_CMD	"/sbin/iptables"
  #define TMPDIR	"/tmp"
#endif

#define NOFAIL_ON_ERR	0
#define FAIL_ON_ERR	1

static int validate_macaddr(const char *mac)
{
        int error;
        int len = 0;
        int colon = 0;

        if (strlen(mac) > MACADDR_LEN) {
		error = EINVAL;
		goto out;
	}

        while (*mac) {
                if (isxdigit(*mac))
                        len++;
                else if (*mac == ':')
                        colon++;
                mac++;
        }
	if (len != 12 || colon != 5) {
		error = EINVAL;
		goto out;
	}
	error = 0;
out:
	return error;
}

/*
 * Build an IPv4 addr based on a /16 prefix
 */
static int build_ipaddr(const char *base_addr, int subnet, int octet, char **retaddr)
{
	char *ip_str;
	struct in_addr ipaddr, masq_addr;
	int error;

	*retaddr = NULL;

	if (subnet < 0 || subnet > 254) {
		error = EINVAL;
		goto out;
	}
	if (octet < 0 || octet > 254) {
		error = EINVAL;
		goto out;
	}

	error = inet_aton(base_addr, &ipaddr);
	if (error == 0) {
		error = EINVAL;
		goto out;
	}
	error = 0;

	masq_addr.s_addr = ipaddr.s_addr & htonl(0xffff0000);
	masq_addr.s_addr |= htonl((subnet << 8) | octet);

	/*
	 * inet_ntoa returns a pointer to a static buffer
	 */
	ip_str = inet_ntoa(masq_addr);
	dupstr((*retaddr), ip_str);

out:
	return error;
}

/*
 * The bridge addr must be a /16
 */
static int setup_net_braddr(const char *user_ipaddr, char **braddr)
{
	return build_ipaddr(user_ipaddr, def_bridge_subnet,
			     def_bridge_ipaddr_octet, braddr);
}

static int setup_net_brname(char **brname) 
{
	int error = 0;

	if (strlen(def_bridge_name) > IFNAMSIZ) {
                warn("Bridge name %s beyone max of %d",
		     def_bridge_name, IFNAMSIZ);
		error = EINVAL;
		goto out;
	}

	dupstr((*brname), def_bridge_name);

out:
	return error;
}

static int setup_net_brmac(char **brmac)
{
	int error = 0;

	error = validate_macaddr(def_bridge_mac);
	if (error) {
		warn("Invalid default mac address %s", def_bridge_mac);
		error = EINVAL;
		goto out;
	}

	dupstr((*brmac), def_bridge_mac);

out:
	return error;
}

static int setup_net_nsname(int subnet, char **nsname)
{
	char devname[IFNAMSIZ];
	int error = 0;

	setstr(devname, "%s%d", def_ns_name, subnet);
	dupstr((*nsname), devname);

out:
	return error;
}

static int setup_net_vtapname(int subnet, char **vtapname)
{
	char devname[IFNAMSIZ];
	int error = 0;

	setstr(devname, "%s%d", def_vtap_name, subnet);
	dupstr((*vtapname), devname);

out:
	return error;
}

int setup_net_vtapmac(int subnet, char **vtapmac)
{
	char macaddr[MACADDR_LEN + 1];
	int error = 0;

	setstr(macaddr, "%s%02d", def_vtap_macprefix, subnet);
	dupstr((*vtapmac), macaddr);

out:
	return error;
}

static int setup_net_vethname(char *nsname, char **vethname)
{
	char devname[IFNAMSIZ];
	int error = 0;

	setstr(devname, "%s%s", nsname, def_veth_devname);
	dupstr((*vethname), devname);

out:
	return error;
}

int setup_net_cidr(char **cidr_str)
{
	char buf[IFNAMSIZ];
	int error = 0;

	setstr(buf, "%d", def_bridge_cidr);
	dupstr((*cidr_str), buf);

out:
	return error;
}

/*
 * Convert a string into an argv[] array
 *
 * NB:
 * 	This does not handle quoted strings
 */
#define MAX_CMDARGS	32	/* arbitrary */


/*
 * Convert an *argv[] array of strings into a single string,
 * with args separated by whitespace
 *
 * There should always be at least one arg, the name of
 * the executable.
 */
int expand_argv(char **arg_str, char *argv[])
{
	char *buf = NULL, *cp;
	int retval, error = 0, i, len, argc;

	/*
	 * Count args. We use a semi-arbitrary max number of args
	 */
	argc = 0;
	for (i = 0; i < ARGC_MAX; i++) {
		if (argv[i])
			argc++;
		else
			break;
	}
	if (argc == 0) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Size the buffer
	 */
	len = 0;
	for (i = 0; i < argc; i++) {
		len += strlen(argv[i]);
		len++;		/* whitespace between args */
	}
	len++;			/* trailing NULL */
	len = roundup(len, 8);	/* avoid unalignment */

	buf = malloc(len);
	if (buf == NULL) {
		error = ENOMEM;
		goto out;
	}
	memset(buf, 0, len);

	/*
	 * Copy args to buffer
	 */
	cp = buf;
	for (i = 0; i < argc; i++) {
		retval = snprintf(cp, len, "%s%s", argv[i], WHITESPACE);
		if (retval <=0 || retval >= len) {
			error = E2BIG;
			goto out;
		}
		len -= retval;
		cp += retval;
	}

out:
	if (error == 0)
		*arg_str = buf;

	return error;
}

static int make_argv(char *buf, char *argv[], int argv_max) 
{
        char *str;
        int error, i = 0;

	i = 0;
        str = strtok(buf, " ");
        while (str && (i < argv_max)) {
                argv[i++] = str;
                str = strtok(NULL, " ");
        }
	if (i >= argv_max) {
		/*
		 * We die here since this is a build error
		 * and should not happen at runtime, except
		 * during debugging
		 */
		die("String %s too many args %d, max %d",
		    buf, i, argv_max);
	}

	argv[i] = NULL;
	error = 0;

        return error;
}

/*
 * Avoid using system(3) since will add an extra fork/exec as
 * everything is spawned from a shell
 */
int execbuf(char *cmd, char *arg)
{
	pid_t	pid, ret;
	int	status, error = 0;
	char	*env[] = { NULL };
	char	*argv[MAX_CMDARGS];
	char	*argbuf = NULL;

 	/*
	 * Since the strings are probably in the in the elf string
	 * table and not writable, we have to dup them
	 */
        argbuf = strdup(arg);
	if (argbuf == NULL) {
		error = ENOMEM;
		goto out;
	}

	error = make_argv(argbuf, argv, MAX_CMDARGS);
	if (error)
		goto out;

	pid = fork();
	if (pid == -1) {
		error = errno;
		warn("Fork of %s failed", cmd);
		goto out;
	}

	if (pid) {
		/*
		 * Parent waits for command to complete
		 */
		for (;;) {
                	ret = waitpid(pid, &status, 0);
                	if (ret >= 0)
                        	break;
                	if (errno != EINTR) {
				error = errno;
				warn("Wait of pid %d for command %s failed error %d",
					pid, cmd, error);
				goto out;
			}
		}
		if (WIFEXITED(status)) {
			/*
			 * Normal child exit
			 */
			error = WEXITSTATUS(status);
		} else  {
			if (WIFSIGNALED(status))
				error = EINTR;
			else 
				error = EINVAL;
		}

	} else {
		ret = execve(cmd, argv, env);
		if (ret) {
			error = errno;
			warn("Can not exec %s, error %d", cmd, error);
			goto out;
		}
	}
out:
	if (argbuf)
		free(argbuf);

	return error;
}


#if defined(__ANDROID__)
/*
 * Android uses UID based routing.  For a client in a container namespace
 * to be able to connect to an Android service, we must add a routing rule
 * that allows the 'system' service. Otherwise, during the listen/connect
 * handling, the connect will be dropped by the kernel (fib_rule_match)
 * The rule in question is
 *        ip rule list all
 *                23000:  from all fwmark 0x0/0xffff uidrange 0-0 lookup main
 * To keep some semblence of default Android behaviour, we leave it in place
 * and add other rule that ends up earlier in the table that will allow
 * routes (and therefore connections) to Android services running as 'system'.
 *
 * Note that if we specify a firewall mark, we can occasionally drop packets
 * when multiple namespaces are launched in parallel
 */
#define ANDROID_UID_MAX 65535

static int fix_android_iprules(char *brname)
{
	char cmdbuf[CMDBUF_SIZE];
	char outfile[PATH_MAX];
	int error;
	struct stat sb;

	/*
	 * This should be executed only a single time, when the bridge is
	 * created. Otherwise, it will keep adding rules
	 */
	setstr(outfile, "%s/%s_uid", TMPDIR, brname);
	setstr(cmdbuf, "ip rule list uidrange 0-%d > %s", ANDROID_UID_MAX, outfile);
	exec_shell(cmdbuf);

	error = stat(outfile, &sb);
	if (error) {
		error = errno;
		goto out;
	}
	(void)unlink(outfile);

	if (sb.st_size != 0) {
		error = 0;
		goto out;
	}

	setstr(cmdbuf, "ip rule add uidrange 0-%d lookup main", ANDROID_UID_MAX);
	exec_cmd(IP_CMD, cmdbuf);

	error = 0;
out:
	if (error)
		warn("Can not setup android uid routing, error %d", error);

	return error;
}

static int del_android_iprule(void)
{
	char cmdbuf[CMDBUF_SIZE];
	int error;

	setstr(cmdbuf, "ip rule del uidrange 0-%d", ANDROID_UID_MAX);
	exec_cmd(IP_CMD, cmdbuf);
out:
	return error;
}
#endif /* ANDROID */

/*
 * Get the ipv4 address of a device
 */
static int get_ipv4_addr(char *devname, char **ipbufp)
{
	struct sockaddr_in *addr;
	struct ifreq ifr;
	int error = 0;
	int sockfd = -1;
	char *ip_str;

	if (strlen(devname) >= IFNAMSIZ) {
		error = EINVAL;
		goto out;
	}
	strcpy(ifr.ifr_name, devname);

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		error = errno;
		goto out;
	}

	if (ioctl( sockfd, SIOCGIFADDR, &ifr) < 0) {
		error = errno;
		warn("Can not get ipaddr for %s error %d",
			devname, error);
		goto out;
	}

	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	ip_str = inet_ntoa(addr->sin_addr);

	dupstr((*ipbufp), ip_str);

out:
	info("device %s is at %s", devname, (error) ? "" : *ipbufp);

	if (sockfd != -1)
		(void)close(sockfd);

	return error;
}

static int delete_net_namespace(char *nsname)
{
	char path[PATH_MAX];
	int error = 0;

	info("Deleting %s", nsname);
	setstr(path, "ip netns delete %s", nsname);
	exec_cmd(IP_CMD, path);
out:
	return error;
}

static int open_unlink_net_namespace(char *nsname, int *unlinked_fd)
{
	char path[PATH_MAX];
	int error = 0, fd;
	struct stat sb;

	setstr(path, "/var/run/netns/%s", nsname);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		error = errno;
		warn("failed to open namespace %s, error %d", path, error);
		goto out;
	}

	/*
	 * It is helpful to known the inode number for debug/triage
	 * to correlate with /proc/pid/ns/net
	 */
	error = stat(path, &sb);
	if (error) {
		error = errno;
		warn("Can not stat %s, error %d", path, error);
		goto out;
	}

	/*
	 * Remove the /var/run/netns/<name> entry. We
	 * can not just unlink the file, that results in EBUSY
	 * because it is actually an nsfs (name space fs) mount point.
	 */
	error = delete_net_namespace(nsname);
	if (error) {
		warn("can not delete namespace %s error %d", nsname, error);
		goto out;
	}

	info("namespace %s ino %ld unlinked", nsname, sb.st_ino);
	error = 0;
	*unlinked_fd = fd;

out:
	return error;
}

/*
 * Since namespaces are unlinked when joined, we can not just
 * look in /var/run/netns. We have to look and see if the devices
 * are still connected to the bridge
 */
static int check_existing_net_namespace(char *brname, char *devname)
{
	char path[PATH_MAX];
	DIR *dir = NULL;
	struct dirent *entry;
	int error = 0;

	setstr(path, "/sys/devices/virtual/net/%s/brif", brname);

	info("Looking for device %s in %s", devname, path);

	dir = opendir(path);
	if (dir == NULL) {
		error = errno;
		goto out;
	}
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, devname) == 0) {
			error = EEXIST;
			goto out;
		}
	}

out:
	if (dir != NULL)
		closedir(dir);

	return error;
}

/*
 * Executed in the context of the new namespace
 */
static int create_vtap_netdev(char *vethname, char *vtapname, char *vtapmac)
{
	char cmdbuf[CMDBUF_SIZE];
	int error = 0;

	info("Creating tapdev %s mac %s", vtapname, vtapmac);

	setstr(cmdbuf, "ip link add link %s %s "
			"address %s type macvtap mode bridge",
			vethname, vtapname, vtapmac)
	exec_cmd(IP_CMD, cmdbuf);

	setstr(cmdbuf, "ip link set %s up", vtapname);
	exec_cmd(IP_CMD, cmdbuf);

	error = 0;
out:
	return error;
}

static int extract_val(char *line, unsigned int *val)
{
        int error = 0;
        char *ptr;

        ptr = strchr(line, '=');
        if (ptr == NULL) {
                error = EINVAL;
                goto out;
        }
        ptr++;
        *val = strtoul(ptr, NULL, 0);

out:
        return error;
}

/*
 * This must be executed in the context of the target network namespace
 * so that the /sys/class/net hierarchy is correct
 *
 * The major and minor come from the uevent in the namespace:
 * # cat /sys/class/net/macvtap1/macvtap/tap2/uevent
 *	MAJOR=249
 *	MINOR=1
 *	DEVNAME=tap2
 *
 * The number of namespaces is static, according to the manifests.
 * The device nodes are uniquely named for each namespace. The namespace
 * names are also unique ('ns<index>').  Therefore,
 * if a prior run did not clean up, we can remove the device node
 * if we find it and create it again with the correct major/minor
 */
static int create_vtap_devnode(char *vtapname, char *tapdev_name)
{
	char path[PATH_MAX];
	char linebuf[80];
	FILE *fp = NULL;
	int error = 0, ifindex, retval, min_found, maj_found, use_existing;
	unsigned int maj, min;
	struct stat sb;

	info("Creating device node for %s", vtapname);

	setstr(path, "/sys/class/net/%s/ifindex", vtapname);
	fp = fopen(path, "r");
	if (fp == NULL) {
		warn("Can not open %s: is this is correct namespace ?", path);
		error = ENOENT;
		goto out;
	}

	retval = fscanf(fp, "%d", &ifindex);
	if (retval != 1)  {
		(void)fclose(fp);
		warn("Can not read %s", path);
		error = EINVAL;
		goto out;
	}
	(void)fclose(fp);

	setstr(path, "/sys/class/net/%s/macvtap/tap%d/uevent", vtapname, ifindex);
	fp = fopen(path, "r");
	if (fp == NULL) {
		warn("Can not open %s", path);
		error = ENOENT;
		goto out;
	}

	/*
	 * Can not rely on the values themselves to indicate if
	 * we found them or not
	 */
	min_found = maj_found = 0;
	while (fscanf(fp, "%80s", linebuf) != EOF) {
		if (strstr(linebuf, "MAJOR")) {
			if (extract_val(linebuf, &maj)) {
				(void)fclose(fp);
				warn("Malformed uevent line %s", linebuf);
				error = EINVAL;
				goto out;
			}
			maj_found = 1;
		}
		if (strstr(linebuf, "MINOR")) {
			if (extract_val(linebuf, &min)) {
				(void)fclose(fp);
				warn("Malformed uevent line %s", linebuf);
				error = EINVAL;
				goto out;
			}
			min_found = 1;
		}
	}
	(void)fclose(fp);

	if (maj_found == 0) {
		warn("No major number in uevent file %s", path);
		error = EINVAL;
		goto out;
	}
	if (min_found == 0) {
		warn("No minor number in uevent file %s", path);
		error = EINVAL;
		goto out;
	}

	/*
	 * If the device node entry already exists, it must have the
	 * correct major/minor
	 */
	info("Creating node %s major %d minor %d", tapdev_name, maj, min);

	use_existing = 0;
	retval = access(tapdev_name, F_OK);
	if (retval == 0) {
		error = stat(tapdev_name, &sb);
		if (error) {
			error = errno;
			warn("Can not stat %s", tapdev_name);
			goto out;
		}
		if ((sb.st_mode & S_IFMT) != S_IFCHR ) {
			warn("%s is not a character device", tapdev_name);
			error = EINVAL;
			goto out;
		}

		if ((major(sb.st_rdev) == maj) && (minor(sb.st_rdev) == min)) {
			info("%s using existing tap device", tapdev_name);
			use_existing = 1;
		} else {
			warn("%s has incorrect major/minor 0x%lx",
				tapdev_name, (unsigned long)sb.st_rdev);

			error = unlink(tapdev_name);
			if (error) {
				error = errno;
				warn("Can not remove tap device %s", tapdev_name);
				error = EINVAL;
				goto out;
			}
		}
	}
	if (use_existing == 0) {
		error = mknod(tapdev_name, S_IFCHR | 0666, makedev(maj, min));
		if (error) {
			error = errno;
			warn("Can not create %s, error %d", tapdev_name, error);
			goto out;
		}
	}
out:
	info("Return device node for %s error %d", vtapname, error);
	return error;
}


/*
 * The bridge addr must be a /16
 */
static int setup_net_nsipaddr(char *braddr, int subnet, char **ipaddr)
{
	return build_ipaddr(braddr, subnet, def_ns_ipaddr_octet, ipaddr);
}

int setup_net_vmipaddr(char *braddr, int subnet, char **ipaddr)
{
	return build_ipaddr(braddr, subnet, def_vm_ipaddr_octet, ipaddr);
}


static int delete_iptables(char *brname, char *brmasq, int errfail)
{
	char cmdbuf[CMDBUF_SIZE];
	int error;

	setstr(cmdbuf,  "iptables -w 30 -t nat -D POSTROUTING "
			"-s %s/%d ! -o %s -j MASQUERADE",
			brmasq, def_bridge_cidr, brname);
	error = execbuf(IPTABLES_CMD, cmdbuf);
	if (error && errfail)
		goto out;

	setstr(cmdbuf, "iptables -w 30 -D FORWARD -i %s -o %s -j ACCEPT",
		brname, brname);
	error = execbuf(IPTABLES_CMD, cmdbuf);
	if (error && errfail)
		goto out;

	setstr(cmdbuf, "iptables -w 30 -D FORWARD -i %s ! -o %s -j ACCEPT",
		brname, brname);
	error = execbuf(IPTABLES_CMD, cmdbuf);
	if (error && errfail)
		goto out;

	setstr(cmdbuf, "iptables -w 30 -D FORWARD -i %s -j ACCEPT",
		brname);
	error = execbuf(IPTABLES_CMD, cmdbuf);
	if (error && errfail)
		goto out;

	setstr(cmdbuf, "iptables -w 30 -D FORWARD -o %s -j ACCEPT "
			"-m conntrack --ctstate RELATED,ESTABLISHED",
			brname);
	error = execbuf(IPTABLES_CMD, cmdbuf);
	if (error && errfail)
		goto out;

out:
	if (errfail == NOFAIL_ON_ERR)
		error = 0;

	return error;
}

/*
 * Delete a possibly partially set up bridge. This is used during
 * cleanup on failure cases, so we make a "best effort" to delete
 * the bridge and cleanup the masq tables
 */
static int delete_bridging(char *braddr, char *brname)
{
	char cmdbuf[CMDBUF_SIZE];
	char *brmasq = NULL;
	int error = 0;

	setstr(cmdbuf, "ip link del dev %s type bridge", brname);
	(void)execbuf(IP_CMD, cmdbuf);

	if (build_ipaddr(braddr, 0, 0, &brmasq) == 0) {
		(void)delete_iptables(brname, brmasq, NOFAIL_ON_ERR);
	}

out:
	if (brmasq)
		free(brmasq);

	return error;
}

static int teardown_bridging(char *braddr)
{
	char path[PATH_MAX];
	char cmdbuf[CMDBUF_SIZE];
	char *brmasq = NULL;
	char *brmac = NULL;
	char *brname = NULL;
	int error = 0;

	error = setup_net_brname(&brname);
	if (error)
		goto out;

	error = setup_net_brmac(&brmac);
	if (error)
		goto out;

	/*
	 * If the bridge does not exist, there is nothing to do
	 */
	setstr(path, "/sys/class/net/%s", brname);
	error = access(path, F_OK);
	if (error)
		goto out;

	info("start teardown bridge %s", brname);

	setstr(cmdbuf, "ip link set %s down", brname);
	exec_cmd(IP_CMD, cmdbuf);

	setstr(cmdbuf, "ip link del dev %s type bridge", brname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Remove IP tables
	 */
	error = build_ipaddr(braddr, 0, 0, &brmasq);
	if (error)
		goto out;

	error = delete_iptables(brname, brmasq, FAIL_ON_ERR);
	if (error)
		goto out;

	setstr(cmdbuf, "echo %d > /proc/sys/net/ipv4/ip_forward", 0);
	exec_shell(cmdbuf);

  #if defined(__ANDROID__)
	error = del_android_iprule();
	if (error)
		goto out;
  #endif /* ANDROID */

	error = 0;

out:
	info("end teardown bridge %s return error %d", brname, error);

	if (error)
		warn("Can not delete bridge %s", brname);

	if (brmasq)
		free(brmasq);
	if (brmac)
		free(brmac);
	if (brname)
		free(brname);

	return error;
}

/*
 * If the bridge already exists, this does nothing
 */
static int create_bridging(char *braddr)
{
	char path[PATH_MAX];
	char cmdbuf[CMDBUF_SIZE];
	char *brmasq = NULL;
	char *brmac = NULL;
	char *brname = NULL;
	char *brip_existing = NULL;
	int error = 0, created = 0;

	info("start creating bridge ip %s", braddr);

	error = setup_net_brname(&brname);
	if (error)
		goto out;

	error = setup_net_brmac(&brmac);
	if (error)
		goto out;

	setstr(path, "/sys/class/net/%s", brname);
	error = access(path, F_OK);
	if (error == 0)  {
		error = get_ipv4_addr(brname, &brip_existing);
		if (error) {
			warn("Can not get ipaddr for %s error %d",
				brname, error);
			goto out;
		}
		if (strcmp(braddr, brip_existing)) {
			error = EINVAL;
			warn("Bridge %s existing with different IPv4: "
				"Expected %s got %s",
				brname, braddr, brip_existing);
			goto out;
		}
		info("Using existing bridge %s", brname);
		goto out;
	}

	setstr(cmdbuf, "ip link add name %s type bridge", brname);
	exec_cmd(IP_CMD, cmdbuf);
	created = 1;

	setstr(cmdbuf, "ip link set %s up", brname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Very important: Add a MAC address. Without this,
	 * every veth attach will *change* the MAC addr of the
	 * bridge. When multiple namespaces are started in
	 * parallel, this causes ARP to get multiple different
	 * MAC addr resolutions for the address of the bridge. Wannsinn
	 */
	setstr(cmdbuf, "ip link set %s address %s",
		brname, brmac);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * broadcast addr with mask used on addr
	 */
	setstr(cmdbuf, "ip addr add %s/%d brd + dev %s",
		braddr, def_bridge_cidr, brname);
	exec_cmd(IP_CMD, cmdbuf);

	error = build_ipaddr(braddr, 0, 0, &brmasq);
	if (error)
		goto out;

	/*
	 * Set up masquerading
	 *
	 * Modelled on docker rules. If we can not get the lock within
	 * 30 seconds, something is horribly wrong
	 */
	setstr(cmdbuf,  "iptables -w 30 -t nat -A POSTROUTING "
			"-s %s/%d ! -o %s -j MASQUERADE",
			brmasq, def_bridge_cidr, brname);
	exec_cmd(IPTABLES_CMD, cmdbuf);

	setstr(cmdbuf, "iptables -w 30 -I FORWARD -i %s -o %s -j ACCEPT",
		brname, brname);
	exec_cmd(IPTABLES_CMD, cmdbuf);

	setstr(cmdbuf, "iptables -w 30 -I FORWARD -i %s ! -o %s -j ACCEPT",
		brname, brname);
	exec_cmd(IPTABLES_CMD, cmdbuf);

	setstr(cmdbuf, "iptables -w 30 -I FORWARD -i %s -j ACCEPT",
		brname);
	exec_cmd(IPTABLES_CMD, cmdbuf);

	setstr(cmdbuf, "iptables -w 30 -I FORWARD -o %s -j ACCEPT "
			"-m conntrack --ctstate RELATED,ESTABLISHED",
			brname);
	exec_cmd(IPTABLES_CMD, cmdbuf);

	setstr(cmdbuf, "echo %d > /proc/sys/net/ipv4/ip_forward", 1);
	exec_shell(cmdbuf);

  #if defined(__ANDROID__)
	error = fix_android_iprules(brname);
	if (error)
		goto out;
  #endif

	error = 0;

out:
	info("end creating bridge %s return error %d", braddr, error);

	if (error && created)
		(void)delete_bridging(braddr, brname);

	if (brmasq)
		free(brmasq);
	if (brmac)
		free(brmac);
	if (brname)
		free(brname);
	if (brip_existing)
		free(brip_existing);

	return error;
}



/*
 * Create and then unlink a namespace
 */
int create_unlink_netns(char *braddr, int subnet, int *unlinked_fd)
{
	char cmdbuf[CMDBUF_SIZE];
	char devname[IFNAMSIZ];
	char *vethname = NULL;
	char *nsname = NULL;
	char *ipaddr = NULL;
	char *brname;
	int error = 0, created = 0;


	info("create_unlink namespace subnet %d", subnet);

	error = setup_net_brname(&brname);
	if (error)
		goto out;

	error = setup_net_nsname(subnet, &nsname);
	if (error)
		goto out;

	 /*
         * The IP addr of the namespace is based on the bridge addr/16
         * with the subnet and a fixed lower octet
         */
        error = setup_net_nsipaddr(braddr, subnet, &ipaddr);
        if (error) {
                warn("Can not create ipaddr for subnet %d, error %d",
                        subnet, error);
                goto out;
        }

	/*
	 * The device name is based on the namespace name
	 */
	error = setup_net_vethname(nsname, &vethname);
	if (error)
		goto out;

	setstr(devname, "%s-peer", vethname);

	error = check_existing_net_namespace(brname, devname);
	if (error) {
		warn("namespace %s already exists", nsname);
		goto out;
	}
	error = 0;

	info("creating namespace %s to subnet %d with %s",
		nsname, subnet, ipaddr);

	setstr(cmdbuf, "ip netns add %s", nsname);
	exec_cmd(IP_CMD, cmdbuf);
	created = 1;

	/*
	 * Bring up the loopback, otherwise self ping fails
	 */
	setstr(cmdbuf, "ip -n %s link set lo up", nsname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Add one end of the veth pair to the namespace
	 */
	setstr(cmdbuf, "ip link add %s type veth peer name %s", vethname, devname);
	exec_cmd(IP_CMD, cmdbuf);
	setstr(cmdbuf, "ip link set %s netns %s", vethname, nsname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Add the other end of the veth pair to the bridge
	 */
	setstr(cmdbuf, "ip link set %s master %s", devname, brname);
	exec_cmd(IP_CMD, cmdbuf);

	setstr(cmdbuf, "ip link set %s up", devname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Add the address and bring up both sides
	 */
	setstr(cmdbuf, "ip -n %s addr add %s/%d dev %s", nsname, ipaddr,
		def_bridge_cidr, vethname);
	exec_cmd(IP_CMD, cmdbuf);

	setstr(cmdbuf, "ip -n %s link set %s up", nsname, vethname);
	exec_cmd(IP_CMD, cmdbuf);

	/*
	 * Add default route
	 */
	setstr(cmdbuf, "ip -n %s route add default via %s", nsname, braddr);
	exec_cmd(IP_CMD, cmdbuf);

	error = 0;

	/*
	 * Since we (the parent) created the namespace, we can
	 * delete (the child gets EBUSY on ip netns del). So
	 * we keep an FD open that the child will then close
	 * after joining the namespace
	 */
	error = open_unlink_net_namespace(nsname, unlinked_fd);
	if (error)
		goto out;

out:
	info("end create to subnet %d with %s return error %d",
		subnet, ipaddr ? ipaddr : "<invalid>" , error);

	if (error && created) {
		(void)delete_net_namespace(nsname);
	}

	if (vethname)
		free(vethname);
	if (nsname)
		free(nsname);
	if (ipaddr)
		free(ipaddr);
	if (brname)
		free(brname);

	return error;
}

/*
 * Executed in the child in the context of the new namespace
 */
int create_net_vtap(int subnet, char *tapdev_name)
{
	int error = 0;
	char *nsname = NULL;
	char *vtapmac = NULL;
	char *vtapname = NULL;
	char *vethname = NULL;

	info("start create tap device for subnet %d", subnet);

	error = setup_net_nsname(subnet, &nsname);
	if (error)
		goto out;
	/*
	 * The network device name is based on the namespace name
	 */
	error = setup_net_vethname(nsname, &vethname);
	if (error)
		goto out;

	/*
	 * The macvtap params are based on the subnet index
	 */
	error = setup_net_vtapname(subnet, &vtapname);
	if (error)
		goto out;
	error = setup_net_vtapmac(subnet, &vtapmac);
	if (error)
		goto out;

	/*
	 * Create the network device in the namespace
	 */
	error = create_vtap_netdev(vethname, vtapname, vtapmac);
	if (error) {
		warn("Can not create macvtap %s for namespace %s, error %d",
			vtapname, nsname, error);
		goto out;
	}

	/*
	 * Create the device node for firecracker
	 */
	error = create_vtap_devnode(vtapname, tapdev_name);
	if (error) {
		warn("Can not create device node for namespace %s, error %d",
			nsname, error);
		goto out;
	}

out:
	info("end create tap device for subnet %d return error %d", subnet, error);

	if (vtapmac)
		free(vtapmac);
	if (vtapname)
		free(vtapname);
	if (vethname)
		free(vethname);
	if (nsname)
		free(nsname);
	return error;
}


/*
 * Executed in context of the child.
 *
 * Join a namespace that the parent has unlinked. This is
 * so that it will go away when we exit
 *
 * We have to remount /sys so that we pick up a new
 * view of the device files. Otherwise, we will see the
 * entries in the context of the process that first
 * mounted it.
 *
 * The magic comes from how the ip utility implements
 * ip netns exec <name> sh
 */
int join_unlinked_netns(int subnet, int unlinked_fd)
{
	char *nsname = NULL;
	int error = 0;

	info("Join namespace subnet %d", subnet);

	error = setup_net_nsname(subnet, &nsname);
	if (error)
		goto out;

	if (setns(unlinked_fd, CLONE_NEWNET)) {
		error = errno;
		warn("Child can not join namespace %s error %d", 
			nsname, error);
		goto out;
	}
	error = close(unlinked_fd);
	if (error) {
		/*
		 * Not fatal, but it should not happen
		 */
		errno = errno;
		warn("Can not close FD for namespace %s error %d", nsname, error);
		error = 0;
	}


	/*
	 * We need a new mount namespace for manipulating /sys
	 */
	error = unshare(CLONE_NEWNS);
	if (error) {
		error = errno;
		warn("Can not unshare filesystems, error %d", error);
		goto out;
	}

	/*
	 * See netns_switch() in iproute2-5.9.0/lib/namespace.c
	 *
	 * This is crucial to avoid screwing up the parent host
	 * Don't let any mounts propagate back to the parent
	 */
	if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
		error = errno;
		warn("Can not set mount flags on root for namespace, error %d",
			error);
		goto out;
	}

	/*
	 * A remount will only change the flags, and we need to get the
	 * kernel to pick up the namespace tags associated with
	 * /sys/class/net, so we do a full mount.
	 */
	error = umount2("/sys", MNT_DETACH);
	if (error) {
		error = errno;
		warn("Can not detach from /sysfs, error %d", error);
		goto out;
	}

	error = mount(nsname, "/sys", "sysfs", 0, NULL);
	if (error) {
		error = errno;
		warn("Can not remount /sys error %d", error);
	}

out:
	info("Join namespace subnet %d done error %d", subnet, error);

	if (nsname)
		free(nsname);

	return error;
}

/*
 * Called at init time
 */
int create_net_bridge(const char *user_ipaddr)
{
	char *braddr = NULL;
	int   error = 0;

	/*
	 * Validate the user ip address. It is assumed to be a
	 * valid /16 IPv4 addr
	 */
	error = setup_net_braddr(user_ipaddr, &braddr);
	if (error) {
		warn("Invalid bridge address %s", user_ipaddr);
		goto out;
	}

	error = create_bridging(braddr);
	if (error)
		goto out;

	/*
	 * Save the ip address for use when tearing down. We
	 * only support one bridge
	 */
	config_bridge_addr = braddr;

out:
	info("create_net_bridge user_ip: '%s' assigned ip: '%s' return %d",
		user_ipaddr, (error ? "" : braddr), error);

	return error;
}

/*
 * Called when shutting down
 */
int remove_net_bridge()
{
	int error = 0;
	char *brname, *braddr = config_bridge_addr;

	brname = NULL;

	/*
	 * The user address should be valid
	 */
	if (braddr == NULL) {
		warn("No bridge address saved");
		goto out;
	}

	/*
	 * Retrieve the defaults for the bridge params
	 */
	error = setup_net_brname(&brname);
	if (error)
		goto out;

	error =  teardown_bridging(braddr);

out:
	info("remove_net_bridge assigned ip: '%s' return %d",
		braddr ? braddr : "", error);

	/*
	 * Regardless of error, we free up the pointer,
	 * since we are being called in the shutdown path
	 */
	if (braddr) {
		free(braddr);
		config_bridge_addr = NULL;
	}
	if (brname)
		free(brname);

	return error;
}

/*
 * When setting up the net namespace, we only have to
 * construct the address used for the bridge gateway. This should
 * not fail, as it was checked when the runtime started
 */
int setup_bridge_addr(const char *user_ipaddr, char **braddr)
{
	int error;

         /*
         * Validate the user ip address. It is assumed to be a
         * valid /16 IPv4 addr
         */
        error = setup_net_braddr(user_ipaddr, braddr);
        if (error)
                warn("Invalid bridge address %s", user_ipaddr);

        return error;
}

/*
 * Save the name of the vtap device node so that the parent
 * can unlink it on exit
 */
int setup_vtap_name(int subnet, char **tapdev_name)
{
	char *nsname = NULL;
	char path[PATH_MAX];
	int error = 0;

	error = setup_net_nsname(subnet, &nsname);
	if (error)
		goto out;

	setstr(path, "/dev/%s%s", def_vtap_name, nsname);
	dupstr((*tapdev_name), path);
out:
	if (nsname)
		free(nsname);

	return error;
}
