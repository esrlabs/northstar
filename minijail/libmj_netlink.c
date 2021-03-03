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

/*
 * Netlink API to replace calls to the IP utility. Derived from 
 * iproute2-5.9.0 via strace and gdb
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <linux/if.h>
#include <linux/fib_rules.h>
#include <errno.h>
#include <sched.h>

#include <libnetlink.h>
#include <linux/veth.h>

#include "libmj_netns.h"
#include "libmj_netlink.h"

struct uidrule {
	uint32_t uid_start;
	uint32_t uid_end;
	int32_t  found;
	int32_t  pad;
};

#define MACADDR_BUFSIZE	32

/*
 * ip/ip_common.h
 */
struct iplink_req {
        struct nlmsghdr         n;
        struct ifinfomsg        i;
        char                    buf[1024];
};

/*
 * From iproute2, lib/ll_addr.c
 */
/*NB: lladdr is char * (rather than u8 *) because sa_data is char * (1003.1g) */
static int ll_addr_a2n(char *lladdr, int len, char *argstr)
{
	int i, retval = 0;
	char *arg, *base = NULL;

	base = strdup(argstr);
	if (base == NULL) {
		retval = -1;
		goto out;
	}
	arg = base;

	for (i = 0; i < len; i++) {
		int temp;
		char *cp = strchr(arg, ':');
		if (cp) {
			*cp = 0;
			cp++;
		}
		if (sscanf(arg, "%x", &temp) != 1) {
			fprintf(stderr, "\"%s\" is invalid lladdr.\n",
				arg);
			retval = -1;
			goto out;
		}
		if (temp < 0 || temp > 255) {
			fprintf(stderr, "\"%s\" is invalid lladdr.\n",
				arg);
			retval = -1;
			goto out;
		}
		lladdr[i] = temp;
		if (!cp)
			break;
		arg = cp;
	}
	retval = i + 1;

out:
	if (base)
		free(base);

	return retval;
}

/*
 * grep for uid rule
 */
static int scan_rule(struct nlmsghdr *n, void *arg)
{
	struct uidrule *urule = (struct uidrule *)arg;
        struct fib_rule_hdr *frh = NLMSG_DATA(n);
        int len = n->nlmsg_len;
        struct rtattr *tb[FRA_MAX+1];

        if (n->nlmsg_type != RTM_NEWRULE && n->nlmsg_type != RTM_DELRULE)
                return 0;

        len -= NLMSG_LENGTH(sizeof(*frh));
        if (len < 0)
                return -1;

        parse_rtattr(tb, FRA_MAX, RTM_RTA(frh), len);

	if (tb[FRA_UID_RANGE]) {
		struct fib_rule_uid_range *r = RTA_DATA(tb[FRA_UID_RANGE]);

		if (r->start == urule->uid_start &&
		    r->end == urule->uid_end)
			urule->found = 1;
	}

	return 0;
}

/*
 * "ip rule add uidrange 0-%d lookup main", ANDROID_UID_MAX
 */
static int add_uidrule(struct rtnl_handle *rth, int start, int end)
{
	struct {
                struct nlmsghdr n;
                struct fib_rule_hdr     frh;
                char                    buf[1024];
        } req = {
                .n.nlmsg_type = RTM_NEWRULE,
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .frh.family = AF_INET,
                .frh.action = FR_ACT_TO_TBL,
		.frh.table = RT_TABLE_MAIN,
        };
	struct fib_rule_uid_range r = {
		.start = start,
		.end = end,
	};

	addattr_l(&req.n, sizeof(req), FRA_UID_RANGE, &r, sizeof(r));

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip rule del uidrange 0-%d lookup main", ANDROID_UID_MAX
 */
int del_uidrule(struct rtnl_handle *rth, int start, int end)
{
	struct {
                struct nlmsghdr n;
                struct fib_rule_hdr     frh;
                char                    buf[1024];
        } req = {
                .n.nlmsg_type = RTM_DELRULE,
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .frh.family = AF_INET,
                .frh.action = FR_ACT_UNSPEC,
        };
	struct fib_rule_uid_range r = {
		.start = start,
		.end = end,
	};

	addattr_l(&req.n, sizeof(req), FRA_UID_RANGE, &r, sizeof(r));

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip rule list uidrange 0-%d > %s", ANDROID_UID_MAX, outfile;
 */
int check_add_rule(struct rtnl_handle *rth, int start, int end)
{
	struct uidrule urule;
	int retval = 0;

	memset(&urule, 0, sizeof(urule));
	urule.uid_start = start;
	urule.uid_end = end;

	retval = rtnl_ruledump_req(rth, AF_INET);
	if (retval < 0)
		goto out;

	retval = rtnl_dump_filter(rth, scan_rule, &urule);
	if (retval < 0)
		goto out;

	if (urule.found) {
		retval = 0;
		goto out;
	}

	retval = add_uidrule(rth, urule.uid_start, urule.uid_end);

out:

	return retval;
}

/*
 * From iproute2
 */
int get_link_index(struct rtnl_handle *rth, char *name, int *index)
{

        struct {
                struct nlmsghdr         n;
                struct ifinfomsg        ifm;
                char                    buf[1024];
        } req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_GETLINK,
                .ifm.ifi_index = 0,
        };
        __u32 filt_mask = RTEXT_FILTER_VF | RTEXT_FILTER_SKIP_STATS;
	struct ifinfomsg *ifm;
        struct nlmsghdr *answer;
        int retval = 0;

        addattr32(&req.n, sizeof(req), IFLA_EXT_MASK, filt_mask);
        addattr_l(&req.n, sizeof(req),
                  IFLA_IFNAME, name, strlen(name) + 1);

        retval =  rtnl_talk(rth, &req.n, &answer);
	if (retval < 0)
		goto out;

	 ifm = NLMSG_DATA(answer);
         *index =  ifm->ifi_index;

        free(answer);

out:
	return retval;
}

/*
 * "ip link set %s netns %s", vethname, nsname
 */
int set_link_ns(struct rtnl_handle *rth, int link_index, int nsfd)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	req.i.ifi_index = link_index;
	addattr_l(&req.n, sizeof(req), IFLA_NET_NS_FD, &nsfd, 4);

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link add %s type veth peer name %s", vethname, devname
 *
 * See veth_parse_opt()
 *
 * Don't need to save flags, change, or index like veth_parse_opts
 * because with new link they are all zero
 *
 */
int add_veth(struct rtnl_handle *rth, char *veth, char *peer)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	char *type = "veth";
	struct rtattr *peerdata, *linkdata, *linkinfo;

	addattr_l(&req.n, sizeof(req),
                  IFLA_IFNAME, veth, strlen(veth) + 1);

	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), 
		  IFLA_INFO_KIND, type, strlen(type));
	linkdata = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);

        peerdata = addattr_nest(&req.n, sizeof(req), VETH_INFO_PEER);
        req.n.nlmsg_len += sizeof(struct ifinfomsg);
	addattr_l(&req.n, sizeof(req),
		 IFLA_IFNAME, peer, strlen(peer) + 1);

        addattr_nest_end(&req.n, peerdata);
	addattr_nest_end(&req.n, linkdata);
	addattr_nest_end(&req.n, linkinfo);

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link set %s master %s", devname, brname
 */
int set_vethpeer_master(struct rtnl_handle *rth, int link_index, int bridge_index)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	req.i.ifi_index = link_index;

 	addattr_l(&req.n, sizeof(req), IFLA_MASTER,
                  &bridge_index, 4);

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link add link %s %s "
                        "address %s type macvtap mode bridge",
                        vethname, vtapname, vtapmac
 */
int add_vtap_link(struct rtnl_handle *rth, int veth_index, char *linkname, char *macaddr)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_UNSPEC,
        };
	struct rtattr *linkinfo, *data;
	char *type = "macvtap";
	char buf[MACADDR_BUFSIZE];
	int retval, addr_len;

        memset(buf, 0, sizeof(buf));
        addr_len = ll_addr_a2n(buf, sizeof(buf), macaddr);
        if (addr_len < 0) {
                retval = -1;
                goto out;
        }
        addattr_l(&req.n, sizeof(req), IFLA_ADDRESS, buf, addr_len);

	addattr32(&req.n, sizeof(req), IFLA_LINK, veth_index);
	req.i.ifi_index = 0;

	addattr_l(&req.n, sizeof(req),
                  IFLA_IFNAME, linkname, strlen(linkname) + 1);

	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), 
		  IFLA_INFO_KIND, type, strlen(type));

	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);

	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);

	retval = rtnl_talk(rth, &req.n, NULL);
out:
	return retval;
}

/*
 * "ip link add name %s type bridge", brname
 */
int add_link(struct rtnl_handle *rth, char *linkname, char *type)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	struct rtattr *linkinfo;

	addattr_l(&req.n, sizeof(req),
                  IFLA_IFNAME, linkname, strlen(linkname) + 1);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), 
		  IFLA_INFO_KIND, type, strlen(type));
	addattr_nest_end(&req.n, linkinfo);

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link del dev %s type bridge", brname
 */
int del_link(struct rtnl_handle *rth, char *linkname, char *type)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_DELLINK,
                .i.ifi_family = AF_INET,
        };
	struct rtattr *linkinfo;

	addattr_l(&req.n, sizeof(req),
                  IFLA_IFNAME, linkname, strlen(linkname) + 1);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), 
		  IFLA_INFO_KIND, type, strlen(type));
	addattr_nest_end(&req.n, linkinfo);

	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link set %s down", brname
 */
int set_link_down(struct rtnl_handle *rth, char *linkname)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	int index, retval;

	retval = get_link_index(rth, linkname, &index);
	if (retval)
		goto out;

	req.i.ifi_change |= IFF_UP;
       	req.i.ifi_flags &= ~IFF_UP;
	req.i.ifi_index = index;
			
	retval =  rtnl_talk(rth, &req.n, NULL);

out:
	return retval;
}

/*
 * "ip link set %s up", brname;
 */
int set_link_up(struct rtnl_handle *rth, int link_index)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };

	req.i.ifi_change |= IFF_UP;
       	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = link_index;
			
	return rtnl_talk(rth, &req.n, NULL);
}

/*
 * "ip link set %s address %s", brname, brmac;
 */
int set_link_mac(struct rtnl_handle *rth, int link_index, char *macaddr)
{
        struct iplink_req req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
                .n.nlmsg_flags = NLM_F_REQUEST,
                .n.nlmsg_type = RTM_NEWLINK,
                .i.ifi_family = AF_INET,
        };
	int retval, addr_len;
	char buf[MACADDR_BUFSIZE];

	req.i.ifi_index = link_index;
			
	memset(buf, 0, sizeof(buf));
	addr_len = ll_addr_a2n(buf, sizeof(buf), macaddr);
        if (addr_len < 0) {
		retval = -1;
		goto out;
	}
	addattr_l(&req.n, sizeof(req), IFLA_ADDRESS, buf, addr_len);

	retval =  rtnl_talk(rth, &req.n, NULL);

out:
	return retval;
}


/*
 * "ip addr add %s/%d brd + dev %s", braddr, def_bridge_cidr, brname;
 */
int set_link_ip(struct rtnl_handle *rth, int link_index, char *ipaddr_str, int type, int cidr)
{
	struct {
                struct nlmsghdr n;
                struct ifaddrmsg        ifa;
                char                    buf[256];
        } req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .n.nlmsg_type = RTM_NEWADDR,
                .ifa.ifa_family = AF_INET,
        };
	struct in_addr ipaddr;
	uint32_t bcast, ipv4;
	int retval;

	req.ifa.ifa_index = link_index;

	retval = inet_aton(ipaddr_str, &ipaddr);
	if (retval == 0) {
		retval = -1;
		goto out;
	}
	ipv4 = ipaddr.s_addr;	/* no htonl */
	req.ifa.ifa_prefixlen = cidr;

	req.ifa.ifa_family = AF_INET;
	addattr_l(&req.n, sizeof(req), IFA_LOCAL, &ipv4, 4);
	addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &ipv4, 4);

	/*
	 * bridge device needs bcast addr
	 */
	if (type == IFLA_BROADCAST) {
		bcast = htonl(htonl(ipv4) | 0xffff);
		addattr_l(&req.n, sizeof(req), IFA_BROADCAST, &bcast, 4);
	}

	retval =  rtnl_talk(rth, &req.n, NULL);

out:
	return retval;
}

/*
 * ip -n %s route add default via %s", nsname, braddr
 */
int set_def_route(struct rtnl_handle *rth, char *ipaddr_str)
{
	 struct {
                struct nlmsghdr n;
                struct rtmsg            r;
                char                    buf[4096];
        } req = {
                .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
                .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
                .n.nlmsg_type = RTM_NEWROUTE,
                .r.rtm_family = AF_INET,
                .r.rtm_table = RT_TABLE_MAIN,
		.r.rtm_protocol = RTPROT_BOOT,
                .r.rtm_scope = RT_SCOPE_UNIVERSE,
                .r.rtm_type = RTN_UNICAST,
        };
	struct in_addr ipaddr;
	int retval;

	retval = inet_aton(ipaddr_str, &ipaddr);
	if (retval == 0) {
		retval = -1;
		goto out;
	}
	addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &ipaddr.s_addr, 4);

	retval =  rtnl_talk(rth, &req.n, NULL);

out:
	return retval;
}

int netns_save(int *fdp, pid_t tid)
{
	char path[PATH_MAX];
	int error = 0;

	*fdp = -1;

	setstr(path, "/proc/%d/ns/net", tid);

	*fdp = open(path, O_RDONLY | O_CLOEXEC);
        if (*fdp < 0)
                error = errno;

out:
	return error;
}

int netns_switch(int fd)
{
	int error = 0;

	if (setns(fd, CLONE_NEWNET)) {
		error = errno;
	}
	return error;
}

int netns_create(int *fdp, pid_t tid)
{
	int error = 0;

	if (unshare(CLONE_NEWNET) < 0) {
		error = errno;
		goto out;
	}
	error = netns_save(fdp, tid);
out:
	return error;
}


