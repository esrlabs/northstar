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

#ifndef _LIBMJ_NETNS_NETLINK_H_
#define _LIBMJ_NETNS_NETLINK_H_

int del_uidrule(struct rtnl_handle *rth, int start, int end);
int check_add_rule(struct rtnl_handle *rth, int start, int end);
int set_link_ns(struct rtnl_handle *rth, int link_index, int nsfd);
int add_veth(struct rtnl_handle *rth, char *veth, char *peer);
int set_vethpeer_master(struct rtnl_handle *rth, int link_index, int bridge_index);
int add_vtap_link(struct rtnl_handle *rth, int veth_index, char *linkname, char *macaddr);
int add_link(struct rtnl_handle *rth, char *linkname, char *type);
int del_link(struct rtnl_handle *rth, char *linkname, char *type);
int set_link_down(struct rtnl_handle *rth, char *linkname);
int set_link_up(struct rtnl_handle *rth, int link_index);
int set_link_mac(struct rtnl_handle *rth, int link_index, char *macaddr);
int set_link_ip(struct rtnl_handle *rth, int link_index, char *ipaddr_str, int type, int cidr);
int set_def_route(struct rtnl_handle *rth, char *ipaddr_str);
int get_link_index(struct rtnl_handle *rth, char *name, int *index);
int netns_create(int *fdp, pid_t tid);
int netns_save(int *fdp, pid_t tid);
int netns_switch(int fd);

#endif /* _LIBMJ_NETNS_NETLINK_H_ */
