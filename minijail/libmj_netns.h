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

#ifndef _LIBMJ_NETNS_H_
#define _LIBMJ_NETNS_H_

/*
 * Macros to simplfy calls to external utilities
 */
#define setbufstr(buf, len, str, ...) { \
        int _retval; \
        _retval = snprintf((buf), (len), (str), __VA_ARGS__) ;\
        if (_retval <= 0 || _retval >= ((int)(len))) { \
               error = E2BIG; \
               goto out; \
        }\
}
#define setstr(buf, str, ...) \
	setbufstr((buf), sizeof(buf), (str), __VA_ARGS__);

#define exec_cmd(cmd, buf) { \
        error = execbuf(cmd, buf); \
        if (error)  \
                goto out;       \
}
#define exec_shell(buf) { \
        int _retval; \
        _retval = system(buf); \
        if (WIFEXITED(_retval)) {        \
                error = WEXITSTATUS(_retval); \
                if (error) \
                        goto out; \
        } else { \
                error = _retval ; \
                goto out;       \
        } \
}
#define dupstr(arg, strarg) { \
	char *_str;	\
	_str = strdup(strarg);	\
	if (_str == NULL) {	\
		error = ENOMEM;	\
		goto out;	\
	} \
	(arg) = _str;	\
}

int remove_net_bridge(void);
int create_net_bridge(const char *user_ipaddr);
int create_unlink_netns(char *braddr, int subnet, int *unlinked_fd);
int create_net_vtap(int subnet, char *tapdev_name);
int join_unlinked_netns(int subnet, int unlinked_fd);
int setup_bridge_addr(const char *user_ipaddr, char **braddr);
int setup_vtap_name(int subnet, char **tapdev_name);
int execbuf(char *cmd, char *arg);
int setup_net_vmipaddr(char *braddr, int subnet, char **ns_ipaddr);
int setup_net_vtapmac(int subnet, char **vtapmac);
int setup_net_cidr(char **cidr_str);

#endif /* _LIBMJ_NETNS_H_ */
