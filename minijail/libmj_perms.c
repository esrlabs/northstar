/* 
 * Copyright (c) 2020 ESRLabs
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <errno.h>
#include <grp.h>

#include "libminijail.h"
#include "util.h"

#include "libcap/include/sys/capability.h"

/*
 * Count the number of non-whitespace strings and convert all non-alpha
 * chars to space for strtok
 */
static int fixup_args(char *str)
{
	char *cp;
	int count = 0;

	cp = str;
	while (*cp) {
		while (*cp && (isalnum(*cp) || ispunct(*cp)))
			cp++;
		count++;
		while (*cp && !(isalnum(*cp) || ispunct(*cp)))
			*cp++ = ' ';
	}
	return count;
}

int minijail_parse_caps(char *capstr, uint64_t *capval)
{
	int error = 0, count, i;
	char *str = NULL, *cp;
	cap_value_t val;
	uint64_t caps = 0;
	const uint64_t one = 1;

	str = strdup(capstr);
	if (str == NULL) {
		error = ENOMEM;
		goto out;
	}
	count = fixup_args(str);

	i = 0;
	cp = strtok(str, " ");
	while (cp && i < count) {
		error = cap_from_name(cp, &val);
		if (error) {
			error = errno;
			warn("Invalid capability %s", cp);
			goto out;
		}
		caps |= (one << val);

		i++;
		cp = strtok(NULL, " ");
	}

	info("Capability vector is 0x%lx", caps);
	*capval = caps;
out:
	if (str)
		free(str);

	return error;
}

int minijail_parse_groups(char *grpstr, int *gidcnt, gid_t **bufp)
{
	int error = 0, count, i;
	char *str = NULL, *cp;
	struct group *grp;
	gid_t *gidbuf = NULL;

	/*
	 * Dup it in case the string is in a read-only section
	 */
	str = strdup(grpstr);
	if (str == NULL) {
		error = ENOMEM;
		goto out;
	}

	count = fixup_args(str);
	info("Groups %s with count %d", grpstr, count);

	gidbuf = malloc(count * sizeof(gid_t));
	if (gidbuf == NULL) {
		error = ENOMEM;
		goto out;
	}

	i = 0;
	cp = strtok(str, " ");
	while (cp && i < count) {
		grp = getgrnam(cp);
		if (grp) {
			info("group %s is gid %d", cp, grp->gr_gid);
			gidbuf[i] = grp->gr_gid;
		} else {
			warn("Can not get group id for %s", cp);
		}
		i++;
		cp = strtok(NULL, " ");
	}

out:
	if (error == 0) {
		*gidcnt = count;
		*bufp = gidbuf;
	} else {
		if (gidbuf)
			free(gidbuf);
	}

	if (str)
		free(str);

	return error;
}
