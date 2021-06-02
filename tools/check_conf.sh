#!/system/bin/sh
#
# Copyright (c) 2020 ESRLabs
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# Script to check for required kernel config options
#
# The default environment is Android. To run on linux
# change the shebang above. Note that this script uses shell
# arrays and will not run on busybox sh/ash
#

# Android/Linux deltas
if [[ -d /data/local/tmp ]]  ; then
	loopdev_dir=/dev/block
	tmpdir=/data/local/tmp
else
	loopdev_dir=/dev
	tmpdir=/tmp
fi

# this appears as 'device_mapper' in northstar.toml
#
# Note that the /dev/mapper/control entry can exist without
# BLK_DEV_DM being configured. This is the case with stock
# ubuntu 20.04 server
mapper_check() {
	local status
	
	find /dev | grep -q mapper
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not find device mapper in /dev"
		echo "Check for CONFIG_BLK_DEV_DM and CONFIG_DM_UEVENT"
		exit 1
	fi
}

# this appears as 'loop_control' in northstar.toml
#
# Check for loop devices. The number is dependent on how many containers
# will be created. For testing the initial config, we check for 8
#
loop_check() {
	local status
	local -i i

	if [[ ! -c /dev/loop-control ]] ; then
		echo "Can not find /dev/loop-control"
		echo "Check for CONFIG_BLK_DEV_LOOP"
		exit 1
	fi
	i=0
	while [[ $i -lt 8 ]] ; do
		if [[ ! -b ${loopdev_dir}/loop${i} ]] ; then
			echo "There does not appear to be at least $i loop devices"
			echo -n "Verify the number of devices for the container count, "
			echo "CONFIG_BLK_DEV_LOOP_MIN_COUNT"
			echo 
			echo "Also check the location; should it be /dev/block/loop ?"
			exit 1
		fi
		((i++))
	done
}

verity_check() {

	if [[ ! -e /sys/module/dm_verity ]] ; then
		echo "dm verity module appears to be missing"
		echo "Check CONFIG_DM_VERITY. Also enable CONFIG_DM_VERITY_FEC"
		echo "The following are also required:"
		echo "    CONFIG_DM_CRYPT"
		echo "    CONFIG_DM_THIN_PROVISIONING"
		echo "    CONFIG_CRYPTO_SHA256"
		exit 1
	fi
}

fs_check() {
	local status

	grep -q tmpfs /proc/filesystems
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "tmpfs does not seem to be configured"
		echo "Check CONFIG_TMPFS"
		exit 1
	fi

	grep -q squashfs /proc/filesystems
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "squashfs does not seem to be configured"
		echo "Check CONFIG_SQUASHFS"
		echo "The following are also required:"
		echo "  CONFIG_SQUASHFS_FILE_DIRECT"
		echo "  CONFIG_SQUASHFS_DECOMP_MULTI"
		echo "  CONFIG_SQUASHFS_4K_DEVBLK_SIZE"
		echo "  CONFIG_SQUASHFS_XATTR"
		echo "  CONFIG_SQUASHFS_ZLIB"
		echo "  CONFIG_SQUASHFS_ZSTD"
		echo "  CONFIG_SQUASHFS_EMBEDDED"
		echo "  CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3"
		exit 1
	fi
}

cgroup_check() {
	local status mntpoint type
	local cgtypes

	cgtypes=( memory pids cpuset blkio )

	grep -q cgroup /proc/filesystems
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "cgroups do not seem to be configured"
		echo "Check CONFIG_CGROUPS"
		exit 1
	fi

	mntpoint=${tmpdir}/mntpoint_$$
	if [[ ! -d $mntpoint ]] ; then
		mkdir $mntpoint
		status=$?
		if [[ $status -ne 0 ]] ; then
			echo "Can not mkdir $mntpoint"
			exit 1
		fi
	fi

	for type in ${cgtypes[@]} ; do
		mount -t cgroup none $mntpoint -o $type > /dev/null 2>&1
		status=$?
		if [[ $status -ne 0 ]] ; then
			echo "Can not mount $type cgroup"
			echo "failed: mount -t cgroup none $mntpoint -o $type "
			echo "Check configuration of the following:"
			echo "   CONFIG_MEMCG "
			echo "   CONFIG_CGROUP_PIDS "
			echo "   CONFIG_CPUSETS "
			echo "   CONFIG_BLK_CGROUP "
			echo "   CONFIG_CGROUP_CPUACCT"
			exit 1
		fi
		umount $mntpoint
	done
	/bin/rmdir $mntpoint

	# explicit check for cpu cgroup because if it is already
	# mounted, another mount can fail
	mount | grep cgroup  | grep -v cpuset | grep -q cpu
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not find cpu cgroup"
		echo "Check configuration of the following:"
		echo "   CONFIG_CGROUP_CPUACCT"
		exit 1
	fi
}

namespace_check() {
	local status type
	local nstypes

	nstypes=( net uts ipc pid user )

	if [[ ! -d /proc/self/ns ]] ; then
		echo "Can not query namespaces"
		echo "Check configuration of CONFIG_NAMESPACES"
		exit 1
	fi

	for type in ${nstypes[@]} ; do
		if [[ ! -e /proc/self/ns/${type} ]] ; then
			echo "Can not query namespace type $type"
			echo "Check configuration of the following:"
			echo "    CONFIG_UTS_NS"
			echo "    CONFIG_USER_NS"
			echo "    CONFIG_PID_NS"
			echo "    CONFIG_NET_NS"
			echo "    CONFIG_IPC_NS"
			exit 1
		fi
	done
}

iputil_check() {
	local status

	which ip > /dev/null 2>&1
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not find 'ip' utility. This utility is required for network setup."
		echo "On Ubuntu: apt install iproute2"
		exit 1
	fi

	which iptables > /dev/null 2>&1
	status=$?
	if [[ status -ne 0 ]] ; then
		echo "Can not 'iptables' utility. This utility is required for network setup."
		echo "On Ubuntu: apt install iptables"
		exit 1
	fi
}

bridge_check() {
	local status

	ip link add name test_bridge type bridge > /dev/null 2>&1
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not create network bridge"
		echo "Check the configuration of the following"
		echo "    CONFIG_BRIDGE"
		echo "    CONFIG_BRIDGE_VLAN_FILTERING"
		exit 1
	fi
	ip link del test_bridge > /dev/null 2>&1
}

veth_check() {
	local status

	ip netns add test_ns > /dev/null 2>&1
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not create network namespace"
		echo "Check the configration of the following:"
		echo "    CONFIG_NET_NS"
		exit 1
	fi

	ip link add test_veth type veth peer test_brveth  > /dev/null 2>&1
	status=$?
	if [[ $status -ne 0 ]] ; then
		ip netns del test_ns > /dev/null 2>&1

		echo "Can not create network veth pair"
		echo "Check the configuration of the following"
		echo "    CONFIG_MACVLAN"
		echo "    CONFIG_MACVTAP"
		echo "    CONFIG_VXLAN"
		echo "    CONFIG_VETH"
		exit 1
	fi

	# This deletes both veths
	ip link del test_veth > /dev/null 2>&1
	ip netns del test_ns > /dev/null 2>&1
}

iptables_check() {
	local status

	iptables -w 30 -t nat -A POSTROUTING -s 169.254.10.0/24 -j MASQUERADE \
			> /dev/null 2>&1
	status=$?
	if [[ $status -ne 0 ]] ; then
		echo "Can not setup up masquerading in iptables"
		echo "Check the configuration of the following:"
		echo "    CONFIG_IP_NF_IPTABLES"
		echo "    CONFIG_IP_NF_NAT"
		echo "    CONFIG_IP_NF_TARGET_MASQUERADE"
		echo "    CONFIG_IP_NF_MANGLE"
		echo "    CONFIG_IP_NF_FILTER"
		echo "    CONFIG_IP_NF_SECURITY"
		exit 1
	fi
	iptables -w 30 -t nat -D POSTROUTING -s 169.254.10.0/24 -j MASQUERADE \
			> /dev/null 2>&1
}



mapper_check
loop_check
verity_check
fs_check
cgroup_check
namespace_check

# The following are only required if setting up network namespaces
iputil_check
bridge_check
veth_check
iptables_check

echo "kernel is correctly configured for northstar"
exit 0
