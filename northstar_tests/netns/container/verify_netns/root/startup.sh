#!/bin/sh

#set -xv
mpub=mosquitto_pub
topic=/north_test/namespace_ino
cap_raw=0x2000
adb_grpid=1011

plat_android=

detect_platform() {
	local status

	# /proc/cmdline is 660, so can't use that
	if [ -e /sys/class/android_usb ] ; then
		plat_android=1
	else
		plat_android=0
	fi
}

#
# Make sure the process has at least CAP_NET_RAW 
# To avoid sh conversions, the variables must remain strings
# except for the actual bitfield check
verify_caps() {
	local caps tmp val status
	local result

	caps=$(grep CapEff /proc/self/status)
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not read /proc/self/status"
		exit 1
	fi
	tmp=${caps##*:}

	# Turn into a string that will later be interpretted as hex
        val=$(printf 0x%s $tmp)
	result=$(($val & $cap_raw))
	if [ $result -eq 0 ] ; then
		echo "Invalid process capability $caps"
		exit 1
	fi
	echo "Process capability $caps has CAP_RAW"
	return 0
}

# For dns to work, the process must be in the inet group, so
# to make sure group processing is working, we look for the
# ADB group
verify_groups() {
	local groups tmp grp status found

	tmp=$(grep Groups /proc/self/status)
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not read /proc/self/status"
		exit 1
	fi
	groups=${tmp##*:}

	if [ -z "${groups}" ] ; then
		echo "No group membership"
		exit 1
	fi

	found=0
	for grp in ${groups[@]} ; do
		if [ $grp = $adb_grpid ] ; then
			found=1
			break;
		fi
	done
	if [ $found -eq 0 ] ; then
		echo "adb group id $adb_grpid not found in group list $groups"
		exit 1
	fi
	echo "group list $groups ok"
	return 0
}


# With pid namespaces, we have no visibility into the root
# (like /proc/1/ns/net). Otherwise, we could just extract
# the inode numbers from root and ourselves and make sure
# they are the same. Instead, we have to send a message
# to the host and have it do the compare. 
#
# This obviously only works if mqtt is working.
#
get_namespace_ino() {
	local self tmp status

	tmp=$(ls -i /proc/self/ns/net)
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not read /proc/self/ns/net"
		exit $status
	fi

	self=${tmp%%/proc*}
	echo $self
	return 0
}

do_ping() {
	local addr=$1 status

	ping -W 2 -c 2 ${addr} > /dev/null 2>&1
	return $?
}

#
# For DNS resolution on Android to work, the entire /dev dir must
# be bind mounted in the manifest, as in
#    mounts:
#      /dev: full
ping_test() {
	local host=$1 status

	do_ping $host
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not ping host $host"
		exit 2
	fi

	do_ping 8.8.8.8
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not ping external host 8.8.8.8"
		exit 2
	fi

	do_ping google.com
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not do dns resolve and ping google.com"
		exit 2
	fi

	echo "Verified ping connectivity"
}

# Get the IP addr of the gateway
get_gwaddr() {
	local status tmp0 tmp1 addr

	# Ask how to get to some external addr
	# Output:
	#    8.8.8.8 via 172.30.0.1 dev vethnsx src 172.30.100.10 uid 0
    	#	cache
	tmp0=$(ip route get 8.8.8.8)
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not get route to 8.8.8.8"
		exit 1
	fi

	tmp1=${tmp0%%dev*}
	tmp0=${tmp1##*via}
	addr=$(printf %s $tmp0)
	echo $addr
}

mosq_pub() {
	local host=$1 ino=$2

	$mpub -h $host -t $topic -m "$ino"
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not mosqitto publish to $host"
		exit 3
	fi

	echo "Verified mosqitto_pub to $host"
	return 0

}

detect_platform

gw=$(get_gwaddr)
nsino=$(get_namespace_ino)
verify_caps

if [ $plat_android -eq 1 ] ; then
	verify_groups
fi

ping_test $gw
mosq_pub $gw $nsino

echo "All tests passed successfully"
exit 0

