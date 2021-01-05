#!/system/bin/sh
#
# Kick off the regression tests for network namespaces.
# FIXME:
# 	This should be in Rust, in order to get the status
#	of the container exit
#

msub=/system/bin/mosquitto_sub
topic=/north_test/namespace_ino
tmpdir=/data/local/tmp
nstar=${tmpdir}/northstar/nstar
container=verify_netns

#
# The container is running in a namespace and does not
# have access to the root namespace. Therefore, it has
# to send the namespace identifier (the inode number) to
# a process running in the root namespace to make sure it
# is different
# 
# This must be started before the containers to eliminate
# any races
start_mosqsub() {
	local tmpfile=$1

	$msub -h localhost -t $topic -C 1 > $tmpfile
}

#
# The output from mosquitto_sub is the inode number, one per line
# for all containers
#
compare_ns_ino() {
	local tmpfile=$1 tmp status root_ino ino
	local cnt 

	tmp=$(ls -i /proc/1/ns/net)
        status=$?
        if [[ $status -ne 0 ]] ; then
                echo "Can not read /proc/1/ns/net"
                exit $status
        fi

        root_ino=${tmp%%/proc*}

	cnt=0
	while read -r line ; do
		ino=$line
		if [[ $ino = $root_ino ]] ; then
			echo "line $cnt same ino $line"
			exit 2
		fi
		((cnt++))
	done < $tmpfile

	echo "Container namespace ino $ino different from root $root_ino"
	return 0
}


# This should be in Rust to avoid having to grok the log output
# .... I north   : Process hello_netns0:0.0.2 exited after 3.38266s and status Exit(0)
#
find_exitstatus() {
	local line tmp0 tmp1 retval

	line=$(logcat -d | grep "Process $container")
	if [[ -z $line ]] ; then
		echo "Can not get process exit status"
		exit 3
	fi
	tmp0=${line##*Exit}
        tmp1=${tmp0##\(}
        retval=${tmp1%%\)*}

	if [[ $retval != 0 ]] ; then
		echo "$container exited with error code $retval"
		echo "Logline: $line"
		exit 4
	fi
	echo "$container exited successfully"
	return 0
}

start_tests() {
	local tmpfile=${tmpdir}/sub_$$.out
	local pid

	echo "Clearing logfile"
	logcat -c

	start_mosqsub $tmpfile &
	pid=$!

	$nstar start $container
	echo "Waiting for test to complete"
	sleep 5

	if [[ ! -s $tmpfile ]] ; then
		echo "No output within 5 seconds"
		kill -HUP $pid > /dev/null 2>&1
		rm -f $tmpfile
		exit 1
	fi

	compare_ns_ino $tmpfile
	rm -f $tmpfile

	find_exitstatus
	return 0
}

start_tests
exit $?
