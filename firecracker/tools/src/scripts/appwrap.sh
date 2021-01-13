#!/bin/sh
#
# Based on the parameters in the config file, spawn
# the application and forward all output to the log server on the host

# set -xv
if [ $# -ne 1 ] ; then
	echo "Usage: $0 config_file"
	exit 1
fi
cfgfile=$1

vsock_server="/bin/nc-vsock"
vsock_srvport=2
vsock_logport=1
vsock_statusport=2

get_timestamp() {
	local now tmp usec

	now=$(date +"%Y-%m-%dT%T")
	tmp=$(adjtimex | grep tv_usec)
	usec=${tmp##*: }
	echo ${now}.${usec}
}

logit() {
        local str="$@" now

        now=$(get_timestamp)
        echo "$now: $str"
}

# Extract a key from a json file
grok() {
	local file=$1 key=$2 val

	val=$(jq -r "$key" $file)
	if [ $? -ne 0 ] ; then
		return 1
	fi
	echo $val
	return 0
}

# The environment vars are a whitespace separated string
export_env() {
	local file=$1 var str

	str=$(jq -r -c '.app.env' $file)
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not get env variables, status $status"
		exit 1
	fi

	for var in $str ; do
		export $var
	done

	return 0
}

start_app() {
	local file=$1 init args env
	local status app_status

	logit "Starting application"

	init=$(grok $file ".app.init")
	if [ $? -ne 0 ] ; then
		echo "no application init"
		exit 1
	fi
	args=$(grok $file ".app.args")
	if [ $? -ne 0 ] ; then
		echo "no application args"
		exit 1
	fi

	export_env $file
	if [ $? -ne 0 ] ; then
		echo "Can not export variables"
		exit 1
	fi

	# We log the start date to make sure we can talk
	# to the logging server
	now=$(date +"%Y-%m-%dT%T")
	echo "Logging started at $now" \
		| $vsock_server $vsock_srvport $vsock_logport
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not log to logging server"
		exit 1
	fi

	(
		set -o errexit
		set -o pipefail

		$init $args | $vsock_server $vsock_srvport $vsock_logport
	)
	app_status=$?
	logit "application exited with status $app_status"

	echo $app_status |  $vsock_server $vsock_srvport $vsock_statusport
	status=$?
	if [ $status -ne 0 ] ; then
		echo "Can not log app exit status $app_status to status server, $status"
		exit 1
	fi
	return $app_status
}

start_app $cfgfile
exit $?
