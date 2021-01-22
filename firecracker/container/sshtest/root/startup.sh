#!/bin/sh

#
# Since this VM is being used for ssh testing, we just need
# an application that will keep the container alive
sleep_forever() {
	sleep 30d
}

sleep_forever
