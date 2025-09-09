#!/bin/sh

#echo "$1 $2 $3 $4 $5 $6 $7 SUCCESS!"
echo "Stopping stream permanatly and live!"

cli -d .outgoing.server
kill -1 $(pidof majestic)

exit 1
