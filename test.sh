#!/bin/sh

MENDER_SERVER_URI='https://localhost'
MENDER_SERVER_USER='nagara@ertl.jp'
PW="mysecretpassword"

#JWT=$(curl -X POST -u $MENDER_SERVER_USER $MENDER_SERVER_URI/api/management/v1/useradm/auth/login --max-time 10 --verbose --insecure)

JWT=$(expect -c "
log_user 0
set timeout 5
spawn curl -X POST -u $MENDER_SERVER_USER $MENDER_SERVER_URI/api/management/v1/useradm/auth/login --max-time 10 --verbose --insecure
expect \"*\"
send \"${PW}\n\"
interact
" )

JWT=$(echo ${JWT##* })
JWT=$(echo ${JWT##* })

# echo $JWT

# list the users of your 
# curl -H "Authorization: Bearer $JWT" $MENDER_SERVER_URI/api/management/v1/useradm/users --max-time 10 --verbose --insecure | jq

curl -H "Authorization: Bearer $JWT" -H 'Content-Type:application/json' --data \
	'{"name":"qemux86-64", "artifact_name":"release-1_1.5.0", "devices":["1"]}' \
	$MENDER_SERVER_URI/api/management/v1/deployments/deployments --max-time 10 --verbose --insecure | jq

# List known artifacts
# curl  -H "Authorization: Bearer $JWT" $MENDER_SERVER_URI/api/management/v1/deployments/artifacts --max-time 10 --verbose --insecure | jq

# curl -H "Authorization: Bearer $JWT" $MENDER_SERVER_URI/api/management/v1/admission/devices/5b6d1eba04da8a00012e1b3c --max-time 10 --verbose --insecure | jq
# curl -H "Authorization: Bearer $JWT" $MENDER_SERVER_URI/api/management/v1/inventory/devices --max-time 10 --verbose --insecure | jq

