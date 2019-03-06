#!/bin/sh

HOST="localhost"
USER="nagara@ertl.jp"
PASS="mysecretpassword"
FILE=$4
CERT="-----BEGIN CERTIFICATE-----\
MIIBbzCCARWgAwIBAgIJAMIqj7cccNhgMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMM\
CWxvY2FsaG9zdDAeFw0xODA5MjEwOTM4MTBaFw0yODA5MTgwOTM4MTBaMBQxEjAQ\
BgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIXVKx7y\
Wz3SHh9+hLyCJacrJGKJBGp/q2tx7Bxi3N+0PQ7V0R6o8uL40SKI8wSrqGJ3v1o1\
n4L5Ld3Iq3xLiMyjUDBOMB0GA1UdDgQWBBRzdrA+/CjsWJoCjcHOSUpMLb9uhjAf\
BgNVHSMEGDAWgBRzdrA+/CjsWJoCjcHOSUpMLb9uhjAMBgNVHRMEBTADAQH/MAoG\
CCqGSM49BAMCA0gAMEUCIDn5H6ojKBEKZtB9sW0iXViBJ07TZVQ8nH5g1muDdtt4\
AiEArUv3JLJkfo4wwiUzqgRHuuOle8WEZ7krGMTcO6OO1Tc=\
-----END CERTIFICATE-----"


JWT=`curl -X POST -s --cacert $CERT -u $USER:$PASS https://$HOST:443/api/management/v1/useradm/auth/login`
echo ${JWT}
SIZE=`ls -l $FILE | cut -d" " -f5`
curl -X POST -s --cacert $CERT -H "Authorization: Bearer $JWT" -F "size=$SIZE" -F "artifact=@$FILE" https://$HOST:443/api/management/v1/deployments/artifacts
