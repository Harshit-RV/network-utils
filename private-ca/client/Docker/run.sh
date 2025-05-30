#!/bin/bash
echo "0 0 */1 * * cd /app && generate-certificate-curl.sh generateHostSSHCert ${CA_LAMBDA_URL} ${USER_SSH_DIR} ${SYSTEM_SSH_DIR} ${AWS_STS_REGION} ${AWS_PROFILE} > /dev/stdout" > crontab.txt
/usr/bin/crontab crontab.txt
/usr/sbin/crond -f -l 8
