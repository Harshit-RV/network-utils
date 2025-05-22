#!/bin/bash

HOST=$1
USER_KEY=$2
TRUSTED_FINGERPRINT_SERVER_URL=${3:-$TRUSTED_FINGERPRINT_SERVER_URL}
TRUSTED_FINGERPRINT_SERVER_TOKEN=${4:-$TRUSTED_FINGERPRINT_SERVER_TOKEN}
HOMEDIR=$(eval echo ~)
KNOWN_HOSTS=${5:-"$HOMEDIR/.ssh/known_hosts"}
USER_KEY_TYPE=$(echo $USER_KEY | cut -d " " -f 1)
KEYSCAN_TIMEOUT=${6:-60}

hash_known_hosts=$(ssh -G * | awk '/hashknownhosts/ {print $2}')
hashed_hostname=$HOST

keyscan_output=$(ssh-keyscan -T $KEYSCAN_TIMEOUT -t $USER_KEY_TYPE $HOST)
[[ "$hash_known_hosts" == "yes" ]] && hashed_hostname=$(echo "$keyscan_output" | grep -v "^#" | awk '{print $1}')
host_key=$(echo "$keyscan_output" | grep -v "^#" | awk '{print $3}')

# Check if the key is empty
if [[ -z "$host_key" ]]; then
    echo "The corresponding $USER_KEY_TYPE key could not be found on the host"
    exit 1
fi

# Check if the hostname exists in known hosts
if [[  $(test -f "$KNOWN_HOSTS"  && grep -q "$hashed_hostname $USER_KEY_TYPE" $KNOWN_HOSTS; echo $?) -eq 0 ]]; then
    echo "Key found in known_hosts."
    exit 0
else
    echo "Key not found in known_hosts."
    echo "Attempting key verification..."

    tempkeyfile="key-$(echo $RANDOM | md5sum | head -c 20; echo;)"
    lambda_response_status=$(curl -sw '%{http_code}' \
    -o $tempkeyfile \
    -X 'POST' \
    -H 'Content-Type: application/json' \
    -d '{
            "Host": '"\"${HOST}\""', 
            "KeyType": '"\"${USER_KEY_TYPE}\""', 
            "Authorization": '"\"Bearer ${TRUSTED_FINGERPRINT_SERVER_TOKEN}\""'
        }' \
    $TRUSTED_FINGERPRINT_SERVER_URL)

    if [[ $lambda_response_status != "200" ]]; then
        echo "Encountered server error"
        exit 1
    fi

    lambda_response_key=$(cat $tempkeyfile)
    rm $tempkeyfile

    if [[
        $host_key == $lambda_response_key
    ]]; then
        
        echo "Key verified."
        echo "Adding keys to known hosts"
        echo "$hashed_hostname $USER_KEY_TYPE $lambda_response_key" >> $KNOWN_HOSTS
        exit 0

    else
        echo "Key could not be verified"
        echo "Host Key ($host_key) does not match with lambda response ($lambda_response_key)"
        exit 1
    fi

fi
