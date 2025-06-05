#!/bin/bash

CA_ACTION=${1:-$CA_ACTION}
CA_URL=${2:-$CA_URL}
ENVIRONMENT=${3:-"client"}
AWS_PROFILE=${4:-"default"}
USER_SSH_DIR=${5:-"/home/$USER/.ssh"}
USER_AWS_DIR=${6:-"/home/$USER/.aws"}
SYSTEM_SSH_DIR=${7:-"/etc/ssh"}
AWS_STS_REGION=${8:-"ap-southeast-1"}

PYTHON_EXEC=$(which python 2>/dev/null || which python3 2>/dev/null)
[[ $? -ne 0 ]] && { echo "Python not installed."; exit 1; }

is_mfa_enabled() {
  grep -q 'get-credentials' ${USER_AWS_DIR}/credentials
}

get_aws_credentials() {
    local method=${1:-"host"}
    
    if [[ $method == "host" ]]; then
        TOKEN=$(curl -s --max-time 30 -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 120")
        
        if [[ -z "$TOKEN" ]]; then
            echo "Failed to fetch EC2 metadata token. Are you running this script on an EC2 instance?"
            exit 1
        fi
        
        INSTANCE_ROLE_NAME=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
        TEMP_CREDS=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$INSTANCE_ROLE_NAME)
        PUBLIC_IP=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
        
        ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r ".AccessKeyId")
        SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r ".SecretAccessKey")
        SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r ".Token")

    elif [[ $method == "client" ]]; then
        if is_mfa_enabled; then
            CALLER_IDENTITY=$(aws sts get-caller-identity --profile $AWS_PROFILE)
            [[ $? -ne 0 ]] && { echo "Your AWS credentials have either expired or are invalid. Please check your credentials and try again."; exit 1; }
            
            TEMP_CREDS=$(get-credentials $AWS_PROFILE)
            ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r ".AccessKeyId")
            SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r ".SecretAccessKey")
            SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r ".SessionToken")

        else
            TEMP_CREDS=$(aws sts get-session-token --profile $AWS_PROFILE)
            ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r ".Credentials.AccessKeyId")  
            SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r ".Credentials.SecretAccessKey")
            SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r ".Credentials.SessionToken")
        fi
    else 
        echo "Invalid environment"
        exit 1
    fi
}

# Check for options
while getopts ":h" option; do
   case $option in
      h)
         echo "Usage: ./generate-certificate.sh [ACTION] [PUBLIC KEY FILE] [LAMBDA URL]"
         echo "Possible actions:"
         echo " generateHostSSHCert: Generates SSH Certificate for Host"
         echo " generateClientSSHCert: Generates SSH Certificate for Client"
         exit;;
      *)
         echo "Error: Invalid option"
         exit;;
   esac
done

# Check for CA Action
if [[ $CA_ACTION = "generateClientSSHCert" ]]; then

    [[ -d "${USER_SSH_DIR}" ]] || { echo "User SSH directory does not exist. Please provide the correct user SSH directory."; exit 1; }

    if test -f ${USER_SSH_DIR}/id_rsa-cert.pub; then
        # Client SSH Certificate already exists
        current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S") 
        certificate_expiration_timestamp=$(ssh-keygen -Lf ${USER_SSH_DIR}/id_rsa-cert.pub | awk '/Valid:/{print $NF}')

        if [[ $certificate_expiration_timestamp > $current_timestamp ]]; then
            # Certificate is valid
            echo "A valid certificate was found at ${USER_SSH_DIR}/id_rsa-cert.pub."
            echo "Aborting..."
            exit;
        else
            # Certificate expired
            rm ${USER_SSH_DIR}/id_rsa-cert.pub
        fi
    fi
    test -f ${USER_SSH_DIR}/id_rsa.pub || ssh-keygen -t rsa -b 4096 -f ${USER_SSH_DIR}/id_rsa -C host_ca -N ""
    CERT_PUBKEY=$(cat ${USER_SSH_DIR}/id_rsa.pub | base64 | tr -d \\n)

elif [[ $CA_ACTION = "generateHostSSHCert" ]]; then
    if test -f ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub; then
        # Host SSH Certificate already exists
        current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S") 
        certificate_expiration_timestamp=$(ssh-keygen -Lf ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub | awk '/Valid:/{print $NF}')

        if [[ $certificate_expiration_timestamp > $current_timestamp ]]; then
            # Certificate is valid 
            echo "A valid certificate was found at ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub."
            echo "Aborting..."
            exit;
        else
            # Certificate expired
            rm ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub
        fi
    fi
    test -f ${SYSTEM_SSH_DIR}/ssh_host_rsa_key.pub || ssh-keygen -t rsa -b 4096 -f ${SYSTEM_SSH_DIR}/ssh_host_rsa_key -C host_ca -N ""
    CERT_PUBKEY=$(cat ${SYSTEM_SSH_DIR}/ssh_host_rsa_key.pub | base64 | tr -d \\n)
else
    echo "Invalid Action"
    echo "Possible actions include:"
    echo " generateHostSSHCert: Generates SSH Certificate for Host"
    echo " generateClientSSHCert: Generates SSH Certificate for Client"
    exit;
fi

get_aws_credentials $ENVIRONMENT

if [ ! -d "env" ]; then
  $PYTHON_EXEC -m venv env
fi
source env/bin/activate
pip install -q --upgrade boto3

# Update PYTHON_EXEC to use the Python executable from the activated virtual environment
# This ensures we use the venv's Python with the installed dependencies (boto3)
PYTHON_EXEC=$(which python 2>/dev/null || which python3 2>/dev/null)

# Auth Headers
output=$($PYTHON_EXEC aws-auth-header.py $ACCESS_KEY_ID $SECRET_ACCESS_KEY $SESSION_TOKEN $AWS_STS_REGION)
auth_header=$(echo $output | jq -r ".Authorization")
date=$(echo $output | jq -r ".Date")

EVENT_JSON=$(echo "{\"auth\":{\"amzDate\":\"${date}\",\"authorizationHeader\":\"${auth_header}\",\"sessionToken\":\"${SESSION_TOKEN}\"},\"certPubkey\":\"${CERT_PUBKEY}\",\"action\":\"${CA_ACTION}\",\"awsSTSRegion\":\"${AWS_STS_REGION}\",\"publicIp\":\"${PUBLIC_IP}\"}")


if [[ $CA_ACTION = "generateClientSSHCert" ]]; then
    LAMBDA_RESPONSE=$(curl "${CA_URL}" -H 'content-type: application/json' -d "$EVENT_JSON")
    ENCODED_CERTIFICATE=$(echo $LAMBDA_RESPONSE | jq -r ".certificate")
    CERTIFICATE=$(echo $ENCODED_CERTIFICATE | base64 -d)
    HOST_CA_PUBKEY=$(echo $LAMBDA_RESPONSE | jq -r ".\"host_ca.pub\"" | base64 -d)

    echo $CERTIFICATE > ${USER_SSH_DIR}/id_rsa-cert.pub
    echo "Certificate written to ${USER_SSH_DIR}/id_rsa-cert.pub"

    [[ -f "${USER_SSH_DIR}/known_hosts" ]] || touch "${USER_SSH_DIR}/known_hosts"

    if [[ $(grep -q "@cert-authority" "${USER_SSH_DIR}/known_hosts"; echo $?) -ne 0 ]]; then
        echo "@cert-authority * ${HOST_CA_PUBKEY}" >> ${USER_SSH_DIR}/known_hosts
    fi

# sudo access is required to generate host certificate
elif [[ $CA_ACTION = "generateHostSSHCert" ]]; then
    LAMBDA_RESPONSE=$(curl "${CA_URL}" -H 'content-type: application/json' -d "$EVENT_JSON")
    ENCODED_CERTIFICATE=$(echo $LAMBDA_RESPONSE | jq -r ".certificate")
    CERTIFICATE=$(echo $ENCODED_CERTIFICATE | base64 -d)    
    USER_CA_PUBKEY=$(echo $LAMBDA_RESPONSE | jq -r ".\"user_ca.pub\"" | base64 -d)

    sh -c "echo $CERTIFICATE > ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub"
    echo "Certificate written to ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub"

    test -f ${SYSTEM_SSH_DIR}/user_ca.pub || echo $USER_CA_PUBKEY > ${SYSTEM_SSH_DIR}/user_ca.pub

    if [[ $(grep -q "HostCertificate" "${SYSTEM_SSH_DIR}/sshd_config"; echo $?) -ne 0 ]]; then
        echo "HostCertificate ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub" >> ${SYSTEM_SSH_DIR}/sshd_config
    fi

    if [[ $(grep -q "TrustedUserCAKeys" "${SYSTEM_SSH_DIR}/sshd_config"; echo $?) -ne 0 ]]; then
        echo "TrustedUserCAKeys ${SYSTEM_SSH_DIR}/user_ca.pub" >> ${SYSTEM_SSH_DIR}/sshd_config
    fi
fi

deactivate