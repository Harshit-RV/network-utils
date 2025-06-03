#!/bin/bash
CA_ACTION=${1:-"generateHostSSHCert"}
AWS_PROFILE=${2:-"default"}
USER_SSH_DIR=${3:-"/home/$USER/.ssh"}
SYSTEM_SSH_DIR=${4:-"/etc/ssh"}
LAMBDA_REGION=${5:-'us-west-2'}
CA_LAMBDA_FUNCTION_NAME=${6:-"privateCA"}
AWS_STS_REGION=${7:-"ap-southeast-1"}

# Edit values here
######################################################
# # Get host SSH certificate
# SSH_ATTRS_VALIDITY=""
# SSH_HOST_RSA_PUBKEY=""

# # Get client SSH certificate
# SSH_ATTRS_VALIDITY=""
# SSH_CLIENT_RSA_PUBKEY=""
######################################################

# Check for options
while getopts ":h" option; do
   case $option in
      h)
         echo "Usage: bash generate-certificate-aws-cli.sh [CA_ACTION] [AWS_PROFILE] [AWS_STS_REGION] [LAMBDA_REGION] [SYSTEM_SSH_DIR] [CA_LAMBDA_FUNCTION_NAME]"
         echo ""
         echo "Parameters:"
         echo "  CA_ACTION               Action to perform (default: generateHostSSHCert)"
         echo "  AWS_PROFILE             AWS profile to use (default: default)"
         echo "  USER_SSH_DIR            User SSH directory path (default: /home/$USER/.ssh)"
         echo "  SYSTEM_SSH_DIR          System SSH directory path (default: /etc/ssh)"
         echo "  LAMBDA_REGION           Lambda function region (default: us-west-2)"
         echo "  CA_LAMBDA_FUNCTION_NAME Lambda function name (default: privateCA)"
         echo "  AWS_STS_REGION          AWS STS region (default: ap-southeast-1)"
         echo ""
         echo "CA_ACTION:"
         echo "  generateHostSSHCert     Generates SSH Certificate for Host"
         echo "  generateClientSSHCert   Generates SSH Certificate for Client"
         exit;;
      *)
         echo "Error: Invalid option"
         exit;;
   esac
done


# Check for CA Action
if [[ $CA_ACTION = "generateClientSSHCert" ]]; then
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

# Temporary Credentials
TEMP_CREDS=$(aws sts get-session-token --profile $AWS_PROFILE)

ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r ".Credentials.AccessKeyId")
SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r ".Credentials.SecretAccessKey")
SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r ".Credentials.SessionToken")
PUBLIC_IP=""

PYTHON_EXEC=$(which python || which python3)

# Auth Headers
$PYTHON_EXEC -m venv env && source env/bin/activate
pip install boto3

output=$($PYTHON_EXEC aws-auth-header.py $ACCESS_KEY_ID $SECRET_ACCESS_KEY $SESSION_TOKEN $AWS_STS_REGION)
auth_header=$(echo $output | jq -r ".Authorization")
date=$(echo $output | jq -r ".Date")
CERT_PUBKEY=$(cat ${SYSTEM_SSH_DIR}/ssh_host_rsa_key.pub | base64 | tr -d \\n)

INNER_JSON=$(jq -n \
  --arg amzDate "$date" \
  --arg authHeader "$auth_header" \
  --arg sessionToken "$SESSION_TOKEN" \
  --arg certPubkey "$CERT_PUBKEY" \
  --arg action "$CA_ACTION" \
  --arg awsRegion "$AWS_STS_REGION" \
  --arg publicIp "$PUBLIC_IP" \
  '{
    auth: {
      amzDate: $amzDate,
      authorizationHeader: $authHeader,
      sessionToken: $sessionToken
    },
    certPubkey: $certPubkey,
    action: $action,
    awsSTSRegion: $awsRegion,
    publicIp: $publicIp
  }' | jq -c)

# JSON with body as stringified JSON
json_body=$(jq -n --arg body "$INNER_JSON" '{body: $body}')
echo "$json_body" > event.json

aws lambda invoke \
    --function-name ${CA_LAMBDA_FUNCTION_NAME} \
    --cli-binary-format raw-in-base64-out \
    --payload file://event.json \
    response.json \
    --region $LAMBDA_REGION \
    --profile $AWS_PROFILE

response_body=$(cat response.json | jq -r ".body")

if [[ $CA_ACTION = "generateClientSSHCert" ]]; then
    ENCODED_CERTIFICATE=$(echo $response_body | jq -r ".certificate")
    CERTIFICATE=$(echo $ENCODED_CERTIFICATE | base64 -d)
    HOST_CA_PUBKEY=$(echo $response_body | jq -r ".\"host_ca.pub\"" | base64 -d)

    echo $CERTIFICATE > ${USER_SSH_DIR}/id_rsa-cert.pub
    echo "Certificate written to ${USER_SSH_DIR}/id_rsa-cert.pub"

    if [[ $(grep -q "@cert-authority" "${USER_SSH_DIR}/known_hosts"; echo $?) -ne 0 ]]; then
        echo "@cert-authority * ${HOST_CA_PUBKEY}" >> ${USER_SSH_DIR}/known_hosts
    fi

elif [[ $CA_ACTION = "generateHostSSHCert" ]]; then
    ENCODED_CERTIFICATE=$(echo $response_body | jq -r ".certificate")
    CERTIFICATE=$(echo $ENCODED_CERTIFICATE | base64 -d)    
    USER_CA_PUBKEY=$(echo $response_body | jq -r ".\"user_ca.pub\"" | base64 -d)

    sudo sh -c "echo $CERTIFICATE > ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub"
    echo "Certificate written to ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub"

    test -f ${SYSTEM_SSH_DIR}/user_ca.pub || echo $USER_CA_PUBKEY > ${SYSTEM_SSH_DIR}/user_ca.pub

    if [[ $(grep -q "HostCertificate" "${SYSTEM_SSH_DIR}/sshd_config"; echo $?) -ne 0 ]]; then
        echo "HostCertificate ${SYSTEM_SSH_DIR}/ssh_host_rsa_key-cert.pub" >> ${SYSTEM_SSH_DIR}/sshd_config
    fi

    if [[ $(grep -q "TrustedUserCAKeys" "${SYSTEM_SSH_DIR}/sshd_config"; echo $?) -ne 0 ]]; then
        echo "TrustedUserCAKeys ${SYSTEM_SSH_DIR}/user_ca.pub" >> ${SYSTEM_SSH_DIR}/sshd_config
    fi
fi

# Clean up
deactivate
sudo rm -r env *.json
