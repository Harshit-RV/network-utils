#!/bin/bash
AWS_PROFILE=${1:-"default"}
AWS_STS_REGION=${2:-"ap-southeast-1"}
SYSTEM_SSH_DIR=${3:-"/etc/ssh"}
CA_LAMBDA_FUNCTION_NAME="privateCA"
LAMBDA_REGION=${AWS_REGION:-'us-west-2'}

# Edit values here
######################################################
CA_ACTION="generateHostSSHCert"
# CA_ACTION="generateClientSSHCert"

# # Get host SSH certificate
# SSH_ATTRS_VALIDITY=""
# SSH_HOST_RSA_PUBKEY=""

# # Get client SSH certificate
# SSH_ATTRS_VALIDITY=""
# SSH_CLIENT_RSA_PUBKEY=""
######################################################

# Temporary Credentials
TEMP_CREDS=$(aws sts get-session-token --profile $AWS_PROFILE)

ACCESS_KEY_ID=$(echo $TEMP_CREDS | jq -r ".Credentials.AccessKeyId")
SECRET_ACCESS_KEY=$(echo $TEMP_CREDS | jq -r ".Credentials.SecretAccessKey")
SESSION_TOKEN=$(echo $TEMP_CREDS | jq -r ".Credentials.SessionToken")

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
  '{
    auth: {
      amzDate: $amzDate,
      authorizationHeader: $authHeader,
      sessionToken: $sessionToken
    },
    certPubkey: $certPubkey,
    action: $action,
    awsSTSRegion: $awsRegion
  }' | jq -c)

# JSON with body as stringified JSON
final_json=$(jq -n --arg body "$INNER_JSON" '{body: $body}')
echo "$final_json" > event.json

aws lambda invoke \
    --function-name ${CA_LAMBDA_FUNCTION_NAME} \
    --cli-binary-format raw-in-base64-out \
    --payload file://event.json \
    response.json \
    --region $LAMBDA_REGION \
    --profile $AWS_PROFILE

response_body=$(cat response.json | jq -r ".body" | tr -d '"' | sed 's/\\r\\n/\\n/g')

echo ${response_body}

# Clean up
deactivate
sudo rm -r env *.json
