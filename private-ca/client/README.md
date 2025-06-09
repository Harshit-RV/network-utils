# PrivateCA

This project provides tools to generate SSH certificates using a Private Certificate Authority (CA). It supports generating SSH certificates for both hosts and clients.

## Prerequisites

### Running via Docker

- Docker

### Running directly

- Python 3
- Bash
- Dependencies: `curl`, `jq`, `ssh-keygen`, `base64`

### Running via AWS CLI (Lambda)

- AWS CLI
- Python 3
- Access to the Lambda function in the specified region

## Usage

### Running directly

#### For client certificates:

```bash
bash generate-certificate-curl.sh generateClientSSHCert <PRIVATE-CA-URL> client
```

#### For host certificates:

```bash
bash generate-certificate-curl.sh generateHostSSHCert <PRIVATE-CA-URL> host
```

**Note:**

1. Sudo privilege is required for generating host certificates as they need to write to system directories like `/etc/ssh`.
2. The `ENVIRONMENT` (host or client) parameter affects how AWS credentials are retrieved. See [Script Parameters](#script-parameters) for more details.

### Running via AWS CLI (Lambda)

The `generate-certificate-aws-cli.sh` script provides an alternative approach to generate certificates. This method uses AWS CLI to invoke a Lambda function rather than making direct HTTP requests.

#### Usage:

```bash
bash generate-certificate-aws-cli.sh <CA_ACTION> <ENVIRONMENT> <AWS-PROFILE> <USER-SSH-DIR> <SYSTEM-SSH-DIR> <LAMBDA-REGION> <CA-LAMBDA-FUNCTION-NAME> <AWS-STS-REGION>
```

### Running via Docker

1. Build the Docker image:

   ```bash
   docker build -t certificate-generator .
   ```

2. Run the Docker container with the required volume mounts and parameters:

   ```bash
   docker run --rm \
      -v /home/$USER/.ssh:/root/.ssh \
      -v /etc/ssh:/etc/ssh \
      -v /etc/ssl/privateCA:/etc/ssl/privateCA \
      certificate-generator \
      generateHostSSHCert \
      https://<PRIVATE-CA-URL>/ \
      host \
      default \
      /root/.ssh
   ```

## Running as a cron job (optional)

Since certificates need to be renewed periodically, you can set up a cron job to automatically regenerate them.

Sample script:

```bash
#!/bin/bash

# Create the cron job entry
echo "* */1 * * * cd bash generate-certificate-curl.sh generateHostSSHCert https://<PRIVATE-CA-URL>/ host >> /home/cron.log 2>&1" > /tmp/root_crontab

# Load into root's crontab
crontab -u root /tmp/root_crontab

# Optionally start cron service (only if not already running)
systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null
```

## Script Parameters

The `generate-certificate-curl.sh` script accepts the following parameters:

1. **CA_ACTION** (required): The action to perform

   - `generateClientSSHCert`: Generates an SSH certificate for clients
   - `generateHostSSHCert`: Generates an SSH certificate for hosts

2. **CA_URL** (required): URL of the Private CA

3. **ENVIRONMENT** (optional): Machine environment type - "client" or "host" (defaults to "client")

   - **"host"**: For EC2 instances - uses EC2 instance metadata for AWS credentials
   - **"client"**: For local user machines - uses AWS CLI/STS for credentials

4. **AWS_PROFILE** (optional): AWS profile name (defaults to "default")

5. **USER_SSH_DIR** (optional): Path to user's SSH directory (defaults to "/home/$USER/.ssh")

6. **USER_AWS_DIR** (optional): Path to user's AWS directory (defaults to "/home/$USER/.aws")

7. **SYSTEM_SSH_DIR** (optional): Path to system SSH directory (defaults to "/etc/ssh")

8. **AWS_STS_REGION** (optional): AWS region for STS (defaults to "ap-southeast-1")

The `generate-certificate-aws-cli.sh` script accepts the following parameters:

1. **CA_ACTION** (required): The action to perform

   - `generateClientSSHCert`: Generates an SSH certificate for clients
   - `generateHostSSHCert`: Generates an SSH certificate for hosts

2. **ENVIRONMENT** (optional): Machine environment type - "client" or "host" (defaults to "client")

   - **"host"**: For EC2 instances - uses EC2 instance metadata for AWS credentials
   - **"client"**: For local user machines - uses AWS CLI/STS for credentials

3. **AWS_PROFILE** (optional): AWS profile name (defaults to "default")

4. **USER_SSH_DIR** (optional): Path to user's SSH directory (defaults to "/home/$USER/.ssh")

5. **SYSTEM_SSH_DIR** (optional): Path to system SSH directory (defaults to "/etc/ssh")

6. **LAMBDA_REGION** (optional): AWS region where the Lambda function is deployed (defaults to "us-west-2")

7. **CA_LAMBDA_FUNCTION_NAME** (optional): Name of the Lambda function (defaults to "privateCA")

8. **AWS_STS_REGION** (optional): AWS region for STS operations (defaults to "ap-southeast-1")

## Important Notes

- **Certificate Type**: Determined by the `CA_ACTION` parameter (`generateClientSSHCert` or `generateHostSSHCert`)
- **Permissions**: Host certificates require sudo privileges for system directory access

## Client Environment Limitations

**Important**: Client environments can only generate client certificates because they don't have a public IP address.

- **Host Certificate Requirements**: Host certificates require the public IP address as a hostname when issuing the certificate. Due to the absence of a public IP address, client environments cannot generate host certificates
- **Recommendation**: Use client environments exclusively for generating client certificates, and use host environments (such as EC2 instances with public IPs) for generating host certificates

## Directory Structure

- `generate-certificate-curl.sh`: Main script for certificate generation using curl
- `generate-certificate-aws-cli.sh`: Alternative script using AWS CLI
- `aws-auth-header.py`: Python helper for generating AWS authentication headers
- `Dockerfile`: Docker container configuration
