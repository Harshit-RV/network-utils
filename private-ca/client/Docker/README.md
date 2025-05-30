# Certificate Generator Docker Container

This Docker container runs a script that generates SSH certificates using a Private Certificate Authority (CA) hosted on AWS Lambda. The script provides options to generate SSH certificates for hosts and clients.

## Prerequisites

- Docker: Install Docker on your system. Refer to the [Docker documentation](https://docs.docker.com/get-docker/) for installation instructions.

## Usage

1. Clone this repository or download the Dockerfile and the `generate-certificate.sh` script.

2. Build the Docker image using the following command:

   ```shell
   docker build -t generate-certificate .
   ```

3. Run the Docker container with the desired parameters. The container requires specific environment variables to be set:

   - `CA_ACTION`: Specify the action to perform. Possible values are:

     - `generateHostSSHCert`: Generates an SSH certificate for the host.
     - `generateClientSSHCert`: Generates an SSH certificate for a client.

   - `CA_LAMBDA_URL`: The URL of the AWS Lambda function hosting the Private CA.

   Optional environment variables:

   - `USER_SSH_DIR`: The path to the directory where the user's SSH keys will be stored. Defaults to "/home/$USER/.ssh".
   - `SYSTEM_SSH_DIR`: The path to the system's SSH directory. Defaults to "/etc/ssh".
   - `AWS_STS_REGION`: The AWS region for the STS (Security Token Service). Defaults to "ap-south-1".
   - `AWS_PROFILE`: The AWS profile for running aws commands. Defaults to "default"

   ```shell
   docker run -it --rm \
       -v /path/to/ssh/directory:/home/$USER/.ssh \
       -v /path/to/system/ssh/directory:/etc/ssh \
       -e CA_ACTION=<action> \
       -e CA_LAMBDA_URL=<lambda_url> \
       -e USER_SSH_DIR=<user_ssh_directory> \
       -e SYSTEM_SSH_DIR=<system_ssh_directory> \
       -e AWS_STS_REGION=<sts_region> \
       -e AWS_PROFILE=<aws_profile> \
       generate-certificate
   ```

4. The script will generate the necessary certificates based on the provided action and store them in the specified directories.

## Script Explanation

The `generate-certificate.sh` script performs the following tasks:

- Parses command-line arguments and checks for the specified CA action.
- Checks if the required SSH or X.509 certificate already exists and is valid. If not, generates new certificates.
- Retrieves temporary AWS credentials using STS (Security Token Service).
- Generates authentication headers required for making authenticated AWS API requests.
- Invokes the AWS Lambda function to generate the certificate based on the specified action.
- Stores the generated certificate in the appropriate directory.

Make sure to adjust the script parameters and environment variables according to your specific requirements.
