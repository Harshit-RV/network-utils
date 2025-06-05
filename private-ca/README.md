# Private Certificate Authority (CA) for SSH Certificates

This project provides a private Certificate Authority (CA) implementation for generating SSH certificates. It allows you to issue certificates for SSH hosts and users for secure communication.

## Installation

Deploy the resources by running:

```bash
./deploy-server-on-lambda.sh
```

This creates the following resources on AWS:

- Secret to store the keys for signing certificates
- A role for the lambda function
- A policy to be attached to the role giving read access to created secret
- An openSSH layer to facilitate SSH operations
- The lambda function to act as a privateCA

Note: Once the lambda is deployed you will need to manually add an environment variable called `AWS_SCRTS_REGION` to store the region in which AWS secrets for privateCA reside.

## Usage

See [client/README.md](client/README.md) for usage.
