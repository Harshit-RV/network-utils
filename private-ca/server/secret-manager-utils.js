import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

export const getSecret = async (secretRegion, secretId) => {
  const client = new SecretsManagerClient({ region: secretRegion });
  const command = new GetSecretValueCommand({ SecretId: secretId });
  const response = await client.send(command);
  const secret = JSON.parse(response.SecretString);
  return secret;
}


/**
export const updateSecret = async (secretRegion, secretId, key, value) => {
  var secretsmanager = new aws.SecretsManager({ region: secretRegion });
  let secret = await getSecret(secretId);
  secret[key] = value;
  var params = {
    SecretId: secretId, 
    SecretString: JSON.stringify(secret)
  };
  const updateRes = await secretsmanager.updateSecret(params).promise();
  return updateRes;
}
**/
