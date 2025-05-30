import { signHostSSHCertificate } from './generate-host-ssh-cert.js';
import { signClientSSHCertificate } from './generate-client-ssh-cert.js';
import { getCallerIdentity } from './get-caller-identity.js';
import { generateClientX509Cert } from './generate-client-x509-cert.js';
import { getSecret } from './secret-manager-utils.js';
const AWS_SCRTS_REGION = process.env.AWS_SCRTS_REGION;

export const handler = async (event) => {
  
  event=JSON.parse(event.body);
  
  // auth
  const callerIdentity = await getCallerIdentity(event);

  // secret
  const secret = await getSecret(AWS_SCRTS_REGION, 'privateCA');
  
  // action
  switch(event.action) {
    case "generateHostSSHCert":
      const hostSSHCert = await signHostSSHCertificate(callerIdentity, secret, event.certPubkey, event.publicIp);
      return {
        statusCode: 200,
        body: "{\"certificate\" : \""+Buffer.from(hostSSHCert).toString('base64')+"\", \"user_ca.pub\": \""+secret["user_ca.pub"]+"\"}"
      };
    case "generateClientSSHCert":
      const clientSSHCert = await signClientSSHCertificate(callerIdentity, secret, event.certPubkey);
      return {
        statusCode: 200,
        body: "{\"certificate\" : \""+Buffer.from(clientSSHCert).toString('base64')+"\", \"host_ca.pub\": \""+secret["host_ca.pub"]+"\"}"
      };
    default:
      console.log("Invalid Action")
      return {
        statusCode: 400,
        body: JSON.stringify('Invalid Action')
      };
  } 
};
