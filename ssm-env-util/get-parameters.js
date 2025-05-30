import {SSMClient, GetParametersCommand } from "@aws-sdk/client-ssm";

  let input = [];
export async function getParameter (keys, region, ssmPrefix = "", ssmSuffix = "") {
  for(let key of keys){
    input.push(ssmPrefix + key + ssmSuffix);
  }
  const client = new SSMClient({
    region: region || process.env.AWS_REGION
  });
  let command = new GetParametersCommand({
    Names: input,
    WithDecryption: true
  });
  const result = await client.send(command);
  return result.Parameters.reduce((acc,val)=>{
    acc[val.Name] = val.Value;
    return acc;
  },{})
};
