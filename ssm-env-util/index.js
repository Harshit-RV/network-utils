import * as dotenv from 'dotenv';
import { getParameter } from './get-parameters.js';

export async function populateEnv (region, ssmPrefix = "", ssmSuffix = "") {
  dotenv.config();
  let keys = Object.keys(process.env);
  let missingKeys = [];
  for (let key of keys){
    if(!process.env[key])
      missingKeys.push(key);
  }
  if (missingKeys.length > 0){
    let parameterValues = await getParameter(missingKeys, region, ssmPrefix, ssmSuffix);
    for(let key of missingKeys) {
      process.env[key] = parameterValues[ssmPrefix + key + ssmSuffix];
    }
  }
};
