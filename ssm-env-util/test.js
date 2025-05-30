import { populateEnv } from './index.js'
import * as dotenv from 'dotenv'
dotenv.config();
populateEnv("PREFIX_", "_SUFFIX").then(() => {
  console.log(process.env.VAR_ONE);
  console.log(process.env.VAR_TWO);
});
