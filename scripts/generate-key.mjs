// Prints a new private RSA JWK for the SIGNING_KEY secret:
//   npm run generate-key | npx wrangler secret put SIGNING_KEY
import * as jose from 'jose';

const { privateKey } = await jose.generateKeyPair('RS256', { extractable: true });
process.stdout.write(JSON.stringify(await jose.exportJWK(privateKey)));
