import 'dotenv/config'
import fs from 'fs';
import axios from 'axios';
import crypto from 'crypto';
import * as jose from 'jose';

const domain = process.env.AUTH0_DOMAIN;
const clientId = process.env.AUTH0_CLIENT_ID;
const audience = process.env.AUTH0_AUDIENCE;
const privateKeyPath = process.env.PRIVATE_KEY_PATH;

const privateKeyData = fs.readFileSync(privateKeyPath, 'utf8');
const privateKey = crypto.createPrivateKey(privateKeyData);

async function getAccessToken() {
    try {
        const tokenEndpoint = `https://${domain}/oauth/token`;

        const assertion = await new jose.SignJWT({
            iss: clientId,
            sub: clientId,
            aud: tokenEndpoint,
            jti: crypto.randomUUID(),
        })
            .setProtectedHeader({ alg: 'RS256' })
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(privateKey);

        const response = await axios.post(tokenEndpoint, {
            client_id: clientId,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion: assertion,
            grant_type: 'client_credentials',
            audience: audience
        });

        return response.data.access_token;
    } catch (error) {
        console.error('Error getting access token:', error.response?.data || error.message);
        throw error;
    }
}

async function main() {
   const token = await getAccessToken();
   console.log(token);
}

main();
