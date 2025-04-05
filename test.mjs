import path from 'path';
import fs from 'fs';
import url from 'url';
import crypto from 'crypto';
import fetch from 'node-fetch'; // or remove if Node 18+
import 'dotenv/config';
import express from 'express';

// -------------------------------------------------------------------
// 0. Confirm .env existence (for debugging only)
// -------------------------------------------------------------------
const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const envPath = path.join(__dirname, '.env');
console.log('[DEBUG] .env file exists?', fs.existsSync(envPath));

// -------------------------------------------------------------------
// 1. Load environment variables
// -------------------------------------------------------------------
const {
  CLIENT_ID,       // Twitter OAuth2 "Client ID"
  CLIENT_SECRET,   // Twitter OAuth2 "Client Secret"
  PORT = 3000,
  // e.g. "tweet.read tweet.write users.read offline.access"
  SCOPES = 'tweet.read tweet.write users.read offline.access',
} = process.env;

// Must match EXACTLY what you've set in the Twitter dev portal
// Example: https://serverless.on-demand.io/apps/access-token/callback
const REDIRECT_URI = process.env.REDIRECT_URI 
  || 'https://serverless.on-demand.io/apps/access-token/callback';

// -------------------------------------------------------------------
// 2. Basic sanity checks
// -------------------------------------------------------------------
if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Missing CLIENT_ID or CLIENT_SECRET in your .env');
  process.exit(1);
}
console.log('[DEBUG] CLIENT_ID:', CLIENT_ID);
console.log('[DEBUG] CLIENT_SECRET:', CLIENT_SECRET ? '***REDACTED***' : 'undefined');
console.log('[DEBUG] PORT:', PORT);
console.log('[DEBUG] REDIRECT_URI:', REDIRECT_URI);
console.log('[DEBUG] SCOPES:', SCOPES);

// -------------------------------------------------------------------
// 3. PKCE Helpers
// -------------------------------------------------------------------
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function base64URLEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generatePKCEPair() {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));
  return { codeVerifier, codeChallenge };
}

// -------------------------------------------------------------------
// 4. Express app
// -------------------------------------------------------------------
const app = express();
app.use(express.json());

// -------------------------------------------------------------------
// 5. /apps/access-token/start
//    - Generate code_verifier and code_challenge
//    - Store code_verifier in "state" param (Base64-encoded JSON)
//    - Redirect the user to Twitter's OAuth page
// -------------------------------------------------------------------
app.get('/apps/access-token/start', (req, res) => {
  const { codeVerifier, codeChallenge } = generatePKCEPair();

  // We embed the codeVerifier in the "state" param 
  // (in production, store it in a signed/encrypted cookie or DB).
  const stateObj = { cv: codeVerifier };
  const encodedState = Buffer.from(JSON.stringify(stateObj)).toString('base64');

  const twitterAuthURL = new URL('https://twitter.com/i/oauth2/authorize');
  twitterAuthURL.searchParams.set('response_type', 'code');
  twitterAuthURL.searchParams.set('client_id', CLIENT_ID);
  twitterAuthURL.searchParams.set('redirect_uri', REDIRECT_URI);
  twitterAuthURL.searchParams.set('scope', SCOPES);
  twitterAuthURL.searchParams.set('state', encodedState);
  twitterAuthURL.searchParams.set('code_challenge', codeChallenge);
  twitterAuthURL.searchParams.set('code_challenge_method', 'S256');

  console.log('[OAUTH FLOW] Redirecting user to:', twitterAuthURL.toString());
  res.redirect(twitterAuthURL.toString());
});

// -------------------------------------------------------------------
// 6. /apps/access-token/callback
//    - Twitter redirects back here
//    - We parse the "state" param to recover code_verifier
//    - We exchange code + code_verifier for tokens
// -------------------------------------------------------------------
app.get('/apps/access-token/callback', async (req, res) => {
  console.log('[CALLBACK] Query params:', req.query);

  const { code, state, error, error_description } = req.query;

  // If Twitter returned an error
  if (error) {
    console.error('[CALLBACK] Error from Twitter:', error, error_description || '');
    return res.send(`Error from Twitter: ${error} - ${error_description || ''}`);
  }

  // If there's no code in the query
  if (!code) {
    console.error('[CALLBACK] Missing code in the query string!');
    return res.send('Missing ?code= param. Check your Twitter App config.');
  }

  // Decode the state param (base64) to recover codeVerifier
  let codeVerifier;
  try {
    const stateJson = Buffer.from(state, 'base64').toString();
    const stateObj = JSON.parse(stateJson);
    codeVerifier = stateObj.cv;
  } catch (err) {
    console.error('[CALLBACK] Error decoding state param:', err);
    return res.send('Invalid state param. Could not decode code_verifier.');
  }

  // Exchange the code + code_verifier for an access token
  try {
    const tokenData = await exchangeCodeForToken(code, codeVerifier);
    console.log('[CALLBACK] Token Data:', tokenData);

    const bearerToken = `Bearer ${tokenData.access_token}`;
    // Show the user the token or store it in DB
    return res.send(`
      <h1>Success!</h1>
      <p>Your Bearer Token:</p>
      <code>${bearerToken}</code>
    `);
  } catch (err) {
    console.error('[CALLBACK] Token exchange error:', err);
    return res.send(`Error exchanging code: ${err.message}`);
  }
});

// -------------------------------------------------------------------
// 7. exchangeCodeForToken
//    - POST to https://api.twitter.com/2/oauth2/token
//    - Include code, code_verifier, redirect_uri
// -------------------------------------------------------------------
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';

  console.log('[TOKEN] Exchanging code for token with:', { code, codeVerifier });

  const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
  const bodyParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': authHeader
    },
    body: bodyParams
  });

  console.log('[TOKEN] Response status:', response.status, response.statusText);

  if (!response.ok) {
    const errorData = await response.json();
    console.error('[TOKEN] Error body:', errorData);
    throw new Error(`Token request failed (HTTP ${response.status}): ${JSON.stringify(errorData)}`);
  }

  return response.json();
}

// -------------------------------------------------------------------
// 8. Start the server
// -------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server listening on http://127.0.0.1:${PORT}`);
  console.log(`Visit http://127.0.0.1:${PORT}/apps/access-token/start to begin the OAuth flow.`);
});
