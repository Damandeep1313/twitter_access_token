//
// test.mjs
//
// Run with: node test.mjs
// Make sure .env is in the same directory and you installed dotenv, express, node-fetch, open.
//

import path from 'path';
import fs from 'fs';
import 'dotenv/config';  // Make sure this is at the VERY TOP, before accessing process.env
import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';
import open from 'open';

// -------------------------------------------------------------------
// 0. Debug: Check if .env file even exists in this directory
// -------------------------------------------------------------------
const envPath = path.resolve('.env');
console.log('[DEBUG] Looking for .env at:', envPath);
console.log('[DEBUG] .env file exists?', fs.existsSync(envPath));

// -------------------------------------------------------------------
// 1. Read environment variables and log them
// -------------------------------------------------------------------
const {
  CLIENT_ID,
  CLIENT_SECRET,
  PORT,
  REDIRECT_URI,
  SCOPES
} = process.env;

console.log('[DEBUG] CLIENT_ID:', CLIENT_ID);
console.log('[DEBUG] CLIENT_SECRET:', CLIENT_SECRET ? '***REDACTED***' : 'undefined');
console.log('[DEBUG] PORT:', PORT);
console.log('[DEBUG] REDIRECT_URI:', REDIRECT_URI);
console.log('[DEBUG] SCOPES:', SCOPES);

// -------------------------------------------------------------------
// 2. If any critical env var is missing, log that and exit early
// -------------------------------------------------------------------
if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !PORT) {
  console.error('[ERROR] One or more required env vars are missing. Fix your .env file.');
  process.exit(1);
}

// -------------------------------------------------------------------
// 3. Set up Express server
// -------------------------------------------------------------------
const app = express();

// We'll store the code_verifier in memory for demo
let codeVerifierGlobal = '';

// PKCE helpers
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

function base64URLEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function generatePKCEPair() {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const challengeBuffer = sha256(codeVerifier);
  const codeChallenge = base64URLEncode(challengeBuffer);
  return { codeVerifier, codeChallenge };
}

// -------------------------------------------------------------------
// 4. The /callback route (Twitter will redirect here)
// -------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  console.log('[CALLBACK] Query Params:', req.query);

  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error('[CALLBACK] Received error param from Twitter:', error, error_description || '');
    return res.send(`Twitter Error: ${error} - ${error_description || ''}`);
  }

  if (!code) {
    console.error('[CALLBACK] No authorization code received!');
    return res.send('No code parameter in the query!');
  }

  // Exchange the code for an access token
  console.log('[CALLBACK] Exchanging code for token...');
  try {
    const tokenData = await exchangeCodeForToken(code, codeVerifierGlobal);
    console.log('[CALLBACK] Token Data:', tokenData);

    // Display them in the browser for quick debug
    res.send(`
        <h1>Success!</h1>
        <p><strong>Bearer Access Token:</strong> Bearer ${tokenData.access_token}</p>
      `);      
  } catch (err) {
    console.error('[CALLBACK] Error while exchanging code:', err);
    res.send(`Error exchanging code: ${err.message}`);
  }
});

// -------------------------------------------------------------------
// 5. Start server and begin OAuth flow
// -------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Server listening on http://127.0.0.1:${PORT}`);
  startOAuthFlow();
});

// -------------------------------------------------------------------
// 6. startOAuthFlow()
//     - Generates PKCE
//     - Builds authorize URL
//     - Opens browser
// -------------------------------------------------------------------
function startOAuthFlow() {
  const { codeVerifier, codeChallenge } = generatePKCEPair();
  codeVerifierGlobal = codeVerifier;

  // Build the authorization URL
  const state = 'randomState123';
  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES); // space or plus separated is fine
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log('[OAUTH FLOW] Opening browser to:', authUrl.toString());
  open(authUrl.toString());
}

// -------------------------------------------------------------------
// 7. exchangeCodeForToken()
//     - Exchanges the code at /2/oauth2/token
// -------------------------------------------------------------------
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';

  console.log('[TOKEN] Exchanging code for token with:');
  console.log('       code:', code);
  console.log('       codeVerifier:', codeVerifier);
  console.log('       redirect_uri:', REDIRECT_URI);

  // Basic Auth header
  const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  // Body
  const bodyParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  // Make request
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': authHeader
    },
    body: bodyParams
  });

  // Log the response status + text
  console.log('[TOKEN] Response status:', response.status, response.statusText);

  if (!response.ok) {
    const errorData = await response.json();
    console.error('[TOKEN] Error response body:', errorData);
    throw new Error(`Token request failed (HTTP ${response.status}): ${JSON.stringify(errorData)}`);
  }

  // Return JSON
  const data = await response.json();
  return data;
}
