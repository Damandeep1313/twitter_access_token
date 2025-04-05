import 'dotenv/config';
import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';

const {
  CLIENT_ID,
  CLIENT_SECRET,
  PORT = 3000,
  REDIRECT_URI,
  SCOPES
} = process.env;

if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
  console.error('[ERROR] Missing CLIENT_ID, CLIENT_SECRET, or REDIRECT_URI in .env');
  process.exit(1);
}

const app = express();

/**
 * Utility: base64-url-encode
 */
function base64URLEncode(buffer) {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Utility: S256 code challenge from a codeVerifier
 */
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

/**
 * GET / 
 * 1) Generate a codeVerifier & codeChallenge
 * 2) Store codeVerifier in the 'state' param so we don't need a session
 * 3) Redirect user to Twitter OAuth
 */
app.get('/', (req, res) => {
  // 1. Generate PKCE
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  // 2. Put the codeVerifier in `state` (as JSON), so we can retrieve it in the callback
  const rawState = { cv: codeVerifier };
  const encodedState = encodeURIComponent(JSON.stringify(rawState));

  // 3. Build the Twitter Auth URL
  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES.replace(/,/g, ' ')); // space-delimited
  authUrl.searchParams.set('state', encodedState);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  console.log('[START] Redirecting user to:', authUrl.toString());
  res.redirect(authUrl.toString());
});

/**
 * GET /callback
 * 1) Parse code & state from query
 * 2) Decode the codeVerifier from state
 * 3) Exchange code for token
 * 4) Show token to user
 */
app.get('/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    console.error('[CALLBACK] Error from Twitter:', error, error_description || '');
    return res.status(400).send(`Error: ${error} - ${error_description || ''}`);
  }
  if (!code || !state) {
    return res.status(400).send('Missing "code" or "state" in the callback.');
  }

  // 2. Decode the codeVerifier from state
  let codeVerifier;
  try {
    const parsedState = JSON.parse(decodeURIComponent(state));
    codeVerifier = parsedState.cv;
    if (!codeVerifier) {
      return res.status(400).send('No codeVerifier found in state.');
    }
  } catch (err) {
    console.error('[CALLBACK] Invalid state JSON:', state, err);
    return res.status(400).send('Invalid state format.');
  }

  // 3. Exchange code for a token
  console.log('[CALLBACK] Exchanging code for token...');
  try {
    const tokenData = await exchangeCodeForToken(code, codeVerifier);
    console.log('[CALLBACK] Token response:', tokenData);

    // 4. Show token
    res.send(`
      <h2>Success!</h2>
      <p><strong>Access Token:</strong> ${tokenData.access_token}</p>
      <p><strong>Refresh Token:</strong> ${tokenData.refresh_token || 'none'}</p>
      <p>Use this token to access Twitter's v2 APIs.</p>
    `);
  } catch (tokenErr) {
    console.error('[CALLBACK] Error exchanging token:', tokenErr);
    res.status(500).send('Failed to exchange code for token. Check server logs.');
  }
});

/**
 * Exchange the authorization code for an access token at /2/oauth2/token
 */
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';
  const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  const bodyParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier
  });

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': authHeader
    },
    body: bodyParams
  });

  if (!response.ok) {
    const errorBody = await response.json();
    throw new Error(`Token exchange failed (${response.status}): ${JSON.stringify(errorBody)}`);
  }

  return response.json();
}

// Listen on specified port (may or may not be used depending on hosting environment)
app.listen(PORT, () => {
  console.log(`[INFO] Server running on port ${PORT}`);
});
