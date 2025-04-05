/**
 * insecure-plain.js
 *
 * HOW TO RUN:
 *   1) npm install express node-fetch
 *   2) node insecure-plain.js
 *   3) Open http://127.0.0.1:3000/start in your browser
 */

import express from 'express';
import fetch from 'node-fetch'; // If Node 18+, you can remove this and use global fetch

const app = express();
const port = 3000;

// ------------------------------------------------------------------------
// REPLACE THESE with your actual OAuth2 credentials from Twitter Dev Portal
// (NOT the old "API Key" / "API Secret" from OAuth 1.0a)
// ------------------------------------------------------------------------
const CLIENT_ID = 'aWhxbmxMTDFQRXlaTG1GeDQ5NFU6MTpjaQ';
const CLIENT_SECRET = 'hZICYkSqCKJtfJKfXRvEt35X98dqV1cu6MPPi-KWYbuopPCtPn';

// This must match exactly the "Callback URL" in the Twitter Dev Portal
const REDIRECT_URI = 'http://127.0.0.1:3000/callback';

// We will do the simplest possible code challenge: plain text
const codeChallenge = 'challenge';
const codeVerifier = 'challenge'; // same string as above, so "plain" is acceptable

// Some default scopes to allow tweets, reads, etc.
const SCOPES = 'tweet.read tweet.write users.read offline.access';

// ------------------------------------------------------------------------
// 1) /start route: build the Twitter authorize URL, redirect user
// ------------------------------------------------------------------------
app.get('/start', (req, res) => {
  // Build the OAuth2 authorize URL
  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', 'someStateValue');  // optional
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'plain'); // insecure

  console.log('[/start] Redirecting to Twitter:', authUrl.toString());
  return res.redirect(authUrl.toString());
});

// ------------------------------------------------------------------------
// 2) /callback route: Twitter redirects here with ?code=...
//    Exchange that code for an access token, using code_verifier='challenge'
// ------------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  console.log('[/callback] Query params:', req.query);
  const { code, error, error_description } = req.query;

  // If Twitter returned an error, show it
  if (error) {
    return res.send(`Error from Twitter: ${error}, ${error_description || ''}`);
  }

  // If no code found, can't proceed
  if (!code) {
    return res.send('No "code" param received. Check your Dev Portal Callback URL settings.');
  }

  try {
    // Exchange the code for a token
    const tokenData = await exchangeCodeForToken(code, codeVerifier);
    console.log('[/callback] tokenData:', tokenData);

    // If success
    if (tokenData.access_token) {
      const bearer = `Bearer ${tokenData.access_token}`;
      return res.send(`
        <h1>Success!</h1>
        <p>Your (insecure) bearer token:</p>
        <code>${bearer}</code>
      `);
    } else {
      return res.send(`Failed to get access_token. Full response: ${JSON.stringify(tokenData)}`);
    }
  } catch (err) {
    console.error('[/callback] Error exchanging code:', err);
    return res.send(`Error: ${err.message}`);
  }
});

// ------------------------------------------------------------------------
// Exchange code for token
// (Uses code_verifier='challenge', code_challenge_method=plain)
// ------------------------------------------------------------------------
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';

  // Basic Auth header: "Basic base64(CLIENT_ID:CLIENT_SECRET)"
  const authHeader = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  const bodyParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  console.log('[exchangeCodeForToken] POST to /2/oauth2/token with code=', code);

  const resp = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': authHeader,
    },
    body: bodyParams
  });

  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    throw new Error(`Token request failed (HTTP ${resp.status}): ${JSON.stringify(errData)}`);
  }

  return resp.json();
}

// ------------------------------------------------------------------------
// Start the server
// ------------------------------------------------------------------------
app.listen(port, () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
  console.log(`Go to http://127.0.0.1:${port}/start to begin (insecure) OAuth flow.`);
});
