import express from 'express';
import fetch from 'node-fetch'; // If Node 18+, you can remove and use global fetch

const app = express();
const port = 3000;

// --------------------------------------------------------------------
// Fill in your actual OAuth2 client ID & client secret from Twitter
// (NOT the old OAuth1.0 "Consumer Key/Secret")
// --------------------------------------------------------------------
const CLIENT_ID = 'YOUR_TWITTER_OAUTH2_CLIENT_ID_HERE';
const CLIENT_SECRET = 'YOUR_TWITTER_OAUTH2_CLIENT_SECRET_HERE';

// This callback must match EXACTLY the Dev Portal Callback URL
const REDIRECT_URI = 'http://127.0.0.1:3000/callback';

// We'll use the same string for both code_challenge and code_verifier
// with method=plain (super insecure, but simplest).
const codeChallenge = 'challenge';
const codeVerifier = 'challenge';

// Scopes can be adjusted
const SCOPES = 'tweet.read tweet.write users.read offline.access';

// --------------------------------------------------------------------
// 1) /start route
//    Builds a plain-code-challenge URL, redirects user to Twitter
// --------------------------------------------------------------------
app.get('/start', (req, res) => {
  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', SCOPES);
  authUrl.searchParams.set('state', 'whateverYouWant');    // Optional
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'plain');

  console.log('[START] Redirecting to Twitter:', authUrl.toString());
  return res.redirect(authUrl.toString());
});

// --------------------------------------------------------------------
// 2) /callback route
//    Twitter redirects here with ?code=...
//    Exchange that code for tokens, using code_verifier="challenge"
// --------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  console.log('[CALLBACK] Query:', req.query);
  const { code, error, error_description } = req.query;

  if (error) {
    return res.send(`Error from Twitter: ${error} - ${error_description || ''}`);
  }
  if (!code) {
    return res.send('No "code" param received from Twitter.');
  }

  try {
    const tokenData = await exchangeCodeForToken(code, codeVerifier);
    console.log('[CALLBACK] Token data:', tokenData);

    if (tokenData.access_token) {
      // Show the user their Bearer token
      const bearer = `Bearer ${tokenData.access_token}`;
      return res.send(`
        <h1>Success!</h1>
        <p>This is your <strong>insecure</strong> OAuth 2.0 Bearer token:</p>
        <code>${bearer}</code>
      `);
    } else {
      return res.send(`Failed to retrieve access token. Response: ${JSON.stringify(tokenData)}`);
    }
  } catch (err) {
    console.error('[CALLBACK] Exchange error:', err);
    return res.send(`Error exchanging code: ${err.message}`);
  }
});

// --------------------------------------------------------------------
// 3) Helper to exchange code for token (with code_verifier="challenge")
// --------------------------------------------------------------------
async function exchangeCodeForToken(code, codeVerifier) {
  const tokenUrl = 'https://api.twitter.com/2/oauth2/token';

  // For OAuth2 "Client ID" / "Client Secret" Basic Auth
  const basicAuth = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

  // Body
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier
  });

  console.log('[TOKEN] code:', code, 'code_verifier:', codeVerifier);

  const resp = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': basicAuth
    },
    body: params
  });

  if (!resp.ok) {
    const errData = await resp.json();
    throw new Error(`Token request failed (HTTP ${resp.status}): ${JSON.stringify(errData)}`);
  }
  return resp.json();
}

// --------------------------------------------------------------------
// Start the server
// --------------------------------------------------------------------
app.listen(port, () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
  console.log(`Go to http://127.0.0.1:${port}/start to begin.`)
});
