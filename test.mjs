import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const verifierMap = new Map();

function log(section, message, obj = null) {
  console.log(`\n🔹 [${section}] ${message}`);
  if (obj) console.log(obj);
}

// === PKCE Helper ===
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}
function base64URLEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function generatePKCE() {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));
  return { codeVerifier, codeChallenge };
}

// === /start ===
app.get('/start', (req, res) => {
  const { codeVerifier, codeChallenge } = generatePKCE();
  const state = crypto.randomBytes(12).toString('hex');
  const tokenId = crypto.randomBytes(12).toString('hex');

  verifierMap.set(tokenId, { codeVerifier, codeChallenge, state });

  const authLink = `${req.protocol}://${req.get('host')}/auth/${tokenId}`;

  log('START', `Generated tokenId: ${tokenId}, state: ${state}`);
  log('START', `Auth link ready: ${authLink}`);

  res.send(`
    <h2>Click below to authenticate with Twitter</h2>
    <a href="${authLink}">${authLink}</a>
  `);
});

// === /auth/:tokenId ===
app.get('/auth/:tokenId', (req, res) => {
  const { tokenId } = req.params;
  const stored = verifierMap.get(tokenId);
  if (!stored) {
    log('AUTH', `Invalid tokenId: ${tokenId}`);
    return res.status(404).send("Invalid or expired token.");
  }

  const { codeChallenge, state } = stored;

  const url = new URL('https://twitter.com/i/oauth2/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', process.env.CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.REDIRECT_URI);
  url.searchParams.set('scope', process.env.SCOPES);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  log('AUTH', `Redirecting tokenId ${tokenId} → Twitter`);
  res.redirect(url.toString());
});

// === /callback ===
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  const tokenEntry = [...verifierMap.entries()].find(([, v]) => v.state === state);
  if (!tokenEntry) {
    log('CALLBACK', `Invalid or expired state: ${state}`);
    return res.status(400).send("Missing or invalid state.");
  }

  const [tokenId, { codeVerifier }] = tokenEntry;
  verifierMap.delete(tokenId);

  log('CALLBACK', `Exchanging code for access token (state: ${state}, tokenId: ${tokenId})`);

  try {
    const response = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.REDIRECT_URI,
        code_verifier: codeVerifier
      })
    });

    const tokenData = await response.json();
    log('CALLBACK', 'Token response received:', tokenData);

    if (!response.ok) {
      log('CALLBACK ERROR', 'Token exchange failed', tokenData);
      return res.status(500).send(`Token error: ${JSON.stringify(tokenData)}`);
    }

    // Tweet posting
    const tweetText = "🚀 This tweet was posted via my OAuth 2.0 PKCE flow!";
    log('TWEET', 'Posting tweet...');

    const tweetResponse = await fetch("https://api.twitter.com/2/tweets", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${tokenData.access_token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ text: tweetText })
    });

    const tweetResult = await tweetResponse.json();
    log('TWEET RESULT', '', tweetResult);

    if (!tweetResponse.ok) {
      log('TWEET ERROR', 'Tweet failed', tweetResult);
      return res.status(500).send(`Tweet failed: ${JSON.stringify(tweetResult)}`);
    }

    res.send(`
      <h1>✅ Success!</h1>
      <p><strong>Bearer Access Token:</strong> Bearer ${tokenData.access_token}</p>
      <p>✅ Tweet posted!</p>
      <p>🔗 <a href="https://twitter.com/i/web/status/${tweetResult.data.id}" target="_blank">View Tweet</a></p>
    `);
  } catch (err) {
    log('FATAL ERROR', 'Exception during callback', err);
    res.status(500).send('Unexpected error occurred.');
  }
});

app.listen(PORT, () => {
  log('SERVER', `Server running at http://localhost:${PORT}`);
});
