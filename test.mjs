import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const verifierMap = new Map(); // key: state, value: code_verifier

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

// === Step 1: Start Route ===
app.get('/start', (req, res) => {
  const { codeVerifier, codeChallenge } = generatePKCE();
  const state = crypto.randomBytes(12).toString('hex');

  verifierMap.set(state, codeVerifier); // Store for later

  const url = new URL('https://twitter.com/i/oauth2/authorize');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', process.env.CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.REDIRECT_URI);
  url.searchParams.set('scope', process.env.SCOPES);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  res.send(`<h2>Click below to authorize:</h2><a href="${url.toString()}">${url.toString()}</a>`);
});

// === Step 2: Callback Route ===
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code || !state || !verifierMap.has(state)) {
    return res.status(400).send("Missing or invalid code/state.");
  }

  const codeVerifier = verifierMap.get(state);
  verifierMap.delete(state); // Clean up memory

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

    const data = await response.json();

    if (!response.ok) {
      console.error('[TOKEN ERROR]', data);
      return res.status(500).send(`Token error: ${JSON.stringify(data)}`);
    }

    res.send(`<h1>Success!</h1><p><strong>Bearer Access Token:</strong> Bearer ${data.access_token}</p>`);
  } catch (err) {
    console.error('[EXCHANGE ERROR]', err);
    res.status(500).send('Exchange failed.');
  }
});

app.listen(PORT, () => {
  console.log(`✅ Live on port ${PORT}`);
});
