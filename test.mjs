import express from 'express';
import fetch from 'node-fetch';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 3000;
const verifierMap = new Map(); // key: tokenId, value: { codeVerifier, codeChallenge, state }

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

// === /start → Generates secure link ===
app.get('/start', (req, res) => {
  const { codeVerifier, codeChallenge } = generatePKCE();
  const state = crypto.randomBytes(12).toString('hex');
  const tokenId = crypto.randomBytes(12).toString('hex');

  verifierMap.set(tokenId, { codeVerifier, codeChallenge, state });

  const authLink = `${req.protocol}://${req.get('host')}/auth/${tokenId}`;
  res.send(`
    <h2>Click below to authenticate with Twitter securely</h2>
    <a href="${authLink}">${authLink}</a>
  `);
});

// === /auth/:tokenId → Redirect to Twitter Auth URL ===
app.get('/auth/:tokenId', (req, res) => {
  const { tokenId } = req.params;
  const stored = verifierMap.get(tokenId);

  if (!stored) return res.status(404).send("Invalid or expired token.");

  const { codeChallenge, state } = stored;

  const authUrl = new URL('https://twitter.com/i/oauth2/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', process.env.CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', process.env.REDIRECT_URI);
  authUrl.searchParams.set('scope', process.env.SCOPES);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  res.redirect(authUrl.toString());
});

// === /callback → Handle redirect from Twitter ===
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  const tokenEntry = [...verifierMap.entries()].find(([, v]) => v.state === state);
  if (!tokenEntry) return res.status(400).send("Missing or invalid state.");

  const [tokenId, { codeVerifier }] = tokenEntry;
  verifierMap.delete(tokenId);

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

    res.send(`
      <h1>✅ Success</h1>
      <p><strong>Bearer Access Token:</strong> Bearer ${data.access_token}</p>
    `);
  } catch (err) {
    console.error('[EXCHANGE ERROR]', err);
    res.status(500).send('Token exchange failed.');
  }
});

// === Start Server ===
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
