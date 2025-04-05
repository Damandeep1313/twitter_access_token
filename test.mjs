/**
 * server.js
 *
 * Run:  node server.js
 *
 * Then visit: http://127.0.0.1:3000/start
 */

const express = require('express');
const axios = require('axios');
const dotenv = require('dotenv');
const crypto = require('crypto');
const fetch = require('node-fetch');  // Or remove if you have Node 18+ with built-in fetch

dotenv.config();

const app = express();
const port = 3000;
app.use(express.json());

// Read your Twitter OAuth credentials from .env
// (Make sure CONSUMER_KEY and CONSUMER_SECRET are set in your .env)
const CLIENT_ID = process.env.CONSUMER_KEY; 
const CLIENT_SECRET = process.env.CONSUMER_SECRET;
const REDIRECT_URI = 'https://serverless.on-demand.io/apps/tweet/callback';
const TOKEN_URL = 'https://api.twitter.com/2/oauth2/token';

// -----------------------------------------------------------------------
// PKCE Helper Functions
// -----------------------------------------------------------------------
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
  // 1. Generate a random code_verifier
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  // 2. Hash it and base64URL-encode for the code_challenge
  const challengeBuffer = sha256(codeVerifier);
  const codeChallenge = base64URLEncode(challengeBuffer);

  return { codeVerifier, codeChallenge };
}

// -----------------------------------------------------------------------
// 1) /start route
//    - Generate PKCE pair
//    - Store code_verifier in `state` param
//    - Redirect user to Twitter
// -----------------------------------------------------------------------
app.get('/start', (req, res) => {
  // Generate the PKCE pair
  const { codeVerifier, codeChallenge } = generatePKCEPair();

  // For a quick demo, embed the codeVerifier in the "state" param (as Base64 JSON).
  // In production, store it in a server session or encrypt it.
  const stateObj = { cv: codeVerifier };
  const encodedState = Buffer.from(JSON.stringify(stateObj)).toString('base64');

  // Build the Twitter OAuth 2.0 Authorization URL
  const twitterAuthURL = new URL('https://twitter.com/i/oauth2/authorize');
  twitterAuthURL.searchParams.set('response_type', 'code');
  twitterAuthURL.searchParams.set('client_id', CLIENT_ID);
  twitterAuthURL.searchParams.set('redirect_uri', REDIRECT_URI);
  twitterAuthURL.searchParams.set('scope', 'tweet.read tweet.write users.read offline.access');
  twitterAuthURL.searchParams.set('state', encodedState);
  twitterAuthURL.searchParams.set('code_challenge', codeChallenge);
  twitterAuthURL.searchParams.set('code_challenge_method', 'S256');

  console.log('Redirecting to Twitter OAuth:', twitterAuthURL.toString());
  return res.redirect(twitterAuthURL.toString());
});

// -----------------------------------------------------------------------
// 2) /apps/tweet/callback route
//    - Twitter redirects here after user login/approval
//    - We decode the `state` (to get our code_verifier)
//    - Exchange the authorization code for tokens
// -----------------------------------------------------------------------
app.get('/apps/tweet/callback', async (req, res) => {
  console.log('Callback received:', req.query);

  const authorizationCode = req.query.code;
  const error = req.query.error;
  const encodedState = req.query.state || '';

  if (error) {
    console.error('Error in callback:', error);
    return res.send('Error: ' + error);
  }

  if (!authorizationCode) {
    console.error('Authorization code not found in query params.');
    return res.send('Authorization code not found. Please try again.');
  }

  // Decode the state param to retrieve the code_verifier
  let codeVerifier;
  try {
    const decodedBuf = Buffer.from(encodedState, 'base64');
    const { cv } = JSON.parse(decodedBuf.toString());
    codeVerifier = cv;
  } catch (err) {
    console.error('Error decoding state param:', err);
    return res.send('Invalid state parameter.');
  }

  // Exchange authorization code + code_verifier for tokens
  try {
    const tokenResponse = await getAccessToken(authorizationCode, codeVerifier);
    console.log('Access Token Response:', tokenResponse);

    if (tokenResponse.access_token) {
      const bearerToken = `Bearer ${tokenResponse.access_token}`;
      console.log('Bearer Token:', bearerToken);
      res.send(`Authorization successful! Access Token: ${bearerToken}`);
    } else {
      res.send('Failed to retrieve access token: ' + JSON.stringify(tokenResponse));
    }
  } catch (err) {
    console.error('Error getting access token:', err);
    res.send('Error retrieving access token. Please try again.');
  }
});

// -----------------------------------------------------------------------
// Exchange authorization code for access token
// -----------------------------------------------------------------------
async function getAccessToken(code, codeVerifier) {
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
  };

  console.log('[DEBUG] Exchanging code for token:', {
    code,
    codeVerifier,
    redirect_uri: REDIRECT_URI,
  });

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  try {
    const response = await axios.post(TOKEN_URL, body.toString(), { headers });
    return response.data; 
  } catch (error) {
    console.error('Error fetching access token:', 
                  error.response ? error.response.data : error.message);
    throw error;
  }
}

// -----------------------------------------------------------------------
// Optional: Write a tweet using the retrieved access token
// -----------------------------------------------------------------------
async function writeTweet(accessToken, tweet) {
  const url = 'https://api.twitter.com/2/tweets';

  // Using fetch, but you can use axios if preferred
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ text: tweet })
  });

  const data = await response.json();
  return data;
}

// -----------------------------------------------------------------------
// POST /post/tweet
//    - Expects a JSON body with { "text": "Hello world" }
//    - Expects an Authorization header with "Bearer <ACCESS_TOKEN>"
// -----------------------------------------------------------------------
app.post("/post/tweet", async (req, res) => {
  console.log('Incoming request body:', req.body);

  // Extract the access token from the Authorization header
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(400).json({ error: 'Authorization header is missing.' });
  }

  // The token is what's after "Bearer "
  const accessToken = authHeader.split(' ')[1];
  if (!accessToken) {
    return res.status(400).json({ error: 'Access token is missing in Authorization header.' });
  }

  // Get the tweet text from the request body
  const { text } = req.body;

  try {
    const tweetResponse = await writeTweet(accessToken, text);
    console.log('Tweet API response:', tweetResponse);

    res.json({ message: 'Tweet sent successfully.', tweetResponse });
  } catch (error) {
    console.error('Error posting tweet:', error);
    res.status(500).json({ error: 'Error posting tweet. Please try again.' });
  }
});

// -----------------------------------------------------------------------
// Start the server
// -----------------------------------------------------------------------
app.listen(port, () => {
  console.log(`Server is running on http://127.0.0.1:${port}`);
  console.log(`Visit http://127.0.0.1:${port}/start to begin the OAuth flow.`);
});
