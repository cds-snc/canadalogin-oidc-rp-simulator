/*
 MIT License

Copyright (c) 2023 - IBM Corp.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 The above copyright notice and this permission notice shall be included in all copies or substantial
 portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// OIDC Relying Party Simulator with PKCE (Proof Key for Code Exchange) Support
// This implementation includes RFC 7636 PKCE for enhanced security in OAuth 2.0 flows

const express = require('express');
const session = require('express-session');
// Create a MemoryStore instance
const memoryStore = new session.MemoryStore();
require('dotenv').config();

const { Issuer, generators } = require('openid-client');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const crpto = require('crypto');
const path = require('path');
const app = express();

const RESPONSE_TYPE = 'code';
const SCOPE = 'openid profile email phone language';


// ========================
// Trust first proxy if behind a proxy (e.g., when using Heroku, Bluemix, AWS ELB, Nginx, etc.)
// see https://expressjs.com/en/guide/behind-proxies.html
app.set('trust proxy', 1);
// ========================

// Init session
app.use(session({
	secret: process.env.SESSION_SECRET,
	resave: true,
	saveUninitialized: false,
	store: memoryStore,
	cookie: {
		secure: process.env.NODE_ENV === 'production',
		sameSite: 'lax',
		httpOnly: process.env.NODE_ENV === 'production'
	},
	genid: (req) => {
		if (req.oidcSID)
			return req.oidcSID;
		else
			return crpto.randomUUID();
	},
}));

//middleware
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'front-end'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get('/health', (req, res) => res.status(200).send('OK'));

// const REDIRECT_URI_PATHNAME = new URL(process.env.REDIRECT_URI).pathname;
const redirectUri = process.env.REDIRECT_URI || 'http://localhost:8080/callback';
const REDIRECT_URI_PATHNAME = new URL(process.env.REDIRECT_URI).pathname;

// Function for create client 
async function setUpOIDC(req, res) {
	try {
		let tenantURL = process.env.IBM_VERIFY_TENANT_URL;
		if (tenantURL?.endsWith('/')) {
			tenantURL = `${tenantURL}oauth2/.well-known/openid-configuration`
		} else {
			tenantURL = `${tenantURL}/oauth2/.well-known/openid-configuration`
		}
		const issuer = await Issuer.discover(tenantURL);
		const client = new issuer.Client({
			client_id: process.env.IBM_VERIFY_RP_CLIENT_ID,
			client_secret: process.env.IBM_VERIFY_RP_CLIENT_SECRET,
			redirect_uris: [process.env.REDIRECT_URI],
			response_types: [RESPONSE_TYPE]
		});

		return client;

	} catch (error) {
		console.error('Error setting up OIDC client:', error);
		handleErrorAndRedirect(req, res, error);
	}

}

// Home route
app.get('/', (req, res) => {
	if (req.session.tokenSet) {
		res.redirect("/dashboard");
	} else {
		res.render('index')
	}
});

// Login require
// store the code_verifier in your framework's session mechanism, if it is a cookie based solution
// it should be httpOnly (not readable by javascript) and encrypted.

app.get('/login', async (req, res, next) => {

	try {
		const client = await setUpOIDC(req, res);
		
		// Generate PKCE parameters
		const code_verifier = generators.codeVerifier();
		const code_challenge = generators.codeChallenge(code_verifier);
		
		// Store code_verifier in session for later use in token exchange
		req.session.code_verifier = code_verifier;
		
		console.log('PKCE: Generated code_verifier and code_challenge for session');
		
		const url = client.authorizationUrl({
			scope: SCOPE,
			state: generators.state(),
			redirect_uri: process.env.REDIRECT_URI,
			response_types: RESPONSE_TYPE,
			code_challenge,
			code_challenge_method: 'S256',
		});
		res.redirect(url);

	} catch (error) {
		handleErrorAndRedirect(req, res, error);
	}
});


app.get(REDIRECT_URI_PATHNAME, async (req, res) => {

	try {
		const client = await setUpOIDC(req, res);
		const params = client.callbackParams(req);
		
		// Retrieve the code_verifier from session for PKCE
		const code_verifier = req.session.code_verifier;
		if (!code_verifier) {
			throw new Error('Missing code_verifier in session. PKCE flow may have been compromised.');
		}
		
		console.log('PKCE: Using code_verifier from session for token exchange');
		
		const tokenSet = await client.callback(process.env.REDIRECT_URI,
			params, { 
				state: req.query.state, 
				nonce: req.session.nonce,
				code_verifier: code_verifier 
			});
		const userinfo = await client.userinfo(tokenSet.access_token);

		// use SID in this sample as session id
		req.oidcSID = tokenSet.claims().sid;
		if (!req.oidcSID) {
			throw new Error('Missing sid claim in ID token. Cannot bind session.');
		}
		console.log('OIDC SID for session binding:', req.oidcSID);
		// regenerate session, so that genid function will use SID as session id
		// in this example, genid function is being used to set session id
		req.session.regenerate((err) => {
			if (err) {
				console.error('Session regeneration error:', err);
				return res.status(500).send('Internal Server Error');
			}
			req.session.tokenSet = tokenSet; // Save tokenSet in session
			req.session.userinfo = userinfo; // Save userinfo in session
			// Clear the code_verifier from session as it's no longer needed
			delete req.session.code_verifier;
			console.log('PKCE: code_verifier cleared from session after successful token exchange');
			res.redirect('/dashboard');
		});

	} catch (error) {
		console.error('Error handling OIDC callback:', error);
		handleErrorAndRedirect(req, res, error);
	}

});

// Page for render userInfo
app.get('/dashboard', ensureAuthenticated, (req, res) => {
	const userinfo = req.session.userinfo;
	const profileApp = {
		url: process.env.PROFILE_MANAGEMENT_URL,
		client_id: process.env.IBM_VERIFY_RP_CLIENT_ID
	}
	if (!userinfo) {
		return res.redirect('/login');
	}
	const tokenSet = req.session.tokenSet;
	res.render('dashboard', { userInfo: userinfo, profileApp: profileApp, tokenSet: tokenSet });
});

app.get("/logout", async (req, res, next) => {
	try {
		const client = await setUpOIDC(req, res);
		const token = req.session.tokenSet;

		req.session.destroy(err => {
			if (err) {
				return next(err);
			}

			const endSessionUrl = client.issuer.metadata.end_session_endpoint;
			let logoutUrl = "/";

			if (endSessionUrl) {
				const params = new URLSearchParams();
				if (token?.id_token) {
					params.append("id_token_hint", token.id_token);
				}
				if (process.env.POST_LOGOUT_REDIRECT_URI) {
					params.append(
						"post_logout_redirect_uri",
						process.env.POST_LOGOUT_REDIRECT_URI
					);
				}
				logoutUrl = `${endSessionUrl}?${params.toString()}`;
			}

			res.redirect(logoutUrl);
		});
	} catch (err) {
		handleErrorAndRedirect(req, res, err);
	}
});

// Back Channel Logout endpoint
app.post('/backchannel_logout', async (req, res) => {
	console.log('Back channel logout init:');
	try {
		const client = await setUpOIDC(req, res);
		const logoutToken = req.body.logout_token;

		if (!logoutToken) {
			return res.status(400).json({ error: 'logout_token is required' });
		}

		const jwks = createRemoteJWKSet(new URL(client.issuer.metadata.jwks_uri));
		const payload = await validateLogoutToken(logoutToken, jwks);

		// Terminate session(s)
		// In this demo, use SID associate to session
		if (payload.sid) {
			await destroySessionsBySid(payload.sid);
		} 

		// Return successful response
		return res.status(200).json({ status: 'ok' });
	} catch (error) {
		console.error('Back channel logout error:', error);
		handleErrorAndRedirect(req, res, error);
	}
});

app.get('/error', (req, res) => {
	const err = req.session.error || {};
	res.render('error', {
		status: 500,
		message: err.message || 'Internal Server Error',
		description: err.error_description || '',
	});
	delete req.session.error;
});

async function validateLogoutToken(logoutToken, jwks) {
	if (!logoutToken) throw new Error('missing logout_token');

	// Verify signature and standard claims (exp, nbf, iss, aud) via jose
	const { payload } = await jwtVerify(logoutToken, jwks, {
		audience: process.env.CLIENT_ID
		// iat/exp/nbf are validated by jwtVerify by default
	});

	// Required: events claim with backchannel-logout event
	const events = payload.events;
	const bcEventKey = 'http://schemas.openid.net/event/backchannel-logout';
	if (!events || typeof events !== 'object' || !events[bcEventKey]) {
		throw new Error('missing backchannel logout event claim');
	}

	// Required: jti present
	//   if (!payload.jti) throw new Error('missing jti claim');

	//   // Replay protection: reject if jti already seen
	//   if (seenJti.has(payload.jti)) throw new Error('replayed logout_token (jti seen)');
	//   // Mark as seen; in production persist with TTL at least until token expiry
	//   seenJti.add(payload.jti);

	// Required: sid present (In this demo, we use sid to identify session)
	if (!payload.sid) throw new Error('must contain sid');

	return payload;
}

// Helper placeholders - implement according to your session store
async function destroySessionsBySid(sid) {
	// Example: find session by sid and destroy it
	memoryStore.destroy(sid, (err) => {
		if (err) {
			console.error('Failed to destroy session:', err);
		}
	});
	console.log('Session destroy by SID:', sid);
}


app.get('/debug', (req, res) => {
	console.log('Session:', req.session);
	res.json(req.session);
});

// Listen PORT
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
	console.log('Server started');
	console.log(`Navigate to http://localhost:${PORT}`);
});

async function refreshAccessToken(req, res) {
	const client = await setUpOIDC(req, res);
	const tokenSet = req.session.tokenSet;

	if (!tokenSet?.refresh_token) {
		throw new Error("No refresh token available");
	}

	try {
		const refreshed = await client.refresh(tokenSet.refresh_token);
		const userinfo = await client.userinfo(refreshed.access_token);

		req.session.tokenSet = refreshed; // overwrite with fresh tokens
		req.session.userinfo = userinfo; // Save userinfo in session
		console.log("Access token refreshed");
		return refreshed;
	} catch (err) {
		console.error("Failed to refresh access token:", err);
		handleErrorAndRedirect(req, res, err);
	}
}

async function ensureAuthenticated(req, res, next) {
	try {
		if (!req.session.tokenSet) {
			return res.redirect("/login");
		}
		// purpose of the refresh token is get the users updated values
		await refreshAccessToken(req, res);

		next();
	} catch (err) {
		console.error("Auth check failed:", err);

		handleErrorAndRedirect(req, res, err);
	}
}

function handleErrorAndRedirect(req, res, err) {
	console.log("Handling error and redirecting to /error:", err);
	req.session.error = {
		message: err.message,
		stack: err.stack,
		description: err.error_description
	};
	res.redirect("/error");
}

// Global error handler (must come after all routes)
// this must always be the last app.use call
function errorHandler(err, req, res, next) {
	//middleware error handler
	console.error("Unhandled server error:", err);

	handleErrorAndRedirect(req, res, err);
}

app.use(errorHandler);
