import { createHmac, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import express, { type Request, type Response, type Router } from 'express';
import type { ApiConfig } from '@cloud-harness/contracts';
import type { RunnerClient } from './runner-client.js';

type RateLimitEntry = { attempts: number; resetAt: number };
const loginAttempts = new Map<string, RateLimitEntry>();
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_ATTEMPT_WINDOW_MS = 60_000;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || entry.resetAt <= now) {
    loginAttempts.set(ip, { attempts: 1, resetAt: now + LOGIN_ATTEMPT_WINDOW_MS });
    return true;
  }
  if (entry.attempts >= MAX_LOGIN_ATTEMPTS) {
    return false;
  }
  entry.attempts += 1;
  return true;
}

function resetRateLimit(ip: string): void {
  loginAttempts.delete(ip);
}

function safeEqual(actual: string | undefined, expected: string | undefined): boolean {
  if (!actual || !expected) return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function generateCsrfToken(clientId: string, codeChallenge: string, secretKey: string): string {
  const timestamp = Date.now().toString();
  const payload = `${timestamp}:${clientId}:${codeChallenge}`;
  const hmac = createHmac('sha256', secretKey).update(payload).digest('base64url');
  return `${timestamp}.${hmac}`;
}

function verifyCsrfToken(token: string | undefined, clientId: string, codeChallenge: string, secretKey: string): boolean {
  if (!token) return false;
  const [timestamp, hmac] = token.split('.');
  if (!timestamp || !hmac) return false;
  const time = Number(timestamp);
  if (!Number.isFinite(time) || Date.now() - time > 900_000 || Date.now() - time < -60_000) {
    return false;
  }
  const payload = `${timestamp}:${clientId}:${codeChallenge}`;
  const expectedHmac = createHmac('sha256', secretKey).update(payload).digest('base64url');
  return safeEqual(hmac, expectedHmac);
}

function renderLoginPage(params: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  resource: string;
  scope: string;
  csrfToken: string;
  errorMessage?: string;
}): string {
  const errorHtml = params.errorMessage
    ? `<div class="error-banner" role="alert">${escapeHtml(params.errorMessage)}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize ChatGPT — Cloud Harness MCP</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --text-muted: #8b949e;
      --primary: #238636;
      --primary-hover: #2ea043;
      --danger: #f85149;
      --danger-bg: rgba(248, 81, 73, 0.15);
      --input-bg: #0d1117;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      width: 100%;
      max-width: 440px;
      padding: 2rem;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    }
    .badge {
      display: inline-block;
      background: #1f6feb22;
      color: #58a6ff;
      border: 1px solid #1f6feb66;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.2rem 0.6rem;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    h1 {
      color: var(--text-bright);
      font-size: 1.35rem;
      margin-bottom: 0.5rem;
    }
    p.desc {
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-bottom: 1.5rem;
      line-height: 1.4;
    }
    .info-list {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.85rem;
      margin-bottom: 1.5rem;
      font-size: 0.85rem;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.4rem;
    }
    .info-row:last-child { margin-bottom: 0; }
    .info-label { color: var(--text-muted); }
    .info-val { color: var(--text-bright); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; text-align: right; max-width: 65%; }
    .error-banner {
      background: var(--danger-bg);
      border: 1px solid var(--danger);
      color: var(--danger);
      border-radius: 6px;
      padding: 0.75rem;
      font-size: 0.875rem;
      margin-bottom: 1.25rem;
    }
    .form-group {
      margin-bottom: 1.25rem;
    }
    label {
      display: block;
      color: var(--text);
      font-size: 0.875rem;
      font-weight: 500;
      margin-bottom: 0.5rem;
    }
    input[type="password"] {
      width: 100%;
      background: var(--input-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-bright);
      padding: 0.65rem 0.85rem;
      font-size: 0.95rem;
      outline: none;
    }
    input[type="password"]:focus {
      border-color: #58a6ff;
      box-shadow: 0 0 0 3px rgba(88,166,255,0.2);
    }
    button[type="submit"] {
      width: 100%;
      background: var(--primary);
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 0.75rem;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
    }
    button[type="submit"]:hover {
      background: var(--primary-hover);
    }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">OAuth 2.1 Authorization</span>
    <h1>Connect ChatGPT Web</h1>
    <p class="desc">ChatGPT Web is requesting permission to access your private Cloud Harness remote coding environment.</p>

    <div class="info-list">
      <div class="info-row">
        <span class="info-label">Client ID</span>
        <span class="info-val">${escapeHtml(params.clientId)}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Resource</span>
        <span class="info-val">${escapeHtml(params.resource)}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Scopes</span>
        <span class="info-val">${escapeHtml(params.scope || 'all')}</span>
      </div>
    </div>

    ${errorHtml}

    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${escapeHtml(params.clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(params.redirectUri)}">
      <input type="hidden" name="state" value="${escapeHtml(params.state)}">
      <input type="hidden" name="code_challenge" value="${escapeHtml(params.codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(params.codeChallengeMethod)}">
      <input type="hidden" name="resource" value="${escapeHtml(params.resource)}">
      <input type="hidden" name="scope" value="${escapeHtml(params.scope)}">
      <input type="hidden" name="csrf_token" value="${escapeHtml(params.csrfToken)}">

      <div class="form-group">
        <label for="password">Owner Password</label>
        <input type="password" id="password" name="password" required autofocus autocomplete="current-password" placeholder="Enter OAUTH_OWNER_PASSWORD">
      </div>

      <button type="submit">Authorize ChatGPT</button>
    </form>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function createOAuthRouter(config: ApiConfig, runnerClient: RunnerClient): Router {
  const router = express.Router();
  const issuer = config.oauthIssuer ?? `https://${config.publicHosts[0]}`;
  const resourceUri = `${issuer}/mcp`;
  const supportedScopes = ['workspace:read', 'workspace:write', 'workspace:execute'];

  // 1. Protected Resource Metadata (RFC 9728)
  const protectedResourceMetadata = (_req: Request, res: Response) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.json({
      resource: resourceUri,
      authorization_servers: [issuer],
      scopes_supported: supportedScopes,
      bearer_methods_supported: ['header']
    });
  };

  router.get('/.well-known/oauth-protected-resource', protectedResourceMetadata);
  router.get('/.well-known/oauth-protected-resource/mcp', protectedResourceMetadata);

  // 2. OAuth Authorization Server Metadata (RFC 8414)
  router.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      scopes_supported: supportedScopes
    });
  });

  // CORS preflight for well-known
  router.options(
    ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server'],
    (_req: Request, res: Response) => {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.sendStatus(204);
    }
  );

  // 3. Authorization Endpoint (GET /oauth/authorize)
  router.get('/oauth/authorize', (req: Request, res: Response) => {
    const clientId = typeof req.query.client_id === 'string' ? req.query.client_id : '';
    const redirectUri = typeof req.query.redirect_uri === 'string' ? req.query.redirect_uri : '';
    const responseType = typeof req.query.response_type === 'string' ? req.query.response_type : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const codeChallenge = typeof req.query.code_challenge === 'string' ? req.query.code_challenge : '';
    const codeChallengeMethod = typeof req.query.code_challenge_method === 'string' ? req.query.code_challenge_method : '';
    const resource = typeof req.query.resource === 'string' ? req.query.resource : resourceUri;
    const scope = typeof req.query.scope === 'string' ? req.query.scope : supportedScopes.join(' ');

    if (!clientId || clientId !== config.oauthClientId) {
      res.status(400).type('text/plain').send('Invalid client_id');
      return;
    }

    const allowedUris = config.oauthAllowedRedirectUris ?? [];
    if (!redirectUri || !allowedUris.includes(redirectUri)) {
      res.status(400).type('text/plain').send('Invalid redirect_uri');
      return;
    }

    if (responseType !== 'code') {
      res.status(400).type('text/plain').send('Unsupported response_type; must be "code"');
      return;
    }

    if (codeChallengeMethod !== 'S256' || !codeChallenge || codeChallenge.length < 43 || codeChallenge.length > 128) {
      res.status(400).type('text/plain').send('Invalid code_challenge or code_challenge_method; S256 required');
      return;
    }

    if (!state) {
      res.status(400).type('text/plain').send('Missing state parameter');
      return;
    }

    const csrfToken = generateCsrfToken(clientId, codeChallenge, config.oauthClientSecret!);
    const html = renderLoginPage({
      issuer,
      clientId,
      redirectUri,
      state,
      codeChallenge,
      codeChallengeMethod,
      resource,
      scope,
      csrfToken
    });

    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
    res.type('html').send(html);
  });

  // 4. Authorization Endpoint (POST /oauth/authorize)
  router.post('/oauth/authorize', express.urlencoded({ extended: false }), async (req: Request, res: Response) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const clientId = typeof req.body.client_id === 'string' ? req.body.client_id : '';
    const redirectUri = typeof req.body.redirect_uri === 'string' ? req.body.redirect_uri : '';
    const state = typeof req.body.state === 'string' ? req.body.state : '';
    const codeChallenge = typeof req.body.code_challenge === 'string' ? req.body.code_challenge : '';
    const codeChallengeMethod = typeof req.body.code_challenge_method === 'string' ? req.body.code_challenge_method : '';
    const resource = typeof req.body.resource === 'string' ? req.body.resource : resourceUri;
    const scope = typeof req.body.scope === 'string' ? req.body.scope : supportedScopes.join(' ');
    const csrfToken = typeof req.body.csrf_token === 'string' ? req.body.csrf_token : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    const allowedUris = config.oauthAllowedRedirectUris ?? [];
    if (!clientId || clientId !== config.oauthClientId || !allowedUris.includes(redirectUri)) {
      res.status(400).type('text/plain').send('Invalid authorization request parameters');
      return;
    }

    if (!checkRateLimit(ip)) {
      res.status(429).type('text/plain').send('Too many login attempts. Please try again later.');
      return;
    }

    if (!verifyCsrfToken(csrfToken, clientId, codeChallenge, config.oauthClientSecret!)) {
      res.status(400).type('text/plain').send('Invalid or expired CSRF token');
      return;
    }

    const passwordValid = safeEqual(password, config.oauthOwnerPassword);
    if (!passwordValid) {
      const newCsrf = generateCsrfToken(clientId, codeChallenge, config.oauthClientSecret!);
      const html = renderLoginPage({
        issuer,
        clientId,
        redirectUri,
        state,
        codeChallenge,
        codeChallengeMethod,
        resource,
        scope,
        csrfToken: newCsrf,
        errorMessage: 'Invalid owner password'
      });
      res.status(401).type('html').send(html);
      return;
    }

    resetRateLimit(ip);

    // Generate authorization code (32 cryptographically random bytes)
    const code = randomBytes(32).toString('base64url');
    const codeHash = sha256Hex(code);

    const result = await runnerClient.callOAuth({
      action: 'create_code',
      codeHash,
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod: 'S256',
      resource,
      scope,
      expiresInSeconds: 120
    });

    if (!result.ok) {
      res.status(500).type('text/plain').send('Failed to issue authorization code');
      return;
    }

    // Redirect back to ChatGPT with code, state, and iss (RFC 9207)
    const callbackUrl = new URL(redirectUri);
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('state', state);
    callbackUrl.searchParams.set('iss', issuer);

    res.redirect(302, callbackUrl.toString());
  });

  // 5. Token Endpoint (POST /oauth/token)
  router.post(
    '/oauth/token',
    express.urlencoded({ extended: false }),
    express.json({ strict: true }),
    async (req: Request, res: Response): Promise<void> => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');

      // Authenticate client via Basic Auth or Post Body
      let reqClientId: string | undefined;
      let reqClientSecret: string | undefined;

      const authHeader = req.header('authorization');
      if (authHeader?.startsWith('Basic ')) {
        const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
        const colonIndex = decoded.indexOf(':');
        if (colonIndex !== -1) {
          reqClientId = decodeURIComponent(decoded.slice(0, colonIndex));
          reqClientSecret = decodeURIComponent(decoded.slice(colonIndex + 1));
        }
      }

      if (!reqClientId && typeof req.body.client_id === 'string') {
        reqClientId = req.body.client_id;
        reqClientSecret = typeof req.body.client_secret === 'string' ? req.body.client_secret : '';
      }

      if (!reqClientId || reqClientId !== config.oauthClientId || !safeEqual(reqClientSecret, config.oauthClientSecret)) {
        res.setHeader('WWW-Authenticate', 'Basic realm="oauth"');
        res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication failed' });
        return;
      }

      const grantType = typeof req.body.grant_type === 'string' ? req.body.grant_type : '';

      if (grantType === 'authorization_code') {
        const code = typeof req.body.code === 'string' ? req.body.code : '';
        const redirectUri = typeof req.body.redirect_uri === 'string' ? req.body.redirect_uri : '';
        const codeVerifier = typeof req.body.code_verifier === 'string' ? req.body.code_verifier : '';

        if (!code || !redirectUri || !codeVerifier) {
          res.status(400).json({ error: 'invalid_request', error_description: 'Missing code, redirect_uri, or code_verifier' });
          return;
        }

        const codeHash = sha256Hex(code);
        const accessToken = randomBytes(32).toString('base64url');
        const refreshToken = randomBytes(32).toString('base64url');
        const accessTokenHash = sha256Hex(accessToken);
        const refreshTokenHash = sha256Hex(refreshToken);

        const result = await runnerClient.callOAuth({
          action: 'consume_code',
          codeHash,
          clientId: reqClientId,
          redirectUri,
          codeVerifier,
          resource: resourceUri,
          newAccessTokenHash: accessTokenHash,
          accessTokenTtlSeconds: config.oauthAccessTokenTtlSeconds ?? 900,
          newRefreshTokenHash: refreshTokenHash,
          refreshTokenTtlSeconds: config.oauthRefreshTokenTtlSeconds ?? 2_592_000
        });

        if (!result.ok) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code is invalid, expired, or already consumed' });
          return;
        }

        const data = result.data as { scope: string; resource: string } | undefined;
        res.status(200).json({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: config.oauthAccessTokenTtlSeconds ?? 900,
          refresh_token: refreshToken,
          scope: data?.scope ?? supportedScopes.join(' ')
        });
        return;
      }

      if (grantType === 'refresh_token') {
        const refreshToken = typeof req.body.refresh_token === 'string' ? req.body.refresh_token : '';
        if (!refreshToken) {
          res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token' });
          return;
        }

        const refreshTokenHash = sha256Hex(refreshToken);
        const newAccessToken = randomBytes(32).toString('base64url');
        const newRefreshToken = randomBytes(32).toString('base64url');
        const newAccessTokenHash = sha256Hex(newAccessToken);
        const newRefreshTokenHash = sha256Hex(newRefreshToken);

        const result = await runnerClient.callOAuth({
          action: 'refresh_token',
          refreshTokenHash,
          clientId: reqClientId,
          newAccessTokenHash,
          accessTokenTtlSeconds: config.oauthAccessTokenTtlSeconds ?? 900,
          newRefreshTokenHash,
          refreshTokenTtlSeconds: config.oauthRefreshTokenTtlSeconds ?? 2_592_000
        });

        if (!result.ok) {
          res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token is invalid, expired, or replayed' });
          return;
        }

        const data = result.data as { scope: string; resource: string } | undefined;
        res.status(200).json({
          access_token: newAccessToken,
          token_type: 'Bearer',
          expires_in: config.oauthAccessTokenTtlSeconds ?? 900,
          refresh_token: newRefreshToken,
          scope: data?.scope ?? supportedScopes.join(' ')
        });
        return;
      }

      res.status(400).json({ error: 'unsupported_grant_type', error_description: `Unsupported grant_type: ${grantType}` });
    }
  );

  return router;
}
