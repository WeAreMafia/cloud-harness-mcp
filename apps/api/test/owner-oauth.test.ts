import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createServer, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ApiConfig, RunnerOperation, RunnerPrincipalSelector, RunnerResponse } from '@cloud-harness/contracts';
import { createApiApp, type ApiRuntime } from '../src/app.js';
import { OAuthStore } from '../../runner/src/oauth-store.js';

const clientId = 'chatgpt-client-id';
const clientSecret = 'chatgpt-client-secret-longer-than-32-chars';
const ownerPassword = 'super-secret-owner-password';
const issuer = 'https://codex-mcp.iamsoftware.com.vn';
const allowedCallback = 'https://chatgpt.com/connector/oauth/unique-12345';
const resourceUri = `${issuer}/mcp`;

function createPkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return { verifier, challenge };
}

describe('owner-oauth auth mode', () => {
  let server: Server;
  let runtime: ApiRuntime;
  let baseUrl: string;
  let oauthStore: OAuthStore;
  let currentTime: number;

  beforeEach(async () => {
    currentTime = 1_700_000_000_000;
    const db = new DatabaseSync(':memory:');
    oauthStore = new OAuthStore(db, () => currentTime);

    const config: ApiConfig = {
      host: '127.0.0.1',
      port: 0,
      authMode: 'owner-oauth',
      ownerId: 'owner',
      bearerToken: 'existing-bearer-token-kept-for-rollback-123456',
      oauthIssuer: issuer,
      oauthClientId: clientId,
      oauthClientSecret: clientSecret,
      oauthOwnerPassword: ownerPassword,
      oauthAllowedRedirectUris: [allowedCallback],
      oauthAccessTokenTtlSeconds: 900,
      oauthRefreshTokenTtlSeconds: 2592000,
      runnerUrl: 'http://runner:3001',
      runnerToken: 'runner-token-that-is-longer-than-32-characters',
      publicHosts: ['127.0.0.1', 'localhost', 'codex-mcp.iamsoftware.com.vn'],
      allowedOrigins: [],
      requestTimeoutMs: 2_000,
      maxBodyBytes: 65_536,
      mcpGatewayTimeoutMs: 30_000,
      mcpGatewayMaxResponseBytes: 262_144,
      mcpGatewayMaxToolsPerServer: 500,
      mcpGatewayMaxSchemaBytes: 65_536,
      mcpGatewayMaxCatalogBytes: 2_097_152,
      mcpGatewayMaxTraceRows: 20_000,
      mcpGatewayMaxConnections: 32,
      mcpGatewayAllowInsecureHttp: false,
      mcpGatewayAllowPrivateEndpoints: false
    };

    const fakeRunnerClient = {
      ready: async () => true,
      call: async (operation: RunnerOperation, _input: Record<string, unknown>, principal: RunnerPrincipalSelector): Promise<RunnerResponse> => {
        return {
          ok: true,
          message: `operation ${operation} executed for ${principal.kind}`
        };
      },
      callOAuth: async (req: any) => oauthStore.handle(req)
    } as any;

    runtime = createApiApp(config, { runnerClient: fakeRunnerClient });
    runtime.app.get('/mcp/scopes-probe', (req: any, res) => {
      res.json({ scopes: req.auth?.scopes, clientId: req.auth?.clientId });
    });
    server = createServer(runtime.app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('test server failed');
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    if (runtime) await runtime.close();
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  // 1. OAuth metadata discovery
  it('1. discovers OAuth Authorization Server Metadata via RFC 8414', async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.issuer).toBe(issuer);
    expect(data.authorization_endpoint).toBe(`${issuer}/oauth/authorize`);
    expect(data.token_endpoint).toBe(`${issuer}/oauth/token`);
    expect(data.response_types_supported).toEqual(['code']);
    expect(data.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(data.code_challenge_methods_supported).toEqual(['S256']);
    expect(data.token_endpoint_auth_methods_supported).toEqual(['client_secret_post', 'client_secret_basic']);
    expect(data.scopes_supported).toContain('workspace:read');
    expect(data.authorization_response_iss_parameter_supported).toBe(true);
  });

  // 2. Protected Resource Metadata
  it('2. discovers Protected Resource Metadata via RFC 9728', async () => {
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const res = await fetch(`${baseUrl}${path}`, {
        headers: { host: 'codex-mcp.iamsoftware.com.vn' }
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.resource).toBe(resourceUri);
      expect(data.authorization_servers).toEqual([issuer]);
      expect(data.bearer_methods_supported).toEqual(['header']);
    }
  });

  // 3. Unauthenticated /mcp -> correct 401 + discovery information
  it('3. challenges unauthenticated /mcp request with 401 and resource_metadata', async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    });
    expect(res.status).toBe(401);
    const wwwAuth = res.headers.get('www-authenticate') ?? '';
    expect(wwwAuth).toContain('Bearer realm="cloud-harness-mcp"');
    expect(wwwAuth).toContain(`resource_metadata="${issuer}/.well-known/oauth-protected-resource"`);
  });

  // 4. Wrong owner password
  it('4. rejects wrong owner password on authorization consent', async () => {
    const { challenge } = createPkce();
    // Fetch login page first to get CSRF token
    const pageRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s1&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    const csrfMatch = html.match(/name="csrf_token" value="([^"]+)"/);
    expect(csrfMatch).toBeTruthy();
    const csrfToken = csrfMatch![1];

    // Submit wrong password
    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: allowedCallback,
        state: 's1',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        csrf_token: csrfToken,
        password: 'wrong-password'
      }).toString()
    });
    expect(postRes.status).toBe(401);
    const postHtml = await postRes.text();
    expect(postHtml).toContain('Invalid owner password');
  });

  // 5. Correct owner authorization
  it('5. authorizes owner with valid password and redirects with code, state, and iss', async () => {
    const { challenge } = createPkce();
    const pageRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=mystate123&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    const html = await pageRes.text();
    const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

    // Submit correct password
    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: allowedCallback,
        state: 'mystate123',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        csrf_token: csrfToken,
        password: ownerPassword
      }).toString()
    });
    expect(postRes.status).toBe(302);
    const location = postRes.headers.get('location') ?? '';
    const redirectUrl = new URL(location);
    expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
    expect(redirectUrl.searchParams.get('state')).toBe('mystate123');
    expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
    expect(redirectUrl.searchParams.get('code')).toBeTruthy();
  });

  // 6. Invalid client_id
  it('6. rejects invalid client_id on authorize and token endpoints', async () => {
    const { challenge } = createPkce();
    // Authorize
    const resAuth = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=unknown-client&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(resAuth.status).toBe(400);

    // Token
    const resToken = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: 'unknown-client',
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code: 'any',
        redirect_uri: allowedCallback,
        code_verifier: 'any'
      }).toString()
    });
    expect(resToken.status).toBe(401);
  });

  // 7. Invalid client_secret
  it('7. rejects invalid client_secret in both Basic auth and POST body', async () => {
    // Basic Auth with wrong secret
    const badBasic = Buffer.from(`${clientId}:wrong-secret`).toString('base64');
    const res1 = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Basic ${badBasic}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ grant_type: 'authorization_code' }).toString()
    });
    expect(res1.status).toBe(401);

    // Body with wrong secret
    const res2 = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: 'wrong-secret',
        grant_type: 'authorization_code'
      }).toString()
    });
    expect(res2.status).toBe(401);
  });

  // 8. Invalid redirect_uri
  it('8. rejects unapproved redirect_uri on authorization request', async () => {
    const { challenge } = createPkce();
    const res = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=https://evil.com/callback&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(res.status).toBe(400);
    const body = await res.text();
    expect(body).toContain('Invalid redirect_uri');
  });

  // 9. Missing PKCE
  it('9. rejects authorize request missing PKCE challenge', async () => {
    const res = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(res.status).toBe(400);
  });

  // 10. PKCE method other than S256
  it('10. rejects PKCE method other than S256 (e.g. plain)', async () => {
    const res = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s&code_challenge=somechallenge123456789012345678901234567890&code_challenge_method=plain`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(res.status).toBe(400);
  });

  // 11. Incorrect code_verifier
  it('11. rejects token exchange with incorrect code_verifier', async () => {
    const { challenge } = createPkce();
    // Authorize
    const pageRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    const html = await pageRes.text();
    const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's',
        code_challenge: challenge, code_challenge_method: 'S256',
        csrf_token: csrfToken, password: ownerPassword
      }).toString()
    });
    const location = postRes.headers.get('location')!;
    const code = new URL(location).searchParams.get('code')!;

    // Exchange with wrong code_verifier
    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: 'incorrect-code-verifier-12345678901234567890'
      }).toString()
    });
    expect(tokenRes.status).toBe(400);
    const body = await tokenRes.json();
    expect(body.error).toBe('invalid_grant');
  });

  // Helper to get authorization code
  async function getAuthorizationCode(challenge: string): Promise<string> {
    const pageRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    const html = await pageRes.text();
    const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's',
        code_challenge: challenge, code_challenge_method: 'S256',
        csrf_token: csrfToken, password: ownerPassword
      }).toString()
    });
    const location = postRes.headers.get('location')!;
    return new URL(location).searchParams.get('code')!;
  }

  // 12. Authorization-code replay
  it('12. rejects authorization-code replay on second token exchange', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    // First exchange succeeds
    const res1 = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    expect(res1.status).toBe(200);

    // Replay exchange fails
    const res2 = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    expect(res2.status).toBe(400);
    const body = await res2.json();
    expect(body.error).toBe('invalid_grant');
  });

  // 13. Expired authorization code
  it('13. rejects expired authorization code', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    // Fast-forward time past 120s TTL
    currentTime += 121_000;

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    expect(tokenRes.status).toBe(400);
    expect((await tokenRes.json()).error).toBe('invalid_grant');
  });

  // 14. Successful authorization-code exchange
  it('14. exchanges authorization code for access and refresh tokens', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    expect(tokenRes.status).toBe(200);
    const tokenData = await tokenRes.json();
    expect(tokenData.access_token).toBeTruthy();
    expect(tokenData.token_type).toBe('Bearer');
    expect(tokenData.expires_in).toBe(900);
    expect(tokenData.refresh_token).toBeTruthy();
    expect(tokenData.scope).toContain('workspace:read');
  });

  // 15. Authenticated MCP request
  it('15. authenticates MCP requests with OAuth access token', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    const { access_token } = await tokenRes.json();

    // Call /mcp with bearer token
    const mcpRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${access_token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } }
      })
    });
    expect(mcpRes.status).toBe(200);
  });

  // 16. Expired access token
  it('16. rejects expired access token with 401 and invalid_token error', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    const { access_token } = await tokenRes.json();

    // Fast-forward past 900s access token TTL
    currentTime += 901_000;

    const mcpRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${access_token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    });
    expect(mcpRes.status).toBe(401);
    expect(mcpRes.headers.get('www-authenticate')).toContain('error="invalid_token"');
  });

  // 17. Invalid access token (and client_secret / owner_password forbidden as bearer token)
  it('17. rejects invalid token, client_secret, and owner_password as bearer tokens', async () => {
    // Random token
    const res1 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', authorization: 'Bearer completely-invalid-random-token', 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(res1.status).toBe(401);

    // Client Secret as bearer token must be rejected!
    const res2 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', authorization: `Bearer ${clientSecret}`, 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(res2.status).toBe(401);
    expect(res2.headers.get('www-authenticate')).toContain('error="invalid_token"');

    // Owner Password as bearer token must be rejected!
    const res3 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', authorization: `Bearer ${ownerPassword}`, 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(res3.status).toBe(401);
    expect(res3.headers.get('www-authenticate')).toContain('error="invalid_token"');
  });

  // 18. Refresh-token exchange
  it('18. exchanges refresh token for new access and rotated refresh tokens', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    const { refresh_token } = await tokenRes.json();

    // Exchange refresh token
    const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token
      }).toString()
    });
    expect(refreshRes.status).toBe(200);
    const refreshData = await refreshRes.json();
    expect(refreshData.access_token).toBeTruthy();
    expect(refreshData.refresh_token).toBeTruthy();
    expect(refreshData.refresh_token).not.toBe(refresh_token); // rotated!
  });

  // 19. Refresh-token rotation
  it('19. invalidates the old refresh token upon rotation', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    const { refresh_token: oldRefreshToken } = await tokenRes.json();

    // Use old refresh token
    await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token: oldRefreshToken
      }).toString()
    });

    // Try using old refresh token again -> must fail!
    const reuseRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token: oldRefreshToken
      }).toString()
    });
    expect(reuseRes.status).toBe(400);
    expect((await reuseRes.json()).error).toBe('invalid_grant');
  });

  // 20. Refresh-token replay detection
  it('20. detects refresh-token replay and revokes token family', async () => {
    const { verifier, challenge } = createPkce();
    const code = await getAuthorizationCode(challenge);

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    const { refresh_token: rt1 } = await tokenRes.json();

    // Legitimate rotation RT1 -> RT2
    const rotateRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token: rt1
      }).toString()
    });
    const { access_token: at2, refresh_token: rt2 } = await rotateRes.json();

    // Verify AT2 works
    const check1 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${at2}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    });
    expect(check1.status).toBe(200);

    // Adversary replays RT1!
    const replayRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token: rt1
      }).toString()
    });
    expect(replayRes.status).toBe(400);

    // Because replay was detected, RT2 and AT2 in the same family must now be revoked!
    const check2 = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${at2}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    });
    expect(check2.status).toBe(401);

    const tryRt2 = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'refresh_token', refresh_token: rt2
      }).toString()
    });
    expect(tryRt2.status).toBe(400);
  });

  // End-to-end integration test simulating the entire ChatGPT flow
  it('approximates the full ChatGPT Web OAuth 2.1 flow', async () => {
    // 1. ChatGPT probes unauthenticated /mcp
    const probeRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    expect(probeRes.status).toBe(401);
    const wwwAuth = probeRes.headers.get('www-authenticate')!;
    const metaUrlMatch = wwwAuth.match(/resource_metadata="([^"]+)"/)!;
    const metaUrl = metaUrlMatch[1];

    // 2. ChatGPT fetches Protected Resource Metadata
    const prmRes = await fetch(metaUrl.replace(issuer, baseUrl), {
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(prmRes.status).toBe(200);
    const prm = await prmRes.json();
    expect(prm.resource).toBe(resourceUri);

    // 3. ChatGPT fetches Authorization Server Metadata
    const asRes = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(asRes.status).toBe(200);
    const asMeta = await asRes.json();

    // 4. ChatGPT generates PKCE and opens /oauth/authorize in browser
    const { verifier, challenge } = createPkce();
    const authorizeRes = await fetch(
      `${asMeta.authorization_endpoint.replace(issuer, baseUrl)}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=chatgpt-state-777&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(authorizeRes.status).toBe(200);
    const authHtml = await authorizeRes.text();
    const csrfToken = authHtml.match(/name="csrf_token" value="([^"]+)"/)![1];

    // 5. Owner submits password form
    const loginRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST',
      redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: allowedCallback,
        state: 'chatgpt-state-777',
        code_challenge: challenge,
        code_challenge_method: 'S256',
        csrf_token: csrfToken,
        password: ownerPassword
      }).toString()
    });
    expect(loginRes.status).toBe(302);
    const callbackUri = new URL(loginRes.headers.get('location')!);
    expect(callbackUri.searchParams.get('state')).toBe('chatgpt-state-777');
    expect(callbackUri.searchParams.get('iss')).toBe(issuer);
    const code = callbackUri.searchParams.get('code')!;

    // 6. ChatGPT backend exchanges authorization code for tokens
    const tokenRes = await fetch(asMeta.token_endpoint.replace(issuer, baseUrl), {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: allowedCallback,
        code_verifier: verifier
      }).toString()
    });
    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json();
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();

    // 7. Authenticated MCP initialize call
    const initRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${tokens.access_token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'init-1',
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'chatgpt', version: '1.0' } }
      })
    });
    expect(initRes.status).toBe(200);

    // 8. Access token expires after 900 seconds; ChatGPT refreshes token
    currentTime += 901_000;
    const expiredRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${tokens.access_token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'tools-1', method: 'tools/list', params: {} })
    });
    expect(expiredRes.status).toBe(401);

    const refreshRes = await fetch(asMeta.token_endpoint.replace(issuer, baseUrl), {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token
      }).toString()
    });
    expect(refreshRes.status).toBe(200);
    const refreshedTokens = await refreshRes.json();

    // 9. Call /mcp with refreshed access token succeeds!
    const successRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${refreshedTokens.access_token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream'
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'init-2',
        method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'chatgpt', version: '1.0' } }
      })
    });
    expect(successRes.status).toBe(200);
  });

  // 21. Scope validation at /oauth/authorize and propagation into request.auth.scopes
  it('21. validates requested scopes at /oauth/authorize and propagates granted scopes to request.auth.scopes', async () => {
    const { challenge: c1 } = createPkce();

    // 21a. Unsupported scope at GET /oauth/authorize is rejected
    const getBadScope = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s1&code_challenge=${c1}&code_challenge_method=S256&scope=admin`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(getBadScope.status).toBe(400);
    const getBadText = await getBadScope.text();
    expect(getBadText).toContain('invalid_scope');

    // 21b. Unsupported scope at POST /oauth/authorize is rejected
    const postBadScope = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: allowedCallback,
        state: 's1',
        code_challenge: c1,
        code_challenge_method: 'S256',
        scope: 'workspace:read evil:scope',
        password: ownerPassword
      }).toString()
    });
    expect(postBadScope.status).toBe(400);
    const postBadText = await postBadScope.text();
    expect(postBadText).toContain('invalid_scope');

    // 21c. Supported scopes survive authorization -> token issuance -> token verification
    // Request specifically 'workspace:read workspace:execute' (excluding 'workspace:write')
    const { verifier, challenge } = createPkce();
    const pageRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s2&code_challenge=${challenge}&code_challenge_method=S256&scope=${encodeURIComponent('workspace:read workspace:execute')}`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's2',
        code_challenge: challenge, code_challenge_method: 'S256',
        scope: 'workspace:read workspace:execute',
        csrf_token: csrfToken, password: ownerPassword
      }).toString()
    });
    expect(postRes.status).toBe(302);
    const code = new URL(postRes.headers.get('location')!).searchParams.get('code')!;

    // Token exchange
    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code,
        redirect_uri: allowedCallback, code_verifier: verifier
      }).toString()
    });
    expect(tokenRes.status).toBe(200);
    const tokenData = await tokenRes.json();
    expect(tokenData.scope).toBe('workspace:read workspace:execute');

    // Call probe endpoint through bearerAuth
    const probeRes = await fetch(`${baseUrl}/mcp/scopes-probe`, {
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        authorization: `Bearer ${tokenData.access_token}`
      }
    });
    expect(probeRes.status).toBe(200);
    const probeData = await probeRes.json();

    // Verify request.auth.scopes reflects the scopes actually granted to the OAuth token
    expect(probeData.scopes).toEqual(['workspace:read', 'workspace:execute']);
    expect(probeData.scopes).not.toContain('workspace:write');
    expect(probeData.scopes).not.toEqual(['workspace:read', 'workspace:write', 'workspace:execute']);
  });

  // 22. Strictly validates RFC 8707 resource parameter
  it('22. strictly validates RFC 8707 resource parameter at /oauth/authorize and /oauth/token', async () => {
    const { challenge: c1 } = createPkce();

    // 22a. Omitted resource defaults to MCP resource on GET /oauth/authorize
    const getOmitted = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s1&code_challenge=${c1}&code_challenge_method=S256`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(getOmitted.status).toBe(200);
    const htmlOmitted = await getOmitted.text();
    expect(htmlOmitted).toContain(resourceUri);
    const csrfOmitted = htmlOmitted.match(/name="csrf_token" value="([^"]+)"/)![1];

    // 22b. Omitted resource defaults to MCP resource on POST /oauth/authorize
    const postOmitted = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's1',
        code_challenge: c1, code_challenge_method: 'S256',
        csrf_token: csrfOmitted, password: ownerPassword
      }).toString()
    });
    expect(postOmitted.status).toBe(302);

    // 22c. Exact MCP resource is accepted on GET and POST /oauth/authorize
    const { challenge: c2 } = createPkce();
    const getExact = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s2&code_challenge=${c2}&code_challenge_method=S256&resource=${encodeURIComponent(resourceUri)}`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(getExact.status).toBe(200);
    const htmlExact = await getExact.text();
    expect(htmlExact).toContain(resourceUri);
    const csrfExact = htmlExact.match(/name="csrf_token" value="([^"]+)"/)![1];

    const postExact = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's2',
        code_challenge: c2, code_challenge_method: 'S256',
        resource: resourceUri,
        csrf_token: csrfExact, password: ownerPassword
      }).toString()
    });
    expect(postExact.status).toBe(302);

    // 22d. Any other resource is rejected on GET /oauth/authorize
    const { challenge: c3 } = createPkce();
    const getForeign = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=s3&code_challenge=${c3}&code_challenge_method=S256&resource=https://evil.example.com/mcp`,
      { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
    );
    expect(getForeign.status).toBe(400);
    expect(await getForeign.text()).toContain('Invalid resource parameter');

    // 22e. Any other resource is rejected on POST /oauth/authorize
    const postForeign = await fetch(`${baseUrl}/oauth/authorize`, {
      method: 'POST', redirect: 'manual',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, redirect_uri: allowedCallback, state: 's3',
        code_challenge: c3, code_challenge_method: 'S256',
        resource: 'https://evil.example.com/mcp',
        csrf_token: csrfExact, password: ownerPassword
      }).toString()
    });
    expect(postForeign.status).toBe(400);
    expect(await postForeign.text()).toContain('Invalid resource parameter');

    // 22f. Any other resource on POST /oauth/token is rejected with invalid_target
    const tokenForeign = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        grant_type: 'authorization_code', code: 'dummy-code',
        redirect_uri: allowedCallback, code_verifier: 'some-verifier-123456789012345678901234567890',
        resource: 'https://evil.example.com/mcp'
      }).toString()
    });
    expect(tokenForeign.status).toBe(400);
    const tokenForeignBody = await tokenForeign.json();
    expect(tokenForeignBody.error).toBe('invalid_target');
  });

  // 23. CORS preflight for /mcp and OAuth interop
  it('23. handles CORS preflight for /mcp without Authorization and enforces auth on POST/GET', async () => {
    // 23a. OPTIONS /mcp without Authorization -> 204 with required CORS headers
    const optionsRes = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: {
        host: 'codex-mcp.iamsoftware.com.vn',
        origin: 'https://chatgpt.com',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type, authorization, mcp-session-id'
      }
    });
    expect(optionsRes.status).toBe(204);
    expect(optionsRes.headers.get('access-control-allow-origin')).toBe('*');

    const allowMethods = (optionsRes.headers.get('access-control-allow-methods') ?? '')
      .split(',')
      .map((m) => m.trim().toUpperCase());
    expect(allowMethods).toContain('POST');
    expect(allowMethods).toContain('GET');
    expect(allowMethods).toContain('DELETE');
    expect(allowMethods).toContain('OPTIONS');

    const allowHeaders = (optionsRes.headers.get('access-control-allow-headers') ?? '')
      .split(',')
      .map((h) => h.trim().toLowerCase());
    expect(allowHeaders).toContain('content-type');
    expect(allowHeaders).toContain('authorization');
    expect(allowHeaders).toContain('mcp-session-id');

    const exposeHeaders = (optionsRes.headers.get('access-control-expose-headers') ?? '')
      .split(',')
      .map((h) => h.trim().toLowerCase());
    expect(exposeHeaders).toContain('mcp-session-id');

    // 23b. OPTIONS /mcp with bare headers returns 204
    const bareOptionsRes = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(bareOptionsRes.status).toBe(204);
    expect(bareOptionsRes.headers.get('access-control-allow-origin')).toBe('*');

    // 23c. POST /mcp without Authorization -> 401 with WWW-Authenticate challenge and CORS origin
    const postRes = await fetch(`${baseUrl}/mcp`, {
      method: 'POST',
      headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
    });
    expect(postRes.status).toBe(401);
    const postWwwAuth = postRes.headers.get('www-authenticate') ?? '';
    expect(postWwwAuth).toContain('Bearer realm="cloud-harness-mcp"');
    expect(postWwwAuth).toContain(`resource_metadata="${issuer}/.well-known/oauth-protected-resource"`);
    expect(postRes.headers.get('access-control-allow-origin')).toBe('*');

    // 23d. GET /mcp without Authorization -> 401 with CORS origin
    const getRes = await fetch(`${baseUrl}/mcp`, {
      method: 'GET',
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(getRes.status).toBe(401);
    const getWwwAuth = getRes.headers.get('www-authenticate') ?? '';
    expect(getWwwAuth).toContain('Bearer realm="cloud-harness-mcp"');
    expect(getRes.headers.get('access-control-allow-origin')).toBe('*');

    // 23e. DELETE /mcp without Authorization -> 401
    const deleteRes = await fetch(`${baseUrl}/mcp`, {
      method: 'DELETE',
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(deleteRes.status).toBe(401);
    expect(deleteRes.headers.get('access-control-allow-origin')).toBe('*');

    // 23f. Discovery endpoints continue to work as expected
    const discRes = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`, {
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(discRes.status).toBe(200);

    const openidRes = await fetch(`${baseUrl}/.well-known/openid-configuration`, {
      headers: { host: 'codex-mcp.iamsoftware.com.vn' }
    });
    expect(openidRes.status).toBe(404);
  });

  // 24. RFC 9207 Issuer Identification: redirects include exact iss on success and errors
  describe('24. RFC 9207 Issuer Identification redirects', () => {
    it('24a. advertises authorization_response_iss_parameter_supported=true in authorization server metadata', async () => {
      const res = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`, {
        headers: { host: 'codex-mcp.iamsoftware.com.vn' }
      });
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.authorization_response_iss_parameter_supported).toBe(true);
    });

    it('24b. successful authorization redirect contains code, state (when supplied), and exact issuer', async () => {
      const { challenge } = createPkce();
      const pageRes = await fetch(
        `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=test_state_123&code_challenge=${challenge}&code_challenge_method=S256`,
        { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
      );
      const html = await pageRes.text();
      const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

      const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          redirect_uri: allowedCallback,
          state: 'test_state_123',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          csrf_token: csrfToken,
          password: ownerPassword
        }).toString()
      });
      expect(postRes.status).toBe(302);
      const redirectUrl = new URL(postRes.headers.get('location')!);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
      expect(redirectUrl.searchParams.get('code')).toBeTruthy();
      expect(redirectUrl.searchParams.get('state')).toBe('test_state_123');
      expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
    });

    it('24c. successful authorization redirect without state omits state parameter and contains code and exact issuer', async () => {
      const { challenge } = createPkce();
      const pageRes = await fetch(
        `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&code_challenge=${challenge}&code_challenge_method=S256`,
        { headers: { host: 'codex-mcp.iamsoftware.com.vn' } }
      );
      const html = await pageRes.text();
      const csrfToken = html.match(/name="csrf_token" value="([^"]+)"/)![1];

      const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          redirect_uri: allowedCallback,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          csrf_token: csrfToken,
          password: ownerPassword
        }).toString()
      });
      expect(postRes.status).toBe(302);
      const redirectUrl = new URL(postRes.headers.get('location')!);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
      expect(redirectUrl.searchParams.get('code')).toBeTruthy();
      expect(redirectUrl.searchParams.has('state')).toBe(false);
      expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
    });

    it('24d. redirected OAuth error on POST consent denial contains error, state (when applicable), and exact issuer', async () => {
      const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          action: 'deny',
          client_id: clientId,
          redirect_uri: allowedCallback,
          state: 'state_denied_post'
        }).toString()
      });
      expect(postRes.status).toBe(302);
      const redirectUrl = new URL(postRes.headers.get('location')!);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
      expect(redirectUrl.searchParams.get('error')).toBe('access_denied');
      expect(redirectUrl.searchParams.get('state')).toBe('state_denied_post');
      expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
      expect(redirectUrl.searchParams.has('code')).toBe(false);
    });

    it('24e. redirected OAuth error without state omits state and contains error and exact issuer', async () => {
      const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: { host: 'codex-mcp.iamsoftware.com.vn', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          action: 'deny',
          client_id: clientId,
          redirect_uri: allowedCallback
        }).toString()
      });
      expect(postRes.status).toBe(302);
      const redirectUrl = new URL(postRes.headers.get('location')!);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
      expect(redirectUrl.searchParams.get('error')).toBe('access_denied');
      expect(redirectUrl.searchParams.has('state')).toBe(false);
      expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
      expect(redirectUrl.searchParams.has('code')).toBe(false);
    });

    it('24f. redirected OAuth error on GET /oauth/authorize contains error, state, and exact issuer', async () => {
      const getRes = await fetch(
        `${baseUrl}/oauth/authorize?action=deny&client_id=${clientId}&redirect_uri=${encodeURIComponent(allowedCallback)}&state=state_denied_get`,
        {
          redirect: 'manual',
          headers: { host: 'codex-mcp.iamsoftware.com.vn' }
        }
      );
      expect(getRes.status).toBe(302);
      const redirectUrl = new URL(getRes.headers.get('location')!);
      expect(redirectUrl.origin + redirectUrl.pathname).toBe(allowedCallback);
      expect(redirectUrl.searchParams.get('error')).toBe('access_denied');
      expect(redirectUrl.searchParams.get('state')).toBe('state_denied_get');
      expect(redirectUrl.searchParams.get('iss')).toBe(issuer);
      expect(redirectUrl.searchParams.has('code')).toBe(false);
    });
  });
});
