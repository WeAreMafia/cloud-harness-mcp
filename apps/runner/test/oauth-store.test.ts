import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { OAuthStore } from '../src/oauth-store.js';

const clientId = 'chatgpt-client';
const redirectUri = 'https://chatgpt.com/connector/oauth/callback';
const resource = 'https://codex-mcp.iamsoftware.com.vn/mcp';
const scope = 'workspace:read workspace:write workspace:execute';

function createPkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return { verifier, challenge };
}

describe('OAuthStore', () => {
  it('creates, consumes single-use code with PKCE, and issues tokens', () => {
    const db = new DatabaseSync(':memory:');
    let currentTime = 1_000_000;
    const store = new OAuthStore(db, () => currentTime);

    const { verifier, challenge } = createPkce();
    const code = randomBytes(32).toString('base64url');
    const codeHash = createHash('sha256').update(code).digest('hex');

    // 1. Create code
    const createResult = store.createCode({
      action: 'create_code',
      codeHash,
      clientId,
      redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      resource,
      scope,
      expiresAt: currentTime + 120_000
    });
    expect(createResult.ok).toBe(true);

    // 2. Consume code with invalid PKCE
    const at1Hash = createHash('sha256').update('at1').digest('hex');
    const rt1Hash = createHash('sha256').update('rt1').digest('hex');
    const badPkceResult = store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: 'wrong-verifier-123456789012345678901234567890',
      resource,
      newAccessTokenHash: at1Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt1Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(badPkceResult.ok).toBe(false);
    expect(badPkceResult.error).toBe('invalid_grant');

    // 3. Consume code successfully
    const consumeResult = store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: verifier,
      resource,
      newAccessTokenHash: at1Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt1Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(consumeResult.ok).toBe(true);
    if (consumeResult.ok) {
      expect(consumeResult.data?.resource).toBe(resource);
      expect(consumeResult.data?.scope).toBe(scope);
    }

    // 4. Code replay fails (single-use)
    const replayResult = store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: verifier,
      resource,
      newAccessTokenHash: at1Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt1Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(replayResult.ok).toBe(false);
    expect(replayResult.error).toBe('invalid_grant');

    // 5. Verify access token
    const verifyValid = store.verifyAccessToken({
      action: 'verify_access_token',
      accessTokenHash: at1Hash,
      expectedResource: resource
    });
    expect(verifyValid.ok).toBe(true);

    // 6. Verify access token with wrong resource fails
    const verifyWrongResource = store.verifyAccessToken({
      action: 'verify_access_token',
      accessTokenHash: at1Hash,
      expectedResource: 'https://other-resource.com'
    });
    expect(verifyWrongResource.ok).toBe(false);

    // 7. Access token expired fails
    currentTime += 900_001;
    const verifyExpired = store.verifyAccessToken({
      action: 'verify_access_token',
      accessTokenHash: at1Hash,
      expectedResource: resource
    });
    expect(verifyExpired.ok).toBe(false);
  });

  it('rejects expired authorization codes', () => {
    const db = new DatabaseSync(':memory:');
    let currentTime = 1_000_000;
    const store = new OAuthStore(db, () => currentTime);

    const { verifier, challenge } = createPkce();
    const codeHash = createHash('sha256').update('code-expired').digest('hex');

    store.createCode({
      action: 'create_code',
      codeHash,
      clientId,
      redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      resource,
      scope,
      expiresAt: currentTime + 60_000
    });

    currentTime += 60_001;
    const result = store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: verifier,
      resource,
      newAccessTokenHash: 'at',
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: 'rt',
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_grant');
  });

  it('rotates refresh tokens and detects token replay attacks', () => {
    const db = new DatabaseSync(':memory:');
    const currentTime = 1_000_000;
    const store = new OAuthStore(db, () => currentTime);

    const { verifier, challenge } = createPkce();
    const codeHash = createHash('sha256').update('c1').digest('hex');
    const at1Hash = createHash('sha256').update('at1').digest('hex');
    const rt1Hash = createHash('sha256').update('rt1').digest('hex');

    store.createCode({
      action: 'create_code',
      codeHash,
      clientId,
      redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      resource,
      scope,
      expiresAt: currentTime + 120_000
    });

    store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: verifier,
      resource,
      newAccessTokenHash: at1Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt1Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });

    // Rotate refresh token RT1 -> RT2
    const at2Hash = createHash('sha256').update('at2').digest('hex');
    const rt2Hash = createHash('sha256').update('rt2').digest('hex');
    const refreshResult = store.refreshToken({
      action: 'refresh_token',
      refreshTokenHash: rt1Hash,
      clientId,
      newAccessTokenHash: at2Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt2Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(refreshResult.ok).toBe(true);

    // AT2 should be valid
    expect(store.verifyAccessToken({
      action: 'verify_access_token',
      accessTokenHash: at2Hash,
      expectedResource: resource
    }).ok).toBe(true);

    // Replaying RT1 must be detected and trigger family revocation!
    const at3Hash = createHash('sha256').update('at3').digest('hex');
    const rt3Hash = createHash('sha256').update('rt3').digest('hex');
    const replayResult = store.refreshToken({
      action: 'refresh_token',
      refreshTokenHash: rt1Hash,
      clientId,
      newAccessTokenHash: at3Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt3Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(replayResult.ok).toBe(false);
    expect(replayResult.error).toBe('replay_detected');

    // Due to replay detection, RT2 should now also be revoked!
    const rotateAfterReplay = store.refreshToken({
      action: 'refresh_token',
      refreshTokenHash: rt2Hash,
      clientId,
      newAccessTokenHash: at3Hash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rt3Hash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });
    expect(rotateAfterReplay.ok).toBe(false);

    // AT2 should also be revoked
    expect(store.verifyAccessToken({
      action: 'verify_access_token',
      accessTokenHash: at2Hash,
      expectedResource: resource
    }).ok).toBe(false);
  });

  it('revokes tokens explicitly', () => {
    const db = new DatabaseSync(':memory:');
    const currentTime = 1_000_000;
    const store = new OAuthStore(db, () => currentTime);

    const { verifier, challenge } = createPkce();
    const codeHash = createHash('sha256').update('c-rev').digest('hex');
    const atHash = createHash('sha256').update('at-rev').digest('hex');
    const rtHash = createHash('sha256').update('rt-rev').digest('hex');

    store.createCode({
      action: 'create_code',
      codeHash,
      clientId,
      redirectUri,
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
      resource,
      scope,
      expiresAt: currentTime + 120_000
    });
    store.consumeCode({
      action: 'consume_code',
      codeHash,
      clientId,
      redirectUri,
      codeVerifier: verifier,
      resource,
      newAccessTokenHash: atHash,
      accessTokenExpiresAt: currentTime + 900_000,
      newRefreshTokenHash: rtHash,
      refreshTokenExpiresAt: currentTime + 2_592_000_000
    });

    expect(store.verifyAccessToken({ action: 'verify_access_token', accessTokenHash: atHash, expectedResource: resource }).ok).toBe(true);

    store.revokeToken({ action: 'revoke_token', tokenHash: atHash });
    expect(store.verifyAccessToken({ action: 'verify_access_token', accessTokenHash: atHash, expectedResource: resource }).ok).toBe(false);
  });
});
