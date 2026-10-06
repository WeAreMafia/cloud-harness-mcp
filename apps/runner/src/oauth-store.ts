import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type {
  OAuthCreateCodeRequest,
  OAuthConsumeCodeRequest,
  OAuthRefreshTokenRequest,
  OAuthVerifyTokenRequest,
  OAuthRevokeTokenRequest,
  OAuthInternalRequest,
  OAuthInternalResponse
} from '@cloud-harness/contracts';

type CodeRow = {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  resource: string;
  scope: string;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
};

type RefreshTokenRow = {
  token_hash: string;
  family_id: string;
  client_id: string;
  resource: string;
  scope: string;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
};

type AccessTokenRow = {
  token_hash: string;
  client_id: string;
  resource: string;
  scope: string;
  created_at: number;
  expires_at: number;
  revoked_at: number | null;
};

function transaction<T>(database: DatabaseSync, action: () => T): T {
  database.exec('BEGIN IMMEDIATE');
  try {
    const value = action();
    database.exec('COMMIT');
    return value;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function verifyCodeChallenge(codeVerifier: string, codeChallenge: string): boolean {
  const digest = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
  const left = Buffer.from(digest);
  const right = Buffer.from(codeChallenge);
  return left.length === right.length && timingSafeEqual(left, right);
}

export class OAuthStore {
  constructor(
    private readonly database: DatabaseSync,
    private readonly now = Date.now
  ) {
    this.initSchema();
  }

  private initSchema(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
        code_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        code_challenge_method TEXT NOT NULL,
        resource TEXT NOT NULL,
        scope TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_authorization_codes(expires_at);

      CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        token_hash TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        resource TEXT NOT NULL,
        scope TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family ON oauth_refresh_tokens(family_id);

      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        token_hash TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        resource TEXT NOT NULL,
        scope TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_oauth_access_expires ON oauth_access_tokens(expires_at);
    `);
  }

  handle(request: OAuthInternalRequest): OAuthInternalResponse {
    switch (request.action) {
      case 'create_code':
        return this.createCode(request);
      case 'consume_code':
        return this.consumeCode(request);
      case 'refresh_token':
        return this.refreshToken(request);
      case 'verify_access_token':
        return this.verifyAccessToken(request);
      case 'revoke_token':
        return this.revokeToken(request);
      default:
        return { ok: false, error: 'unknown_action' };
    }
  }

  createCode(request: OAuthCreateCodeRequest): OAuthInternalResponse {
    const now = this.now();
    const expiresAt = request.expiresAt ?? (now + (request.expiresInSeconds ?? 120) * 1000);
    try {
      this.database.prepare(`
        INSERT INTO oauth_authorization_codes
          (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, resource, scope, created_at, expires_at, consumed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
      `).run(
        request.codeHash,
        request.clientId,
        request.redirectUri,
        request.codeChallenge,
        request.codeChallengeMethod,
        request.resource,
        request.scope,
        now,
        expiresAt
      );
      return { ok: true };
    } catch {
      return { ok: false, error: 'storage_error' };
    }
  }

  consumeCode(request: OAuthConsumeCodeRequest): OAuthInternalResponse {
    return transaction(this.database, () => {
      const now = this.now();
      const row = this.database.prepare(
        'SELECT * FROM oauth_authorization_codes WHERE code_hash = ?'
      ).get(request.codeHash) as CodeRow | undefined;

      if (!row) {
        return { ok: false, error: 'invalid_grant' };
      }
      if (row.consumed_at !== null) {
        // Code replay detected!
        return { ok: false, error: 'invalid_grant' };
      }
      if (row.expires_at <= now) {
        return { ok: false, error: 'invalid_grant' };
      }
      if (row.client_id !== request.clientId || row.redirect_uri !== request.redirectUri) {
        return { ok: false, error: 'invalid_grant' };
      }
      if (row.resource !== request.resource) {
        return { ok: false, error: 'invalid_grant' };
      }
      if (!verifyCodeChallenge(request.codeVerifier, row.code_challenge)) {
        return { ok: false, error: 'invalid_grant' };
      }

      // Mark code consumed atomically
      this.database.prepare(
        'UPDATE oauth_authorization_codes SET consumed_at = ? WHERE code_hash = ?'
      ).run(now, request.codeHash);

      const accessExpiresAt = request.accessTokenExpiresAt ?? (now + (request.accessTokenTtlSeconds ?? 900) * 1000);
      const refreshExpiresAt = request.refreshTokenExpiresAt ?? (now + (request.refreshTokenTtlSeconds ?? 2_592_000) * 1000);

      // Insert access token
      this.database.prepare(`
        INSERT INTO oauth_access_tokens
          (token_hash, client_id, resource, scope, created_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
      `).run(
        request.newAccessTokenHash,
        row.client_id,
        row.resource,
        row.scope,
        now,
        accessExpiresAt
      );

      // Generate family ID for refresh token rotation tracking
      const familyId = randomBytes(16).toString('hex');
      this.database.prepare(`
        INSERT INTO oauth_refresh_tokens
          (token_hash, family_id, client_id, resource, scope, created_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
      `).run(
        request.newRefreshTokenHash,
        familyId,
        row.client_id,
        row.resource,
        row.scope,
        now,
        refreshExpiresAt
      );

      return {
        ok: true,
        data: {
          scope: row.scope,
          resource: row.resource
        }
      };
    });
  }

  refreshToken(request: OAuthRefreshTokenRequest): OAuthInternalResponse {
    return transaction(this.database, () => {
      const now = this.now();
      const row = this.database.prepare(
        'SELECT * FROM oauth_refresh_tokens WHERE token_hash = ?'
      ).get(request.refreshTokenHash) as RefreshTokenRow | undefined;

      if (!row) {
        return { ok: false, error: 'invalid_grant' };
      }

      if (row.revoked_at !== null) {
        // Replay detected! Invalidate all tokens in the same family
        this.database.prepare(
          'UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL'
        ).run(now, row.family_id);
        this.database.prepare(
          'UPDATE oauth_access_tokens SET revoked_at = ? WHERE client_id = ? AND resource = ? AND revoked_at IS NULL'
        ).run(now, row.client_id, row.resource);
        return { ok: false, error: 'replay_detected' };
      }

      if (row.expires_at <= now) {
        return { ok: false, error: 'invalid_grant' };
      }

      if (row.client_id !== request.clientId) {
        return { ok: false, error: 'invalid_grant' };
      }

      // Revoke current refresh token
      this.database.prepare(
        'UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ?'
      ).run(now, request.refreshTokenHash);

      const accessExpiresAt = request.accessTokenExpiresAt ?? (now + (request.accessTokenTtlSeconds ?? 900) * 1000);
      const refreshExpiresAt = request.refreshTokenExpiresAt ?? (now + (request.refreshTokenTtlSeconds ?? 2_592_000) * 1000);

      // Issue new refresh token within same family
      this.database.prepare(`
        INSERT INTO oauth_refresh_tokens
          (token_hash, family_id, client_id, resource, scope, created_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
      `).run(
        request.newRefreshTokenHash,
        row.family_id,
        row.client_id,
        row.resource,
        row.scope,
        now,
        refreshExpiresAt
      );

      // Issue new access token
      this.database.prepare(`
        INSERT INTO oauth_access_tokens
          (token_hash, client_id, resource, scope, created_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
      `).run(
        request.newAccessTokenHash,
        row.client_id,
        row.resource,
        row.scope,
        now,
        accessExpiresAt
      );

      return {
        ok: true,
        data: {
          scope: row.scope,
          resource: row.resource
        }
      };
    });
  }

  verifyAccessToken(request: OAuthVerifyTokenRequest): OAuthInternalResponse {
    const now = this.now();
    const row = this.database.prepare(
      'SELECT * FROM oauth_access_tokens WHERE token_hash = ?'
    ).get(request.accessTokenHash) as AccessTokenRow | undefined;

    if (!row || row.revoked_at !== null || row.expires_at <= now) {
      return { ok: false, error: 'invalid_token' };
    }

    if (row.resource !== request.expectedResource) {
      return { ok: false, error: 'invalid_token' };
    }

    return {
      ok: true,
      data: {
        clientId: row.client_id,
        scope: row.scope,
        resource: row.resource
      }
    };
  }

  revokeToken(request: OAuthRevokeTokenRequest): OAuthInternalResponse {
    const now = this.now();
    this.database.prepare(
      'UPDATE oauth_access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL'
    ).run(now, request.tokenHash);
    this.database.prepare(
      'UPDATE oauth_refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL'
    ).run(now, request.tokenHash);
    return { ok: true };
  }
}
