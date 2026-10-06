import { z } from 'zod';

export const OAuthCreateCodeRequestSchema = z.object({
  action: z.literal('create_code'),
  codeHash: z.string().length(64),
  clientId: z.string().min(1).max(256),
  redirectUri: z.string().min(1).max(2048),
  codeChallenge: z.string().min(43).max(128),
  codeChallengeMethod: z.literal('S256'),
  resource: z.string().min(1).max(2048),
  scope: z.string().max(1024).default(''),
  expiresInSeconds: z.number().int().positive().optional(),
  expiresAt: z.number().int().positive().optional()
}).strict();

export const OAuthConsumeCodeRequestSchema = z.object({
  action: z.literal('consume_code'),
  codeHash: z.string().length(64),
  clientId: z.string().min(1).max(256),
  redirectUri: z.string().min(1).max(2048),
  codeVerifier: z.string().min(43).max(128),
  resource: z.string().min(1).max(2048),
  newAccessTokenHash: z.string().length(64),
  accessTokenTtlSeconds: z.number().int().positive().optional(),
  accessTokenExpiresAt: z.number().int().positive().optional(),
  newRefreshTokenHash: z.string().length(64),
  refreshTokenTtlSeconds: z.number().int().positive().optional(),
  refreshTokenExpiresAt: z.number().int().positive().optional()
}).strict();

export const OAuthRefreshTokenRequestSchema = z.object({
  action: z.literal('refresh_token'),
  refreshTokenHash: z.string().length(64),
  clientId: z.string().min(1).max(256),
  newAccessTokenHash: z.string().length(64),
  accessTokenTtlSeconds: z.number().int().positive().optional(),
  accessTokenExpiresAt: z.number().int().positive().optional(),
  newRefreshTokenHash: z.string().length(64),
  refreshTokenTtlSeconds: z.number().int().positive().optional(),
  refreshTokenExpiresAt: z.number().int().positive().optional()
}).strict();

export const OAuthVerifyTokenRequestSchema = z.object({
  action: z.literal('verify_access_token'),
  accessTokenHash: z.string().length(64),
  expectedResource: z.string().min(1).max(2048)
}).strict();

export const OAuthRevokeTokenRequestSchema = z.object({
  action: z.literal('revoke_token'),
  tokenHash: z.string().length(64)
}).strict();

export const OAuthInternalRequestSchema = z.discriminatedUnion('action', [
  OAuthCreateCodeRequestSchema,
  OAuthConsumeCodeRequestSchema,
  OAuthRefreshTokenRequestSchema,
  OAuthVerifyTokenRequestSchema,
  OAuthRevokeTokenRequestSchema
]);

export const OAuthInternalSuccessResponseSchema = z.object({
  ok: z.literal(true),
  data: z.record(z.string(), z.unknown()).optional()
}).strict();

export const OAuthInternalFailureResponseSchema = z.object({
  ok: z.literal(false),
  error: z.string()
}).strict();

export const OAuthInternalResponseSchema = z.discriminatedUnion('ok', [
  OAuthInternalSuccessResponseSchema,
  OAuthInternalFailureResponseSchema
]);

export type OAuthCreateCodeRequest = z.infer<typeof OAuthCreateCodeRequestSchema>;
export type OAuthConsumeCodeRequest = z.infer<typeof OAuthConsumeCodeRequestSchema>;
export type OAuthRefreshTokenRequest = z.infer<typeof OAuthRefreshTokenRequestSchema>;
export type OAuthVerifyTokenRequest = z.infer<typeof OAuthVerifyTokenRequestSchema>;
export type OAuthRevokeTokenRequest = z.infer<typeof OAuthRevokeTokenRequestSchema>;
export type OAuthInternalRequest = z.infer<typeof OAuthInternalRequestSchema>;
export type OAuthInternalResponse = z.infer<typeof OAuthInternalResponseSchema>;
