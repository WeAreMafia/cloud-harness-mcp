import { readFileSync } from 'node:fs';
import type { RunnerConfig } from '@cloud-harness/contracts';

/**
 * Safely normalize a repository path by removing leading/trailing slashes,
 * stripping an optional case-insensitive `.git` suffix, and lowercasing.
 * Does not permit prefix or substring attacks.
 */
export function normalizeRepositoryPath(rawPath: string): string {
  const withoutQueryOrHash = rawPath.split(/[?#]/)[0] ?? '';
  let normalized = withoutQueryOrHash.trim();
  normalized = normalized.replace(/^\/+/, '').replace(/\/+$/, '');
  normalized = normalized.replace(/\.git$/i, '');
  normalized = normalized.replace(/\/+$/, '');
  return normalized.toLowerCase();
}

/**
 * Check whether a repository URL strictly matches the configured GitLab repository.
 * Requires:
 * 1. Exact hostname match (case-insensitive).
 * 2. Exact normalized pathname match (case-insensitive, no prefix matching).
 * Fails closed if any required configuration element is missing.
 */
export function isConfiguredGitLabRepository(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabRepository' | 'gitlabTokenFile'>,
  repositoryUrl: URL
): boolean {
  if (!config.gitlabHost || !config.gitlabRepository || !config.gitlabTokenFile) {
    return false;
  }
  const expectedHost = config.gitlabHost.trim().toLowerCase();
  const actualHost = repositoryUrl.hostname.trim().toLowerCase();
  if (actualHost !== expectedHost) {
    return false;
  }
  const expectedPath = normalizeRepositoryPath(config.gitlabRepository);
  const actualPath = normalizeRepositoryPath(repositoryUrl.pathname);
  return actualPath.length > 0 && actualPath === expectedPath;
}

/**
 * Read the GitLab Project Access Token on demand from the configured secret file.
 * Fails closed (returns undefined) if the file cannot be read, does not exist,
 * or contains an empty/whitespace token.
 * Trims any trailing/leading newlines or whitespace.
 * Never logs the token and never embeds the token or secret path into error messages.
 */
export function resolveGitLabRepositoryToken(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabRepository' | 'gitlabTokenFile'>,
  repositoryUrl: URL
): string | undefined {
  if (!isConfiguredGitLabRepository(config, repositoryUrl)) {
    return undefined;
  }
  const tokenFile = config.gitlabTokenFile;
  if (!tokenFile) return undefined;
  try {
    const raw = readFileSync(tokenFile, 'utf8');
    const token = raw.trim();
    if (!token) {
      return undefined;
    }
    return token;
  } catch {
    return undefined;
  }
}

/**
 * Verify whether a valid, non-empty GitLab token credential is currently readable
 * for the given repository URL, without exposing the secret plaintext.
 */
export function hasGitLabRepositoryCredential(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabRepository' | 'gitlabTokenFile'>,
  repositoryUrl: URL
): boolean {
  return resolveGitLabRepositoryToken(config, repositoryUrl) !== undefined;
}
