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
 * Check whether a raw repository URL string contains ambiguous, malformed,
 * or canonicalization-attack constructs such as:
 * - percent-encoded slash (%2F)
 * - percent-encoded backslash (%5C)
 * - literal backslash
 * - repeated slashes in path
 * - dot segments ("." or "..")
 * - percent-encoded dot segments (%2e, %2e%2e)
 * - embedded username/password
 * - unexpected explicit port (port !== 443)
 *
 * CRITICAL SECURITY INVARIANT: Must be performed on the raw input string
 * BEFORE WHATWG URL parsing can canonicalize or resolve path segments away.
 */
export function isAmbiguousOrMaliciousUrl(rawRepositoryUrl: string): boolean {
  if (typeof rawRepositoryUrl !== 'string' || !rawRepositoryUrl.trim()) {
    return true;
  }
  if (rawRepositoryUrl.includes('\\')) return true;
  if (/%2f/i.test(rawRepositoryUrl)) return true;
  if (/%5c/i.test(rawRepositoryUrl)) return true;
  if (!/^https:\/\//i.test(rawRepositoryUrl)) return true;

  const withoutScheme = rawRepositoryUrl.slice(8);
  const slashIndex = withoutScheme.indexOf('/');
  if (slashIndex === -1) return true;

  const rawAuthority = withoutScheme.slice(0, slashIndex);
  const rawPath = withoutScheme.slice(slashIndex).split(/[?#]/)[0] ?? '';

  if (rawPath.includes('//')) return true;
  if (/(?:^|\/)(?:%2e|\.)(?:%2e|\.)?(?:\/|$)/i.test(rawPath)) return true;
  if (rawAuthority.includes('@')) return true;
  if (rawAuthority.includes(':')) {
    const port = rawAuthority.slice(rawAuthority.lastIndexOf(':') + 1);
    if (port !== '443') return true;
  }

  return false;
}

/**
 * Check whether a raw repository URL string strictly matches the configured GitLab host and an allowed namespace.
 *
 * CRITICAL SECURITY INVARIANT: Receives the raw repository URL string. Pre-parsed URL objects
 * MUST NOT be accepted because WHATWG URL parsing normalizes dot segments before inspection.
 *
 * Requires:
 * 1. Raw URL string passes canonicalization/ambiguity checks BEFORE parsing with new URL().
 * 2. Protocol is https, no embedded credentials, standard port 443 only.
 * 3. Exact hostname match (case-insensitive, no wildcards or substrings).
 * 4. Repository belongs DIRECTLY inside an explicitly allowed namespace.
 * Fails closed if any required configuration element is missing.
 */
export function isConfiguredGitLabRepository(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabAllowedNamespaces' | 'gitlabTokenFile'>,
  rawRepositoryUrl: string
): boolean {
  if (!config.gitlabHost || !config.gitlabAllowedNamespaces || !config.gitlabTokenFile) {
    return false;
  }
  const allowedList = Array.isArray(config.gitlabAllowedNamespaces)
    ? config.gitlabAllowedNamespaces
    : [config.gitlabAllowedNamespaces];
  if (allowedList.length === 0) {
    return false;
  }
  if (typeof rawRepositoryUrl !== 'string' || !rawRepositoryUrl.trim()) {
    return false;
  }
  if (isAmbiguousOrMaliciousUrl(rawRepositoryUrl)) {
    return false;
  }

  let url: URL;
  try {
    url = new URL(rawRepositoryUrl);
  } catch {
    return false;
  }

  if (url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  if (url.port && url.port !== '443') return false;

  const expectedHost = config.gitlabHost.trim().toLowerCase();
  const actualHost = url.hostname.trim().toLowerCase();
  if (actualHost !== expectedHost) {
    return false;
  }

  const normalizedRepoPath = normalizeRepositoryPath(url.pathname);
  if (!normalizedRepoPath) {
    return false;
  }
  const repoSegments = normalizedRepoPath.split('/');
  if (repoSegments.length === 0 || repoSegments.some((s) => !s || s === '.' || s === '..')) {
    return false;
  }

  for (const ns of allowedList) {
    if (!ns || typeof ns !== 'string') continue;
    const normalizedNs = ns.trim().replace(/^\/+/, '').replace(/\/+$/, '').toLowerCase();
    if (!normalizedNs) continue;
    const nsSegments = normalizedNs.split('/');
    if (nsSegments.some((s) => !s || s === '.' || s === '..')) continue;

    // Direct containment: repo must be directly inside the allowed namespace
    if (repoSegments.length !== nsSegments.length + 1) {
      continue;
    }

    let match = true;
    for (let i = 0; i < nsSegments.length; i++) {
      if (repoSegments[i] !== nsSegments[i]) {
        match = false;
        break;
      }
    }
    if (match) {
      const repoName = repoSegments[nsSegments.length];
      if (repoName && repoName !== '.' && repoName !== '..') {
        return true;
      }
    }
  }

  return false;
}

/**
 * Read the GitLab Personal Access Token on demand from the configured secret file.
 * Fails closed (returns undefined) if the file cannot be read, does not exist,
 * or contains an empty/whitespace token.
 * Trims any trailing/leading newlines or whitespace.
 * Never logs the token and never embeds the token or secret path into error messages.
 */
export function resolveGitLabRepositoryToken(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabAllowedNamespaces' | 'gitlabTokenFile'>,
  rawRepositoryUrl: string
): string | undefined {
  if (typeof rawRepositoryUrl !== 'string' || !isConfiguredGitLabRepository(config, rawRepositoryUrl)) {
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
 * for the given raw repository URL string, without exposing the secret plaintext.
 */
export function hasGitLabRepositoryCredential(
  config: Pick<RunnerConfig, 'gitlabHost' | 'gitlabAllowedNamespaces' | 'gitlabTokenFile'>,
  rawRepositoryUrl: string
): boolean {
  if (typeof rawRepositoryUrl !== 'string') return false;
  return resolveGitLabRepositoryToken(config, rawRepositoryUrl) !== undefined;
}
