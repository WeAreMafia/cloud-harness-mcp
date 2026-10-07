import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { RunnerConfigSchema, parseGitLabAllowedNamespaces } from '@cloud-harness/contracts';
import {
  hasGitLabRepositoryCredential,
  isAmbiguousOrMaliciousUrl,
  isConfiguredGitLabRepository,
  normalizeRepositoryPath,
  resolveGitLabRepositoryToken
} from '../src/gitlab-credential-broker.js';
import { loadRunnerConfigWithReadiness } from '../src/config.js';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch { /* ignore */ }
  }
});

function createTempSecretDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'gitlab-secret-test-'));
  tempDirs.push(dir);
  return dir;
}

describe('GitLab repository path normalization', () => {
  it('normalizes repository paths with and without leading/trailing slashes and .git suffix', () => {
    expect(normalizeRepositoryPath('hoa.ngominh/bandodoanhnghiep')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('/hoa.ngominh/bandodoanhnghiep')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('hoa.ngominh/bandodoanhnghiep/')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('/hoa.ngominh/bandodoanhnghiep/')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('hoa.ngominh/bandodoanhnghiep.git')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('/hoa.ngominh/bandodoanhnghiep.git')).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(normalizeRepositoryPath('/hoa.ngominh/bandodoanhnghiep.git/')).toBe('hoa.ngominh/bandodoanhnghiep');
  });

  it('normalizes case-insensitively', () => {
    expect(normalizeRepositoryPath('Hoa.NgoMinh/BandoDoanhNghiep.GIT')).toBe('hoa.ngominh/bandodoanhnghiep');
  });

  it('strips query parameters and fragments if present', () => {
    expect(normalizeRepositoryPath('/hoa.ngominh/bandodoanhnghiep.git?ref=main#readme')).toBe('hoa.ngominh/bandodoanhnghiep');
  });
});

describe('isAmbiguousOrMaliciousUrl canonicalization detection', () => {
  it('identifies ambiguous or malicious URLs and allows clean URLs', () => {
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team\\repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team%2frepo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team%5crepo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team//repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/./repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/../repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/%2e/repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/%2e%2e/repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('http://git.example.com/team/repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://user:pass@git.example.com/team/repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com:8443/team/repo')).toBe(true);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/repo.git')).toBe(false);
    expect(isAmbiguousOrMaliciousUrl('https://git.example.com/team/repo')).toBe(false);
    // Non-string inputs fail closed and are considered ambiguous/malicious
    expect(isAmbiguousOrMaliciousUrl(new URL('https://git.example.com/team/repo.git') as any)).toBe(true);
    expect(isAmbiguousOrMaliciousUrl(undefined as any)).toBe(true);
  });
});

describe('GitLab namespace configuration normalization (parseGitLabAllowedNamespaces)', () => {
  it('accepts single and comma-separated namespaces', () => {
    expect(parseGitLabAllowedNamespaces('hoa.ngominh')).toEqual(['hoa.ngominh']);
    expect(parseGitLabAllowedNamespaces('hoa.ngominh,team-a/platform')).toEqual(['hoa.ngominh', 'team-a/platform']);
    expect(parseGitLabAllowedNamespaces(['hoa.ngominh', 'team-a/platform'])).toEqual(['hoa.ngominh', 'team-a/platform']);
  });

  it('trims whitespace and removes leading/trailing slashes', () => {
    expect(parseGitLabAllowedNamespaces('  /hoa.ngominh/ ,  /team-a/platform/ ')).toEqual(['hoa.ngominh', 'team-a/platform']);
  });

  it('normalizes entries to lowercase', () => {
    expect(parseGitLabAllowedNamespaces('Hoa.NgoMinh,Team-A/Platform')).toEqual(['hoa.ngominh', 'team-a/platform']);
  });

  it('deduplicates entries preserving first-seen ordering after normalization', () => {
    expect(parseGitLabAllowedNamespaces('hoa.ngominh,Hoa.NgoMinh,/hoa.ngominh/')).toEqual(['hoa.ngominh']);
    expect(parseGitLabAllowedNamespaces('hoa.ngominh,team-a/platform,HOA.NGOMINH,/team-a/platform/')).toEqual(['hoa.ngominh', 'team-a/platform']);
    expect(parseGitLabAllowedNamespaces(['hoa.ngominh', 'Hoa.NgoMinh', '/hoa.ngominh/'])).toEqual(['hoa.ngominh']);
  });

  it('rejects empty configuration or empty entries', () => {
    expect(() => parseGitLabAllowedNamespaces('')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces('   ')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh,,team-a')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh, ,team-a')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces('/')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces('///')).toThrow(/empty/i);
    expect(() => parseGitLabAllowedNamespaces([])).toThrow(/at least one/i);
  });

  it('rejects dot and dot-dot path segments', () => {
    expect(() => parseGitLabAllowedNamespaces('.')).toThrow(/dot segment/i);
    expect(() => parseGitLabAllowedNamespaces('..')).toThrow(/dot segment/i);
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh/./sub')).toThrow(/dot segment/i);
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh/../sub')).toThrow(/dot segment/i);
  });

  it('rejects query and fragment syntax', () => {
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh?ref=main')).toThrow(/query or fragment/i);
    expect(() => parseGitLabAllowedNamespaces('hoa.ngominh#readme')).toThrow(/query or fragment/i);
  });

  it('rejects full URLs and schemes/ports', () => {
    expect(() => parseGitLabAllowedNamespaces('https://git.iamsoftware.com.vn/hoa.ngominh')).toThrow(/full URL/i);
    expect(() => parseGitLabAllowedNamespaces('http://example.com/hoa.ngominh')).toThrow(/full URL/i);
    expect(() => parseGitLabAllowedNamespaces('host:8443/hoa.ngominh')).toThrow(/full URL/i);
  });

  it('rejects backslash and percent-encoded characters', () => {
    expect(() => parseGitLabAllowedNamespaces('hoa\\ngominh')).toThrow(/backslash or percent/i);
    expect(() => parseGitLabAllowedNamespaces('hoa%2fngominh')).toThrow(/backslash or percent/i);
    expect(() => parseGitLabAllowedNamespaces('hoa%5cngominh')).toThrow(/backslash or percent/i);
  });

  it('rejects repeated slashes within namespace', () => {
    expect(() => parseGitLabAllowedNamespaces('team-a//platform')).toThrow(/repeated slashes/i);
  });
});

describe('GitLab namespace-scoped authorization and matching (Requirements 1, 2, 3, 9)', () => {
  const testDir = createTempSecretDir();
  const tokenFile = join(testDir, 'token');
  writeFileSync(tokenFile, 'glpat-test-secret-token\n');

  const config = {
    gitlabHost: 'git.iamsoftware.com.vn',
    gitlabAllowedNamespaces: ['hoa.ngominh', 'team-a/platform'],
    gitlabTokenFile: tokenFile
  };

  describe('ALLOW cases', () => {
    it('authorizes exact host + hoa.ngominh/repo-a', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a')).toBe(true);
    });

    it('authorizes exact host + hoa.ngominh/repo-b.git', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-b.git')).toBe(true);
    });

    it('authorizes nested configured namespace team-a/platform/repo', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/team-a/platform/repo')).toBe(true);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/team-a/platform/repo.git')).toBe(true);
    });

    it('authorizes case-insensitively for host and namespace', () => {
      expect(isConfiguredGitLabRepository(config, 'https://GIT.IAMSOFTWARE.COM.VN/Hoa.NgoMinh/repo-a.git')).toBe(true);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/Team-A/Platform/repo.git')).toBe(true);
    });

    it('authorizes URLs with trailing slashes', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a/')).toBe(true);
    });
  });

  describe('DENY cases', () => {
    it('denies same host + other/repo', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/other/repo')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/other/repo.git')).toBe(false);
    });

    it('denies hoa.ngominh-evil/repo (prefix attack)', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh-evil/repo')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh-evil/repo.git')).toBe(false);
    });

    it('denies other/hoa.ngominh/repo (super-group mismatch)', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/other/hoa.ngominh/repo')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/other/hoa.ngominh/repo.git')).toBe(false);
    });

    it('denies repository path with extra segment (unlisted subgroup)', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo/subpath')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/team-a/platform/repo/subpath')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/team-a/repo')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/team-a/platform-evil/repo')).toBe(false);
    });

    it('denies wrong host', () => {
      expect(isConfiguredGitLabRepository(config, 'https://other.example.com/hoa.ngominh/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://gitlab.com/hoa.ngominh/repo-a.git')).toBe(false);
    });

    it('fails closed when configuration is missing any required field', () => {
      expect(isConfiguredGitLabRepository({ gitlabHost: undefined, gitlabAllowedNamespaces: ['hoa.ngominh'], gitlabTokenFile: tokenFile }, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository({ gitlabHost: 'git.iamsoftware.com.vn', gitlabAllowedNamespaces: undefined, gitlabTokenFile: tokenFile }, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository({ gitlabHost: 'git.iamsoftware.com.vn', gitlabAllowedNamespaces: [], gitlabTokenFile: tokenFile }, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository({ gitlabHost: 'git.iamsoftware.com.vn', gitlabAllowedNamespaces: ['hoa.ngominh'], gitlabTokenFile: undefined }, 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a')).toBe(false);
    });

    it('denies encoded slash/backslash ambiguity (%2F, %5C, \\)', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh%2frepo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh%2Frepo-a.git')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh%5crepo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh%5Crepo-a.git')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh\\repo-a')).toBe(false);
    });

    it('denies repeated slash in path', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh//repo-a')).toBe(false);
    });

    it('denies dot-segment ambiguity (., .., %2e, %2e%2e)', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/./repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/../repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/%2e/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/%2e%2e/repo-a')).toBe(false);
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn/hoa.ngominh/..%2frepo-a')).toBe(false);
    });

    it('denies embedded URL credentials', () => {
      expect(isConfiguredGitLabRepository(config, 'https://user:pass@git.iamsoftware.com.vn/hoa.ngominh/repo-a.git')).toBe(false);
    });

    it('denies unexpected explicit port', () => {
      expect(isConfiguredGitLabRepository(config, 'https://git.iamsoftware.com.vn:8443/hoa.ngominh/repo-a.git')).toBe(false);
    });
  });

  describe('Pre-parsed URL vs Raw URL invariant demonstration', () => {
    it('demonstrates WHATWG URL parser canonicalizes dot-segments away and proves why broker rejects pre-parsed input', () => {
      const maliciousRaw = 'https://git.iamsoftware.com.vn/hoa.ngominh/./repo-a';
      const parsed = new URL(maliciousRaw);
      // WHATWG URL parser automatically normalizes '/hoa.ngominh/./repo-a' to '/hoa.ngominh/repo-a'
      expect(parsed.pathname).toBe('/hoa.ngominh/repo-a');

      // The raw string is rejected by the broker because of dot segment ambiguity
      expect(isConfiguredGitLabRepository(config, maliciousRaw)).toBe(false);
      expect(isAmbiguousOrMaliciousUrl(maliciousRaw)).toBe(true);

      // If passed a URL object directly at runtime, the broker fails closed
      expect(isConfiguredGitLabRepository(config, parsed as any)).toBe(false);
      expect(resolveGitLabRepositoryToken(config, parsed as any)).toBeUndefined();
      expect(hasGitLabRepositoryCredential(config, parsed as any)).toBe(false);
    });
  });
});

describe('GitLab token resolution and read-on-demand', () => {
  it('reads token on demand and trims trailing newlines and whitespace', () => {
    const testDir = createTempSecretDir();
    const tokenFile = join(testDir, 'token');
    writeFileSync(tokenFile, '  glpat-test-pat-token-12345\n\n');

    const config = {
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: ['hoa.ngominh'],
      gitlabTokenFile: tokenFile
    };
    const repoUrl = 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a.git';

    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBe('glpat-test-pat-token-12345');
    expect(hasGitLabRepositoryCredential(config, repoUrl)).toBe(true);

    // Test zero-downtime rotation: update file without changing config
    writeFileSync(tokenFile, 'glpat-rotated-token-67890\n');
    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBe('glpat-rotated-token-67890');
  });

  it('fails closed and rejects empty or whitespace-only token files', () => {
    const testDir = createTempSecretDir();
    const tokenFile = join(testDir, 'empty-token');
    writeFileSync(tokenFile, '   \n\t\n');

    const config = {
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: ['hoa.ngominh'],
      gitlabTokenFile: tokenFile
    };
    const repoUrl = 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a.git';

    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBeUndefined();
    expect(hasGitLabRepositoryCredential(config, repoUrl)).toBe(false);
  });

  it('fails closed when token file does not exist without leaking paths or throwing uncaught errors', () => {
    const config = {
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: ['hoa.ngominh'],
      gitlabTokenFile: '/non-existent-path/secret-token-file'
    };
    const repoUrl = 'https://git.iamsoftware.com.vn/hoa.ngominh/repo-a.git';

    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBeUndefined();
    expect(hasGitLabRepositoryCredential(config, repoUrl)).toBe(false);
  });
});

describe('Runner configuration validation for GitLab integration', () => {
  const baseValid = {
    serviceToken: 'runner-service-token-longer-than-32-chars-test',
    jobsRoot: '/tmp/jobs',
    stateDb: '/tmp/state.db',
    executorImage: 'cloud-harness-executor:local',
    allowedGitHosts: ['github.com', 'git.iamsoftware.com.vn']
  };

  it('accepts complete GitLab configuration with string or array of namespaces', () => {
    const parsed1 = RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: 'hoa.ngominh',
      gitlabTokenFile: '/run/cloud-harness-secrets/gitlab-mcp-pat'
    });
    expect(parsed1.gitlabHost).toBe('git.iamsoftware.com.vn');
    expect(parsed1.gitlabAllowedNamespaces).toEqual(['hoa.ngominh']);
    expect(parsed1.gitlabTokenFile).toBe('/run/cloud-harness-secrets/gitlab-mcp-pat');

    const parsed2 = RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: ['hoa.ngominh', 'team-a/platform'],
      gitlabTokenFile: '/run/cloud-harness-secrets/gitlab-mcp-pat'
    });
    expect(parsed2.gitlabAllowedNamespaces).toEqual(['hoa.ngominh', 'team-a/platform']);
  });

  it('accepts configuration when all GitLab fields are absent', () => {
    const parsed = RunnerConfigSchema.parse(baseValid);
    expect(parsed.gitlabHost).toBeUndefined();
    expect(parsed.gitlabAllowedNamespaces).toBeUndefined();
    expect(parsed.gitlabTokenFile).toBeUndefined();
  });

  it('rejects partial GitLab configurations', () => {
    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn'
    })).toThrow(/gitlabAllowedNamespaces/);

    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: 'hoa.ngominh'
    })).toThrow(/gitlabTokenFile/);

    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabTokenFile: '/run/secrets/token'
    })).toThrow(/gitlabHost/);
  });

  it('rejects non-absolute gitlabTokenFile', () => {
    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabAllowedNamespaces: 'hoa.ngominh',
      gitlabTokenFile: 'relative/path/token'
    })).toThrow(/absolute path/);
  });

  it('throws clear error when legacy GITLAB_REPOSITORY environment variable is set', () => {
    const originalEnv = { ...process.env };
    try {
      process.env.GITLAB_REPOSITORY = 'hoa.ngominh/bandodoanhnghiep';
      expect(() => loadRunnerConfigWithReadiness()).toThrow(/GITLAB_REPOSITORY was replaced by GITLAB_ALLOWED_NAMESPACES/);
    } finally {
      process.env = originalEnv;
    }
  });

  it('loads GitLab configuration from process.env via loadRunnerConfigWithReadiness', () => {
    const originalEnv = { ...process.env };
    try {
      delete process.env.GITLAB_REPOSITORY;
      process.env.RUNNER_TOKEN = 'runner-service-token-longer-than-32-chars-test';
      process.env.GITLAB_HOST = 'git.iamsoftware.com.vn';
      process.env.GITLAB_ALLOWED_NAMESPACES = 'hoa.ngominh,team-a/platform';
      process.env.GITLAB_TOKEN_FILE = '/run/cloud-harness-secrets/gitlab-mcp-pat';

      const result = loadRunnerConfigWithReadiness();
      expect(result.config.gitlabHost).toBe('git.iamsoftware.com.vn');
      expect(result.config.gitlabAllowedNamespaces).toEqual(['hoa.ngominh', 'team-a/platform']);
      expect(result.config.gitlabTokenFile).toBe('/run/cloud-harness-secrets/gitlab-mcp-pat');
    } finally {
      process.env = originalEnv;
    }
  });
});
