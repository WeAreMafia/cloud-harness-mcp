import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { RunnerConfigSchema } from '@cloud-harness/contracts';
import {
  hasGitLabRepositoryCredential,
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

describe('GitLab repository path normalization (Requirement A)', () => {
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

describe('GitLab repository exact matching (Requirement B)', () => {
  const testDir = createTempSecretDir();
  const tokenFile = join(testDir, 'token');
  writeFileSync(tokenFile, 'glpat-test-secret-token\n');

  const config = {
    gitlabHost: 'git.iamsoftware.com.vn',
    gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
    gitlabTokenFile: tokenFile
  };

  it('allows exact host and normalized path match', () => {
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep'))).toBe(true);
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git'))).toBe(true);
    expect(isConfiguredGitLabRepository(config, new URL('https://GIT.IAMSOFTWARE.COM.VN/Hoa.NgoMinh/bandodoanhnghiep.git'))).toBe(true);
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep/'))).toBe(true);
  });

  it('denies different repository on the same host', () => {
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/other'))).toBe(false);
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/other.git'))).toBe(false);
  });

  it('denies prefix/suffix collision attacks', () => {
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep-evil'))).toBe(false);
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep/sub'))).toBe(false);
    expect(isConfiguredGitLabRepository(config, new URL('https://git.iamsoftware.com.vn/other-hoa.ngominh/bandodoanhnghiep'))).toBe(false);
  });

  it('denies matching path on a different host', () => {
    expect(isConfiguredGitLabRepository(config, new URL('https://other.example.com/hoa.ngominh/bandodoanhnghiep'))).toBe(false);
    expect(isConfiguredGitLabRepository(config, new URL('https://gitlab.com/hoa.ngominh/bandodoanhnghiep.git'))).toBe(false);
  });

  it('fails closed when configuration is missing any required field', () => {
    expect(isConfiguredGitLabRepository({ gitlabHost: undefined, gitlabRepository: 'a/b', gitlabTokenFile: tokenFile }, new URL('https://git.iamsoftware.com.vn/a/b'))).toBe(false);
    expect(isConfiguredGitLabRepository({ gitlabHost: 'git.iamsoftware.com.vn', gitlabRepository: undefined, gitlabTokenFile: tokenFile }, new URL('https://git.iamsoftware.com.vn/a/b'))).toBe(false);
    expect(isConfiguredGitLabRepository({ gitlabHost: 'git.iamsoftware.com.vn', gitlabRepository: 'a/b', gitlabTokenFile: undefined }, new URL('https://git.iamsoftware.com.vn/a/b'))).toBe(false);
  });
});

describe('GitLab token resolution and read-on-demand (Requirements C & D)', () => {
  it('reads token on demand and trims trailing newlines and whitespace', () => {
    const testDir = createTempSecretDir();
    const tokenFile = join(testDir, 'token');
    writeFileSync(tokenFile, '  glpat-test-project-access-token-12345\n\n');

    const config = {
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
      gitlabTokenFile: tokenFile
    };
    const repoUrl = new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git');

    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBe('glpat-test-project-access-token-12345');
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
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
      gitlabTokenFile: tokenFile
    };
    const repoUrl = new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git');

    expect(resolveGitLabRepositoryToken(config, repoUrl)).toBeUndefined();
    expect(hasGitLabRepositoryCredential(config, repoUrl)).toBe(false);
  });

  it('fails closed when token file does not exist without leaking paths or throwing uncaught errors', () => {
    const config = {
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
      gitlabTokenFile: '/non-existent-path/secret-token-file'
    };
    const repoUrl = new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git');

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

  it('accepts complete GitLab configuration', () => {
    const parsed = RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
      gitlabTokenFile: '/run/cloud-harness-secrets/gitlab-bandodoanhnghiep-token'
    });
    expect(parsed.gitlabHost).toBe('git.iamsoftware.com.vn');
    expect(parsed.gitlabRepository).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(parsed.gitlabTokenFile).toBe('/run/cloud-harness-secrets/gitlab-bandodoanhnghiep-token');
  });

  it('accepts configuration when all GitLab fields are absent', () => {
    const parsed = RunnerConfigSchema.parse(baseValid);
    expect(parsed.gitlabHost).toBeUndefined();
    expect(parsed.gitlabRepository).toBeUndefined();
    expect(parsed.gitlabTokenFile).toBeUndefined();
  });

  it('rejects partial GitLab configurations', () => {
    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn'
    })).toThrow(/gitlabRepository/);

    expect(() => RunnerConfigSchema.parse({
      ...baseValid,
      gitlabHost: 'git.iamsoftware.com.vn',
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep'
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
      gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
      gitlabTokenFile: 'relative/path/token'
    })).toThrow(/absolute path/);
  });

  it('loads GitLab configuration from process.env via loadRunnerConfigWithReadiness', () => {
    const originalEnv = { ...process.env };
    try {
      process.env.RUNNER_TOKEN = 'runner-service-token-longer-than-32-chars-test';
      process.env.GITLAB_HOST = 'git.iamsoftware.com.vn';
      process.env.GITLAB_REPOSITORY = 'hoa.ngominh/bandodoanhnghiep';
      process.env.GITLAB_TOKEN_FILE = '/run/cloud-harness-secrets/gitlab-bandodoanhnghiep-token';

      const result = loadRunnerConfigWithReadiness();
      expect(result.config.gitlabHost).toBe('git.iamsoftware.com.vn');
      expect(result.config.gitlabRepository).toBe('hoa.ngominh/bandodoanhnghiep');
      expect(result.config.gitlabTokenFile).toBe('/run/cloud-harness-secrets/gitlab-bandodoanhnghiep-token');
    } finally {
      process.env = originalEnv;
    }
  });
});
