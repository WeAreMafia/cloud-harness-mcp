import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import { StateStore, type WorkspaceRecord } from '../src/state-store.js';

const gitlabToken = 'glpat-test-project-access-token-secret-9999';

const docker = vi.hoisted(() => ({
  runDocker: vi.fn(async (args: string[]) => {
    if (args.includes('/opt/harness/worker-runner.sh')) {
      return { stdout: JSON.stringify({ ok: true, message: 'worker complete', data: { output: 'worker-ok' }, truncated: false }), stderr: '', exitCode: 0, truncated: false };
    }
    if (args.includes('branch') && args.includes('--show-current')) {
      return { stdout: 'main\n', stderr: '', exitCode: 0, truncated: false };
    }
    if (args.includes('rev-parse') && args.includes('HEAD')) {
      return { stdout: '0123456789abcdef0123456789abcdef01234567\n', stderr: '', exitCode: 0, truncated: false };
    }
    if (args.includes('/opt/harness/git-transfer-helper.sh')) {
      return { stdout: 'push porcelain ok\n', stderr: '', exitCode: 0, truncated: false };
    }
    return { stdout: '', stderr: '', exitCode: 0, truncated: false };
  }),
  removeContainer: vi.fn(async () => undefined),
  inspectContainer: vi.fn(async () => undefined),
  terminateContainerProcessGroup: vi.fn(async () => undefined)
}));

vi.mock('../src/docker-engine.js', () => docker);
vi.mock('../src/repository-policy.js', () => ({
  validateRepositoryUrl: vi.fn(async (value: string) => new URL(value))
}));

import { WorkspaceService } from '../src/workspace-service.js';

const temporaryDirectories: string[] = [];
const openStores: StateStore[] = [];

afterEach(() => {
  vi.clearAllMocks();
  for (const store of openStores.splice(0)) {
    try { store.database.close(); } catch { /* ignore */ }
  }
  for (const path of temporaryDirectories.splice(0)) {
    try { rmSync(path, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

function fixture(tokenContent: string = gitlabToken) {
  const directory = mkdtempSync(join(tmpdir(), 'gitlab-workspace-test-'));
  temporaryDirectories.push(directory);
  const tokenFile = join(directory, 'gitlab-token');
  if (tokenContent) {
    writeFileSync(tokenFile, `${tokenContent}\n`);
  }

  const workspaceId = `ws_${'g'.repeat(24)}`;
  const workspacePath = join(directory, 'jobs', workspaceId);
  mkdirSync(join(workspacePath, 'repo'), { recursive: true });

  const otherWorkspaceId = `ws_${'o'.repeat(24)}`;
  const otherWorkspacePath = join(directory, 'jobs', otherWorkspaceId);
  mkdirSync(join(otherWorkspacePath, 'repo'), { recursive: true });

  const config: RunnerConfig = {
    authMode: 'owner-oauth',
    host: '127.0.0.1',
    port: 3001,
    serviceToken: 'runner-test-token-that-is-longer-than-32-characters',
    jobsRoot: join(directory, 'jobs'),
    stateDb: join(directory, 'state.db'),
    executorImage: 'executor',
    allowedGitHosts: ['github.com', 'git.iamsoftware.com.vn'],
    networkProfile: 'network-none',
    wallTtlSeconds: 300,
    idleTtlSeconds: 180,
    maxOutputBytes: 262_144,
    minFreeBytes: 0,
    maxWorkspaceBytes: 1_048_576,
    reaperIntervalSeconds: 30,
    gitlabHost: 'git.iamsoftware.com.vn',
    gitlabRepository: 'hoa.ngominh/bandodoanhnghiep',
    gitlabTokenFile: tokenFile
  };

  const store = new StateStore(config.stateDb);
  openStores.push(store);

  const now = Date.now();
  const configuredRecord: WorkspaceRecord = {
    id: workspaceId,
    ownerId: 'owner',
    idempotencyKey: 'idemp-gitlab-1',
    repositoryUrl: 'https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git',
    repositoryRef: null,
    containerName: 'executor-container-gitlab',
    workspacePath,
    status: 'ACTIVE',
    networkProfile: 'network-none',
    createdAt: now,
    lastActivityAt: now,
    expiresAt: now + 60_000,
    generation: 1,
    error: null
  };
  store.create(configuredRecord);

  const otherRecord: WorkspaceRecord = {
    id: otherWorkspaceId,
    ownerId: 'owner',
    idempotencyKey: 'idemp-gitlab-other',
    repositoryUrl: 'https://git.iamsoftware.com.vn/hoa.ngominh/other-project.git',
    repositoryRef: null,
    containerName: 'executor-container-other',
    workspacePath: otherWorkspacePath,
    status: 'ACTIVE',
    networkProfile: 'network-none',
    createdAt: now,
    lastActivityAt: now,
    expiresAt: now + 60_000,
    generation: 1,
    error: null
  };
  store.create(otherRecord);

  const service = new WorkspaceService(config, store);
  return {
    workspaceId,
    otherWorkspaceId,
    configuredRecord,
    otherRecord,
    config,
    tokenFile,
    service,
    store
  };
}

describe('GitLab workspace capabilities (Requirement E)', () => {
  it('reports repository push capability true for the configured GitLab repository', () => {
    const { service, configuredRecord } = fixture();
    const caps = service.computeWorkspaceCapabilities(configuredRecord);

    expect(caps.repository).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(caps.capabilities.repository.read).toBe(true);
    expect(caps.capabilities.repository.push).toBe(true);
    expect(caps.permissions.contents.read).toBe(true);
    expect(caps.permissions.contents.write).toBe(true);
    expect(caps.operations.gitFetch).toBe(true);
    expect(caps.operations.gitPull).toBe(true);
    expect(caps.operations.gitPush).toBe(true);

    // GitHub-only actions remain disabled
    expect(caps.capabilities.repository.issuesRead).toBe(false);
    expect(caps.capabilities.repository.issuesWrite).toBe(false);
    expect(caps.capabilities.repository.pullRequestsRead).toBe(false);
    expect(caps.capabilities.repository.pullRequestsWrite).toBe(false);
    expect(caps.operations.commitList).toBe(false);
    expect(caps.operations.compare).toBe(false);
    expect(caps.operations.releaseList).toBe(false);
    expect(caps.operations.tagList).toBe(false);
  });

  it('reports repository push capability false for an unconfigured repository on the same GitLab host', () => {
    const { service, otherRecord } = fixture();
    const caps = service.computeWorkspaceCapabilities(otherRecord);

    expect(caps.repository).toBe('hoa.ngominh/other-project');
    expect(caps.capabilities.repository.read).toBe(true);
    expect(caps.capabilities.repository.push).toBe(false);
    expect(caps.permissions.contents.write).toBe(false);
    expect(caps.operations.gitPush).toBe(false);
  });
});

describe('GitLab push credential flow and provider-neutral error (Requirements C, 4, 7)', () => {
  it('passes the write token only to the push helper over stdin for configured GitLab repo', async () => {
    const { service, workspaceId } = fixture();
    const result = await service.execute('owner', 'git_push', {
      workspaceId,
      remote: 'origin',
      refspec: 'HEAD:refs/heads/main'
    });

    expect(result.ok).toBe(true);
    // Token must NOT appear in operation output or JSON result
    expect(JSON.stringify(result)).not.toContain(gitlabToken);

    // Token must NOT appear in command-line arguments (argv)
    expect(JSON.stringify(docker.runDocker.mock.calls.map(([args]) => args))).not.toContain(gitlabToken);

    // Token is piped strictly via stdin to git-transfer-helper.sh push
    const stdinCalls = docker.runDocker.mock.calls.filter(([, opt]) => opt?.stdin === `${gitlabToken}\n`);
    expect(stdinCalls).toHaveLength(1);
    expect(stdinCalls[0]?.[0]).toEqual(expect.arrayContaining(['/opt/harness/git-transfer-helper.sh', 'push']));
  });

  it('fails closed with provider-neutral error when pushing to unconfigured repo on same host', async () => {
    const { service, otherWorkspaceId } = fixture();
    await expect(service.execute('owner', 'git_push', {
      workspaceId: otherWorkspaceId,
      remote: 'origin',
      refspec: 'HEAD:refs/heads/main'
    })).rejects.toThrow('Git push requires repository write credentials to be configured');
  });

  it('fails closed with provider-neutral error when token file is missing', async () => {
    const { service, workspaceId, tokenFile } = fixture();
    rmSync(tokenFile);

    await expect(service.execute('owner', 'git_push', {
      workspaceId,
      remote: 'origin',
      refspec: 'HEAD:refs/heads/main'
    })).rejects.toThrow('Git push requires repository write credentials to be configured');
  });
});

describe('GitLab secret redaction (Requirement F & 5)', () => {
  it('registers GITLAB_TOKEN in redactionSecrets and masks it in output redactor', () => {
    const { service, workspaceId } = fixture();
    const secrets = service.redactionSecrets(workspaceId);

    expect(secrets['GITLAB_TOKEN']).toBe(gitlabToken);

    const redactor = (service as unknown as { getRedactor: (id: string) => { sanitizeString: (t: string) => string } }).getRedactor(workspaceId);
    const leakedOutput = `Git error: fatal authentication failed for token ${gitlabToken} on remote`;
    const redacted = redactor.sanitizeString(leakedOutput);

    expect(redacted).not.toContain(gitlabToken);
    expect(redacted).toContain('[REDACTED_SECRET: GITLAB_TOKEN]');
  });

  it('protects rotated token B and historical token A when token rotates in active workspace', async () => {
    const tokenA = 'glpat-token-alpha-original-1111';
    const tokenB = 'glpat-token-beta-rotated-2222';
    const { service, workspaceId, tokenFile } = fixture(tokenA);

    // 1. Build and cache redactor for workspace with token A
    const redactorBefore = (service as unknown as { getRedactor: (id: string) => { sanitizeString: (t: string) => string } }).getRedactor(workspaceId);
    expect(redactorBefore.sanitizeString(`output with ${tokenA}`)).toBe('output with [REDACTED_SECRET: GITLAB_TOKEN]');
    expect(redactorBefore.sanitizeString(`output with ${tokenB}`)).toBe(`output with ${tokenB}`);

    // 2. Rotate token file to token B while workspace remains active
    writeFileSync(tokenFile, `${tokenB}\n`);

    // 3. Simulate Git operation (git_push) where git helper succeeds but outputs token B
    docker.runDocker.mockImplementation(async (args: string[]) => {
      if (args.includes('/opt/harness/worker-runner.sh')) {
        return { stdout: JSON.stringify({ ok: true, message: 'worker complete', data: { output: 'worker-ok' }, truncated: false }), stderr: '', exitCode: 0, truncated: false };
      }
      if (args.includes('branch') && args.includes('--show-current')) {
        return { stdout: 'main\n', stderr: '', exitCode: 0, truncated: false };
      }
      if (args.includes('rev-parse') && args.includes('HEAD')) {
        return { stdout: '0123456789abcdef0123456789abcdef01234567\n', stderr: '', exitCode: 0, truncated: false };
      }
      if (args.includes('/opt/harness/git-transfer-helper.sh')) {
        return { stdout: `push remote success: response echo ${tokenB}\n`, stderr: '', exitCode: 0, truncated: false };
      }
      return { stdout: '', stderr: '', exitCode: 0, truncated: false };
    });

    const pushResult = await service.execute('owner', 'git_push', {
      workspaceId,
      remote: 'origin',
      refspec: 'HEAD:refs/heads/main'
    });

    expect(pushResult.ok).toBe(true);
    expect(JSON.stringify(pushResult)).not.toContain(tokenB);
    expect(JSON.stringify(pushResult)).toContain('[REDACTED_SECRET: GITLAB_TOKEN]');
    expect((pushResult.data as Record<string, unknown>).output).toContain('[REDACTED_SECRET: GITLAB_TOKEN]');
    expect((pushResult.data as Record<string, unknown>).output).not.toContain(tokenB);

    // 4. Simulate Git operation failure where helper stderr contains token B
    docker.runDocker.mockImplementation(async (args: string[]) => {
      if (args.includes('branch') && args.includes('--show-current')) {
        return { stdout: 'main\n', stderr: '', exitCode: 0, truncated: false };
      }
      if (args.includes('rev-parse') && args.includes('HEAD')) {
        return { stdout: '0123456789abcdef0123456789abcdef01234567\n', stderr: '', exitCode: 0, truncated: false };
      }
      if (args.includes('/opt/harness/git-transfer-helper.sh')) {
        return { stdout: '', stderr: `fatal: remote rejected token ${tokenB} auth failure`, exitCode: 1, truncated: false };
      }
      return { stdout: '', stderr: '', exitCode: 0, truncated: false };
    });

    let surfacedError: Error | undefined;
    try {
      await service.execute('owner', 'git_push', {
        workspaceId,
        remote: 'origin',
        refspec: 'HEAD:refs/heads/main'
      });
    } catch (err) {
      surfacedError = err as Error;
    }

    expect(surfacedError).toBeDefined();
    expect(surfacedError!.message).not.toContain(tokenB);
    expect(surfacedError!.message).toContain('[REDACTED_SECRET: GITLAB_TOKEN]');

    // 5. Assert token A is still protected if cached historical output is processed
    const redactorAfter = (service as unknown as { getRedactor: (id: string) => { sanitizeString: (t: string) => string } }).getRedactor(workspaceId);
    const historicalOutput = `historical log line with old token ${tokenA} and new token ${tokenB}`;
    const sanitized = redactorAfter.sanitizeString(historicalOutput);

    expect(sanitized).not.toContain(tokenA);
    expect(sanitized).not.toContain(tokenB);
    expect(sanitized).toBe('historical log line with old token [REDACTED_SECRET: GITLAB_TOKEN] and new token [REDACTED_SECRET: GITLAB_TOKEN]');
  });
});

describe('Repository name extraction (Requirement 8)', () => {
  it('extracts owner/repo generically for both GitHub and GitLab URLs', () => {
    const { service } = fixture();
    const extract = (service as unknown as { extractRepositoryName: (url: URL) => string | null }).extractRepositoryName.bind(service);

    expect(extract(new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep.git'))).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(extract(new URL('https://git.iamsoftware.com.vn/hoa.ngominh/bandodoanhnghiep'))).toBe('hoa.ngominh/bandodoanhnghiep');
    expect(extract(new URL('https://github.com/owner/repo.git'))).toBe('owner/repo');
    expect(extract(new URL('https://github.com/owner/repo'))).toBe('owner/repo');
  });
});
