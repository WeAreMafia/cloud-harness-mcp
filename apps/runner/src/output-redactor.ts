export type SecretEntry = {
  name: string;
  value: string;
};

type OutputMatch = {
  name: string;
  length: number;
};

type TrieNode = {
  next: Map<number, TrieNode>;
  fail: TrieNode | null;
  output: OutputMatch[];
  depth: number;
};

function createNode(depth = 0): TrieNode {
  return {
    next: new Map(),
    fail: null,
    output: [],
    depth
  };
}

export class StreamRedactor {
  private currentNode: TrieNode;
  private root: TrieNode;
  private hasPatterns: boolean;
  private holdback: Buffer = Buffer.alloc(0);
  private readonly snapshot?: SecretSnapshotRedactor;
  private snapshotVersion = 0;

  constructor(
    rootOrSnapshot: TrieNode | SecretSnapshotRedactor,
    hasPatterns?: boolean
  ) {
    if (rootOrSnapshot instanceof SecretSnapshotRedactor) {
      this.snapshot = rootOrSnapshot;
      this.root = rootOrSnapshot.rootNode;
      this.hasPatterns = rootOrSnapshot.active;
      this.snapshotVersion = rootOrSnapshot.version;
    } else {
      this.root = rootOrSnapshot;
      this.hasPatterns = Boolean(hasPatterns);
    }
    this.currentNode = this.root;
  }

  private syncAutomaton(): void {
    if (this.snapshot && this.snapshot.version !== this.snapshotVersion) {
      this.root = this.snapshot.rootNode;
      this.hasPatterns = this.snapshot.active;
      this.snapshotVersion = this.snapshot.version;
      this.currentNode = this.root;
    }
  }

  processChunk(chunk: Buffer): Buffer {
    this.syncAutomaton();
    if (!this.hasPatterns || chunk.length === 0) {
      if (this.holdback.length === 0) return chunk;
      const combined = Buffer.concat([this.holdback, chunk]);
      this.holdback = Buffer.alloc(0);
      return combined;
    }

    const input = this.holdback.length > 0 ? Buffer.concat([this.holdback, chunk]) : chunk;
    const outputParts: Buffer[] = [];
    let safeOffset = 0;
    let pendingMatch: { name: string; matchStart: number; matchEnd: number } | null = null;

    let i = 0;
    while (i < input.length) {
      const byte = input[i]!;

      if (this.currentNode.next.has(byte)) {
        this.currentNode = this.currentNode.next.get(byte)!;
        if (this.currentNode.output.length > 0) {
          const match = this.currentNode.output[0]!;
          pendingMatch = {
            name: match.name,
            matchStart: i - match.length + 1,
            matchEnd: i + 1
          };
        }
        i++;
      } else {
        if (pendingMatch) {
          if (pendingMatch.matchStart > safeOffset) {
            outputParts.push(input.subarray(safeOffset, pendingMatch.matchStart));
          }
          outputParts.push(Buffer.from(`[REDACTED_SECRET: ${pendingMatch.name}]`, 'utf8'));
          safeOffset = pendingMatch.matchEnd;
          this.currentNode = this.root;
          pendingMatch = null;
          if (i < safeOffset) {
            i = safeOffset;
          }
        } else if (this.currentNode !== this.root) {
          this.currentNode = this.currentNode.fail ?? this.root;
        } else {
          i++;
        }
      }
    }

    if (pendingMatch && this.currentNode.next.size === 0) {
      if (pendingMatch.matchStart > safeOffset) {
        outputParts.push(input.subarray(safeOffset, pendingMatch.matchStart));
      }
      outputParts.push(Buffer.from(`[REDACTED_SECRET: ${pendingMatch.name}]`, 'utf8'));
      safeOffset = pendingMatch.matchEnd;
      this.currentNode = this.root;
      pendingMatch = null;
    }

    const holdStart = pendingMatch
      ? Math.min(pendingMatch.matchStart, input.length - this.currentNode.depth)
      : (this.currentNode.depth > 0 ? input.length - this.currentNode.depth : input.length);

    const actualHoldStart = Math.max(safeOffset, holdStart);
    if (actualHoldStart > safeOffset) {
      outputParts.push(input.subarray(safeOffset, actualHoldStart));
    }
    this.holdback = Buffer.from(input.subarray(actualHoldStart));

    return Buffer.concat(outputParts);
  }

  flush(): Buffer {
    this.syncAutomaton();
    if (this.holdback.length === 0) return Buffer.alloc(0);
    const input = this.holdback;
    this.holdback = Buffer.alloc(0);
    this.currentNode = this.root;

    const outputParts: Buffer[] = [];
    let safeOffset = 0;
    let pendingMatch: { name: string; matchStart: number; matchEnd: number } | null = null;
    let i = 0;

    while (i < input.length) {
      const byte = input[i]!;
      if (this.currentNode.next.has(byte)) {
        this.currentNode = this.currentNode.next.get(byte)!;
        if (this.currentNode.output.length > 0) {
          const match = this.currentNode.output[0]!;
          pendingMatch = {
            name: match.name,
            matchStart: i - match.length + 1,
            matchEnd: i + 1
          };
        }
        i++;
      } else {
        if (pendingMatch) {
          if (pendingMatch.matchStart > safeOffset) {
            outputParts.push(input.subarray(safeOffset, pendingMatch.matchStart));
          }
          outputParts.push(Buffer.from(`[REDACTED_SECRET: ${pendingMatch.name}]`, 'utf8'));
          safeOffset = pendingMatch.matchEnd;
          this.currentNode = this.root;
          pendingMatch = null;
          if (i < safeOffset) {
            i = safeOffset;
          }
        } else if (this.currentNode !== this.root) {
          this.currentNode = this.currentNode.fail ?? this.root;
        } else {
          i++;
        }
      }
    }

    if (pendingMatch) {
      if (pendingMatch.matchStart > safeOffset) {
        outputParts.push(input.subarray(safeOffset, pendingMatch.matchStart));
      }
      outputParts.push(Buffer.from(`[REDACTED_SECRET: ${pendingMatch.name}]`, 'utf8'));
      safeOffset = pendingMatch.matchEnd;
    }

    if (safeOffset < input.length) {
      outputParts.push(input.subarray(safeOffset));
    }

    return Buffer.concat(outputParts);
  }
}

export class SecretSnapshotRedactor {
  private root: TrieNode;
  private readonly patterns: SecretEntry[];
  private _version = 0;

  constructor(secrets: Record<string, string> = {}) {
    const raw: SecretEntry[] = [];
    for (const [name, value] of Object.entries(secrets)) {
      if (typeof value === 'string' && value.length > 0) {
        raw.push({ name, value });
      }
    }
    this.patterns = raw.sort((a, b) => Buffer.byteLength(b.value, 'utf8') - Buffer.byteLength(a.value, 'utf8'));
    this.root = createNode(0);
    this.buildTrie(this.root);
  }

  get version(): number {
    return this._version;
  }

  get rootNode(): TrieNode {
    return this.root;
  }

  get active(): boolean {
    return this.patterns.length > 0;
  }

  registerSecret(name: string, value: string): void {
    if (typeof value !== 'string' || value.length === 0) return;
    if (this.patterns.some((p) => p.value === value)) return;
    this.patterns.push({ name, value });
    this.patterns.sort((a, b) => Buffer.byteLength(b.value, 'utf8') - Buffer.byteLength(a.value, 'utf8'));
    const newRoot = createNode(0);
    this.buildTrie(newRoot);
    this.root = newRoot;
    this._version++;
  }

  createStream(): StreamRedactor {
    return new StreamRedactor(this);
  }

  sanitizeString(text: string): string {
    if (!this.active || !text) return text;
    let result = text;
    for (const pattern of this.patterns) {
      if (result.includes(pattern.value)) {
        result = result.split(pattern.value).join(`[REDACTED_SECRET: ${pattern.name}]`);
      }
    }
    return result;
  }

  sanitizeObject<T>(value: T): T {
    if (!this.active || value === null || value === undefined) return value;
    if (typeof value === 'string') {
      return this.sanitizeString(value) as unknown as T;
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.sanitizeObject(item)) as unknown as T;
    }
    if (typeof value === 'object') {
      const sanitized: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        sanitized[k] = this.sanitizeObject(v);
      }
      return sanitized as T;
    }
    return value;
  }

  private buildTrie(root: TrieNode): void {
    for (const pattern of this.patterns) {
      const bytes = Buffer.from(pattern.value, 'utf8');
      let current = root;
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]!;
        let nextNode = current.next.get(byte);
        if (!nextNode) {
          nextNode = createNode(current.depth + 1);
          current.next.set(byte, nextNode);
        }
        current = nextNode;
      }
      current.output.push({ name: pattern.name, length: bytes.length });
    }

    const queue: TrieNode[] = [];
    for (const child of root.next.values()) {
      child.fail = root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const [byte, child] of current.next.entries()) {
        let fallback = current.fail;
        while (fallback !== null && !fallback.next.has(byte)) {
          fallback = fallback.fail;
        }
        child.fail = fallback ? (fallback.next.get(byte) ?? root) : root;
        if (child.fail.output.length > 0) {
          child.output.push(...child.fail.output);
        }
        queue.push(child);
      }
    }
  }
}
