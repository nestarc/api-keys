import { createHash, timingSafeEqual } from 'node:crypto';

export interface HashedSecret {
  hash: string;
  pepperVersion: number;
}

export interface HasherOptions {
  peppers: Record<number, string>;
  currentVersion: number;
}

export class Sha256Hasher {
  constructor(private readonly options: HasherOptions) {
    if (!options.peppers[options.currentVersion]) {
      throw new Error(`pepper for current version ${options.currentVersion} missing`);
    }
  }

  hash(secret: string): HashedSecret {
    const pepper = this.options.peppers[this.options.currentVersion];
    const hash = createHash('sha256').update(secret + pepper).digest('hex');

    return {
      hash,
      pepperVersion: this.options.currentVersion,
    };
  }

  verify(secret: string, expectedHash: string, pepperVersion: number): boolean {
    const pepper = this.options.peppers[pepperVersion];
    if (!pepper) {
      throw new Error(`unknown pepper version ${pepperVersion}`);
    }

    const computedHash = createHash('sha256').update(secret + pepper).digest('hex');
    return safeEqualHex(computedHash, expectedHash);
  }

  dummyVerify(secret: string): boolean {
    const pepper = this.options.peppers[this.options.currentVersion];
    createHash('sha256').update(secret + pepper).digest('hex');
    return false;
  }
}

function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
