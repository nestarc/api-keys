import { Sha256Hasher } from './hasher';

describe('Sha256Hasher', () => {
  const peppers = { 1: 'a'.repeat(32), 2: 'b'.repeat(32) };
  const hasher = new Sha256Hasher({ peppers, currentVersion: 2 });

  it('hash uses currentVersion pepper', () => {
    const hashed = hasher.hash('secret-abc');

    expect(hashed.pepperVersion).toBe(2);
    expect(hashed.hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('verify returns true for matching secret', () => {
    const hashed = hasher.hash('secret-abc');

    expect(hasher.verify('secret-abc', hashed.hash, hashed.pepperVersion)).toBe(true);
  });

  it('verify returns false for non-matching secret', () => {
    const hashed = hasher.hash('secret-abc');

    expect(hasher.verify('secret-xyz', hashed.hash, hashed.pepperVersion)).toBe(false);
  });

  it('verify uses the recorded pepperVersion, not the current one', () => {
    const oldHash = new Sha256Hasher({ peppers, currentVersion: 1 }).hash('secret-abc');

    expect(hasher.verify('secret-abc', oldHash.hash, 1)).toBe(true);
  });

  it('throws when pepper version is unknown', () => {
    expect(() => hasher.verify('s', 'x'.repeat(64), 99)).toThrow(/pepper version/);
  });

  it('dummyVerify always returns false but executes a hash compare (timing)', () => {
    expect(hasher.dummyVerify('any-secret')).toBe(false);
  });
});
