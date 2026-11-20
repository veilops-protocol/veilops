import { describe, it, expect } from 'vitest';
import { canonicalJson, contentId, toBase64, fromBase64, randomId } from '@veilops/shared';

describe('shared', () => {
  it('canonicalJson sorts keys recursively and drops undefined', () => {
    expect(canonicalJson({ b: 1, a: { d: [2, { z: 1, y: 2 }], c: undefined } })).toBe('{"a":{"d":[2,{"y":2,"z":1}]},"b":1}');
  });
  it('contentId is deterministic and order-independent', () => {
    expect(contentId('x', { a: 1, b: 2 })).toBe(contentId('x', { b: 2, a: 1 }));
    expect(contentId('x', { a: 1 })).not.toBe(contentId('x', { a: 2 }));
  });
  it('base64 round-trips binary', () => {
    const b = new Uint8Array(256).map((_, i) => i);
    expect(fromBase64(toBase64(b))).toEqual(b);
  });
  it('randomId has the prefix and length', () => {
    expect(randomId('op')).toMatch(/^op_[0-9a-f]{16}$/);
  });
});
