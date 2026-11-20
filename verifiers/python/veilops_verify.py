#!/usr/bin/env python3
"""Independent pure-Python verifier for the VEILOPS proof system (veilops-range-v1).

A second implementation, written from the specifications (RFC 9496, RFC 9380, RFC 8032 and the
`encoding` section of test-vectors/veilops-range-v1.json) rather than from the TypeScript library
internals. It exists to cross-check the reference test vectors. It is NOT an external audit.

Python 3.10+, standard library only. All arithmetic is variable-time: it is only ever applied to
public data (verification), never to secrets. Do not reuse it for signing or proving with real keys.

Usage:
    python3 verifiers/python/veilops_verify.py test-vectors/veilops-range-v1.json [--quiet]
Exit code 0 only if every vector case matches its expected verdict AND all RFC self-tests pass.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys
import time

# ============================================================================================
# Field arithmetic mod p = 2^255 - 19
# ============================================================================================

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # order of the prime-order (sub)group


def fe(x: int) -> int:
    return x % P


def inv(x: int) -> int:
    return pow(x, P - 2, P)


def is_negative(x: int) -> bool:
    """RFC 9496 Section 3.1: an element is negative iff its canonical encoding has the low bit set."""
    return (x % P) & 1 == 1


def ct_abs(x: int) -> int:
    x %= P
    return (P - x) % P if is_negative(x) else x


def fe_bytes(x: int) -> bytes:
    return (x % P).to_bytes(32, 'little')


def sqrt_ratio_m1(u: int, v: int) -> tuple[bool, int]:
    """RFC 9496 Section 4.2."""
    u %= P
    v %= P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    correct_sign_sqrt = check == u
    flipped_sign_sqrt = check == (-u) % P
    flipped_sign_sqrt_i = check == (-u * SQRT_M1) % P
    if flipped_sign_sqrt or flipped_sign_sqrt_i:
        r = SQRT_M1 * r % P
    r = ct_abs(r)
    return (correct_sign_sqrt or flipped_sign_sqrt), r


# Constants. Derived here from their definitions; the self-test compares them with RFC 9496 Section 4.1.
SQRT_M1 = pow(2, (P - 1) // 4, P)          # a square root of -1 (2 is a non-residue mod p)
if is_negative(SQRT_M1):
    SQRT_M1 = P - SQRT_M1
assert SQRT_M1 * SQRT_M1 % P == P - 1
D = (-121665 * inv(121666)) % P            # Edwards d of edwards25519 (RFC 7748 Section 4.1)
_ok, SQRT_AD_MINUS_ONE = sqrt_ratio_m1((-D - 1) % P, 1)      # a square root of a*d - 1, a = -1
assert _ok
# RFC 9496 Section 4.1 fixes the *negative* (odd) root here, unlike the other constants.
SQRT_AD_MINUS_ONE = P - SQRT_AD_MINUS_ONE
_ok, INVSQRT_A_MINUS_D = sqrt_ratio_m1(1, (-1 - D) % P)      # 1/sqrt(a - d)
assert _ok
ONE_MINUS_D_SQ = (1 - D * D) % P
D_MINUS_ONE_SQ = (D - 1) * (D - 1) % P

# ============================================================================================
# edwards25519 (a = -1) in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z
# ============================================================================================

IDENTITY = (0, 1, 1, 0)


def ed_add(p1, p2):
    """add-2008-hwcd-3 (complete for a = -1 twisted Edwards with non-square d)."""
    X1, Y1, Z1, T1 = p1
    X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * D * T1 % P * T2 % P
    Dd = 2 * Z1 * Z2 % P
    E, F, G_, H_ = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G_ * H_ % P, F * G_ % P, E * H_ % P)


def ed_neg(p1):
    X, Y, Z, T = p1
    return ((-X) % P, Y, Z, (-T) % P)


def ed_double(p1):
    return ed_add(p1, p1)


def ed_mul(p1, k: int):
    """Variable-time double-and-add. Public scalars only."""
    if k < 0:
        return ed_mul(ed_neg(p1), -k)
    acc = IDENTITY
    for bit in bin(k)[2:] if k else '':
        acc = ed_double(acc)
        if bit == '1':
            acc = ed_add(acc, p1)
    return acc


def ed_eq(p1, p2) -> bool:
    """Equality of Edwards points (projective)."""
    X1, Y1, Z1, _ = p1
    X2, Y2, Z2, _ = p2
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


# Base point: y = 4/5, x even (RFC 8032 Section 5.1). Also the ristretto255 generator.
_by = 4 * inv(5) % P
_ok, _bx = sqrt_ratio_m1((_by * _by - 1) % P, (D * _by * _by + 1) % P)
assert _ok and not is_negative(_bx)
BASE = (_bx, _by, 1, _bx * _by % P)

# ============================================================================================
# ristretto255 (RFC 9496 Section 4.3)
# ============================================================================================


class DecodeError(ValueError):
    pass


def r255_decode(b: bytes):
    """RFC 9496 Section 4.3.1. Raises DecodeError on any non-canonical or invalid encoding."""
    if not isinstance(b, (bytes, bytearray)) or len(b) != 32:
        raise DecodeError('length')
    s = int.from_bytes(b, 'little')
    if s >= P:
        raise DecodeError('non-canonical field element')
    if is_negative(s):
        raise DecodeError('negative field element')
    ss = s * s % P
    u1 = (1 - ss) % P
    u2 = (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 % P * u1) - u2_sqr) % P
    was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x % P * v % P
    x = ct_abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or is_negative(t) or y == 0:
        raise DecodeError('invalid encoding')
    return (x, y, 1, t)


def r255_encode(pt) -> bytes:
    """RFC 9496 Section 4.3.2."""
    x0, y0, z0, t0 = pt
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = sqrt_ratio_m1(1, u1 * u2 % P * u2 % P)
    den1 = invsqrt * u1 % P
    den2 = invsqrt * u2 % P
    z_inv = den1 * den2 % P * t0 % P
    ix0 = x0 * SQRT_M1 % P
    iy0 = y0 * SQRT_M1 % P
    enchanted_denominator = den1 * INVSQRT_A_MINUS_D % P
    rotate = is_negative(t0 * z_inv)
    x = iy0 if rotate else x0
    y = ix0 if rotate else y0
    z = z0
    den_inv = enchanted_denominator if rotate else den2
    if is_negative(x * z_inv):
        y = (-y) % P
    s = ct_abs(den_inv * (z - y))
    return fe_bytes(s)


def r255_eq(p1, p2) -> bool:
    """RFC 9496 Section 4.3.3."""
    x1, y1, _, _ = p1
    x2, y2, _, _ = p2
    return (x1 * y2 - y1 * x2) % P == 0 or (y1 * y2 - x1 * x2) % P == 0


def _r255_map(b32: bytes):
    """MAP of RFC 9496 Section 4.3.4."""
    t = (int.from_bytes(b32, 'little') & ((1 << 255) - 1)) % P
    r = SQRT_M1 * t % P * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = sqrt_ratio_m1(u, v)
    s_prime = (-ct_abs(s * t)) % P
    s = s if was_square else s_prime
    c = (P - 1) if was_square else r
    N = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
    w0 = 2 * s * v % P
    w1 = N * SQRT_AD_MINUS_ONE % P
    w2 = (1 - s * s) % P
    w3 = (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def r255_from_uniform(b64: bytes):
    """RFC 9496 Section 4.3.4 element derivation (one-way map) on 64 bytes."""
    if len(b64) != 64:
        raise ValueError('need 64 bytes')
    return ed_add(_r255_map(b64[:32]), _r255_map(b64[32:]))


def expand_message_xmd_sha512(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380 Section 5.3.1 with H = SHA-512 (b_in_bytes = 64, s_in_bytes = 128)."""
    b_in_bytes, s_in_bytes = 64, 128
    ell = math.ceil(len_in_bytes / b_in_bytes)
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError('expand_message_xmd: invalid lengths')
    dst_prime = dst + bytes([len(dst)])
    z_pad = bytes(s_in_bytes)
    l_i_b_str = len_in_bytes.to_bytes(2, 'big')
    msg_prime = z_pad + msg + l_i_b_str + b'\x00' + dst_prime
    b0 = hashlib.sha512(msg_prime).digest()
    bi = hashlib.sha512(b0 + b'\x01' + dst_prime).digest()
    out = bi
    for i in range(2, ell + 1):
        bi = hashlib.sha512(bytes(a ^ c for a, c in zip(b0, bi)) + bytes([i]) + dst_prime).digest()
        out += bi
    return out[:len_in_bytes]


def hash_to_ristretto255(msg: bytes, dst: bytes):
    """RFC 9380 Appendix B: P = ristretto255_map(expand_message(msg, DST, 64))."""
    return r255_from_uniform(expand_message_xmd_sha512(msg, dst, 64))


# ============================================================================================
# Strict hex / scalar parsing
# ============================================================================================

_HEX64 = re.compile(r'[0-9a-f]{64}')


def point_from_hex(h):
    """Lowercase 64-hex-char canonical ristretto255 encoding -> point. Raises on anything else."""
    if not isinstance(h, str) or not _HEX64.fullmatch(h):
        raise DecodeError('point must be 64 lowercase hex chars')
    return r255_decode(bytes.fromhex(h))


def scalar_from_hex(h) -> int:
    """32-byte big-endian lowercase hex scalar, must be < L."""
    if not isinstance(h, str) or not _HEX64.fullmatch(h):
        raise ValueError('scalar must be 64 lowercase hex chars')
    s = int(h, 16)
    if s >= L:
        raise ValueError('scalar out of range (>= L)')
    return s


def scalar_hex(s: int) -> str:
    return format(s, '064x')


# ============================================================================================
# Generators, Pedersen commitments, Fiat-Shamir challenge
# ============================================================================================

H_MSG = b'VEILOPS/pedersen/H/v1'
H_DST = b'VEILOPS-V01-CS01-with-ristretto255_XMD:SHA-512_R255MAP_RO_'
G = BASE
H = hash_to_ristretto255(H_MSG, H_DST)


def commit(value: int, blinding: int):
    return ed_add(ed_mul(G, value % L), ed_mul(H, blinding % L))


def challenge(domain: str, *parts) -> int:
    """SHA-512(utf8(domain) || for each part: u32be(len) || part), little-endian, mod L."""
    buf = bytearray(domain.encode('utf-8'))
    for p in parts:
        b = p.encode('utf-8') if isinstance(p, str) else bytes(p)
        buf += len(b).to_bytes(4, 'big') + b
    return int.from_bytes(hashlib.sha512(bytes(buf)).digest(), 'little') % L


# ============================================================================================
# Canonical JSON (must match the JS canonicalJson in packages/shared)
# ============================================================================================


def _js_number(x) -> str:
    if isinstance(x, bool):
        return 'true' if x else 'false'
    if isinstance(x, int):
        return str(x)
    if not math.isfinite(x):
        raise ValueError('canonicalJson: non-finite number')
    if x.is_integer() and abs(x) < 1e21:
        return str(int(x))  # JS prints 1.0 as "1"
    return repr(x)  # shortest round-trip; matches JS for ordinary magnitudes


def canonical_json(v) -> str:
    """Keys sorted (by UTF-16 code units, as JS Array.prototype.sort does), no whitespace,
    non-ASCII emitted raw (like JSON.stringify)."""
    if v is None:
        return 'null'
    if isinstance(v, (bool, int, float)):
        return _js_number(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return '[' + ','.join(canonical_json(x) for x in v) + ']'
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(json.dumps(k, ensure_ascii=False) + ':' + canonical_json(v[k]) for k in keys) + '}'
    raise TypeError('canonicalJson: unsupported type %r' % type(v))


def content_id(prefix: str, content, nbytes: int = 10) -> str:
    return prefix + '_' + hashlib.sha256(canonical_json(content).encode('utf-8')).hexdigest()[:2 * nbytes]


# ============================================================================================
# Range proofs (bit decomposition with CDS OR-proofs) and policy proofs
# ============================================================================================

BIT_DOMAIN = 'VEILOPS/range/bit-or/v1'
PROOF_SYSTEM = 'veilops-range-v1'
MAX_SAFE_INTEGER = 2**53 - 1


def _as_int(x):
    """JSON number -> int if it is an integer (JS has a single number type); else None."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, float) and math.isfinite(x) and x.is_integer():
        return int(x)
    return None


def _verify_bit(bp, ctx: str, index: int):
    if not isinstance(bp, dict):
        raise ValueError('bit proof must be an object')
    Ci = point_from_hex(bp.get('C'))
    c0, c1 = scalar_from_hex(bp.get('c0')), scalar_from_hex(bp.get('c1'))
    s0, s1 = scalar_from_hex(bp.get('s0')), scalar_from_hex(bp.get('s1'))
    Y0 = Ci
    Y1 = ed_add(Ci, ed_neg(G))
    A0 = ed_add(ed_mul(H, s0), ed_neg(ed_mul(Y0, c0)))
    A1 = ed_add(ed_mul(H, s1), ed_neg(ed_mul(Y1, c1)))
    e = challenge(BIT_DOMAIN, ctx, str(index), r255_encode(Ci), r255_encode(A0), r255_encode(A1))
    return Ci if (c0 + c1) % L == e else None


def verify_range(C, proof, ctx: str) -> bool:
    """Verify 0 <= v < 2^n for commitment point C. Never raises; malformed input -> False."""
    try:
        if not isinstance(proof, dict):
            return False
        n = _as_int(proof.get('n'))
        bits = proof.get('bits')
        if n is None or not isinstance(bits, list) or len(bits) != n or n < 1 or n > 64:
            return False
        acc = IDENTITY
        for i in range(n):
            Ci = _verify_bit(bits[i], ctx, i)
            if Ci is None:
                return False
            acc = ed_add(acc, ed_mul(Ci, 1 << i))
        return r255_eq(acc, C)
    except Exception:
        return False


def transcript_context(pi: dict) -> str:
    return canonical_json({'v': PROOF_SYSTEM, **pi})


def proof_id_of(proof) -> str:
    return content_id('prf', proof, 10)


def verify_policy(pi, proof) -> tuple[bool, dict]:
    """Verify a veilops-range-v1 policy proof against public inputs. Never raises."""
    checks = {}
    try:
        if not isinstance(pi, dict) or not isinstance(proof, dict):
            return False, {'shape': False}
        checks['system'] = proof.get('system') == PROOF_SYSTEM
        bits = _as_int(pi.get('rangeBits'))
        lower, upper = proof.get('lower'), proof.get('upper')
        checks['bits'] = (bits is not None and 1 <= bits <= 48
                          and isinstance(lower, dict) and _as_int(lower.get('n')) == bits
                          and isinstance(upper, dict) and _as_int(upper.get('n')) == bits)
        mx = _as_int(pi.get('maxAmount'))
        checks['limit'] = (checks['bits'] and mx is not None and 0 <= mx <= MAX_SAFE_INTEGER
                           and mx < 2**bits)
        try:
            C = point_from_hex(pi.get('amountCommitment'))
        except Exception:
            C = None
        checks['commitment'] = C is not None
        pre = all(checks.values())
        ctx = transcript_context(pi)
        checks['lower'] = pre and verify_range(C, lower, ctx + '|lower')
        if pre and checks['lower']:
            Dpt = ed_add(ed_mul(G, mx), ed_neg(C))  # D = maxAmount*G - C
            checks['upper'] = verify_range(Dpt, upper, ctx + '|upper')
        else:
            checks['upper'] = False
        return all(checks.values()), checks
    except Exception as exc:  # defensive: report, never crash
        checks['exception'] = repr(exc)
        return False, checks


# ============================================================================================
# Ed25519 (RFC 8032 Section 5.1), strict
# ============================================================================================


def ed25519_decode_point(b: bytes):
    """RFC 8032 Section 5.1.3, rejecting y >= p and x = 0 with sign bit set."""
    if len(b) != 32:
        raise DecodeError('length')
    n = int.from_bytes(b, 'little')
    x0 = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        raise DecodeError('non-canonical y')
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) % P * pow(u * pow(v, 7, P) % P, (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = x * SQRT_M1 % P
    else:
        raise DecodeError('no square root')
    if x == 0 and x0 == 1:
        raise DecodeError('x = 0 with sign bit set')
    if x & 1 != x0:
        x = P - x
    return (x, y, 1, x * y % P)


def ed25519_encode_point(pt) -> bytes:
    X, Y, Z, _ = pt
    zi = inv(Z)
    x, y = X * zi % P, Y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _ed25519_expand(seed: bytes):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, 'little'), h[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError('seed must be 32 bytes')
    a, _ = _ed25519_expand(seed)
    return ed25519_encode_point(ed_mul(BASE, a))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    """Used only by the RFC 8032 self-test (variable time; never use with real keys)."""
    a, prefix = _ed25519_expand(seed)
    A = ed25519_encode_point(ed_mul(BASE, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), 'little') % L
    R = ed25519_encode_point(ed_mul(BASE, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), 'little') % L
    S = (r + k * a) % L
    return R + S.to_bytes(32, 'little')


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """RFC 8032 Section 5.1.7, cofactored check [8][S]B = [8]R + [8][k]A; S >= L rejected."""
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        A = ed25519_decode_point(pub)
        R = ed25519_decode_point(sig[:32])
        S = int.from_bytes(sig[32:], 'little')
        if S >= L:
            return False
        k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % L
        lhs = ed_mul(ed_mul(BASE, S), 8)
        rhs = ed_mul(ed_add(R, ed_mul(A, k)), 8)
        return ed_eq(lhs, rhs)
    except Exception:
        return False


# ============================================================================================
# Public records
# ============================================================================================

RECORD_PREFIX = 'VEILOPS/record/v1|'
_HEX_ANY = re.compile(r'(?:[0-9a-f]{2})*')


def _hex_bytes(h, n: int) -> bytes:
    if not isinstance(h, str) or len(h) != 2 * n or not _HEX_ANY.fullmatch(h):
        raise ValueError('bad hex')
    return bytes.fromhex(h)


def verify_attestation(record: dict) -> bool:
    try:
        att = record['attestation']
        rest = {k: v for k, v in record.items() if k != 'attestation'}
        msg = (RECORD_PREFIX + canonical_json(rest)).encode('utf-8')
        return ed25519_verify(_hex_bytes(att['publicKey'], 32), msg, _hex_bytes(att['signature'], 64))
    except Exception:
        return False


def public_inputs_of(rec: dict) -> dict:
    pol = rec['policy']
    return {
        'operationId': rec['operationId'], 'policyId': pol['id'], 'maxAmount': pol['maxAmount'],
        'rangeBits': pol['rangeBits'], 'asset': rec['asset'], 'category': rec['category'],
        'amountCommitment': rec['amountCommitment'],
    }


def decode_proof(b64: str):
    raw = base64.b64decode(b64, validate=True)
    return json.loads(raw.decode('utf-8'))


def verify_record(rec) -> dict:
    """Proof + proofId binding + operator signature. Never raises."""
    try:
        proof = decode_proof(rec['proof'])
        decoded = True
    except (KeyError, TypeError, ValueError, binascii.Error, UnicodeDecodeError):
        proof, decoded = None, False
    try:
        pi = public_inputs_of(rec)
    except Exception:
        pi = None
    policy_ok = decoded and pi is not None and verify_policy(pi, proof)[0]
    try:
        pid_ok = decoded and proof_id_of(proof) == rec.get('proofId')
    except Exception:
        pid_ok = False
    att_ok = isinstance(rec, dict) and verify_attestation(rec)
    return {'valid': bool(policy_ok and pid_ok and att_ok), 'attestation': att_ok,
            'proofIdMatches': bool(pid_ok), 'policy': bool(policy_ok)}


# ============================================================================================
# veilops-range-v2 (binary encoding, SHA-256 Fiat-Shamir; same statement and generators as v1)
# ============================================================================================

PROOF_SYSTEM_V2 = 'veilops-range-v2'
V2_VERSION = 2
V2_BIT_BYTES = 160
V2_MAX_BITS = 48
_TEXT_FIELD = re.compile(r'[A-Za-z0-9_.-]{1,64}')
V2_TEXT_FIELDS = ('operationId', 'policyId', 'asset', 'category')


def validate_public_inputs_v2(pi) -> None:
    """Raises ValueError unless the public inputs satisfy the v2 rules."""
    if not isinstance(pi, dict):
        raise ValueError('public inputs must be an object')
    for k in V2_TEXT_FIELDS:
        v = pi.get(k)
        if not isinstance(v, str) or not _TEXT_FIELD.fullmatch(v):
            raise ValueError('%s must match [A-Za-z0-9_.-]{1,64}' % k)
    bits = _as_int(pi.get('rangeBits'))
    if bits is None or not 1 <= bits <= V2_MAX_BITS:
        raise ValueError('rangeBits must be 1..48')
    mx = _as_int(pi.get('maxAmount'))
    if mx is None or not 0 <= mx <= MAX_SAFE_INTEGER or mx >= 2**bits:
        raise ValueError('maxAmount must be in [0, 2^rangeBits)')
    c = pi.get('amountCommitment')
    if not isinstance(c, str) or not _HEX64.fullmatch(c):
        raise ValueError('amountCommitment must be 64 lowercase hex chars')


def transcript_context_v2(pi: dict) -> str:
    return canonical_json({'v': PROOF_SYSTEM_V2, **pi})


def ctx_hash_v2(pi: dict, tag: str) -> bytes:
    """SHA-256(utf8("VEILOPS/range/v2|") || ctx || utf8("|" + tag))."""
    assert tag in ('lower', 'upper')
    return hashlib.sha256(b'VEILOPS/range/v2|' + transcript_context_v2(pi).encode('utf-8')
                          + b'|' + tag.encode()).digest()


def bit_challenge_v2(ctx_hash: bytes, index: int, Ci_enc: bytes, A0_enc: bytes, A1_enc: bytes) -> int:
    """T = "VEILOPS/range/v2/bit" || ctxHash || u32be(i) || C_i || A_0 || A_1;
    e = LE(SHA-256(0x00||T) || SHA-256(0x01||T)) mod L."""
    T = b'VEILOPS/range/v2/bit' + ctx_hash + index.to_bytes(4, 'big') + Ci_enc + A0_enc + A1_enc
    wide = hashlib.sha256(b'\x00' + T).digest() + hashlib.sha256(b'\x01' + T).digest()
    return int.from_bytes(wide, 'little') % L


def scalar_from_le(b: bytes) -> int:
    if len(b) != 32:
        raise ValueError('scalar must be 32 bytes')
    s = int.from_bytes(b, 'little')
    if s >= L:
        raise ValueError('non-canonical scalar (>= L)')
    return s


def decode_proof_v2(data: bytes):
    """u8 version (2) || u8 n || n lower bits || n upper bits; bit = C(32)||c0||c1||s0||s1 (LE scalars).
    Returns (n, lower, upper), each a list of (Ci_point, Ci_bytes, c0, c1, s0, s1). Raises on anything malformed."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2 or data[0] != V2_VERSION:
        raise ValueError('not a veilops-range-v2 proof (version byte)')
    n = data[1]
    if not 1 <= n <= V2_MAX_BITS or len(data) != 2 + 2 * n * V2_BIT_BYTES:
        raise ValueError('bad proof length')

    def read(start):
        bits = []
        for i in range(n):
            o = start + i * V2_BIT_BYTES
            cb = bytes(data[o:o + 32])
            bits.append((r255_decode(cb), cb) + tuple(scalar_from_le(bytes(data[o + 32 * k:o + 32 * (k + 1)])) for k in (1, 2, 3, 4)))
        return bits

    return n, read(2), read(2 + n * V2_BIT_BYTES)


def proof_id_v2(data: bytes) -> str:
    return 'prf_' + hashlib.sha256(data).hexdigest()[:20]


def _verify_range_v2(C, bits, ctx_hash: bytes) -> bool:
    acc = IDENTITY
    negG = ed_neg(G)
    for i, (Ci, cb, c0, c1, s0, s1) in enumerate(bits):
        A0 = ed_add(ed_mul(H, s0), ed_neg(ed_mul(Ci, c0)))
        A1 = ed_add(ed_mul(H, s1), ed_neg(ed_mul(ed_add(Ci, negG), c1)))
        if (c0 + c1) % L != bit_challenge_v2(ctx_hash, i, cb, r255_encode(A0), r255_encode(A1)):
            return False
        acc = ed_add(acc, ed_mul(Ci, 1 << i))
    return r255_eq(acc, C)


def verify_policy_v2(pi, proof_bytes) -> tuple[bool, str]:
    """Verify a v2 policy proof (bytes) against public inputs. Never raises. Returns (ok, reason)."""
    try:
        try:
            validate_public_inputs_v2(pi)
        except ValueError as e:
            return False, 'public inputs: %s' % e
        try:
            n, lower, upper = decode_proof_v2(proof_bytes)
        except (ValueError, DecodeError) as e:
            return False, 'decode: %s' % e
        if n != _as_int(pi['rangeBits']):
            return False, 'n != rangeBits'
        try:
            C = point_from_hex(pi['amountCommitment'])
        except DecodeError as e:
            return False, 'commitment: %s' % e
        if not _verify_range_v2(C, lower, ctx_hash_v2(pi, 'lower')):
            return False, 'lower range proof rejected'
        Dpt = ed_add(ed_mul(G, _as_int(pi['maxAmount'])), ed_neg(C))
        if not _verify_range_v2(Dpt, upper, ctx_hash_v2(pi, 'upper')):
            return False, 'upper range proof rejected'
        return True, 'ok'
    except Exception as exc:  # defensive: never crash
        return False, 'exception: %r' % exc


# ============================================================================================
# RFC self-tests
# ============================================================================================


def rfc_self_tests():
    """Yield (name, passed, detail) for each group of official RFC vectors."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.dont_write_bytecode = True  # don't leave __pycache__ in the repo
    import rfc_vectors as R

    c = R.RISTRETTO255_CONSTANTS
    mine = {'D': D, 'SQRT_M1': SQRT_M1, 'SQRT_AD_MINUS_ONE': SQRT_AD_MINUS_ONE,
            'INVSQRT_A_MINUS_D': INVSQRT_A_MINUS_D, 'ONE_MINUS_D_SQ': ONE_MINUS_D_SQ,
            'D_MINUS_ONE_SQ': D_MINUS_ONE_SQ}
    bad = [k for k in c if c[k] != mine[k]]
    yield 'RFC 9496 4.1 constants (%d)' % len(c), not bad, ('mismatch: %s' % bad) if bad else ''

    bad = []
    for u, v, sq, r in R.SQRT_RATIO_M1:
        got = sqrt_ratio_m1(int.from_bytes(bytes.fromhex(u), 'little'), int.from_bytes(bytes.fromhex(v), 'little'))
        if got != (sq, int.from_bytes(bytes.fromhex(r), 'little')):
            bad.append((u[:8], v[:8]))
    yield 'RFC 9496 A.4 SQRT_RATIO_M1 (%d)' % len(R.SQRT_RATIO_M1), not bad, str(bad) if bad else ''

    bad = []
    acc = IDENTITY
    for i, h in enumerate(R.RISTRETTO255_MULTIPLES):
        enc = r255_encode(acc).hex()
        ok = enc == h and r255_eq(r255_decode(bytes.fromhex(h)), acc) and r255_encode(r255_decode(bytes.fromhex(h))).hex() == h
        ok = ok and r255_encode(ed_mul(BASE, i)).hex() == h
        if not ok:
            bad.append(i)
        acc = ed_add(acc, BASE)
    yield 'RFC 9496 A.1 multiples of generator B[0..15] (encode/decode/add/mul)', not bad, str(bad) if bad else ''

    bad = []
    for cat, h in R.RISTRETTO255_INVALID:
        try:
            r255_decode(bytes.fromhex(h))
            bad.append((cat, h[:16]))
        except DecodeError:
            pass
    yield 'RFC 9496 A.2 invalid encodings rejected (%d)' % len(R.RISTRETTO255_INVALID), not bad, str(bad) if bad else ''

    bad = [i for i, (I, O) in enumerate(R.RISTRETTO255_MAP) if r255_encode(r255_from_uniform(bytes.fromhex(I))).hex() != O]
    bad += ['same%d' % i for i, I in enumerate(R.RISTRETTO255_MAP_SAME_INPUTS)
            if r255_encode(r255_from_uniform(bytes.fromhex(I))).hex() != R.RISTRETTO255_MAP_SAME_OUTPUT]
    yield 'RFC 9496 A.3 element derivation / one-way map (%d)' % (len(R.RISTRETTO255_MAP) + len(R.RISTRETTO255_MAP_SAME_INPUTS)), not bad, str(bad) if bad else ''

    bad = []
    lens = sorted({len(m) for m, _, _ in R.EXPAND_XMD_SHA512})
    for m, n, u in R.EXPAND_XMD_SHA512:
        if expand_message_xmd_sha512(m.encode(), R.EXPAND_XMD_SHA512_DST.encode(), n).hex() != u:
            bad.append((m[:6], n))
    lens_ok = lens == [0, 3, 16, 133, 517]  # '', abc, abcdef0123456789, q128_+128q, a512_+512a
    yield 'RFC 9380 K.3 expand_message_xmd(SHA-512) (%d)' % len(R.EXPAND_XMD_SHA512), not bad and lens_ok, (str(bad) if bad else '') + ('' if lens_ok else ' msg lengths %s' % lens)

    for t, sk, pk, msg, sig in R.ED25519:
        sk_b, pk_b, m_b, s_b = (bytes.fromhex(x) for x in (sk, pk, msg, sig))
        ok_pk = ed25519_public_key(sk_b) == pk_b
        ok_sign = ed25519_sign(sk_b, m_b) == s_b
        ok_ver = ed25519_verify(pk_b, m_b, s_b)
        # Negative checks: flipped message bit, S + L (non-canonical S), tampered R.
        neg1 = not ed25519_verify(pk_b, m_b + b'\x00', s_b)
        s_plus_l = s_b[:32] + (int.from_bytes(s_b[32:], 'little') + L).to_bytes(32, 'little')
        neg2 = not ed25519_verify(pk_b, m_b, s_plus_l)
        neg3 = not ed25519_verify(pk_b, m_b, bytes([s_b[0] ^ 1]) + s_b[1:])
        ok = ok_pk and ok_sign and ok_ver and neg1 and neg2 and neg3
        yield 'RFC 8032 7.1 Ed25519 TEST %s (pubkey/sign/verify + 3 negatives)' % t, ok, \
            '' if ok else 'pk=%s sign=%s verify=%s neg=%s,%s,%s' % (ok_pk, ok_sign, ok_ver, neg1, neg2, neg3)

    # Ed25519 strict point decoding: y = p (non-canonical encoding of y = 0) must be rejected.
    try:
        ed25519_decode_point(P.to_bytes(32, 'little'))
        strict = False
    except DecodeError:
        strict = True
    yield 'Ed25519 strict decoding rejects y >= p', strict, ''

    # Malformed-input robustness for the range verifier (must return False, never raise).
    junk = [None, 5, 'x', [], {}, {'n': 1}, {'n': True, 'bits': [{}]}, {'n': 1, 'bits': [None]},
            {'n': 1, 'bits': [{'C': 'zz', 'c0': 1}]}, {'n': 1.5, 'bits': []}, {'n': 65, 'bits': [{}] * 65},
            {'n': 1, 'bits': [{'C': 'E2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76',
                               'c0': '0' * 64, 'c1': '0' * 64, 's0': '0' * 64, 's1': '0' * 64}]},
            {'n': 1, 'bits': [{'C': r255_encode(G).hex(), 'c0': '0' * 64 + '\n', 'c1': '0' * 64, 's0': '0' * 64, 's1': '0' * 64}]}]
    try:
        robust = all(verify_range(G, j, 'ctx') is False for j in junk)
        robust = robust and verify_policy(None, None)[0] is False and verify_policy({}, {})[0] is False
        robust = robust and verify_record({})['valid'] is False and verify_record({'proof': '!!'})['valid'] is False
    except Exception:
        robust = False
    yield 'malformed inputs return False without raising (%d range shapes)' % len(junk), robust, ''

    good_pi = {'operationId': 'op_x', 'policyId': 'pol_x', 'asset': 'USDC', 'category': 'vendor',
               'maxAmount': 1, 'rangeBits': 1, 'amountCommitment': r255_encode(G).hex()}
    junk2 = [None, b'', b'\x02', b'\x02\x00', b'\x02\x01' + bytes(319), b'\x02\x01' + bytes(320),
             b'\x02\x31' + bytes(2 + 2 * 49 * 160), 'not bytes', b'\x01\x01' + bytes(320),
             b'\x02\x01' + b'\xff' * 320]
    try:
        robust2 = all(verify_policy_v2(good_pi, j)[0] is False for j in junk2)
        robust2 = robust2 and all(verify_policy_v2(p, b'\x02\x01' + bytes(320))[0] is False for p in
                                  (None, {}, {**good_pi, 'asset': 'US DC'}, {**good_pi, 'asset': 5},
                                   {**good_pi, 'rangeBits': 0}, {**good_pi, 'maxAmount': 2},
                                   {**good_pi, 'amountCommitment': good_pi['amountCommitment'].upper()},
                                   {**good_pi, 'operationId': 'a' * 65}, {**good_pi, 'policyId': 'x\n'}))
    except Exception:
        robust2 = False
    yield 'v2 malformed proofs / public inputs return False without raising', robust2, ''


# ============================================================================================
# Test-vector runner
# ============================================================================================


def run_vectors(doc: dict):
    """Yield (name, passed, detail) for every case in the vector file."""
    enc = doc.get('encoding', {})
    yield 'encoding.L equals group order', str(L) == enc.get('L'), ''

    gen = doc['generators']
    yield 'generators.G is the ristretto255 base point', r255_encode(G).hex() == gen['G'], ''
    hd = gen['H_derivation']
    Hx = r255_encode(hash_to_ristretto255(hd['msg'].encode(), hd['DST'].encode())).hex()
    yield 'generators.H = hash_to_ristretto255(msg, DST)', Hx == gen['H'] and Hx == r255_encode(H).hex(), \
        '' if Hx == gen['H'] else 'computed %s' % Hx

    att = doc['attestation']
    pk = ed25519_public_key(bytes.fromhex(att['seedHex'])).hex()
    yield 'attestation.publicKey derived from seedHex', pk == att['publicKey'], '' if pk == att['publicKey'] else 'derived %s' % pk

    for i, c in enumerate(doc['commitments']):
        got = r255_encode(commit(int(c['value']), scalar_from_hex(c['blinding']))).hex()
        yield 'commitments[%d] v=%s' % (i, c['value']), got == c['commitment'], '' if got == c['commitment'] else 'got %s' % got

    for i, c in enumerate(doc['challenges']):
        parts = []
        for p in c['parts']:
            parts.append(p['utf8'] if 'utf8' in p else bytes.fromhex(p['hex']))
        got = scalar_hex(challenge(c['domain'], *parts))
        yield 'challenges[%d] %s (%d parts)' % (i, c['domain'], len(parts)), got == c['expected'], '' if got == c['expected'] else 'got %s' % got

    for i, c in enumerate(doc['rangeProofs']):
        try:
            C = point_from_hex(c['commitment'])
            got = verify_range(C, c['proof'], c['context'])
        except Exception:
            got = False
        yield 'rangeProofs[%d] %s' % (i, c['description']), got == c['expected'], 'verdict %s, expected %s' % (got, c['expected'])

    for i, c in enumerate(doc['policyProofs']):
        got, checks = verify_policy(c['publicInputs'], c['proof'])
        ctx_ok = transcript_context(c['publicInputs']) == c['transcriptContext']
        pid_ok = proof_id_of(c['proof']) == c['proofId']
        detail = 'verdict %s, expected %s; transcriptContext %s; proofId %s' % (
            got, c['expected'], 'ok' if ctx_ok else 'MISMATCH', 'ok' if pid_ok else 'MISMATCH')
        if got != c['expected']:
            detail += '; checks %s' % checks
        yield 'policyProofs[%d] %s' % (i, c['description']), got == c['expected'] and ctx_ok and pid_ok, detail

    for i, c in enumerate(doc['records']):
        r = verify_record(c['record'])
        exp = c['expected']
        got = {k: r[k] for k in exp}
        same_key = c['record'].get('attestation', {}).get('publicKey') == att['publicKey']
        yield 'records[%d] %s' % (i, c['description']), got == exp, 'got %s, expected %s%s' % (
            got, exp, '' if same_key else ' (signed by a key other than attestation.publicKey)')


def run_vectors_v2(doc: dict):
    """Yield (name, passed, detail) for every case in a veilops-range-v2 vector file."""
    for i, c in enumerate(doc['contexts']):
        pi = c['publicInputs']
        ctx_ok = transcript_context_v2(pi) == c['transcriptContext']
        lo = ctx_hash_v2(pi, 'lower').hex()
        up = ctx_hash_v2(pi, 'upper').hex()
        ch = c['challenge']
        e = bit_challenge_v2(bytes.fromhex(c['ctxHashLower']), ch['index'], bytes.fromhex(ch['Ci']),
                             bytes.fromhex(ch['A0']), bytes.fromhex(ch['A1']))
        e_le = e.to_bytes(32, 'little').hex()
        res = [('transcriptContext', ctx_ok), ('ctxHashLower', lo == c['ctxHashLower']),
               ('ctxHashUpper', up == c['ctxHashUpper']), ('challenge.expectedLE', e_le == ch['expectedLE'])]
        bad = [k for k, ok in res if not ok]
        yield 'v2 contexts[%d] transcriptContext, ctxHashLower/Upper, bit challenge (index %d)' % (i, ch['index']), \
            not bad, ('mismatch: %s (challenge got %s)' % (bad, e_le)) if bad else ''

    for i, c in enumerate(doc['cases']):
        try:
            data = bytes.fromhex(c['proofHex'])
        except (ValueError, TypeError):
            data = None
        got, reason = verify_policy_v2(c['publicInputs'], data)
        pid_ok = data is not None and proof_id_v2(data) == c['proofId']
        yield 'v2 cases[%d] %s' % (i, c['description']), got == c['expected'] and pid_ok, \
            'verdict %s (%s), expected %s; proofId %s' % (got, reason, c['expected'], 'ok' if pid_ok else 'MISMATCH')


def detect_system(doc) -> str | None:
    name = doc.get('name', '') if isinstance(doc, dict) else ''
    for sysname in (PROOF_SYSTEM, PROOF_SYSTEM_V2):
        if isinstance(name, str) and name.split()[0:1] == [sysname]:
            return sysname
    return None


def main(argv) -> int:
    args = [a for a in argv[1:] if a != '--quiet']
    quiet = '--quiet' in argv[1:]
    if not args or any(a.startswith('-') for a in args):
        print('usage: veilops_verify.py <vectors.json> [<vectors.json> ...] [--quiet]', file=sys.stderr)
        return 2
    t0 = time.perf_counter()
    counts = {'rfc': [0, 0]}

    def report(kind, name, ok, detail):
        counts.setdefault(kind, [0, 0])[0 if ok else 1] += 1
        if ok and quiet:
            return
        print('%s  [%s] %s%s' % ('PASS' if ok else 'FAIL', 'rfc' if kind == 'rfc' else 'vec', name,
                                 ('  -- ' + detail) if detail else ''))

    try:
        for name, ok, detail in rfc_self_tests():
            report('rfc', name, ok, detail)
    except Exception as exc:
        report('rfc', 'RFC self-tests crashed', False, repr(exc))
    files = []
    for path in args:
        key = os.path.basename(path)
        while key in counts:
            key += "'"
        files.append(key)
        counts[key] = [0, 0]
        try:
            with open(path, encoding='utf-8') as f:
                doc = json.load(f)
            system = detect_system(doc)
            if system == PROOF_SYSTEM:
                runner = run_vectors(doc)
            elif system == PROOF_SYSTEM_V2:
                runner = run_vectors_v2(doc)
            else:
                report(key, '%s: unrecognised vector file name %r' % (key, doc.get('name') if isinstance(doc, dict) else None), False, '')
                continue
            for name, ok, detail in runner:
                report(key, name, ok, detail)
        except Exception as exc:
            report(key, '%s: vector runner crashed' % key, False, repr(exc))
    dt = time.perf_counter() - t0
    rp, rf = counts['rfc']
    vp = sum(counts[k][0] for k in files)
    vf = sum(counts[k][1] for k in files)
    allok = rf == 0 and vf == 0 and rp > 0 and all(counts[k][0] > 0 for k in files)
    per_file = ', '.join('%s %d/%d' % (k, counts[k][0], sum(counts[k])) for k in files)
    print('SUMMARY: %s -- RFC self-tests %d/%d passed, vector cases %d/%d passed (%s), %.2fs' % (
        'ALL PASS' if allok else 'FAILURES', rp, rp + rf, vp, vp + vf, per_file, dt))
    return 0 if allok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
