//! VEILOPS on-chain verifier for `veilops-range-v2` zero-knowledge range proofs.
//!
//! Status: experimental, not audited. Devnet only.
//!
//! The program checks, entirely on-chain, that a Pedersen commitment `C = v·G + r·H` hides an amount with
//! `0 ≤ v ≤ maxAmount`, without learning `v`. It verifies every CDS OR-proof of both bit-decomposition range
//! proofs (on `C` and on `D = maxAmount·G − C`) with Solana's curve25519 (ristretto255) syscalls, and the
//! Fiat–Shamir challenges with the SHA-256 syscall. Only a fully verified proof produces a `Record` account.
//!
//! Flow (a proof is ~10 KB, larger than one transaction):
//!   1. client creates a zeroed buffer account owned by this program (SystemProgram.createAccount)
//!   2. `begin`        — binds the buffer to the public inputs; the program rebuilds the transcript context itself
//!   3. `write`        — uploads the proof bytes in chunks
//!   4. `verify_bits`  — verifies the next `count` bit proofs of the lower or upper range (locks the buffer)
//!   5. `finalize`     — checks Σ 2^i·C_i = C and = D, then creates the `Record` (one per operation id)
//!
//! Any failed check aborts the transaction, so a forged proof can never reach `finalize`.

use anchor_lang::prelude::*;
use curve25519_dalek::scalar::Scalar;
use solana_curve25519::{
    ristretto::{multiply_ristretto, multiscalar_multiply_ristretto, subtract_ristretto, validate_ristretto, PodRistrettoPoint},
    scalar::PodScalar,
};
use solana_sha256_hasher::hashv;

declare_id!("4fWHkQi8HgWPvw5fS4vudFGn6u6eZvdRKwfQqBgVexTZ");

/// ristretto255 base point (RFC 9496).
const G: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82,
    0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];
/// H = hash_to_ristretto255("VEILOPS/pedersen/H/v1", DST "VEILOPS-V01-CS01-with-ristretto255_XMD:SHA-512_R255MAP_RO_").
const H: [u8; 32] = [
    0xfa, 0xf4, 0xcb, 0x11, 0xe4, 0xf3, 0xde, 0x1b, 0xc3, 0x5d, 0x55, 0x3d, 0xf8, 0xd4, 0xd3, 0x02, 0xcd, 0xf9, 0x65, 0xf4, 0xfd, 0x2e,
    0x78, 0xa0, 0xa6, 0x96, 0xb1, 0x77, 0x3b, 0x4d, 0x7c, 0x34,
];

pub const PROOF_VERSION: u8 = 2;
pub const BIT_BYTES: usize = 160;
pub const HEADER_BYTES: usize = 2;
pub const MAX_BITS: u8 = 48;
pub const MAX_TEXT: usize = 64;

pub fn proof_len(n: u8) -> usize {
    HEADER_BYTES + 2 * (n as usize) * BIT_BYTES
}

#[program]
pub mod veilops_verifier {
    use super::*;

    /// Bind a fresh proof buffer to a statement. The transcript context is rebuilt here from the public
    /// inputs, so a proof can only ever verify for exactly these inputs.
    pub fn begin(ctx: Context<Begin>, args: BeginArgs) -> Result<()> {
        for f in [&args.operation_id, &args.policy_id, &args.asset, &args.category] {
            require!(valid_text(f), VeilopsError::InvalidText);
        }
        require!(args.range_bits >= 1 && args.range_bits <= MAX_BITS, VeilopsError::InvalidRangeBits);
        require!(args.max_amount < (1u64 << args.range_bits), VeilopsError::LimitTooLarge);
        require!(validate_ristretto(&PodRistrettoPoint(args.commitment)), VeilopsError::InvalidPoint);

        let buffer = &ctx.accounts.buffer;
        let data = buffer.try_borrow_data()?;
        require!(data.len() == proof_len(args.range_bits), VeilopsError::BadBufferLength);
        require!(data[..8].iter().all(|b| *b == 0), VeilopsError::BufferNotFresh);
        drop(data);

        let ctx_json = canonical_context(&args);
        let v = &mut ctx.accounts.verification;
        v.authority = ctx.accounts.authority.key();
        v.buffer = buffer.key();
        v.ctx_hash_lower = hashv(&[b"VEILOPS/range/v2|", ctx_json.as_bytes(), b"|lower"]).to_bytes();
        v.ctx_hash_upper = hashv(&[b"VEILOPS/range/v2|", ctx_json.as_bytes(), b"|upper"]).to_bytes();
        v.operation_id = args.operation_id;
        v.policy_id = args.policy_id;
        v.asset = args.asset;
        v.category = args.category;
        v.max_amount = args.max_amount;
        v.range_bits = args.range_bits;
        v.commitment = args.commitment;
        v.next_lower = 0;
        v.next_upper = 0;
        v.locked = false;
        v.bump = ctx.bumps.verification;
        Ok(())
    }

    /// Upload part of the proof. Only the authority can write, and only before verification starts.
    pub fn write(ctx: Context<Write>, offset: u32, bytes: Vec<u8>) -> Result<()> {
        require!(!ctx.accounts.verification.locked, VeilopsError::Locked);
        let mut data = ctx.accounts.buffer.try_borrow_mut_data()?;
        let start = offset as usize;
        let end = start.checked_add(bytes.len()).ok_or(VeilopsError::OutOfBounds)?;
        require!(end <= data.len(), VeilopsError::OutOfBounds);
        data[start..end].copy_from_slice(&bytes);
        Ok(())
    }

    /// Verify the next `count` bit proofs of the lower (range = 0) or upper (range = 1) range proof.
    pub fn verify_bits(ctx: Context<VerifyBits>, range: u8, count: u8) -> Result<()> {
        require!(range <= 1, VeilopsError::InvalidRange);
        let v = &mut ctx.accounts.verification;
        let data = ctx.accounts.buffer.try_borrow_data()?;
        if !v.locked {
            require!(data[0] == PROOF_VERSION && data[1] == v.range_bits, VeilopsError::BadHeader);
            v.locked = true;
        }
        let n = v.range_bits as usize;
        let next = if range == 0 { v.next_lower } else { v.next_upper } as usize;
        let stop = (next + count as usize).min(n);
        require!(next < n, VeilopsError::RangeComplete);
        let ctx_hash = if range == 0 { v.ctx_hash_lower } else { v.ctx_hash_upper };
        let base = HEADER_BYTES + (range as usize) * n * BIT_BYTES;
        for i in next..stop {
            let o = base + i * BIT_BYTES;
            verify_bit(&data[o..o + BIT_BYTES], &ctx_hash, i as u32)?;
        }
        if range == 0 { v.next_lower = stop as u8 } else { v.next_upper = stop as u8 }
        Ok(())
    }

    /// Check both bit decompositions against the commitment and create the verified `Record`.
    pub fn finalize(ctx: Context<Finalize>) -> Result<()> {
        let v = &ctx.accounts.verification;
        let n = v.range_bits as usize;
        require!(v.locked && v.next_lower as usize == n && v.next_upper as usize == n, VeilopsError::NotComplete);
        let data = ctx.accounts.buffer.try_borrow_data()?;

        let lower = weighted_sum(&data, 0, n)?;
        require!(lower.0 == v.commitment, VeilopsError::SumMismatch);
        // D = maxAmount·G − C
        let max_g = multiply_ristretto(&scalar_u64(v.max_amount), &PodRistrettoPoint(G)).ok_or(VeilopsError::CurveOp)?;
        let d = subtract_ristretto(&max_g, &PodRistrettoPoint(v.commitment)).ok_or(VeilopsError::CurveOp)?;
        let upper = weighted_sum(&data, 1, n)?;
        require!(upper.0 == d.0, VeilopsError::SumMismatch);

        let proof_hash = hashv(&[&data[..]]).to_bytes();
        drop(data);

        let r = &mut ctx.accounts.record;
        r.authority = v.authority;
        r.verification = v.key();
        r.buffer = v.buffer;
        r.operation_id = v.operation_id.clone();
        r.policy_id = v.policy_id.clone();
        r.asset = v.asset.clone();
        r.category = v.category.clone();
        r.max_amount = v.max_amount;
        r.range_bits = v.range_bits;
        r.commitment = v.commitment;
        r.proof_hash = proof_hash;
        r.verified_slot = Clock::get()?.slot;
        r.bump = ctx.bumps.record;
        emit!(RecordVerified {
            operation_id: r.operation_id.clone(),
            policy_id: r.policy_id.clone(),
            max_amount: r.max_amount,
            commitment: r.commitment,
            proof_hash,
            slot: r.verified_slot,
        });
        Ok(())
    }
}

/* ---------------- verification helpers ---------------- */

/// One CDS OR-proof: C_i commits to 0 or to 1. Bit layout: C ‖ c0 ‖ c1 ‖ s0 ‖ s1 (scalars little-endian, < L).
fn verify_bit(bit: &[u8], ctx_hash: &[u8; 32], index: u32) -> Result<()> {
    let c_i: [u8; 32] = bit[0..32].try_into().unwrap();
    let c0 = canonical_scalar(&bit[32..64])?;
    let c1 = canonical_scalar(&bit[64..96])?;
    let s0 = canonical_scalar(&bit[96..128])?;
    let s1 = canonical_scalar(&bit[128..160])?;
    let ci = PodRistrettoPoint(c_i);
    let h = PodRistrettoPoint(H);
    // Y1 = C_i − G (fails if C_i is not a valid ristretto255 encoding)
    let y1 = subtract_ristretto(&ci, &PodRistrettoPoint(G)).ok_or(VeilopsError::InvalidPoint)?;
    // A_b = s_b·H − c_b·Y_b
    let a0 = multiscalar_multiply_ristretto(&[PodScalar(s0.to_bytes()), PodScalar((-c0).to_bytes())], &[h, ci]).ok_or(VeilopsError::CurveOp)?;
    let a1 = multiscalar_multiply_ristretto(&[PodScalar(s1.to_bytes()), PodScalar((-c1).to_bytes())], &[h, y1]).ok_or(VeilopsError::CurveOp)?;
    let idx = index.to_be_bytes();
    let tag: &[u8] = b"VEILOPS/range/v2/bit";
    let h0 = hashv(&[&[0u8], tag, ctx_hash, &idx, &c_i, &a0.0, &a1.0]).to_bytes();
    let h1 = hashv(&[&[1u8], tag, ctx_hash, &idx, &c_i, &a0.0, &a1.0]).to_bytes();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&h0);
    wide[32..].copy_from_slice(&h1);
    let e = Scalar::from_bytes_mod_order_wide(&wide);
    require!(c0 + c1 == e, VeilopsError::BitProofInvalid);
    Ok(())
}

/// Σ 2^i·C_i over the bit commitments of one range proof (one multiscalar multiplication).
fn weighted_sum(data: &[u8], range: usize, n: usize) -> Result<PodRistrettoPoint> {
    let base = HEADER_BYTES + range * n * BIT_BYTES;
    let mut scalars = Vec::with_capacity(n);
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        let o = base + i * BIT_BYTES;
        points.push(PodRistrettoPoint(data[o..o + 32].try_into().unwrap()));
        scalars.push(scalar_u64(1u64 << i));
    }
    multiscalar_multiply_ristretto(&scalars, &points).ok_or_else(|| VeilopsError::CurveOp.into())
}

fn canonical_scalar(bytes: &[u8]) -> Result<Scalar> {
    let arr: [u8; 32] = bytes.try_into().unwrap();
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| VeilopsError::NonCanonicalScalar.into())
}

fn scalar_u64(x: u64) -> PodScalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&x.to_le_bytes());
    PodScalar(b)
}

fn valid_text(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TEXT && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
}

/// Canonical JSON of {v: "veilops-range-v2", ...publicInputs}, keys in sorted order — byte-identical to the
/// TypeScript `transcriptContextV2` (text fields are restricted, so no escaping is needed).
fn canonical_context(a: &BeginArgs) -> String {
    let hex: String = a.commitment.iter().map(|b| format!("{:02x}", b)).collect();
    format!(
        "{{\"amountCommitment\":\"{}\",\"asset\":\"{}\",\"category\":\"{}\",\"maxAmount\":{},\"operationId\":\"{}\",\"policyId\":\"{}\",\"rangeBits\":{},\"v\":\"veilops-range-v2\"}}",
        hex, a.asset, a.category, a.max_amount, a.operation_id, a.policy_id, a.range_bits
    )
}

/* ---------------- accounts ---------------- */

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct BeginArgs {
    pub operation_id: String,
    pub policy_id: String,
    pub asset: String,
    pub category: String,
    pub max_amount: u64,
    pub range_bits: u8,
    pub commitment: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct Verification {
    pub authority: Pubkey,
    pub buffer: Pubkey,
    #[max_len(64)]
    pub operation_id: String,
    #[max_len(64)]
    pub policy_id: String,
    #[max_len(64)]
    pub asset: String,
    #[max_len(64)]
    pub category: String,
    pub max_amount: u64,
    pub range_bits: u8,
    pub commitment: [u8; 32],
    pub ctx_hash_lower: [u8; 32],
    pub ctx_hash_upper: [u8; 32],
    pub next_lower: u8,
    pub next_upper: u8,
    pub locked: bool,
    pub bump: u8,
}

/// Exists only for operations whose proof fully verified on-chain. One per operation id.
#[account]
#[derive(InitSpace)]
pub struct Record {
    pub authority: Pubkey,
    pub verification: Pubkey,
    pub buffer: Pubkey,
    #[max_len(64)]
    pub operation_id: String,
    #[max_len(64)]
    pub policy_id: String,
    #[max_len(64)]
    pub asset: String,
    #[max_len(64)]
    pub category: String,
    pub max_amount: u64,
    pub range_bits: u8,
    pub commitment: [u8; 32],
    pub proof_hash: [u8; 32],
    pub verified_slot: u64,
    pub bump: u8,
}

#[event]
pub struct RecordVerified {
    pub operation_id: String,
    pub policy_id: String,
    pub max_amount: u64,
    pub commitment: [u8; 32],
    pub proof_hash: [u8; 32],
    pub slot: u64,
}

#[derive(Accounts)]
pub struct Begin<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: raw proof buffer created zeroed by the client and owned by this program; checked fresh and sized in `begin`.
    #[account(owner = crate::ID)]
    pub buffer: UncheckedAccount<'info>,
    #[account(init, payer = authority, space = 8 + Verification::INIT_SPACE, seeds = [b"verification", buffer.key().as_ref()], bump)]
    pub verification: Account<'info, Verification>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Write<'info> {
    pub authority: Signer<'info>,
    #[account(has_one = authority, has_one = buffer)]
    pub verification: Account<'info, Verification>,
    /// CHECK: bound to `verification` via has_one; owned by this program.
    #[account(mut, owner = crate::ID)]
    pub buffer: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct VerifyBits<'info> {
    pub authority: Signer<'info>,
    #[account(mut, has_one = authority, has_one = buffer)]
    pub verification: Account<'info, Verification>,
    /// CHECK: bound to `verification` via has_one; owned by this program.
    #[account(owner = crate::ID)]
    pub buffer: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Finalize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(has_one = authority, has_one = buffer)]
    pub verification: Account<'info, Verification>,
    /// CHECK: bound to `verification` via has_one; owned by this program.
    #[account(owner = crate::ID)]
    pub buffer: UncheckedAccount<'info>,
    #[account(init, payer = authority, space = 8 + Record::INIT_SPACE,
        seeds = [b"record", hashv(&[verification.operation_id.as_bytes()]).as_ref()], bump)]
    pub record: Account<'info, Record>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum VeilopsError {
    #[msg("text fields must match [A-Za-z0-9_.-], 1 to 64 chars")]
    InvalidText,
    #[msg("rangeBits must be 1..=48")]
    InvalidRangeBits,
    #[msg("maxAmount must be < 2^rangeBits")]
    LimitTooLarge,
    #[msg("invalid ristretto255 point")]
    InvalidPoint,
    #[msg("proof buffer has the wrong length")]
    BadBufferLength,
    #[msg("proof buffer is not fresh")]
    BufferNotFresh,
    #[msg("proof is locked: verification has started")]
    Locked,
    #[msg("write out of bounds")]
    OutOfBounds,
    #[msg("range must be 0 (lower) or 1 (upper)")]
    InvalidRange,
    #[msg("bad proof header (version or bit count)")]
    BadHeader,
    #[msg("all bits of this range are already verified")]
    RangeComplete,
    #[msg("non-canonical scalar")]
    NonCanonicalScalar,
    #[msg("curve operation failed")]
    CurveOp,
    #[msg("bit proof failed: challenge mismatch")]
    BitProofInvalid,
    #[msg("verification not complete")]
    NotComplete,
    #[msg("bit commitments do not sum to the commitment")]
    SumMismatch,
}
