//! RFC 6962 / RFC 9162 `O(log N)` inclusion proof generation and verification.

use crate::plane1::crypto::hmac::ct_eq;
use crate::plane1::merkle::{LeafHash, MerkleLog, NodeHash};

/// Largest power of two strictly less than `n`.
pub fn largest_pow2_lt(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    1usize << ((usize::BITS - (n - 1).leading_zeros()) - 1)
}

/// Compute RFC 6962 audit path for leaf `m` in `hashes`.
pub fn audit_path(m: usize, hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = hashes.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = largest_pow2_lt(n);
    if m < k {
        let mut p = audit_path(m, &hashes[..k]);
        p.push(MerkleLog::mth_raw(&hashes[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &hashes[k..]);
        p.push(MerkleLog::mth_raw(&hashes[..k]));
        p
    }
}

/// Independently verify an RFC 6962 Merkle inclusion proof in `O(log N)`.
pub fn verify_inclusion_hex(
    leaf_payload_jcs: &[u8],
    leaf_index: usize,
    tree_size: usize,
    proof_hex: &[String],
    expected_root_hex: &str,
) -> bool {
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    let mut fn_idx = leaf_index;
    let mut sn = tree_size - 1;
    let mut r = LeafHash::compute(leaf_payload_jcs).0;

    for p_hex in proof_hex {
        let p_vec = match hex::decode(p_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut p = [0u8; 32];
        p.copy_from_slice(&p_vec);
        if sn == 0 {
            return false;
        }
        if (fn_idx & 1) == 1 || fn_idx == sn {
            r = NodeHash::combine(p, r).0;
            while (fn_idx & 1) == 0 && fn_idx != 0 {
                fn_idx >>= 1;
                sn >>= 1;
            }
        } else {
            r = NodeHash::combine(r, p).0;
        }
        fn_idx >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return false;
    }
    let computed = hex::encode(r);
    ct_eq(computed.as_bytes(), expected_root_hex.as_bytes())
}
