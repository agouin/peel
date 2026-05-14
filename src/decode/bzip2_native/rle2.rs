//! RUNA / RUNB run-length-2 inverse — bzip2's pre-Huffman zero-run
//! collapser, run in reverse here.
//!
//! `internal/PLAN_bz2_support.md` Phase 4. The encoder collapses
//! runs of MTF index 0 into a sequence of `RUNA` / `RUNB` tokens
//! using a bijective base-2 numbering (every positive integer has a
//! unique representation as a sum of digits 1 and 2 weighted by
//! powers of two). The decoder inverts the encoding:
//!
//! - Symbol `0` (RUNA): contribute `1 << N` to the running count,
//!   bump `N` by 1.
//! - Symbol `1` (RUNB): contribute `2 << N` to the running count,
//!   bump `N` by 1.
//! - Any other symbol terminates the run; emit `run_length` copies
//!   of the current MTF-front byte before processing the
//!   terminating symbol.
//!
//! This module owns only the run-length accumulator. The full
//! pipeline (MTF + RLE2 expansion → byte stream) lives in
//! [`super::body`] / the orchestrating decoder, which threads the
//! [`super::mtf::MtfState`] for the front byte.

use super::error::Bzip2Error;
use super::mtf::MtfState;

/// Translate a Huffman-decoded symbol stream into the post-MTF byte
/// stream (the BWT-permuted block content).
///
/// - `symbols`: the Huffman symbol stream from [`super::body`]. Each
///   value is a Huffman alphabet symbol — `0` / `1` for RUNA / RUNB,
///   `2..alpha_size - 2` for MTF rank `1..` (un-shifted by adding 1
///   inside this function), and *never* the EOB value (the body
///   loop already stopped before EOB).
/// - `mtf`: the per-block move-to-front state, pre-seeded by
///   [`MtfState::new`] from the block-header symbols-used bitmap.
/// - `max_block_size`: the configured per-block ceiling
///   (`level * 100_000`); the decoder caps output at this value to
///   detect runaway runs early.
///
/// Returns the post-MTF (= BWT-permuted) byte stream.
///
/// # Errors
///
/// - [`Bzip2Error::BlockTooLarge`] if the accumulated run length
///   would overflow `max_block_size`.
/// - [`Bzip2Error::MalformedHuffman`] forwarded from
///   [`MtfState::pop`].
pub fn apply_inverse(
    symbols: &[u16],
    mtf: &mut MtfState,
    max_block_size: u32,
) -> Result<Vec<u8>, Bzip2Error> {
    let mut out = Vec::new();
    let max = max_block_size as usize;
    let mut run_len: u64 = 0;
    let mut weight: u64 = 1;
    for &sym in symbols {
        match sym {
            0 => {
                // RUNA: contribute `weight * 1` to the run length.
                run_len = run_len.saturating_add(weight);
                weight = weight.saturating_mul(2);
            }
            1 => {
                // RUNB: contribute `weight * 2`.
                run_len = run_len.saturating_add(weight.saturating_mul(2));
                weight = weight.saturating_mul(2);
            }
            _ => {
                // Flush any accumulated zero-run before applying
                // the non-RUNA/RUNB symbol.
                if run_len > 0 {
                    push_run(&mut out, mtf.front(), run_len, max)?;
                    run_len = 0;
                    weight = 1;
                }
                // INVARIANT: sym > 1 here, so sym - 1 >= 1 is the
                // MTF rank (un-shifted).
                let rank = (sym - 1) as usize;
                let byte = mtf.pop(rank)?;
                if out.len() >= max {
                    return Err(Bzip2Error::BlockTooLarge {
                        seen: out.len() as u32,
                        max: max_block_size,
                    });
                }
                out.push(byte);
            }
        }
    }
    // Flush any trailing RUN sequence; in well-formed bzip2 streams
    // the encoder always emits a non-RUNA/RUNB symbol before EOB,
    // but defensively flush here too.
    if run_len > 0 {
        push_run(&mut out, mtf.front(), run_len, max)?;
    }
    Ok(out)
}

fn push_run(out: &mut Vec<u8>, byte: u8, run_len: u64, max: usize) -> Result<(), Bzip2Error> {
    // INVARIANT: `max` is the per-block ceiling, `out.len() <= max`
    // when entering. Use checked add to surface the overflow case
    // as BlockTooLarge.
    let total = (out.len() as u64).saturating_add(run_len);
    if total > max as u64 {
        return Err(Bzip2Error::BlockTooLarge {
            // INVARIANT: total may overflow u32 only if max already
            // does; cap at u32::MAX for the diagnostic.
            seen: total.min(u64::from(u32::MAX)) as u32,
            max: max as u32,
        });
    }
    // INVARIANT: total fits in u32 (the per-block ceiling is
    // ≤ 900_000), and out.len() + run_len <= max so the resize is
    // bounded.
    let new_len = out.len() + run_len as usize;
    out.resize(new_len, byte);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn used_set(bytes: &[u8]) -> [bool; 256] {
        let mut s = [false; 256];
        for &b in bytes {
            s[b as usize] = true;
        }
        s
    }

    #[test]
    fn lone_runa_emits_single_front_byte() {
        // alphabet {0x41}, front = 0x41. RUNA → 1 byte.
        let mut mtf = MtfState::new(&used_set(&[0x41]));
        // No further symbol after RUNA: trailing-flush path.
        let out = apply_inverse(&[0], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x41]);
    }

    #[test]
    fn runb_emits_two_front_bytes() {
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[1], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x42, 0x42]);
    }

    #[test]
    fn run_sequence_encodes_bijective_base_two() {
        // RUNA RUNA = 1 + 1*2 = 3 (three copies).
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[0, 0], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x42; 3]);

        // RUNA RUNB = 1 + 2*2 = 5.
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[0, 1], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x42; 5]);

        // RUNB RUNA = 2 + 1*2 = 4.
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[1, 0], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x42; 4]);

        // RUNB RUNB = 2 + 2*2 = 6.
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[1, 1], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x42; 6]);
    }

    #[test]
    fn non_runa_symbol_after_run_flushes_run_first() {
        // alphabet {0x41, 0x42}: sorted = [0x41, 0x42]. front = 0x41.
        // Symbols: RUNA (→ 1×0x41), then Huffman sym 2 (MTF rank 1)
        // which pops 0x42 and moves it to the front.
        let mut mtf = MtfState::new(&used_set(&[0x41, 0x42]));
        let out = apply_inverse(&[0, 2], &mut mtf, 1000).expect("inverse");
        assert_eq!(out, vec![0x41, 0x42]);
    }

    #[test]
    fn block_size_overflow_surfaces() {
        // RUNA RUNA RUNA = 7 bytes, max_block_size = 5 → reject.
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        match apply_inverse(&[0, 0, 0], &mut mtf, 5) {
            Err(Bzip2Error::BlockTooLarge { .. }) => {}
            other => panic!("expected BlockTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn mtf_rank_out_of_range_propagates() {
        // alphabet {0x41} → MTF rank 0 only. Huffman sym 3 = MTF
        // rank 2 → out of range.
        let mut mtf = MtfState::new(&used_set(&[0x41]));
        match apply_inverse(&[3], &mut mtf, 1000) {
            Err(Bzip2Error::MalformedHuffman(_)) => {}
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn long_run_decodes_to_expected_count() {
        // 6 RUNA = 1 + 2 + 4 + 8 + 16 + 32 = 63 bytes.
        let mut mtf = MtfState::new(&used_set(&[0x42]));
        let out = apply_inverse(&[0, 0, 0, 0, 0, 0], &mut mtf, 100).expect("inverse");
        assert_eq!(out.len(), 63);
        assert!(out.iter().all(|&b| b == 0x42));
    }
}
