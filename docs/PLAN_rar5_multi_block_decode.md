# PLAN — RAR5 multi-block decode gap

**Status**: investigated 2026-05-10. **Diagnosed, not yet fixed.**
**Trigger**: searching for a §F1 "Goldilocks" fixture (a compressed
RAR5 archive large enough for the coordinator's mid-entry checkpoint
to fire, simple enough for the round-one decoder to handle).
**Related plans / docs**:

- [`PLAN_rar5_decoder.md`](PLAN_rar5_decoder.md) — parent plan.
  This gap blocks the §F1 crash-resume demo against compressed
  entries and the §E1 differential-corpus rollout.
- [`tests/test_coordinator_rar.rs`](../tests/test_coordinator_rar.rs)
  lines 329-353 — deferred-test comment that motivated this
  investigation. The current "no Goldilocks fixture" rationale
  there is incorrect: the gap is not "we lack an external encoder",
  it is the bug documented below.

## TL;DR — what's wrong

`LzssDecoder::decode_block` ([`src/decode/rar_native/lzss.rs`](../src/decode/rar_native/lzss.rs#L323))
treats each RAR5 block's bitstream as bit-isolated: it constructs
a fresh `BitReader` per block and runs the symbol-decode loop until
`bits_consumed >= block_bit_budget(&hdr)`. That works for entries
that fit in a single block (`is_last_block = true` on the only
block). It does **not** work for entries split across multiple
blocks: the encoder leaves the trailing symbol *partially encoded*
in the non-last block's bit budget, expecting the next block's
bits to complete the symbol. The round-one decoder runs the loop
until it hits the partial symbol's prefix, calls `ld.decode`, and
under-runs by 2 bits.

Concrete trace from the smallest known repro
(`rar a -m5` of `b'X' * 27 * 2_500_000`, ~2.9 KB compressed):

```
block_size=2768 bit_size=7 is_last=false total_bits=22144
after parse_tables: bits_consumed=107
after 16381 symbols: bits_consumed=22142     ← last whole symbol
loop tries one more LD decode:                ← only 2 bits left
LzssError::HuffDecode { table: "LD", source: Underrun }
```

The matching working case (same payload, 100 K fewer reps so it
fits in one block) ends with `bits_consumed == total_bits` exactly
and the loop exits cleanly.

This means **`bit_size` on a non-last block is not "valid bits in
last byte" the way it is on a last block** — it is the libarchive-
equivalent of "bits at the end of this block that belong to the
next-block-spanning symbol's prefix" (or, equivalently, the
encoder's bitstream is logically continuous across non-last block
boundaries and the per-block byte-alignment is bookkeeping only).
`block_bit_budget`'s `(block_size - 1) * 8 + bit_size + 1` formula
is correct for last-block termination but wrong as a per-block
loop terminator.

## Failure boundary (precise)

| Input shape                          | Compressed | Blocks | Result |
|--------------------------------------|-----------:|:------:|:-------|
| `Testing 123\n` (12 B)               | 27 B       | 1      | OK     |
| 1 MB of `'lorem ipsum...'` (period 27) | 211 B    | 1      | OK     |
| 64.8 MB of `b'X'*27` (period 27)     | 2 704 B    | 1      | OK     |
| **67.5 MB of `b'X'*27` (period 27)** | **2 841 B**| **2**  | **FAIL** |
| 180 MB of `'The quick brown fox...'` | 7 625 B    | 3      | FAIL   |
| 1 MB of random text (28-char alphabet) | 691 KB   | 38+    | FAIL   |

The transition is at the moment RAR's encoder fills its internal
block buffer and emits the first non-last block — empirically
~2.8 KB of compressed output for the `rar a -m5` profile. The cap
appears to be the encoder's, not the format's; libarchive supports
arbitrary block counts per entry.

The single-block ramp-data failure (`(0..N) & 0xff` for 10 MiB →
876 B compressed → fails) is a **separate** filter-VM-related
issue, almost certainly a different bug. Out of scope for this
plan.

## Repro recipe

1. Install `rar` somewhere convenient (the probe doesn't need it,
   but the fixtures do).
2. Build the diagnostic probe:
   ```
   cargo build --example rar_decode_probe --features rar
   ```
3. Generate a minimal failing archive:
   ```
   python3 -c 'import sys; sys.stdout.buffer.write(b"X"*27*2_500_000)' > /tmp/p27.txt
   rar a -ma5 -m5 -tsm- -tsa- -tsc- -ep /tmp/p27.rar /tmp/p27.txt
   ```
4. Run the probe:
   ```
   cargo run --example rar_decode_probe --features rar -- /tmp/p27.rar
   ```
   Expected output: `err name=p27.txt method=5 ... err=decoder failed
   after consuming 0 bytes from source`.

## Disproven hypotheses

- **LDD/RD slice swap in `install_tables_from_lengths`.** The order
  of `[LD, DD, LDD, RD]` vs `[LD, DD, RD, LDD]` looked suspicious
  at first read. Confirmed not the cause: the failing 27-period
  payload only ever produces match distances ≤ 27 (slot ≤ 9, dbits
  ≤ 3) — the LDD low-distance path never fires — and the dispatcher
  still fails the same way.
- **Adversarial payloads triggering the §C1 filter VM.** The 27-
  period text payload doesn't trigger any filter; the failure
  reproduces with a clean LZSS-only bitstream.

## Recommended fix sketch

The architectural change: **own a single `BitReader` across the
entry's blocks, not per-block**. The dispatcher's
`decode_block(&mut self, block: &[u8], out: &mut Vec<u8>) -> Result<bool, _>`
becomes (sketch):

```rust
pub fn feed_block(&mut self, block: &[u8]) -> Result<(), LzssError>;
pub fn decode_until_block_drained(&mut self, out: &mut Vec<u8>) -> Result<(), LzssError>;
```

Or fold both into a streaming pull where the dispatcher owns a
`Vec<u8>` of buffered bitstream bytes and consumes them as the
`BitReader` advances. The non-last block's `block_bit_budget` then
becomes the **floor** at which we *stop* loop iterations to wait
for more bytes (so the partial-symbol prefix isn't mis-decoded as
a complete symbol against pad bits). When the next block arrives,
its bytes append to the buffer and the loop resumes from the
preserved bit position.

This also folds in correctly with the `is_table_present` flag:
when set on the new block, the next read off the `BitReader` is
fresh meta-Huffman bits (libarchive's `parse_tables` discipline);
when unset, the existing tables stay in place.

Ballpark scope, modeled on the `xz_native` Phase B → C transition:

- ~200-400 LOC structural change in
  [`src/decode/rar_native/lzss.rs`](../src/decode/rar_native/lzss.rs).
- Upper-layer ([`stream.rs`](../src/decode/rar_native/stream.rs))
  loses the per-block `staging.start_pos` recompute and gains
  a "feed bytes, then drain" two-step.
- `serialize_into` / `resume` (the §F1 snapshot path) gains a
  `buffered_bitstream_tail` field — bytes already pulled off the
  source but not yet consumed by the dispatcher.
- A new positive `decode_block` test against a curated multi-block
  bitstream (synthesizable in-memory now that the failure shape
  is understood; or use the `p27-fails.rar` repro from above
  committed under `tests/fixtures/rar5/`).

The bump is non-trivial but bounded. Estimate 1-2 weeks of focused
work; comparable in scope to the §F1 mid-entry-snapshot landing.

## Tests to add when fixing

1. **Unit**: `decode_block_handles_two_block_split` — synthesize a
   2-block bitstream where a single Huffman symbol straddles the
   boundary; the fix must decode the symbol once.
2. **Integration**: commit the `p27-fails.rar` repro under
   `tests/fixtures/rar5/` (with a `*.expected.bin` sibling produced
   by `unrar` for byte-compare); the `RarStreamDecoder` must emit
   the expected bytes.
3. **Crash-resume**: with the multi-block bug fixed, the deferred
   §F1 compressed-entry crash-resume test in
   [`tests/test_coordinator_rar.rs`](../tests/test_coordinator_rar.rs)
   §F1 lines 329-353 lights up directly — that fixture is the
   Goldilocks the original plan asked for.

## Schedule guidance

This investigation closes the loop on `PLAN_rar5_decoder.md` §F1's
deferred crash-resume test: the blocker is decoder coverage, not
fixture availability. Slot a Phase F2 (or §B2-revisit) sub-section
into `PLAN_rar5_decoder.md` ahead of §G (throughput) — correctness
first.
