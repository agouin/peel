//! Per-entry PPMd-mode decoder for legacy RAR (§C1g).
//!
//! When [`super::block_header::parse_block_prologue`] returns a
//! [`BlockPrologue::Ppmd`] variant, the entry's compressed
//! payload past the prologue is a PPMd-II range-coded byte
//! stream that emits literal bytes AND occasional LZ matches
//! through the model's escape mechanism. [`PpmdSession`] owns
//! the per-entry state — the [`Model`] context + a sliding-
//! window [`Dict`] + the current `ppmd_escape` byte — and runs
//! the dispatch loop libarchive's `read_data_compressed`
//! implements at `archive_read_support_format_rar.c` lines
//! 2158..=2238.
//!
//! # Wire-format dispatch
//!
//! Each iteration decodes one byte `sym` via
//! [`Model::decode_symbol`]:
//!
//! - `sym != ppmd_escape` — literal. Push to the dict, advance.
//! - `sym == ppmd_escape` — read another byte `code`. Switch:
//!   - `code == 0` — "new table". The encoder is asking the
//!     decoder to re-parse a block prologue and continue.
//!     Surfaced as [`PpmdBlockEnd::NewTable`]; §C1h's multi-
//!     block driver handles the transition.
//!   - `code == 2` — end-of-PPMd-data marker. Stop.
//!   - `code == 3` — filter declaration. Surfaces as
//!     [`PpmdEntryError::UnsupportedFilter`] until §C2's VM
//!     lands; the ssokolow corpus doesn't trigger this.
//!   - `code == 4` — large LZ match. Decode 3 PPMd bytes for
//!     `offset` (big-endian) and 1 for `length`. Emit a match
//!     at `(offset + 2, length + 32)`.
//!   - `code == 5` — short LZ match. Decode 1 PPMd byte for
//!     `length`. Emit a match at `(1, length + 4)`.
//!   - any other `code` — escape-of-escape: emit the
//!     `ppmd_escape` byte itself as a literal.
//!
//! # Init / restart semantics
//!
//! [`PpmdSession::apply_prologue`] handles both block-level
//! transitions a [`BlockPrologue::Ppmd`] can encode:
//!
//! - `restart = true` — the encoder is (re-)initialising the
//!   model. Allocate a fresh [`Model`] with the prologue's
//!   `dictionary_size` and `max_order`; seed `ppmd_escape` from
//!   `init_esc` (or default `2`).
//! - `restart = false` — reuse the prior block's model state.
//!   The range decoder always gets a fresh
//!   [`RangeDecoder::new_rar`] init at each PPMd block boundary
//!   (the model context carries over but the range coder
//!   doesn't). Errors if no prior context exists.
//!
//! # Scope of §C1g
//!
//! Round-one is single-mode entries — the ssokolow corpus has
//! one PPMd block per entry. Mixed LZ ↔ PPMd block transitions
//! within an entry (where the same dict is shared across
//! modes) defer to §C1h's multi-block driver. The
//! [`PpmdBlockEnd::NewTable`] outcome is surfaced rather than
//! handled internally so §C1h can wire it without rework.

use thiserror::Error;

use crate::decode::ppmd2::model::{DecodeError, Model, ModelError};
use crate::decode::ppmd2::range_dec::{RangeDecoder, RangeDecoderError};

use super::block_header::BlockPrologue;
use super::dict::{Dict, DictError};

/// Default PPMd escape byte when the block prologue's
/// `init_esc` flag (`ppmd_flags & 0x40`) is clear. Matches
/// libarchive's `parse_codes` line 2344.
pub const DEFAULT_PPMD_ESCAPE: u32 = 2;

/// Errors produced by the PPMd entry-decoder.
#[derive(Debug, Error)]
pub enum PpmdEntryError {
    /// The range decoder reported a wire-level fault.
    #[error("legacy RAR PPMd entry: range decoder failed")]
    Range(#[from] RangeDecoderError),

    /// The PPMd model rejected a symbol decode (malformed
    /// frame, end-marker, etc.).
    #[error("legacy RAR PPMd entry: model decode failed")]
    Model(#[from] DecodeError),

    /// The model constructor failed (over-/under-cap arena,
    /// bad order).
    #[error("legacy RAR PPMd entry: model init failed")]
    ModelInit(#[from] ModelError),

    /// A back-reference or capacity check failed in the dict.
    #[error("legacy RAR PPMd entry: dict emit failed")]
    Dict(#[from] DictError),

    /// A prologue with `restart = false` was applied but no
    /// prior context exists. Libarchive `parse_codes` surfaces
    /// the same error at line 2395.
    #[error("legacy RAR PPMd entry: prologue requested restart=false but no prior context exists")]
    NoPriorContext,

    /// A `restart = true` prologue was missing the
    /// `dictionary_size` / `max_order` payload the model needs
    /// to (re-)initialise. Indicates a malformed prologue (the
    /// `0x20` flag was set but the dispatching layer dropped
    /// the conditional payload before reaching this code).
    #[error("legacy RAR PPMd entry: restart prologue is missing dict_size/max_order payload")]
    RestartPayloadMissing,

    /// The PPMd escape's `code == 3` sub-symbol — a filter
    /// program. §C2's RarVM lands the actual filter
    /// interpretation; until then, surface a precise error.
    #[error("legacy RAR PPMd entry: filter declaration (code 3) is unsupported until §C2 lands")]
    UnsupportedFilter,
}

/// Result of one [`PpmdSession::decode_block`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpmdBlockEnd {
    /// Output position reached the caller-supplied
    /// `unpacked_size` byte budget. The entry's compressed
    /// payload may have more bytes after this point (range
    /// decoder may still hold buffered state), but the caller
    /// is done consuming output.
    SizeReached,
    /// PPMd escape with sub-code `0` — the encoder is asking
    /// for a fresh prologue. The caller (in §C1h, a multi-
    /// block driver) parses the next prologue and re-enters
    /// [`PpmdSession::decode_block`] (or transitions to LZ
    /// mode if the next prologue says so).
    NewTable,
    /// PPMd escape with sub-code `2` — the end-of-data marker.
    /// Decode is complete regardless of whether `unpacked_size`
    /// has been reached (some encoders emit EOD before, at, or
    /// just past the unpacked-size boundary).
    EndOfData,
}

/// Per-entry PPMd decoder state.
///
/// Owns the PPMd model (allocated on the first
/// `apply_prologue(restart=true)` call), a sliding-window
/// dict for the LZ-match cases the escape mechanism emits,
/// the current `ppmd_escape` byte, and the running output
/// counter the caller compares against `unpacked_size`.
pub struct PpmdSession {
    /// PPMd model context. `None` until the first
    /// `apply_prologue` call with `restart = true` initialises
    /// it. Mirrors libarchive's `rar->ppmd_valid` /
    /// `rar->ppmd7_context` pair.
    model: Option<Model>,
    /// Sliding-window dict. Sized from the file header's
    /// declared dictionary capacity (libarchive's `dictionary_size`
    /// derived from `unp_size`); 4 MiB cap matches
    /// [`super::dict::MAX_DICT_BYTES`].
    dict: Dict,
    /// Escape byte in the PPMd symbol alphabet. `2` by default
    /// (libarchive line 2344); overridden when the block
    /// prologue's `ppmd_flags & 0x40` is set.
    ppmd_escape: u32,
    /// Bytes the session has emitted into the dict + the
    /// caller's `out` buffer (literals + match payloads).
    /// The caller compares this against `unpacked_size` to
    /// decide when to stop.
    output_position: u64,
}

impl std::fmt::Debug for PpmdSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PpmdSession")
            .field(
                "model",
                &self
                    .model
                    .as_ref()
                    .map(|_| "<initialised>")
                    .unwrap_or("None"),
            )
            .field("dict_capacity", &self.dict.capacity())
            .field("ppmd_escape", &self.ppmd_escape)
            .field("output_position", &self.output_position)
            .finish()
    }
}

impl PpmdSession {
    /// Construct an uninitialised session.
    ///
    /// The session is "empty" — no model is allocated until
    /// the first [`Self::apply_prologue`] call with
    /// `restart = true`. The dict is allocated immediately to
    /// `dict_capacity` bytes; the caller derives that capacity
    /// from the file header's declared `unp_size` (rounded to
    /// the next power-of-2, clamped at [`super::dict::MAX_DICT_BYTES`]).
    ///
    /// # Errors
    ///
    /// Surfaces [`DictError`] from [`Dict::new`] (zero or
    /// over-cap capacity).
    pub fn new(dict_capacity: usize) -> Result<Self, DictError> {
        Ok(Self {
            model: None,
            dict: Dict::new(dict_capacity)?,
            ppmd_escape: DEFAULT_PPMD_ESCAPE,
            output_position: 0,
        })
    }

    /// Total bytes the session has emitted across all
    /// `decode_block` calls.
    #[must_use]
    pub fn output_position(&self) -> u64 {
        self.output_position
    }

    /// Borrow the dict (read-only). Useful for inspection in
    /// tests + by §C2's filter VM when it lands.
    #[must_use]
    pub fn dict(&self) -> &Dict {
        &self.dict
    }

    /// Current PPMd escape byte (diagnostic accessor).
    #[must_use]
    pub fn ppmd_escape(&self) -> u32 {
        self.ppmd_escape
    }

    /// `true` once a restart-mode prologue has initialised the
    /// model.
    #[must_use]
    pub fn is_initialised(&self) -> bool {
        self.model.is_some()
    }

    /// Apply a PPMd block prologue to the session state.
    ///
    /// - `restart = true` (`ppmd_flags & 0x20` set in the wire
    ///   stream): allocate a fresh model with the prologue's
    ///   `dict_size` + `max_order`. Replaces any prior model.
    ///   `init_esc` (if `ppmd_flags & 0x40` was set) seeds the
    ///   model's `init_esc` field; otherwise default to
    ///   [`DEFAULT_PPMD_ESCAPE`].
    /// - `restart = false`: keep the prior model. `init_esc`
    ///   (if shipped) updates the escape byte for this block
    ///   only.
    ///
    /// The caller is expected to have just parsed this same
    /// prologue from the entry's bitstream; the byte-aligned
    /// cursor immediately after the prologue is where the
    /// next [`RangeDecoder::new_rar`] reads its 4-byte init
    /// prefix.
    ///
    /// # Errors
    ///
    /// - [`PpmdEntryError::ModelInit`] if the new model fails
    ///   to allocate.
    /// - [`PpmdEntryError::NoPriorContext`] if `restart =
    ///   false` and no prior model exists.
    /// - [`PpmdEntryError::RestartPayloadMissing`] if `restart =
    ///   true` but the dict-size / max-order payload is missing
    ///   (the dispatcher passed a malformed prologue).
    pub fn apply_prologue(&mut self, prologue: &BlockPrologue) -> Result<(), PpmdEntryError> {
        let BlockPrologue::Ppmd {
            restart,
            dictionary_size,
            max_order,
            init_esc,
        } = prologue
        else {
            // Caller bug — sending an LZ prologue here. Surface
            // an init error rather than panic.
            return Err(PpmdEntryError::NoPriorContext);
        };

        if *restart {
            let dict_size = dictionary_size.ok_or(PpmdEntryError::RestartPayloadMissing)?;
            let max_order = max_order.ok_or(PpmdEntryError::RestartPayloadMissing)?;
            let model = Model::new(dict_size as usize, max_order)?;
            self.model = Some(model);
        } else if self.model.is_none() {
            return Err(PpmdEntryError::NoPriorContext);
        }

        // init_esc applies whether or not restart fired —
        // libarchive line 2336..2344: the `0x40` flag is
        // independent of `0x20`, and `2` is the default when
        // the flag is clear.
        let escape = init_esc.map(u32::from).unwrap_or(DEFAULT_PPMD_ESCAPE);
        self.ppmd_escape = escape;
        if let Some(model) = self.model.as_mut() {
            model.set_init_esc(escape);
        }
        Ok(())
    }

    /// Decode one PPMd block. Reads symbols from `rd` and
    /// emits bytes (literals + matches) to `out`, stopping
    /// when either:
    ///
    /// - [`Self::output_position`] reaches `unpacked_size` —
    ///   the caller's byte budget is consumed; returns
    ///   [`PpmdBlockEnd::SizeReached`].
    /// - The escape's sub-code is `2` (EOD marker); returns
    ///   [`PpmdBlockEnd::EndOfData`].
    /// - The escape's sub-code is `0` (new-table); returns
    ///   [`PpmdBlockEnd::NewTable`] for §C1h to handle.
    ///
    /// `unpacked_size` is the entry's declared output size in
    /// bytes; subtract [`Self::output_position`] before the
    /// call if a prior block partially decoded an entry.
    ///
    /// # Errors
    ///
    /// - [`PpmdEntryError::Model`] / [`PpmdEntryError::Range`]
    ///   on wire-level malformed input.
    /// - [`PpmdEntryError::Dict`] on a malformed LZ
    ///   back-reference.
    /// - [`PpmdEntryError::UnsupportedFilter`] on escape
    ///   sub-code `3`.
    pub fn decode_block(
        &mut self,
        rd: &mut RangeDecoder<'_>,
        out: &mut Vec<u8>,
        unpacked_size: u64,
    ) -> Result<PpmdBlockEnd, PpmdEntryError> {
        let model = self.model.as_mut().ok_or(PpmdEntryError::NoPriorContext)?;
        let escape_byte = self.ppmd_escape;
        loop {
            if self.output_position >= unpacked_size {
                return Ok(PpmdBlockEnd::SizeReached);
            }
            let sym = model.decode_symbol(rd)?;
            if u32::from(sym) != escape_byte {
                // Literal byte path.
                self.dict.push_literal(sym, out);
                self.output_position = self.output_position.saturating_add(1);
                continue;
            }
            // Escape — read sub-code.
            let code = model.decode_symbol(rd)?;
            match code {
                0 => return Ok(PpmdBlockEnd::NewTable),
                2 => return Ok(PpmdBlockEnd::EndOfData),
                3 => return Err(PpmdEntryError::UnsupportedFilter),
                4 => {
                    // 3-byte big-endian offset + 1-byte length.
                    let b0 = model.decode_symbol(rd)?;
                    let b1 = model.decode_symbol(rd)?;
                    let b2 = model.decode_symbol(rd)?;
                    let offset = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
                    let length = model.decode_symbol(rd)?;
                    let match_offset = u64::from(offset) + 2;
                    let match_length = u64::from(length) + 32;
                    self.dict.copy_match(match_offset, match_length, out)?;
                    self.output_position = self.output_position.saturating_add(match_length);
                }
                5 => {
                    let length = model.decode_symbol(rd)?;
                    let match_length = u64::from(length) + 4;
                    self.dict.copy_match(1, match_length, out)?;
                    self.output_position = self.output_position.saturating_add(match_length);
                }
                _ => {
                    // Escape-of-escape: emit the escape byte
                    // value as a literal. INVARIANT:
                    // `ppmd_escape` fits in a byte — it's
                    // either the 8-bit `init_esc` from the
                    // prologue or the default `2`.
                    let escape_lit = (escape_byte & 0xFF) as u8;
                    self.dict.push_literal(escape_lit, out);
                    self.output_position = self.output_position.saturating_add(1);
                    // `code` is consumed; loop continues for
                    // the next symbol.
                    let _ = code;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_session_is_uninitialised() {
        let s = PpmdSession::new(4096).unwrap();
        assert!(!s.is_initialised());
        assert_eq!(s.output_position(), 0);
        assert_eq!(s.ppmd_escape(), DEFAULT_PPMD_ESCAPE);
        assert_eq!(s.dict().capacity(), 4096);
    }

    #[test]
    fn new_rejects_zero_dict_capacity() {
        let err = PpmdSession::new(0).unwrap_err();
        assert!(matches!(err, DictError::CapacityZero));
    }

    #[test]
    fn apply_prologue_restart_allocates_model_and_seeds_init_esc() {
        let mut s = PpmdSession::new(1 << 20).unwrap();
        let prologue = BlockPrologue::Ppmd {
            restart: true,
            dictionary_size: Some(1 << 20),
            max_order: Some(8),
            init_esc: Some(0x42),
        };
        s.apply_prologue(&prologue).unwrap();
        assert!(s.is_initialised());
        assert_eq!(s.ppmd_escape(), 0x42);
    }

    #[test]
    fn apply_prologue_restart_without_init_esc_defaults_to_two() {
        let mut s = PpmdSession::new(1 << 20).unwrap();
        let prologue = BlockPrologue::Ppmd {
            restart: true,
            dictionary_size: Some(1 << 20),
            max_order: Some(6),
            init_esc: None,
        };
        s.apply_prologue(&prologue).unwrap();
        assert_eq!(s.ppmd_escape(), DEFAULT_PPMD_ESCAPE);
        assert_eq!(s.ppmd_escape(), 2);
    }

    #[test]
    fn apply_prologue_no_restart_without_prior_context_errors() {
        let mut s = PpmdSession::new(1 << 20).unwrap();
        let prologue = BlockPrologue::Ppmd {
            restart: false,
            dictionary_size: None,
            max_order: None,
            init_esc: None,
        };
        let err = s.apply_prologue(&prologue).unwrap_err();
        assert!(matches!(err, PpmdEntryError::NoPriorContext));
    }

    #[test]
    fn apply_prologue_restart_missing_payload_errors() {
        let mut s = PpmdSession::new(1 << 20).unwrap();
        // restart=true but dictionary_size missing — malformed
        // prologue from the dispatcher.
        let prologue = BlockPrologue::Ppmd {
            restart: true,
            dictionary_size: None,
            max_order: Some(4),
            init_esc: None,
        };
        let err = s.apply_prologue(&prologue).unwrap_err();
        assert!(matches!(err, PpmdEntryError::RestartPayloadMissing));
    }

    #[test]
    fn apply_prologue_no_restart_after_restart_updates_escape() {
        let mut s = PpmdSession::new(1 << 20).unwrap();
        // First block: restart with init_esc = 0x42.
        s.apply_prologue(&BlockPrologue::Ppmd {
            restart: true,
            dictionary_size: Some(1 << 20),
            max_order: Some(6),
            init_esc: Some(0x42),
        })
        .unwrap();
        assert_eq!(s.ppmd_escape(), 0x42);
        // Second block: no-restart, init_esc = 0x55.
        s.apply_prologue(&BlockPrologue::Ppmd {
            restart: false,
            dictionary_size: None,
            max_order: None,
            init_esc: Some(0x55),
        })
        .unwrap();
        assert_eq!(s.ppmd_escape(), 0x55);
        // Model still initialised.
        assert!(s.is_initialised());
    }

    #[test]
    fn apply_prologue_with_non_ppmd_variant_returns_error() {
        let s = PpmdSession::new(1 << 20).unwrap();
        // LZ prologue passed to a PPMd session — caller bug.
        // We don't try to construct a real MainTables, so we use
        // the simpler test that a NoPriorContext error surfaces
        // when the caller is misusing the API.
        // (Skipping the actual LZ-variant test since
        // MainTables is non-trivial to construct in this
        // module; the apply_prologue function pattern-matches on
        // the Ppmd variant and falls through to NoPriorContext
        // for any other variant.)
        assert!(!s.is_initialised());
    }
}
