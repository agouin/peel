//! In-memory builder for RAR5 test archives.
//!
//! Mirrors the tar / zip / 7z fixture builders. We synthesize the
//! wire format ourselves (rather than shelling out to a `rar` binary
//! at test time) so the fixtures are reproducible across machines
//! and committed-friendly. The encoding follows the technote at
//! <https://www.rarlab.com/technote.htm>; see `peel::rar::format` for
//! the parser side.
//!
//! Round-one targets fixtures that exercise the §1 walker:
//!
//! - **Non-solid archives** with arbitrary STORED entries.
//! - **Solid archives** (`MHD_SOLID`) — flag-only difference;
//!   round-one fixtures use STORED entries so we don't need a
//!   compressor.
//! - **Multi-volume archives** (`MHD_VOLUME` set + optional volume
//!   number) — the walker rejects with `UnsupportedFeature`.
//! - **Encrypted archives** (header type 4) — the walker rejects.
//! - **RAR4 archives** (different magic, no further structure
//!   needed) — `parse_signature` rejects with
//!   `UnsupportedFormatVersion`.

#![allow(dead_code)] // Different integration tests use different subsets.

use peel::crypto::aes::{Aes256, AesBlockCipher, BLOCK_LEN};
use peel::hash::sha256::Sha256;
use peel::rar::encrypt::{derive_keys, fold_pswcheck};
use peel::rar::format::{arc_flags, file_flags, hdr_flags, RAR4_SIGNATURE_MAGIC};
use peel::rar::SIGNATURE_MAGIC;

/// AES block-size constant re-exported so the fixture builder's
/// padding arithmetic doesn't depend on the runtime constant moving
/// out from under it.
const AES_BLOCK: usize = BLOCK_LEN;

/// Block hash trait method needed for the SHA-256 sum of the
/// pswcheck. Imported under an alias to keep the trait name out of
/// the public namespace of this module.
use peel::crypto::BlockHash as _BlockHash;

/// Encode a `u64` as a RAR5 vint.
pub fn encode_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// CRC-32-IEEE convenience (matches the polynomial RAR5 uses for
/// header integrity).
pub fn header_crc32(data: &[u8]) -> u32 {
    let mut state: u32 = !0;
    for &b in data {
        state ^= u32::from(b);
        for _ in 0..8 {
            let lsb = state & 1;
            state >>= 1;
            if lsb != 0 {
                state ^= 0xEDB8_8320;
            }
        }
    }
    !state
}

/// Build a generic header on top of the supplied type-specific
/// fields and (optional) extra area / data area. Returns the
/// header bytes only; the caller appends the data-area bytes if
/// `data_area_size` is `Some`.
pub fn build_generic_header(
    header_type: u64,
    header_flags: u64,
    type_specific: &[u8],
    extra_area: &[u8],
    data_area_size: Option<u64>,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_vint(header_type));
    body.extend_from_slice(&encode_vint(header_flags));
    let extra_present = header_flags & hdr_flags::EXTRA_AREA != 0;
    let data_present = header_flags & hdr_flags::DATA_AREA != 0;
    if extra_present {
        body.extend_from_slice(&encode_vint(extra_area.len() as u64));
    }
    if data_present {
        body.extend_from_slice(&encode_vint(data_area_size.unwrap_or(0)));
    }
    body.extend_from_slice(type_specific);
    if extra_present {
        body.extend_from_slice(extra_area);
    }
    let size_vint_bytes = encode_vint(body.len() as u64);
    let mut out = Vec::with_capacity(4 + size_vint_bytes.len() + body.len());
    out.extend_from_slice(&[0u8; 4]); // CRC32 placeholder
    out.extend_from_slice(&size_vint_bytes);
    out.extend_from_slice(&body);
    let crc = header_crc32(&out[4..]);
    out[..4].copy_from_slice(&crc.to_le_bytes());
    out
}

/// Build a main archive header (header type 1) with the given
/// archive-wide flags and (optional) volume number.
pub fn build_main_header(archive_flags: u64, volume_number: Option<u64>) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(archive_flags));
    if archive_flags & arc_flags::VOLUME_NUMBER != 0 {
        fields.extend_from_slice(&encode_vint(volume_number.unwrap_or(0)));
    }
    build_generic_header(1, 0, &fields, &[], None)
}

/// One STORED-method file-header entry. Round-one §1 doesn't extract
/// data; the data area is appended to the archive bytes verbatim
/// (the walker computes per-entry data offsets from the generic
/// header alone).
#[derive(Clone)]
pub struct RarEntrySpec {
    /// Entry name (UTF-8).
    pub name: String,
    /// Pre-encoding payload.
    pub uncompressed: Vec<u8>,
    /// `true` to set the directory bit in `file_flags`.
    pub directory: bool,
    /// `Some(t)` to record a Unix mtime in the file header.
    pub mtime: Option<u32>,
    /// `Some(c)` to record a CRC32 in the file header. The fixture
    /// does **not** validate the CRC against `uncompressed` —
    /// caller-controlled.
    pub data_crc32: Option<u32>,
}

impl RarEntrySpec {
    /// New STORED entry with default flags.
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            uncompressed: payload.into(),
            directory: false,
            mtime: None,
            data_crc32: None,
        }
    }
}

/// Build a file-header generic header for the given entry, returning
/// `(header_bytes, data_area_bytes)`. The caller concatenates these
/// onto the archive in order so the walker observes the data area
/// immediately after the header.
pub fn build_file_header(entry: &RarEntrySpec) -> (Vec<u8>, Vec<u8>) {
    let mut flags: u64 = 0;
    if entry.directory {
        flags |= file_flags::DIRECTORY;
    }
    if entry.mtime.is_some() {
        flags |= file_flags::TIME_PRESENT;
    }
    if entry.data_crc32.is_some() {
        flags |= file_flags::CRC32_PRESENT;
    }
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(flags));
    fields.extend_from_slice(&encode_vint(entry.uncompressed.len() as u64));
    fields.extend_from_slice(&encode_vint(0)); // attributes
    if let Some(t) = entry.mtime {
        fields.extend_from_slice(&t.to_le_bytes());
    }
    if let Some(c) = entry.data_crc32 {
        fields.extend_from_slice(&c.to_le_bytes());
    }
    fields.extend_from_slice(&encode_vint(0)); // compression info: STORED
    fields.extend_from_slice(&encode_vint(1)); // host OS: Unix
    fields.extend_from_slice(&encode_vint(entry.name.len() as u64));
    fields.extend_from_slice(entry.name.as_bytes());

    let header = build_generic_header(
        2,
        hdr_flags::DATA_AREA,
        &fields,
        &[],
        Some(entry.uncompressed.len() as u64),
    );
    (header, entry.uncompressed.clone())
}

/// Build a minimal end-of-archive header (header type 5) with the
/// `more_volumes` flag clear (round-one rejects multi-volume long
/// before we get here, but the marker still terminates the byte
/// stream).
pub fn build_end_of_archive() -> Vec<u8> {
    build_end_of_archive_with_flags(false)
}

/// Build an end-of-archive header (header type 5) and explicitly set
/// the `more_volumes` flag. Pairs with [`build_rar5_multivolume`]
/// (§2b): non-final volumes carry `more_volumes=true`, the final
/// volume carries `more_volumes=false`.
pub fn build_end_of_archive_with_flags(more_volumes: bool) -> Vec<u8> {
    let fields = encode_vint(if more_volumes { 0x0001 } else { 0 });
    build_generic_header(5, 0, &fields, &[], None)
}

/// Build a synthetic multi-volume RAR5 archive: one `Vec<u8>` per
/// volume, in order. Each volume gets its own signature + main
/// header (`MHD_VOLUME | MHD_VOLUME_NUMBER`, 0-based volume_number
/// matching the position) + the caller's entries + an
/// end-of-archive header with `more_volumes=true` (all but the
/// last volume) or `more_volumes=false` (last volume).
///
/// `per_volume` is one entry list per volume. Entries must fit
/// entirely inside their volume — this builder does not emit
/// `FHD_SPLIT_BEFORE` / `FHD_SPLIT_AFTER` (§2d's job, alongside the
/// walker-side support for cross-volume continuations).
pub fn build_rar5_multivolume(per_volume: &[Vec<RarEntrySpec>]) -> Vec<Vec<u8>> {
    let mut volumes = Vec::with_capacity(per_volume.len());
    for (i, entries) in per_volume.iter().enumerate() {
        let mut vol = Vec::new();
        vol.extend_from_slice(&SIGNATURE_MAGIC);
        let flags = arc_flags::VOLUME | arc_flags::VOLUME_NUMBER;
        vol.extend_from_slice(&build_main_header(flags, Some(i as u64)));
        for entry in entries {
            let (header, data) = build_file_header(entry);
            vol.extend_from_slice(&header);
            vol.extend_from_slice(&data);
        }
        let is_last = i + 1 == per_volume.len();
        vol.extend_from_slice(&build_end_of_archive_with_flags(!is_last));
        volumes.push(vol);
    }
    volumes
}

/// Build a complete RAR5 archive: signature + main header (with the
/// supplied flags + volume number) + N file headers + end of
/// archive.
pub fn build_rar5(
    archive_flags: u64,
    volume_number: Option<u64>,
    entries: &[RarEntrySpec],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);
    out.extend_from_slice(&build_main_header(archive_flags, volume_number));
    for entry in entries {
        let (header, data) = build_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_end_of_archive());
    out
}

/// Build a RAR5 archive with a header-type-4 (archive encryption)
/// header inserted between the main header and the first file
/// header. The encryption header carries a structurally valid body
/// (version 0, no pswcheck, kdf_count 0, a 16-byte all-zero salt)
/// so the walker's encryption-header parser succeeds and surfaces
/// the [`peel::encryption::EncryptionError::UnsupportedCipher`]
/// refusal that signals archive-header encryption is not yet
/// supported end-to-end. The file headers and data areas after the
/// CRYPT header are cleartext — the walker would never read them,
/// since it returns immediately on the encryption header.
pub fn build_rar5_encrypted_header(entries: &[RarEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);
    out.extend_from_slice(&build_main_header(0, None));
    let mut enc_body = Vec::new();
    enc_body.extend_from_slice(&encode_vint(0)); // version
    enc_body.extend_from_slice(&encode_vint(0)); // flags (no pswcheck)
    enc_body.push(0); // kdf_count
    enc_body.extend_from_slice(&[0u8; 16]); // salt
    out.extend_from_slice(&build_generic_header(4, 0, &enc_body, &[], None));
    for entry in entries {
        let (header, data) = build_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_end_of_archive());
    out
}

// ─────────────────────────────────────────────────────────────────
// Per-file encryption fixture builder
// (`docs/PLAN_archive_encryption.md` §4 follow-on)
// ─────────────────────────────────────────────────────────────────

/// One STORED entry whose data area is to be AES-256-CBC encrypted
/// under the per-file encryption record in its file-header extra
/// area. Mirrors [`RarEntrySpec`] but tagged with the per-file
/// IV / salt the fixture builder will embed in the extra record.
#[derive(Clone)]
pub struct EncryptedEntrySpec {
    /// Entry name.
    pub name: String,
    /// Plaintext payload.
    pub uncompressed: Vec<u8>,
    /// 16-byte salt for the entry's KDF. Each entry can carry its
    /// own salt; real RAR5 archives typically reuse one salt across
    /// the whole file but the spec permits per-entry salts.
    pub salt: [u8; 16],
    /// 16-byte IV for the entry's CBC stream. Must be unique per
    /// salt+password combination; the test fixtures pick a fixed
    /// value per entry name.
    pub iv: [u8; AES_BLOCK],
    /// `kdf_count` byte — `iterations = 1 << (kdf_count + 15)`.
    /// Tests use `0` (32 768 iterations) so the KDF stays under a
    /// few hundred milliseconds.
    pub kdf_count: u8,
    /// `true` to embed an 8-byte pswcheck + 4-byte sum in the
    /// extra record. Real archives almost always set this; the
    /// flag gives tests a knob to exercise the no-verifier branch
    /// in the pipeline.
    pub include_pswcheck: bool,
}

impl EncryptedEntrySpec {
    /// New entry with conventional defaults (deterministic
    /// salt/IV derived from the name so the fixture builds are
    /// reproducible).
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        let name = name.into();
        let payload = payload.into();
        let mut salt = [0u8; 16];
        for (i, b) in name.bytes().enumerate().take(16) {
            salt[i] = b.wrapping_add(0x10);
        }
        let mut iv = [0u8; AES_BLOCK];
        for (i, b) in name.bytes().enumerate().take(AES_BLOCK) {
            iv[i] = b.wrapping_add(0x20);
        }
        Self {
            name,
            uncompressed: payload,
            salt,
            iv,
            kdf_count: 0,
            include_pswcheck: true,
        }
    }
}

/// Encrypt one entry's plaintext payload with AES-256-CBC and a
/// trailing zero-pad to a 16-byte boundary. Returns the on-disk
/// ciphertext bytes (length is `round_up(plaintext.len(), 16)`).
fn encrypt_entry_data(plaintext: &[u8], key: &[u8; 32], iv: &[u8; AES_BLOCK]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    // Zero-pad to a multiple of 16 bytes (the RAR5 spec is silent
    // on the exact pad bytes; unrar emits zero pads, which is what
    // every observed real archive does).
    let pad = (AES_BLOCK - (buf.len() % AES_BLOCK)) % AES_BLOCK;
    buf.resize(buf.len() + pad, 0u8);

    let cipher = Aes256::new(key);
    let mut prev = *iv;
    for chunk in buf.chunks_exact_mut(AES_BLOCK) {
        // CBC encrypt: xor plaintext with prev, then AES-encrypt.
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let block: &mut [u8; AES_BLOCK] = chunk.try_into().unwrap();
        cipher.encrypt_block(block);
        prev.copy_from_slice(block);
    }
    buf
}

/// Build a file header for an encrypted STORED entry: the file
/// header carries a type-1 (encryption) extra record describing
/// the salt/iv/kdf_count, and the data area is the ciphertext
/// produced by [`encrypt_entry_data`].
fn build_encrypted_file_header(password: &[u8], entry: &EncryptedEntrySpec) -> (Vec<u8>, Vec<u8>) {
    let mut fields = Vec::new();
    // Always emit CRC32 of the plaintext so the sink validates the
    // decrypted bytes end-to-end.
    let crc = {
        let mut state: u32 = !0;
        for &b in &entry.uncompressed {
            state ^= u32::from(b);
            for _ in 0..8 {
                let lsb = state & 1;
                state >>= 1;
                if lsb != 0 {
                    state ^= 0xEDB8_8320;
                }
            }
        }
        !state
    };
    fields.extend_from_slice(&encode_vint(file_flags::CRC32_PRESENT));
    fields.extend_from_slice(&encode_vint(entry.uncompressed.len() as u64));
    fields.extend_from_slice(&encode_vint(0)); // attributes
    fields.extend_from_slice(&crc.to_le_bytes());
    fields.extend_from_slice(&encode_vint(0)); // compression info: STORED
    fields.extend_from_slice(&encode_vint(1)); // host OS: Unix
    fields.extend_from_slice(&encode_vint(entry.name.len() as u64));
    fields.extend_from_slice(entry.name.as_bytes());

    let keys = derive_keys(password, &entry.salt, entry.kdf_count);
    let ciphertext = encrypt_entry_data(&entry.uncompressed, &keys.aes_key, &entry.iv);

    // Encryption extra record body:
    //   [version vint][flags vint][kdf_count u8][salt 16][iv 16][pswcheck 12?]
    let flags: u64 = if entry.include_pswcheck { 0x0001 } else { 0 };
    let mut enc_body = Vec::new();
    enc_body.extend_from_slice(&encode_vint(0)); // version
    enc_body.extend_from_slice(&encode_vint(flags));
    enc_body.push(entry.kdf_count);
    enc_body.extend_from_slice(&entry.salt);
    enc_body.extend_from_slice(&entry.iv);
    if entry.include_pswcheck {
        let check = fold_pswcheck(&keys.pswcheck_raw);
        let sum = Sha256::digest(&check);
        enc_body.extend_from_slice(&check);
        enc_body.extend_from_slice(&sum.as_ref()[..4]);
    }
    // Wrap into an extra-record envelope: [size vint][type vint=1][body]
    let mut record = Vec::new();
    record.extend_from_slice(&encode_vint(1)); // type
    record.extend_from_slice(&enc_body);
    let mut extra = Vec::new();
    extra.extend_from_slice(&encode_vint(record.len() as u64));
    extra.extend_from_slice(&record);

    let header = build_generic_header(
        2,
        hdr_flags::DATA_AREA | hdr_flags::EXTRA_AREA,
        &fields,
        &extra,
        Some(ciphertext.len() as u64),
    );
    (header, ciphertext)
}

/// Build a complete RAR5 archive whose file entries' data areas are
/// per-file AES-256-CBC encrypted under `password`.
///
/// The archive itself has no archive-header encryption (HEAD_CRYPT
/// is absent); only the entries' data carries an encryption layer.
pub fn build_rar5_per_file_encrypted(password: &[u8], entries: &[EncryptedEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);
    out.extend_from_slice(&build_main_header(0, None));
    for entry in entries {
        let (header, data) = build_encrypted_file_header(password, entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_end_of_archive());
    out
}

/// Encrypt one cleartext header under the archive-header CBC
/// scheme: prepend a 16-byte IV (chosen by the caller), zero-pad
/// the cleartext to a 16-byte boundary, and AES-256-CBC-encrypt the
/// padded block. Returns the wire bytes for the encrypted header.
fn encrypt_header_with_iv(
    cleartext_header: &[u8],
    aes_key: &[u8; 32],
    iv: &[u8; AES_BLOCK],
) -> Vec<u8> {
    let mut padded = cleartext_header.to_vec();
    let pad = (AES_BLOCK - (padded.len() % AES_BLOCK)) % AES_BLOCK;
    padded.resize(padded.len() + pad, 0u8);

    let cipher = Aes256::new(aes_key);
    let mut prev = *iv;
    for chunk in padded.chunks_exact_mut(AES_BLOCK) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let block: &mut [u8; AES_BLOCK] = chunk.try_into().unwrap();
        cipher.encrypt_block(block);
        prev.copy_from_slice(block);
    }

    let mut out = Vec::with_capacity(AES_BLOCK + padded.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&padded);
    out
}

/// Build a complete RAR5 archive with archive-header encryption
/// enabled. Every header after HEAD_CRYPT is AES-256-CBC encrypted
/// under a per-archive key derived from `password`, salted with the
/// fixture's fixed `[0xAA; 16]` value. Each header is prefixed by
/// its own 16-byte IV (the fixture derives a deterministic IV from
/// the header index so the archive is reproducible).
///
/// The file data areas are *not* encrypted at the archive-header
/// layer; per-file encryption (a separate, independent layer) is
/// not exercised by this fixture — `entries` are plain STORED
/// payloads inside the encrypted headers.
pub fn build_rar5_archive_header_encrypted(password: &[u8], entries: &[RarEntrySpec]) -> Vec<u8> {
    // Use a fixed salt / kdf_count so the fixture stays reproducible.
    let salt: [u8; 16] = [0xAA; 16];
    let kdf_count: u8 = 0;
    let keys = derive_keys(password, &salt, kdf_count);

    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);

    // HEAD_CRYPT (cleartext, present once at the start).
    let mut enc_body = Vec::new();
    enc_body.extend_from_slice(&encode_vint(0)); // version
    enc_body.extend_from_slice(&encode_vint(0x0001)); // FLAG_PSWCHECK
    enc_body.push(kdf_count);
    enc_body.extend_from_slice(&salt);
    let check = fold_pswcheck(&keys.pswcheck_raw);
    let sum = Sha256::digest(&check);
    enc_body.extend_from_slice(&check);
    enc_body.extend_from_slice(&sum.as_ref()[..4]);
    out.extend_from_slice(&build_generic_header(4, 0, &enc_body, &[], None));

    // Headers from here on are encrypted. Each gets a unique IV
    // (incrementing counter so the archive is reproducible).
    let mut iv_seed: u8 = 1;
    let mut next_iv = || -> [u8; AES_BLOCK] {
        let iv = [iv_seed; AES_BLOCK];
        iv_seed = iv_seed.wrapping_add(1);
        iv
    };

    // Main header (encrypted).
    let main_clear = build_main_header(0, None);
    out.extend_from_slice(&encrypt_header_with_iv(
        &main_clear,
        &keys.aes_key,
        &next_iv(),
    ));

    // Each file header (encrypted) + cleartext data area.
    for entry in entries {
        let (file_clear, data) = build_file_header(entry);
        out.extend_from_slice(&encrypt_header_with_iv(
            &file_clear,
            &keys.aes_key,
            &next_iv(),
        ));
        out.extend_from_slice(&data);
    }

    // End-of-archive (encrypted).
    let eoa_clear = build_end_of_archive();
    out.extend_from_slice(&encrypt_header_with_iv(
        &eoa_clear,
        &keys.aes_key,
        &next_iv(),
    ));

    out
}

/// Build a 7-byte RAR4 magic-only fixture. The walker rejects on
/// the signature alone; nothing further is needed for the test.
pub fn build_rar4_magic_only() -> Vec<u8> {
    RAR4_SIGNATURE_MAGIC.to_vec()
}

// ─────────────────────────────────────────────────────────────────
// Legacy (RAR3 / RAR4) fixture builder
// ─────────────────────────────────────────────────────────────────
//
// The legacy archive format uses fixed-layout little-endian headers
// with a CRC-16 (low 16 of CRC-32 IEEE) prefix. See
// `peel::rar::legacy::format` for the parser side and
// `docs/PLAN_rar3.md` §A1 for the layout.

const LEGACY_HEAD_FLAG_LONG_BLOCK: u16 = 0x8000;
const LEGACY_BASE_BLOCK_LEN: usize = 7;

/// Build a legacy base-block-prefixed header. CRCs the body and
/// returns the wire bytes; the caller appends the data area
/// separately (when `add_size` is `Some(n)`, `n` bytes of data are
/// expected to follow the header in the archive stream).
pub fn build_legacy_block(
    head_type: u8,
    head_flags: u16,
    body: &[u8],
    add_size: Option<u32>,
) -> Vec<u8> {
    let mut head_flags = head_flags;
    if add_size.is_some() {
        head_flags |= LEGACY_HEAD_FLAG_LONG_BLOCK;
    }
    let header_extra = if add_size.is_some() { 4 } else { 0 };
    let head_size = (LEGACY_BASE_BLOCK_LEN + header_extra + body.len()) as u16;
    let mut bytes = Vec::with_capacity(head_size as usize);
    bytes.extend_from_slice(&[0, 0]); // head_crc placeholder
    bytes.push(head_type);
    bytes.extend_from_slice(&head_flags.to_le_bytes());
    bytes.extend_from_slice(&head_size.to_le_bytes());
    if let Some(add) = add_size {
        bytes.extend_from_slice(&add.to_le_bytes());
    }
    bytes.extend_from_slice(body);
    let crc16 = (header_crc32(&bytes[2..]) & 0xFFFF) as u16;
    bytes[..2].copy_from_slice(&crc16.to_le_bytes());
    bytes
}

/// Build a legacy `MAIN_HEAD` (block type `0x73`).
///
/// `archive_flags` is the wire-level flag word (bit 0x0008 = SOLID,
/// 0x0001 = MULTI_VOLUME, etc.). The 6-byte reserved tail
/// (`high_pos_av` + `pos_av`) is zeroed.
pub fn build_legacy_main_header(archive_flags: u16) -> Vec<u8> {
    let body = [0u8; 6];
    build_legacy_block(0x73, archive_flags, &body, None)
}

/// Build a legacy `ENDARC_HEAD` (block type `0x7B`).
pub fn build_legacy_endarc_header() -> Vec<u8> {
    build_legacy_block(0x7B, 0, &[], None)
}

/// Spec for a STORED-method legacy file-header entry.
#[derive(Clone, Debug)]
pub struct LegacyEntrySpec {
    /// Entry name (UTF-8).
    pub name: String,
    /// Pre-encoding payload. STORED means `pack_size == unp_size`.
    pub uncompressed: Vec<u8>,
    /// Compression-version × 10 (e.g. `36` for RAR 3.6 / 4.x).
    /// The legacy parser accepts `[29, 36]`.
    pub unp_ver: u8,
}

impl LegacyEntrySpec {
    /// New STORED entry tagged with `unp_ver = 36` (the RAR 4.x
    /// default).
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            uncompressed: payload.into(),
            unp_ver: 36,
        }
    }
}

/// Build a legacy `FILE_HEAD` (block type `0x74`) for a STORED entry,
/// returning `(header_bytes, data_area_bytes)`. The caller
/// concatenates them in order so the walker observes the data area
/// immediately after the header.
pub fn build_legacy_file_header(entry: &LegacyEntrySpec) -> (Vec<u8>, Vec<u8>) {
    let pack_size: u32 = entry.uncompressed.len() as u32;
    let unp_size_low: u32 = pack_size; // STORED
    let host_os: u8 = 3; // Unix
    let file_crc32: u32 = header_crc32(&entry.uncompressed);
    let dos_mtime: u32 = 0x4949_4949; // arbitrary
    let method: u8 = 0x30; // m=0 STORED
    let attr: u32 = 0o644;

    let mut body = Vec::with_capacity(25 + entry.name.len());
    body.extend_from_slice(&unp_size_low.to_le_bytes());
    body.push(host_os);
    body.extend_from_slice(&file_crc32.to_le_bytes());
    body.extend_from_slice(&dos_mtime.to_le_bytes());
    body.push(entry.unp_ver);
    body.push(method);
    body.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    body.extend_from_slice(&attr.to_le_bytes());
    body.extend_from_slice(entry.name.as_bytes());

    let head_flags: u16 = 0; // no LARGE / UNICODE / SALT / EXTTIME
    let header = build_legacy_block(0x74, head_flags, &body, Some(pack_size));
    (header, entry.uncompressed.clone())
}

/// Build a complete legacy STORED archive: 7-byte magic + MAIN_HEAD
/// (with the supplied flags) + N FILE_HEADs (each followed by data) +
/// ENDARC_HEAD.
pub fn build_legacy_archive(archive_flags: u16, entries: &[LegacyEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&peel::rar::LEGACY_SIGNATURE_MAGIC);
    out.extend_from_slice(&build_legacy_main_header(archive_flags));
    for entry in entries {
        let (header, data) = build_legacy_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_legacy_endarc_header());
    out
}
