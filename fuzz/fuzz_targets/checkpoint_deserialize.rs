//! Fuzz target: `Checkpoint::deserialize` must never panic on adversarial
//! bytes, and any input it accepts must round-trip identically through
//! `serialize` → `deserialize`.
//!
//! Required per `internal/ENGINEERING_STANDARDS.md` §5.2 ("checkpoint file
//! parsing").

#![no_main]

use libfuzzer_sys::fuzz_target;
use peel::checkpoint::Checkpoint;

fuzz_target!(|data: &[u8]| {
    let Ok(cp) = Checkpoint::deserialize(data) else {
        return;
    };
    let bytes = cp.serialize();
    let cp2 =
        Checkpoint::deserialize(&bytes).expect("freshly serialized checkpoint must deserialize");
    assert_eq!(
        cp, cp2,
        "Checkpoint serialize/deserialize round-trip mismatch"
    );
});
