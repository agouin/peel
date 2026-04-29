# peel

**Sick of downloading an archive just to extract it and delete it?**
**Tired of provisioning disk for *both* the compressed file and the
extracted contents — only to throw half of it away?**

`peel` downloads, decompresses, and extracts in a single pass. The
compressed bytes never fully land on disk: as the decoder consumes them,
the download buffer is hole-punched out from underneath. Your archive
and your extracted tree never coexist at full size.

```
peel https://example.com/dataset.tar.zst -C ./out
```

## What it does

- Downloads the archive in parallel ranged chunks (like aria2c).
- Decompresses and extracts on the fly — never materializes the full
  compressed file on disk.
- Punches holes in the partial download as the decoder consumes it, so
  on-disk usage stays bounded by the download window, not the archive
  size.
- Checkpoints at compression-frame boundaries so a `kill -9` mid-run
  resumes exactly where it left off.

## Why you want this

**Local workstations.** Pulling a 40 GB `.tar.zst` dataset shouldn't
require 80 GB free. With `peel`, peak disk usage is roughly
`extracted_size + a few hundred MB` — not `compressed_size +
extracted_size`.

**Kubernetes / PVCs.** Loading a database snapshot, ML model bundle, or
seed dataset into a PersistentVolumeClaim is the canonical case. The
naive approach forces you to size the PVC for `archive + extracted`,
then shrink it (or live with the waste) once extraction finishes. PVCs
don't shrink gracefully, so in practice you over-provision forever.
`peel` lets you size the PVC for the **extracted** contents plus a
small download window — which is what you actually need to keep around.
Drop it into an `initContainer` and the volume is ready by the time
your workload starts.

**CI runners and ephemeral disks.** Same story: bounded disk, resumable
on flaky networks, no scratch space gymnastics.

## Status

Pre-MVP. See [`docs/PLAN.md`](docs/PLAN.md) for the implementation plan.

## For contributors and AI agents

Start with [`CLAUDE.md`](CLAUDE.md) (or [`AGENTS.md`](AGENTS.md) — both
point at the same docs). The full doc set:

- [`CLAUDE.md`](CLAUDE.md) — entry point, house rules summary
- [`AGENTS.md`](AGENTS.md) — workflow rules for coding agents
- [`docs/PLAN.md`](docs/PLAN.md) — sequenced MVP plan
- [`docs/ENGINEERING_STANDARDS.md`](docs/ENGINEERING_STANDARDS.md) —
  non-negotiable rules
- [`docs/ENGINEERING_BEST_PRACTICES.md`](docs/ENGINEERING_BEST_PRACTICES.md)
  — idiomatic patterns
- [`docs/OPTIMIZATIONS.md`](docs/OPTIMIZATIONS.md) — explicitly deferred,
  do not implement during MVP

## License

TBD.
