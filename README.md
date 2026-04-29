# peel

A streaming, resumable, space-efficient extractor for compressed archives
downloaded over HTTP.

```
peel https://example.com/dataset.tar.zst -C ./out
```

What it does:

- Downloads the archive in parallel ranged chunks (like aria2c).
- Decompresses and extracts on the fly — never materializes the full
  compressed file on disk.
- Punches holes in the partial download as the decoder consumes it, so
  on-disk usage stays bounded by the download window, not the archive
  size.
- Checkpoints at compression-frame boundaries so a `kill -9` mid-run
  resumes exactly where it left off.

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
