# Arbitrum snapshot bundle

Arbitrum publishes Nitro chain snapshots as **multi-part archives**:
`pruned.tar.part0000` through `pruned.tar.partNNNN`, each ~5–15 GiB,
totalling 200–500 GiB depending on chain and pruning mode. Per-part
SHA-256s are published in a manifest.

This workload uses `peel`'s [multi-part URL](../multi-part-urls.md)
path. The bundled `scripts/arb-snapshot.sh` in the repo wraps it.

## The manual version

```sh
peel \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0000 \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0001 \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0002 \
  ... \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5e8aa72a2ab39310af020bdb6f76d6f7c75c7c14ade38c6ce \
  --sha256 c40bf8a2cb9d9a90e4c80a5b7c6e9c5d3b8a2e1f9d4a6c1b7e2f8d3a5c0b9e1f0 \
  ... \
  -o ./nova-out/
```

The byte-concatenation of every URL's body is decoded as one
logical `pruned.tar`, written into `./nova-out/`. Per-part hashes
are verified at each part boundary as the decoder advances.

## Via a manifest file

For chains with dozens of parts, a per-line manifest is cleaner:

```text
# nova-volumes.txt
https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0000
https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0001
https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0002
# ... etc
```

```sh
peel @nova-volumes.txt -o ./nova-out/
```

For hashes, generate a `--sha256` arg list from the published
manifest:

```sh
peel @nova-volumes.txt \
  $(jq -r '.parts[] | "--sha256 \(.sha256)"' nova-manifest.json) \
  -o ./nova-out/
```

## Disk math

A typical Nitro Nova snapshot:

- Total compressed (sum of all parts): ~120 GiB
- Extracted: ~340 GiB

With `peel`, peak disk = `extracted_size + lookahead_window` ≈
**~341 GiB**. The `--max-disk-buffer` default (1 GiB) bounds the
compressed-side window.

Without `peel` (download-all-then-extract):
peak disk = `compressed_size + extracted_size` ≈ **~460 GiB**.

This is a 120 GiB savings on a single node. For a fleet, the
multiplier matters. For a one-node bootstrapping flow on tight
disk, it is the difference between "works" and "does not fit."

## On Kubernetes

Snapshot hydration matches the
[Kubernetes init container](./kubernetes.md) workflow. The PVC sizes
to ~`extracted_size + 1 GiB` instead of ~`compressed + extracted`,
and a pod restart mid-hydration resumes at the last checkpoint:

```yaml
initContainers:
  - name: hydrate-nova
    image: ghcr.io/agouin/peel:latest
    args:
      - @/manifest/nova-volumes.txt
      - --sha256-from-file=/manifest/nova-hashes.txt   # (planned)
      - --max-bandwidth
      - 500MB/s
      - -o
      - /chain/
    volumeMounts:
      - name: chain
        mountPath: /chain
      - name: manifest
        mountPath: /manifest
        readOnly: true
```

(`--sha256-from-file` is on the roadmap; for now, expand inline via
shell substitution.)

## Bandwidth limiting

Arbitrum snapshot mirrors are CloudFront-fronted with generous burst
allowances, but a fleet of nodes hydrating simultaneously will hit
rate-limits. The default `--workers 4` is conservative. Raise to
`--workers 8` on a fat pipe when needed. Add
`--max-bandwidth 500MB/s` to bound aggregate throughput.

## Recovery from `kill -9`

Snapshot hydration is a long-running, interruptible workload. Power
loss, OOM, scheduler eviction, and upstream rate-limit-induced
retries are all normal.

In every case, re-run the same command:

```sh
peel @nova-volumes.txt --sha256 ... -o ./nova-out/
```

`peel` reads the `.peel.ckpt` next to `./nova-out`, picks up at the
checkpointed part and byte, and continues. Bytes already extracted to
`./nova-out/` are kept, not re-written. Final output is byte-identical
to a clean single run.

## See also

- The shipped wrapper script:
  [`scripts/arb-snapshot.sh`](https://github.com/agouin/peel/blob/main/scripts/arb-snapshot.sh).
- [Multi-part URLs](../multi-part-urls.md): the full feature
  reference.
- [Integrity verification](../integrity.md): how per-part `--sha256`
  is verified.
- [Checkpoint and resume](../checkpoint-resume.md): what the
  `.peel.ckpt` sidecar captures across the part boundary.
