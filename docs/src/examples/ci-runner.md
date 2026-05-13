# CI runner with flaky network

CI runners typically have **small ephemeral disks**, **flaky outbound
network** (especially in self-hosted runners behind corporate proxies),
and a **strong preference for fail-fast**. A job that silently
produces a different artifact is worse than a job that errors clearly.

`peel` addresses all three:

- Bounded compressed-side disk usage via the sliding lookahead window.
- Resume on transient network failure without losing the partial
  download.
- `--strict-format` and `--sha256` turn upstream drift into a clear
  exit code 1 rather than a degraded build.

## GitHub Actions example

```yaml
name: ml-test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install peel
        run: cargo install peel-rs --locked

      - name: Hydrate model fixtures
        run: |
          peel \
            https://fixtures.example.com/models-v3.tar.zst \
            --sha256 ${{ vars.MODELS_SHA256 }} \
            --strict-format \
            --max-disk-buffer 512MiB \
            -o ./fixtures/

      - name: Run tests
        run: cargo test --release
```

Flag behavior:

- **`--sha256 ${{ vars.MODELS_SHA256 }}`**: the expected hash is in
  the repo's Actions variables, so a wrong-fixture upload fails CI
  immediately. The hash is in version control implicitly. It ratchets
  forward as the team uploads new fixtures and updates the variable.
- **`--strict-format`**: if the upstream URL ever serves a different
  shape (e.g. a 404 HTML page with a 200 status code from a misbehaving
  proxy), the run fails clearly instead of producing a corrupt
  fixtures directory.
- **`--max-disk-buffer 512MiB`**: GitHub-hosted runners have ~14 GB
  free. Capping the lookahead avoids transient disk pressure during
  hydration.

## GitLab CI example

```yaml
test:
  stage: test
  image: rust:1.93
  before_script:
    - cargo install peel-rs --locked
  script:
    - >
      peel
      "$FIXTURE_URL"
      --sha256 "$FIXTURE_SHA256"
      --strict-format
      --max-disk-buffer 256MiB
      -o ./fixtures/
    - cargo test --release
  variables:
    FIXTURE_URL: https://fixtures.example.com/models-v3.tar.zst
    FIXTURE_SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  cache:
    paths:
      - fixtures.peel.part
      - fixtures.peel.ckpt
```

The **cache directive** retains `fixtures.peel.part` and
`fixtures.peel.ckpt` between runs. If a previous run was interrupted
partway through (timeout, runner restart), the next run resumes from
the checkpoint, saving network bandwidth and wall-clock on every retry.

## Self-hosted runner behind a corporate proxy

A frequent CI failure mode is a self-hosted runner behind an HTTPS
proxy that does TLS termination with its own CA. `peel` honours
`SSL_CERT_FILE`:

```yaml
- name: Hydrate fixtures
  env:
    HTTPS_PROXY: https://proxy.corp.example.com:8443
    SSL_CERT_FILE: /etc/ssl/certs/corp-bundle.pem
  run: peel "$FIXTURE_URL" --sha256 "$FIXTURE_SHA256" -o ./fixtures/
```

If the proxy mangles HTTP/2 (the most common cause of intermittent
hydration failures on locked-down corporate networks), force HTTP/1.1:

```yaml
run: peel "$FIXTURE_URL" --http-version h1 -o ./fixtures/
```

## Caching the extracted output

If the CI cache supports it, cache the **extracted output** directly
rather than only the sidecars:

```yaml
- uses: actions/cache@v4
  with:
    path: ./fixtures/
    key: fixtures-${{ vars.MODELS_SHA256 }}

- if: steps.cache.outputs.cache-hit != 'true'
  run: peel "$URL" --sha256 "$SHA256" -o ./fixtures/
```

Hydration runs only when the cache misses. The cache key
includes the SHA-256, so an updated fixture set automatically
invalidates the cache.

## Failing the build on upstream drift

The combination of `--sha256` + `--strict-format` is the strongest
guarantee:

| Failure | `--sha256` catches? | `--strict-format` catches? |
| --- | --- | --- |
| Upstream re-uploaded a corrupted file | ✓ | |
| Upstream serves a 200 status on a 404 HTML body | | ✓ |
| Upstream changed the format (`.tar.zst` → `.tar.gz`) | | ✓ |
| Upstream re-uploaded a legitimately-different file | ✓ | |
| Mirror is serving stale content | ✓ | |

Use both in CI. Omit them only when downloading a non-deterministic
resource by intent.

## Comparison with `actions/cache`

If the CI has a well-managed artifact cache (sized, verified,
mirrored), and the archive is small enough that download time is not
a concern, `actions/cache` (or `actions/restore-cache`, or the CI's
equivalent) is simpler. `peel` is preferable when:

- The archive is large enough that hydration time matters.
- **End-to-end** verification of the source is required, not just
  the cache.
- The CI's cache TTL is shorter than the fixture's lifetime, so cache
  misses force a re-hydration where bounded disk and resume matter.
- Integration is from outside the CI (e.g. a pre-job step in a
  test orchestrator that lacks CI-native caching).

## Exit code handling

CI scripts want to distinguish "fixture hydration failed transiently"
from "fixture is wrong":

```bash
#!/usr/bin/env bash
set -u

peel "$URL" --sha256 "$SHA256" --strict-format -o ./fixtures/
rc=$?

case "$rc" in
  0)   echo "fixtures ready"; exit 0 ;;
  1)
    # Generic failure: could be transient network, disk full, hash mismatch.
    # Check stderr to distinguish. For CI, retry once.
    echo "first attempt failed; sleeping 10s then retry"
    sleep 10
    peel "$URL" --sha256 "$SHA256" --strict-format -o ./fixtures/
    ;;
  *)
    echo "peel failed with $rc; not retrying"
    exit "$rc"
    ;;
esac
```

See [Exit codes](../exit-codes.md) for the full list.
