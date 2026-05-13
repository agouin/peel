# Kubernetes init container

A Kubernetes init container that hydrates a PersistentVolumeClaim from
a remote archive is a primary `peel` use case. The PVC is sized for
the **extracted** contents plus a small download window, not for
`compressed + extracted`. Resume across pod restarts is automatic.

## The minimal Pod spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: model-server
spec:
  volumes:
    - name: model
      persistentVolumeClaim:
        claimName: model-pvc

  initContainers:
    - name: hydrate
      image: ghcr.io/agouin/peel:latest
      args:
        - https://models.example.com/llama-3.tar.zst
        - --sha256
        - ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        - --max-bandwidth
        - 200MB/s
        - -o
        - /model/
      volumeMounts:
        - name: model
          mountPath: /model

  containers:
    - name: app
      image: ghcr.io/example/model-server
      volumeMounts:
        - name: model
          mountPath: /model
          readOnly: true
```

Properties of this configuration:

- **PVC sizing**: `extracted_size + ~300 MB`, not `archive_size +
  extracted_size`. A 40 GiB extracted model fits on a 41 GiB PVC.
- **Resume across pod restarts**: if the init container OOM-kills or
  the node reboots mid-extraction, the next pod restart picks up at
  the last checkpoint. The sidecars (`.peel.part`, `.peel.ckpt`) live
  on the PVC, so they survive the restart.
- **Integrity**: `--sha256` verifies the source end-to-end. A
  corrupted upstream produces a clear failure rather than a
  silently-bad model.
- **Bandwidth limiting**: `--max-bandwidth 200MB/s` prevents the
  hydration from saturating shared cluster network.

## Sizing the PVC

Roughly:

```text
PVC size = extracted_size                 # the model / dataset
         + --max-disk-buffer (default 1G) # in-flight window
         + ~100 MiB                       # checkpoint + filesystem overhead
         + some slack                     # for the workload to grow
```

If disk is tight, lower `--max-disk-buffer`:

```yaml
args:
  - https://models.example.com/llama-3.tar.zst
  - --max-disk-buffer
  - 256MiB
  - -o
  - /model/
```

This tightens the lookahead floor to 256 MiB. The decoder blocks
briefly when the network outruns it. There is no correctness penalty.

## Sidecars on ephemeral scratch

To keep per-pod sidecars off a shared PVC, place them on the
container's writable scratch layer:

```yaml
args:
  - https://models.example.com/llama-3.tar.zst
  - --workdir
  - /tmp/peel-state
  - -o
  - /model/
volumeMounts:
  - name: model
    mountPath: /model
```

Tradeoff: the sidecars do not survive a pod restart, so resume is
lost. The next pod restart re-fetches from scratch. This is
acceptable for short-running hydration and unsuitable for large
archives over flaky networks.

## RBAC / network policy

`peel` makes outbound HTTP/HTTPS to the supplied URLs. It does
not talk to the Kubernetes API. The cluster's egress policy must
allow the origin host(s). The `peel` container itself requires no
elevated permissions: it runs as a normal user and requires no
`CAP_*` capabilities.

## Multi-mirror in-cluster

For intra-cluster mirrors of the same archive (e.g. a `MinIO` bucket
inside the cluster plus a public origin outside), use
[`--mirror`](../multi-mirror.md):

```yaml
args:
  - https://internal-cache.svc.cluster.local/llama-3.tar.zst
  - --mirror
  - https://models.example.com/llama-3.tar.zst
  - --sha256
  - ba7816bf...
  - -o
  - /model/
```

`peel` prefers the internal mirror (faster, no egress cost) and
falls back to the public origin only if the internal one fails.

## io_uring inside the pod

By default on Linux 5.6+, `peel` uses `io_uring` for sockets.
**cri-o's default seccomp profile blocks `io_uring_*` syscalls**, so
in practice `peel` logs one fallback warning at startup and continues
with the blocking backend. Two options exist for enabling `io_uring`:

1. **Loosen the seccomp profile** (requires
   `securityContext.seccompProfile.type: Unconfined` or a custom
   profile that allows `io_uring_*`).
2. **Accept the fallback**. `peel` operates correctly without
   `io_uring`, with reduced throughput on high-bandwidth links.

Most clusters take option 2. Revisit if the workload is
bandwidth-bound.

## A complete example with secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: archive-password
type: Opaque
stringData:
  password: my-archive-password

---
apiVersion: v1
kind: Pod
metadata:
  name: hydrated-app
spec:
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: data-pvc

  initContainers:
    - name: hydrate
      image: ghcr.io/agouin/peel:latest
      env:
        - name: PEEL_PW
          valueFrom:
            secretKeyRef:
              name: archive-password
              key: password
      args:
        - https://example.com/secret.tar.zst
        - --password-from
        - env:PEEL_PW
        - --sha256
        - ba7816bf...
        - -o
        - /data/
      volumeMounts:
        - name: data
          mountPath: /data

  containers:
    - name: app
      image: ghcr.io/example/app
      volumeMounts:
        - name: data
          mountPath: /data
          readOnly: true
```

The password is mounted as an env var via the standard Secret
mechanism. `peel` reads it via `--password-from env:PEEL_PW`. The
secret never appears on the command line.

## Comparison with `curl + tar -x`

The naive shape, which has the problems described below:

```yaml
# NOT recommended
- name: hydrate
  image: alpine
  command: [sh, -c]
  args:
    - |
      apk add curl tar zstd
      curl -fL "$URL" -o /tmp/data.tar.zst
      tar -I zstd -xf /tmp/data.tar.zst -C /data/
      rm /tmp/data.tar.zst
```

Problems:

- **PVC size**: peak disk = `archive_size + extracted_size`. A 40 GiB
  extracted model needs an 80+ GiB PVC.
- **No resume**: OOM-kill mid-download restarts from byte 0.
- **No integrity**: curl does not verify a hash. Layering `sha256sum`
  on afterwards is a separate step.
- **Single TCP stream**: parallel ranged GETs are faster on
  high-RTT origins.
- **Image bulk**: `apk add` pulls packages every pod restart.

A single `peel` invocation addresses all of these.
