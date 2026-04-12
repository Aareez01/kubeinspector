# kubeinspector

A small CLI that audits a Kubernetes cluster for cruft, misconfigurations, and
security issues — orphaned resources, ingress problems, a rough per-namespace
cost estimate, and a security audit that catches everything from privileged
containers to crypto miners. One static binary, no agents, no dashboards, no
cluster components.

> **Status:** early but usable. All core checks are implemented and tested.
> Expect flags and output formats to stabilize over the next few releases.

---

## Why

Clusters accumulate junk over time:

- PVCs whose owning StatefulSet was deleted but the data was "kept just in case"
- ConfigMaps and Secrets nothing references anymore
- Ingresses with duplicate hosts, missing TLS, or backends pointing at Services
  that no longer exist
- Old ReplicaSets scaled to zero that nobody bothered to clean up
- Namespaces that quietly consume a surprising fraction of the compute bill
- Containers running privileged, as root, or with dangerous capabilities
- Crypto miners hiding in your cluster behind innocuous-looking pod names
- RBAC grants that give cluster-admin to non-system accounts

`kubeinspector` scans for all of this and prints a focused report. It's
designed to be run on-demand by a human, or in CI as a gate on a PR that
changes cluster state.

It is **not** a replacement for Kubecost, Polaris, kube-bench, or any of the
bigger ecosystem tools. It's the small, scriptable version you reach for
when you just want to know what's wrong in the next 30 seconds.

---

## Install

### From source

```sh
go install github.com/Aareez01/kubeinspector@latest
```

Requires Go 1.22+. The resulting binary uses your current `$KUBECONFIG` /
`~/.kube/config` exactly like `kubectl` does.

### Build locally

```sh
git clone https://github.com/Aareez01/kubeinspector
cd kubeinspector
go build -o kubeinspector .
./kubeinspector version
```

---

## Usage

```
kubeinspector [command] [flags]

Commands:
  orphans     Find unused PVCs, ConfigMaps, Secrets, ReplicaSets, Services
  ingress     Audit Ingresses for duplicate hosts, missing TLS, broken backends
  cost        Rough per-namespace monthly cost estimate from resource requests
  security    Audit pods and RBAC for security issues, crypto miners, resource abuse
  audit       Run all checks and produce a combined report
  version     Print the version

Global flags:
  -n, --namespace string    namespace to scan (default: current context)
  -A, --all-namespaces      scan all namespaces
  -o, --output string       output format: text, json, markdown (default "text")
      --kubeconfig string   path to kubeconfig (defaults to $KUBECONFIG or ~/.kube/config)
```

### Find orphaned resources

```sh
$ kubeinspector orphans -n payments
KIND                   NAMESPACE  NAME                    AGE      REASON
PersistentVolumeClaim  payments   redis-data-old-0        42d      not mounted by any pod
ConfigMap              payments   feature-flags-v1        18d      not referenced by any pod or ingress
Secret                 payments   stripe-staging-key      91d      not referenced by any pod or ingress
ReplicaSet             payments   api-7c9f8b4d            14d      scaled to zero, owned by Deployment (rollback history)
Service                payments   api-canary              22d      selector matches no ready pods
```

Exempt a resource from being flagged by annotating it:

```sh
kubectl annotate pvc redis-data-old-0 kubeinspector.io/keep=true
```

### Audit Ingresses

```sh
$ kubeinspector ingress -A
SEVERITY  NAMESPACE  INGRESS      RULE                MESSAGE
error     web        site-a       example.com/        duplicate host+path also claimed by [web/site-b]
error     web        site-b       example.com/        duplicate host+path also claimed by [web/site-a]
error     api        public-api   api.example.com/    TLS secret "api-tls" does not exist
warning   docs       handbook                         hosts defined but no spec.tls block — traffic will be plain HTTP
error     web        legacy       old.example.com/    backend Service "frontend-v1" does not exist
```

### Estimate cost

```sh
$ kubeinspector cost -A
NAMESPACE  CPU         MEMORY     STORAGE     CPU $/mo  MEM $/mo  STORAGE $/mo  TOTAL $/mo
data       12.50 cores 64.00 GiB  2048.0 GiB  288.35    213.05    163.84        665.24
payments    4.00 cores 16.00 GiB   500.0 GiB   92.27     53.26     40.00        185.53
web         2.25 cores  8.00 GiB    80.0 GiB   51.90     26.63      6.40         84.93
                                              TOTAL (USD)                       935.70
```

Customize rates via `--pricing pricing.yaml`:

```yaml
cpu_core_hour: 0.0316
memory_gb_hour: 0.00456
storage_gb_month:
  gp3: 0.08
  standard: 0.04
  io2: 0.125
currency: USD
```

This is a **rough** estimate based on pod requests and PVC storage requests,
not actual usage. Use it as a signal, not as a billing source of truth.

### Security audit

```sh
$ kubeinspector security -A
SEVERITY  KIND                NAMESPACE  NAME         CONTAINER  CHECK                 MESSAGE
critical  Pod                 app        api-server   api        privileged             container runs in privileged mode
critical  Pod                 app        api-server   api        dangerous-cap          adds dangerous capability SYS_ADMIN
critical  Pod                 mining     suspicious   worker     crypto-miner-image     image "xmrig/xmrig:latest" matches known mining software
critical  Pod                 mining     suspicious   worker     crypto-miner-command   command/args contain mining-related pattern "stratum+tcp://"
warning   Pod                 web        frontend     nginx      run-as-root            container may run as root
warning   Pod                 web        frontend     nginx      writable-rootfs        root filesystem is writable
warning   Pod                 web        frontend     nginx      no-cpu-limit           no CPU limit set — can starve neighboring pods
warning   Pod                 web        frontend     nginx      secret-in-env          secret "db-creds" exposed via env var DB_PASSWORD
warning   Pod                 data       analytics    spark      excessive-cpu-request  requests 16.0 CPU cores (threshold: 8)
warning   Role                app                     dev-all                           rule grants wildcard permissions: resources=[*] verbs=[get list]
critical  ClusterRoleBinding                          dev-admin  cluster-admin-binding  User "intern@example.com" bound to cluster-admin
```

**Checks performed:**

| Category | Check | Severity |
|---|---|---|
| Pod | Privileged containers | critical |
| Pod | Running as root | warning |
| Pod | Host network/PID/IPC | critical |
| Pod | Dangerous capabilities (SYS_ADMIN, NET_ADMIN, NET_RAW, ALL, ...) | critical |
| Pod | Writable root filesystem | warning |
| Pod | Missing CPU/memory limits | warning |
| Pod | Default ServiceAccount with auto-mounted token | warning |
| Pod | Secrets exposed via env vars | warning |
| Miner | Known crypto mining images (xmrig, cpuminer, etc.) | critical |
| Miner | Mining-related environment variables (POOL, WALLET, STRATUM) | warning |
| Miner | Mining-related commands/args (stratum://, --algo, pool URLs) | critical |
| Resource | Excessive CPU/memory requests or limits (>8 cores / >32 GiB) | warning |
| Resource | Huge limit/request ratio (>10x — burst can starve neighbors) | warning |
| RBAC | Non-system cluster-admin bindings | critical |
| RBAC | Roles with wildcard permissions | warning |

### Run everything at once

```sh
kubeinspector audit -A
kubeinspector audit -A -o json | jq '.ingress[] | select(.severity=="error")'
kubeinspector audit -A -o markdown > audit.md
```

Exit codes: `0` clean, `1` warnings, `2` errors. Good for CI gating.

---

## Use in CI

Post an audit report as a PR comment on every change to your cluster
manifests:

```yaml
name: cluster audit
on: pull_request
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/k8s-set-context@v4
        with:
          kubeconfig: ${{ secrets.KUBECONFIG }}
      - run: go install github.com/Aareez01/kubeinspector@latest
      - name: Run audit
        run: kubeinspector audit -A -o markdown > audit.md
      - uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: audit.md
```

---

## Design notes

- **No custom controller.** Everything is on-demand and read-only; it never
  writes to your cluster.
- **`client-go/kubernetes/fake` in tests.** Every check has a fake-client
  unit test, so contributors can run the suite offline without a cluster.
- **Grace periods on every check.** A PVC that's 2 minutes old isn't an
  orphan — it's a rollout in progress. Defaults are tuned to avoid noise;
  override per-check if you want.
- **Opt-out via annotation.** Anything with `kubeinspector.io/keep=true` is
  skipped, so you can silence individual intentional exceptions without
  disabling a whole check.

---

## Contributing

Bugs and feature ideas are welcome — open an issue describing the problem
you're trying to solve, not the implementation. PRs for new checks should
come with fake-client tests.

## License

MIT — see [LICENSE](./LICENSE).
