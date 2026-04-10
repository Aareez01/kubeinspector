# kubeinspector

Audit Kubernetes clusters for orphaned resources, rough cost, and Ingress misconfigurations — one small binary, no agents, no dashboards.

Clusters accumulate cruft over time: PVCs whose pods were deleted, ConfigMaps nothing references, Ingresses with duplicate hosts or missing TLS. `kubeinspector` scans a namespace (or the whole cluster) and tells you what's worth cleaning up or fixing.

## Status

Early development. Not yet usable. See open issues for the roadmap.

## Planned commands

```
kubeinspector orphans     # find unused PVCs, ConfigMaps, Secrets, ReplicaSets, Services
kubeinspector ingress     # audit Ingresses for duplicate hosts, missing TLS, orphaned backends
kubeinspector cost        # rough per-namespace cost estimate from resource requests
kubeinspector audit       # run all checks and produce a combined report
```

Global flags: `--kubeconfig`, `--namespace`, `--output text|json|markdown`.

## Building from source

```sh
go build -o kubeinspector .
```

Requires Go 1.22+.

## License

MIT
