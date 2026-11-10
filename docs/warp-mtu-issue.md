# WARP userspace tunnel verification times out on reduced-MTU networks such as Railway

## Context

When `warp.enabled: true` is used on Railway, opencode2api v1.4.7 can fail during startup while verifying the WARP egress:

```text
failed to initialize runtime ... initialize WARP egress: verify WARP ipv4 egress:
Get "https://1.1.1.1/cdn-cgi/trace": context deadline exceeded
```

The same symptom can occur with `stack: "ipv6"` while probing `https://[2606:4700:4700::1111]/cdn-cgi/trace`.

The deployment measurements were:

- WARP configuration applied as `enabled=true`, `pool_size=1`, `stack=ipv4`.
- Direct IPv4 and IPv6 HTTPS worked with WARP disabled.
- General UDP worked, including DNS responses up to 1139 bytes.
- The container interface had MTU 1316.
- IPv4 DF path-MTU tests passed at total IP packet sizes 1228, 1280 and 1300, and failed at 1328 and 1428.
- WARP account registration over HTTPS succeeded, but traffic through the tunnel timed out.

## Suspected cause

The userspace tunnel currently creates the gVisor TUN with a fixed MTU of 1280. WireGuard adds approximately 60 bytes of outer IPv4 overhead or 80 bytes of outer IPv6 overhead, so a path MTU of 1316 leaves roughly 1256 bytes for IPv4 or 1236 bytes for IPv6 tunnel traffic. Small handshakes can pass while larger TLS packets are lost.

An independent UDP filtering issue should still be ruled out when validating a deployment.

## Proposed fix

Add a configurable `warp.mtu` option:

- Preserve the historical 1280-byte behavior when absent or zero.
- Validate the value in the range 1000–1420.
- Pass the value to `netstack.CreateNetTUN`.
- Include it in WARP pool reuse identity so hot reloads rebuild the pool when it changes.
- Include the selected MTU in WARP verification errors with a hint to lower it on reduced-MTU paths.
- Expose it through the strict config loader, management API, WebUI, example config and documentation.

For Railway, `1200` is the conservative recommended starting point based on the supplied path-MTU measurements. The lower value has a small overhead/throughput trade-off. The exact highest working value remains platform-dependent and must be measured on the deployment.

## Compatibility

Existing configurations without `warp.mtu` continue to use 1280, so WARP-disabled configurations and existing WARP deployments retain their previous behavior.

## Validation

The fork implementation was checked with:

- `go test ./...`
- `go vet ./...`
- `CGO_ENABLED=0 go build -o opencode2api ./cmd/opencode2api`
- `gofmt -l cmd internal webui`
- WebUI `node --input-type=module --check`
- `sh -n docker-entrypoint.sh`

Docker-based Railway functional tests could not be run in the development sandbox because Docker was unavailable; they should be run on Railway or a Docker-capable host.
