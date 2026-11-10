## Summary

- Add a configurable `warp.mtu` for the userspace Cloudflare WARP tunnel.
- Preserve the existing 1280-byte default when the field is absent or zero.
- Propagate the value through config normalization, hot reload, pool creation and `netstack.CreateNetTUN`.
- Surface the MTU in WARP verification failures and document reduced-MTU deployment guidance.

## Motivation

On Railway, a container path MTU of 1316 was measured. Direct HTTPS and general UDP worked, and WARP registration succeeded, but traffic through the WARP tunnel timed out during the Cloudflare trace verification. The previous fixed tunnel MTU of 1280 leaves too little room after WireGuard overhead on constrained paths.

The measured IPv4 DF path tests passed at total IP packet sizes 1228, 1280 and 1300, and failed at 1328 and 1428. WireGuard overhead is approximately 60 bytes over an IPv4 outer path and 80 bytes over an IPv6 outer path, giving approximate tunnel payload ceilings of 1256 and 1236 respectively for a 1316-byte path.

## Details

- `warp.mtu` accepts values from 1000 through 1420.
- `0` and an omitted field normalize to 1280 for backward compatibility.
- Changing the MTU during configuration reload creates a new WARP pool rather than reusing a pool created with another MTU.
- The WebUI includes the field and translations for all supported non-Chinese locales.
- Strict JSON decoding continues to reject unknown configuration fields.
- The example and README files recommend trying 1200 on Railway-like reduced-MTU networks. This is a conservative recommendation, not a claim of a completed Railway test in this environment.

## Tests

Passed:

```text
gofmt -l cmd internal webui
go vet ./...
go test ./...
CGO_ENABLED=0 go build -o opencode2api ./cmd/opencode2api
node --input-type=module --check < webui/js/*.js
node --input-type=module --check < webui/js/pages/*.js
sh -n docker-entrypoint.sh
git diff --check
```

Added unit coverage for the default/absent value, valid value, lower and upper bounds, invalid config rejection, config save/reload round-trip, and constructor validation before network registration.

Not run: Docker MTU-1316 reproduction and the Railway functional matrix, because Docker is not available in the development sandbox. No network test is claimed as successful.

## Backward compatibility

No default MTU change is made. WARP-disabled startup, config persistence, management API serialization, WebUI save/reload, and existing configurations without `warp.mtu` continue to use the prior behavior.
