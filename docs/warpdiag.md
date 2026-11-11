# `warpdiag`

`warpdiag` est un outil de diagnostic du chemin WARP userspace. Il réutilise le registrar, la construction WireGuard/netstack et la vérification de trafic du package `internal/warp`; il n’utilise ni périphérique TUN du système, ni root, ni `NET_ADMIN`.

## Compilation et exécution

```bash
go build ./cmd/warpdiag
CGO_ENABLED=0 go build ./cmd/warpdiag
go run ./cmd/warpdiag -timeout 300s
go run ./cmd/warpdiag -config config.json -timeout 300s
```

Options :

- `-config <chemin>` : configuration complète facultative. Sans cette option, l’outil utilise une configuration diagnostique minimale avec `stack=ipv6` et `mtu=1280`.
- `-timeout <durée>` : budget global, `300s` par défaut. Le rapport est toujours écrit entre `===== WARPDIAG REPORT BEGIN =====` et `===== WARPDIAG REPORT END =====` et le programme retourne 0, y compris en cas d’échec réseau.

## Séquence

L’outil affiche l’environnement, le délai d’initialisation historique du runtime (`330s`), puis effectue une seule inscription WARP. Il réutilise cette inscription pour les combinaisons IPv4/IPv6, ports WARP connus et MTU `1200`; les MTU `1280` et `1100` sont ensuite testés sur les ports/familles ayant observé un handshake.

Pour chaque tunnel, `IpcGet` est interrogé jusqu’au premier `last_handshake_time_sec`. Les tests suivants utilisent la même netstack : ICMP avec petites et grandes charges, TCP vers Cloudflare, le GET `/cdn-cgi/trace` exact de l’application et un téléchargement de 300 Ko. Des envois UDP bruts de 148, 512, 1200 et 1280 octets sont aussi affichés pour les endpoints résolus.

Avec `-config`, `application_flow` reconstruit le chemin d’exit et le probe exacts de l’application, en réutilisant l’inscription unique, et capture les logs WireGuard verbose dans la ligne de rapport correspondante.

Les erreurs réseau sont abrégées et les clés WireGuard ne sont jamais imprimées. La couche portable `net.UDPConn` ne fournit pas directement une file `IP_RECVERR`; la section `raw_udp` indique donc les erreurs d’écriture observées et précise cette limite. Les ports forcés sont appliqués par `warp.endpoint_port` dans l’application et par le paramètre de chaque cas dans le diagnostic.

## Options de correction

```json
"warp": {
  "endpoint_port": 0,
  "init_timeout_seconds": 0,
  "mtu": 1280
}
```

`endpoint_port=0` garde le port Cloudflare actuel. `init_timeout_seconds=0` garde le comportement historique : fenêtre d’enregistrement maximale de cinq minutes plus trente secondes. Une valeur explicite est bornée à 900 secondes et permet de distinguer un tunnel réellement lent d’un délai d’initialisation trop court.
