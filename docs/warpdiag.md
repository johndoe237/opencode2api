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

L’outil affiche l’environnement, le délai d’initialisation historique du runtime (`330s`), puis effectue une seule inscription WARP. Il réutilise cette inscription pour les 16 combinaisons famille interne `{ipv4, ipv6}` × famille endpoint externe `{ipv4, ipv6}` × MTU `{1280, 1200}` × `tcp_mss` `{0, 1160}`, toujours sur le port `2408`.

Pour chaque tunnel, `IpcGet` est interrogé jusqu’au premier `last_handshake_time_sec`, puis relu après les sondes afin de rapporter les compteurs finaux. Les tests suivants utilisent la même netstack : TCP vers Cloudflare, le GET `/cdn-cgi/trace` exact de l’application et un téléchargement de 300 Ko. La sonde ICMP a été supprimée car elle échouait même lorsque TCP fonctionnait. Des envois UDP bruts de 148, 512, 1200 et 1280 octets sont affichés pour au plus un endpoint 2408 par famille externe.

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

`tcp_mss=0` garde le comportement historique. `tcp_mss=1160` réécrit uniquement les options MSS des SYN/SYN-ACK TCP dans les deux directions et recalcule le checksum avec le pseudo-en-tête IPv4 ou IPv6. La netstack reste à MTU 1280 ou plus pour préserver la contrainte IPv6 ; le clamp limite les paquets TCP internes. `endpoint_port=0` garde le port Cloudflare actuel. `init_timeout_seconds=0` garde le comportement historique : fenêtre d’enregistrement maximale de cinq minutes plus trente secondes. Une valeur explicite est bornée à 900 secondes.
