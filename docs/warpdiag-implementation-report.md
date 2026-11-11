# Rapport d’implémentation `warpdiag`

## État

Travail effectué sur `feat/warp-mtu` du fork `johndoe237/opencode2api`. Aucun changement vers `upstream`, aucune PR et aucune issue.

## Fonctionnalités livrées

- `cmd/warpdiag`, compilable par `go build ./cmd/warpdiag` et sans CGO.
- Flags exacts : `-config <chemin>` facultatif et `-timeout <durée>` avec défaut `300s`.
- Sortie bornée par `WARPDIAG REPORT BEGIN/END` et code de sortie 0 même en cas d’échec réseau.
- Une seule inscription WARP réutilisée pour toute la matrice.
- Collecte de l’environnement, des MTU d’interfaces, de l’en-tête `Date` Cloudflare et du délai historique de l’application.
- Matrice initiale de tous les ports demandés avec MTU 1200 pour IPv4 et IPv6 ; MTU 1280/1100 ensuite sur les ports ayant établi un handshake.
- Construction WireGuard userspace + netstack réelle, métriques `IpcGet` (`last_handshake_time_sec`, `tx_bytes`, `rx_bytes`), ICMP 56/1172, TCP 443, GET Trace exact, téléchargement 300 Ko.
- Contrôle UDP brut en tailles 148/512/1200/1280. Le support portable Go ne fournit pas `IP_RECVERR` directement ; le rapport l’indique plutôt que de prétendre distinguer les erreurs ICMP quand elles ne sont pas accessibles.
- Étape `application_flow` utilisant le constructeur d’exit et le probe Trace exacts de l’application, avec la même inscription déjà créée, et capture des logs WireGuard verbose.
- Verdict déterministe et configuration recommandée lorsqu’un cas fonctionne.
- Tests unitaires du parsing `IpcGet`, de l’arbre de décision, des ports et des options de configuration.

## Options de correction

Ajoutées avec défauts rétrocompatibles :

- `warp.endpoint_port` : `0` conserve le port Cloudflare, sinon port UDP 1–65535.
- `warp.init_timeout_seconds` : `0` conserve la stratégie historique ; valeur explicite jusqu’à 900 secondes.
- `warp.mtu` reste inchangé, défaut 1280.

Le délai historique réellement imposé par le runtime est actuellement `5m30s` : fenêtre d’enregistrement maximale de cinq minutes plus trente secondes. Les probes individuelles ont un timeout de cinq secondes.

## Tests locaux

Réussis :

```text
go test ./...
go vet ./...
CGO_ENABLED=0 go build -o /tmp/opencode2api ./cmd/opencode2api
CGO_ENABLED=0 go build -o /tmp/warpdiag ./cmd/warpdiag
gofmt -l cmd internal webui
node --input-type=module --check < webui/js/*.js
node --input-type=module --check < webui/js/pages/*.js
sh -n docker-entrypoint.sh
git diff --check
```

Le smoke test `go run ./cmd/warpdiag -timeout 1ms` a confirmé le contrat : code 0, marqueurs présents, erreur d’enregistrement rapportée proprement. Le réseau a volontairement été interrompu par le timeout ; aucune réussite réseau n’est revendiquée.

Docker, Railway et un endpoint WARP fonctionnel ne sont pas disponibles dans le sandbox. La matrice réelle et le test témoin hors Railway doivent donc être exécutés après déploiement, avec :

```text
go run ./cmd/warpdiag -config config.json -timeout 300s
```

Le rapport produit par cette commande est le livrable décisif à copier après le déploiement.
